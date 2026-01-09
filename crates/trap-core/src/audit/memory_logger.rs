// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! In-memory audit logger for testing and development.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use super::error::AuditResult;
use super::types::{AuditAction, AuditFilter, AuditLog, AuditSeverity};
use super::AuditLogger;

// =============================================================================
// In-Memory Audit Logger
// =============================================================================

/// In-memory audit logger for testing and development.
///
/// Stores all audit entries in memory, supporting both logging and querying.
/// This is primarily intended for testing, but can also be useful for
/// development and debugging.
///
/// # Thread Safety
///
/// This logger is thread-safe and can be shared across multiple tasks.
/// Entries are stored in a `RwLock`-protected vector.
///
/// # Example
///
/// ```rust,ignore
/// use trap_core::audit::{InMemoryAuditLogger, AuditLog, AuditAction, AuditFilter};
///
/// let logger = InMemoryAuditLogger::new();
///
/// // Log entries
/// logger.log(AuditLog::login("admin", None, true)).await?;
/// logger.log(AuditLog::login("user", None, false)).await?;
///
/// // Query entries
/// let logins = logger.query(AuditFilter::new().action(AuditAction::Login)).await?;
/// assert_eq!(logins.len(), 2);
///
/// // Access entries directly
/// assert_eq!(logger.len(), 2);
///
/// // Clear entries
/// logger.clear();
/// assert!(logger.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct InMemoryAuditLogger {
    /// Stored log entries.
    logs: Arc<RwLock<Vec<AuditLog>>>,
    /// Maximum number of entries to keep (0 = unlimited).
    max_entries: usize,
    /// Name of this logger.
    name: String,
}

impl Default for InMemoryAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryAuditLogger {
    /// Creates a new in-memory logger with unlimited capacity.
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            max_entries: 0,
            name: "memory".to_string(),
        }
    }

    /// Creates a new in-memory logger with a maximum capacity.
    ///
    /// When the capacity is reached, oldest entries are removed.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::with_capacity(max_entries.min(10000)))),
            max_entries,
            name: "memory".to_string(),
        }
    }

    /// Sets the name of this logger.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Returns all logged entries.
    pub fn entries(&self) -> Vec<AuditLog> {
        self.logs.read().clone()
    }

    /// Returns entries matching a predicate.
    pub fn entries_where<F>(&self, predicate: F) -> Vec<AuditLog>
    where
        F: Fn(&AuditLog) -> bool,
    {
        self.logs.read().iter().filter(|l| predicate(l)).cloned().collect()
    }

    /// Returns the last N entries.
    pub fn last_entries(&self, n: usize) -> Vec<AuditLog> {
        let logs = self.logs.read();
        logs.iter().rev().take(n).cloned().collect()
    }

    /// Clears all entries.
    pub fn clear(&self) {
        self.logs.write().clear();
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.logs.read().len()
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.logs.read().is_empty()
    }

    /// Returns entries for a specific user.
    pub fn entries_for_user(&self, user_id: &str) -> Vec<AuditLog> {
        self.entries_where(|l| l.user_id.as_deref() == Some(user_id))
    }

    /// Returns entries for a specific action.
    pub fn entries_for_action(&self, action: AuditAction) -> Vec<AuditLog> {
        self.entries_where(|l| l.action == action)
    }

    /// Returns entries at or above a severity level.
    pub fn entries_by_severity(&self, min_severity: AuditSeverity) -> Vec<AuditLog> {
        self.entries_where(|l| l.severity.level() >= min_severity.level())
    }

    /// Returns security-sensitive entries.
    pub fn security_events(&self) -> Vec<AuditLog> {
        self.entries_where(|l| l.action.is_security_sensitive())
    }

    /// Returns failed entries.
    pub fn failed_entries(&self) -> Vec<AuditLog> {
        self.entries_where(|l| l.result.is_failure() || l.result.is_denied())
    }

    /// Checks if any entry matches the predicate.
    pub fn has_entry<F>(&self, predicate: F) -> bool
    where
        F: Fn(&AuditLog) -> bool,
    {
        self.logs.read().iter().any(predicate)
    }

    /// Counts entries matching a predicate.
    pub fn count_where<F>(&self, predicate: F) -> usize
    where
        F: Fn(&AuditLog) -> bool,
    {
        self.logs.read().iter().filter(|l| predicate(l)).count()
    }
}

#[async_trait]
impl AuditLogger for InMemoryAuditLogger {
    async fn log(&self, entry: AuditLog) -> AuditResult<()> {
        let mut logs = self.logs.write();

        // Enforce capacity limit
        if self.max_entries > 0 && logs.len() >= self.max_entries {
            logs.remove(0);
        }

        logs.push(entry);
        Ok(())
    }

    async fn log_batch(&self, entries: Vec<AuditLog>) -> AuditResult<()> {
        let mut logs = self.logs.write();

        for entry in entries {
            if self.max_entries > 0 && logs.len() >= self.max_entries {
                logs.remove(0);
            }
            logs.push(entry);
        }

        Ok(())
    }

    async fn query(&self, filter: AuditFilter) -> AuditResult<Vec<AuditLog>> {
        let logs = self.logs.read();
        let mut results: Vec<AuditLog> = logs.iter().filter(|log| filter.matches(log)).cloned().collect();

        // Sort by timestamp
        if filter.descending {
            results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        } else {
            results.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        }

        // Apply offset and limit
        if let Some(offset) = filter.offset {
            results = results.into_iter().skip(offset).collect();
        }

        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    async fn flush(&self) -> AuditResult<()> {
        // No-op for in-memory logger
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn supports_query(&self) -> bool {
        true
    }

    async fn health_check(&self) -> bool {
        true
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{ActionResult, AuditResource};

    #[tokio::test]
    async fn test_memory_logger_basic() {
        let logger = InMemoryAuditLogger::new();

        assert!(logger.is_empty());

        let log = AuditLog::new(
            AuditAction::Write,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        );

        logger.log(log).await.unwrap();

        assert_eq!(logger.len(), 1);
        assert!(!logger.is_empty());
    }

    #[tokio::test]
    async fn test_memory_logger_batch() {
        let logger = InMemoryAuditLogger::new();

        let logs: Vec<AuditLog> = (0..10)
            .map(|i| {
                AuditLog::new(
                    AuditAction::Write,
                    AuditResource::device(format!("plc-{:03}", i)),
                    ActionResult::Success,
                )
            })
            .collect();

        logger.log_batch(logs).await.unwrap();

        assert_eq!(logger.len(), 10);
    }

    #[tokio::test]
    async fn test_memory_logger_capacity() {
        let logger = InMemoryAuditLogger::with_capacity(5);

        for i in 0..10 {
            let log = AuditLog::new(
                AuditAction::Write,
                AuditResource::device(format!("plc-{:03}", i)),
                ActionResult::Success,
            );
            logger.log(log).await.unwrap();
        }

        // Should only keep last 5 entries
        assert_eq!(logger.len(), 5);

        // First entry should be plc-005 (entries 0-4 were removed)
        let entries = logger.entries();
        assert!(entries[0].resource.resource_id.contains("plc-005"));
    }

    #[tokio::test]
    async fn test_memory_logger_query() {
        let logger = InMemoryAuditLogger::new();

        // Add various entries
        logger
            .log(
                AuditLog::new(
                    AuditAction::Login,
                    AuditResource::user("admin"),
                    ActionResult::Success,
                )
                .with_user("admin", None),
            )
            .await
            .unwrap();

        logger
            .log(
                AuditLog::new(
                    AuditAction::Write,
                    AuditResource::device("plc-001"),
                    ActionResult::Success,
                )
                .with_user("admin", None),
            )
            .await
            .unwrap();

        logger
            .log(
                AuditLog::new(
                    AuditAction::Login,
                    AuditResource::user("user"),
                    ActionResult::failure("Invalid credentials"),
                )
                .with_user("user", None),
            )
            .await
            .unwrap();

        // Query all logins
        let logins = logger
            .query(AuditFilter::new().action(AuditAction::Login))
            .await
            .unwrap();
        assert_eq!(logins.len(), 2);

        // Query by user
        let admin_logs = logger
            .query(AuditFilter::new().user("admin"))
            .await
            .unwrap();
        assert_eq!(admin_logs.len(), 2);

        // Query with limit
        let limited = logger
            .query(AuditFilter::new().limit(2))
            .await
            .unwrap();
        assert_eq!(limited.len(), 2);
    }

    #[tokio::test]
    async fn test_memory_logger_helpers() {
        let logger = InMemoryAuditLogger::new();

        logger.log(AuditLog::login("admin", None, true)).await.unwrap();
        logger.log(AuditLog::login("user", None, false)).await.unwrap();
        logger
            .log(AuditLog::new(
                AuditAction::Write,
                AuditResource::device("plc-001"),
                ActionResult::Success,
            ))
            .await
            .unwrap();

        // Test helper methods
        assert_eq!(logger.entries_for_action(AuditAction::Login).len(), 2);
        assert_eq!(logger.security_events().len(), 2); // Both logins are security events
        assert_eq!(logger.failed_entries().len(), 1);
        assert!(logger.has_entry(|l| l.action == AuditAction::Write));
        assert_eq!(logger.count_where(|l| l.action == AuditAction::Login), 2);
    }

    #[tokio::test]
    async fn test_memory_logger_clear() {
        let logger = InMemoryAuditLogger::new();

        logger.log(AuditLog::login("admin", None, true)).await.unwrap();
        logger.log(AuditLog::login("user", None, true)).await.unwrap();

        assert_eq!(logger.len(), 2);

        logger.clear();

        assert!(logger.is_empty());
    }

    #[tokio::test]
    async fn test_memory_logger_clone() {
        let logger1 = InMemoryAuditLogger::new();
        let logger2 = logger1.clone();

        logger1.log(AuditLog::login("admin", None, true)).await.unwrap();

        // Both should see the same entries (shared Arc)
        assert_eq!(logger1.len(), 1);
        assert_eq!(logger2.len(), 1);
    }

    #[test]
    fn test_supports_query() {
        let logger = InMemoryAuditLogger::new();
        assert!(logger.supports_query());
    }
}
