// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Composite audit logger that chains multiple loggers together.

use std::sync::Arc;

use async_trait::async_trait;

use super::error::{AuditError, AuditResult};
use super::types::{AuditFilter, AuditLog};
use super::AuditLogger;

// =============================================================================
// Composite Audit Logger
// =============================================================================

/// A composite logger that forwards entries to multiple underlying loggers.
///
/// This is useful for scenarios where you want to:
/// - Write to both a file and a remote system
/// - Send security-sensitive events to a separate destination
/// - Fan out audit logs to multiple consumers
///
/// # Error Handling
///
/// By default, failures in individual loggers don't prevent other loggers from
/// receiving entries. The composite logger continues to forward to all loggers
/// and collects errors at the end.
///
/// # Example
///
/// ```rust,ignore
/// use trap_core::audit::{
///     CompositeAuditLogger, FileAuditLogger, InMemoryAuditLogger, RotationConfig,
/// };
///
/// let file_logger = FileAuditLogger::new("audit.log", RotationConfig::daily())?;
/// let memory_logger = InMemoryAuditLogger::new();
///
/// let composite = CompositeAuditLogger::new()
///     .add(file_logger)
///     .add(memory_logger)
///     .fail_fast(false); // Continue on individual failures
///
/// // Logs will be written to both loggers
/// composite.log(entry).await?;
/// ```
pub struct CompositeAuditLogger {
    /// The underlying loggers.
    loggers: Vec<Arc<dyn AuditLogger>>,
    /// Whether to fail fast on the first error.
    fail_fast: bool,
    /// Name of this composite logger.
    name: String,
}

impl CompositeAuditLogger {
    /// Creates a new empty composite logger.
    pub fn new() -> Self {
        Self {
            loggers: Vec::new(),
            fail_fast: false,
            name: "composite".to_string(),
        }
    }

    /// Adds a logger to the chain.
    pub fn add<L: AuditLogger + 'static>(mut self, logger: L) -> Self {
        self.loggers.push(Arc::new(logger));
        self
    }

    /// Adds a logger wrapped in an Arc.
    pub fn add_arc(mut self, logger: Arc<dyn AuditLogger>) -> Self {
        self.loggers.push(logger);
        self
    }

    /// Sets whether to fail fast on the first error.
    ///
    /// When `true`, the first error will abort the operation.
    /// When `false` (default), all loggers will be tried and errors collected.
    pub fn fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// Sets the name of this composite logger.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Returns the number of loggers in this composite.
    pub fn len(&self) -> usize {
        self.loggers.len()
    }

    /// Returns `true` if this composite has no loggers.
    pub fn is_empty(&self) -> bool {
        self.loggers.is_empty()
    }

    /// Returns an iterator over the logger names.
    pub fn logger_names(&self) -> impl Iterator<Item = &str> {
        self.loggers.iter().map(|l| l.name())
    }
}

impl Default for CompositeAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditLogger for CompositeAuditLogger {
    async fn log(&self, entry: AuditLog) -> AuditResult<()> {
        let mut errors = Vec::new();

        for logger in &self.loggers {
            let result = logger.log(entry.clone()).await;

            if let Err(e) = result {
                if self.fail_fast {
                    return Err(e);
                }
                errors.push((logger.name().to_string(), e));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            let error_msg = errors
                .iter()
                .map(|(name, e)| format!("{}: {}", name, e))
                .collect::<Vec<_>>()
                .join("; ");

            Err(AuditError::batch_failed(error_msg, errors.len()))
        }
    }

    async fn log_batch(&self, entries: Vec<AuditLog>) -> AuditResult<()> {
        let mut errors = Vec::new();

        for logger in &self.loggers {
            let result = logger.log_batch(entries.clone()).await;

            if let Err(e) = result {
                if self.fail_fast {
                    return Err(e);
                }
                errors.push((logger.name().to_string(), e));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            let error_msg = errors
                .iter()
                .map(|(name, e)| format!("{}: {}", name, e))
                .collect::<Vec<_>>()
                .join("; ");

            Err(AuditError::batch_failed(error_msg, errors.len()))
        }
    }

    async fn query(&self, filter: AuditFilter) -> AuditResult<Vec<AuditLog>> {
        // Try each logger that supports querying until one succeeds
        for logger in &self.loggers {
            if logger.supports_query() {
                match logger.query(filter.clone()).await {
                    Ok(results) => return Ok(results),
                    Err(e) => {
                        tracing::debug!(
                            logger = logger.name(),
                            error = %e,
                            "Query failed, trying next logger"
                        );
                    }
                }
            }
        }

        // No logger supports querying or all queries failed
        Err(AuditError::query_not_supported("CompositeAuditLogger"))
    }

    async fn flush(&self) -> AuditResult<()> {
        let mut errors = Vec::new();

        for logger in &self.loggers {
            if let Err(e) = logger.flush().await {
                errors.push((logger.name().to_string(), e));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            let error_msg = errors
                .iter()
                .map(|(name, e)| format!("{}: {}", name, e))
                .collect::<Vec<_>>()
                .join("; ");

            Err(AuditError::batch_failed(error_msg, errors.len()))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn supports_query(&self) -> bool {
        self.loggers.iter().any(|l| l.supports_query())
    }

    async fn health_check(&self) -> bool {
        // All loggers must be healthy
        for logger in &self.loggers {
            if !logger.health_check().await {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Debug for CompositeAuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeAuditLogger")
            .field("name", &self.name)
            .field("loggers", &self.loggers.iter().map(|l| l.name()).collect::<Vec<_>>())
            .field("fail_fast", &self.fail_fast)
            .finish()
    }
}

// =============================================================================
// Filtering Logger
// =============================================================================

/// A logger that filters entries before forwarding to an inner logger.
///
/// This is useful for routing specific types of events to specific destinations.
///
/// # Example
///
/// ```rust,ignore
/// use trap_core::audit::{FilteringLogger, FileAuditLogger, AuditAction};
///
/// // Only log security events to this logger
/// let security_logger = FilteringLogger::new(file_logger)
///     .filter(|log| log.action.is_security_sensitive());
/// ```
pub struct FilteringLogger<F> {
    inner: Arc<dyn AuditLogger>,
    filter: F,
    name: String,
}

impl<F> FilteringLogger<F>
where
    F: Fn(&AuditLog) -> bool + Send + Sync,
{
    /// Creates a new filtering logger.
    pub fn new<L: AuditLogger + 'static>(inner: L, filter: F) -> Self {
        Self {
            inner: Arc::new(inner),
            filter,
            name: "filtering".to_string(),
        }
    }

    /// Sets the name of this logger.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

#[async_trait]
impl<F> AuditLogger for FilteringLogger<F>
where
    F: Fn(&AuditLog) -> bool + Send + Sync,
{
    async fn log(&self, entry: AuditLog) -> AuditResult<()> {
        if (self.filter)(&entry) {
            self.inner.log(entry).await
        } else {
            Ok(())
        }
    }

    async fn log_batch(&self, entries: Vec<AuditLog>) -> AuditResult<()> {
        let filtered: Vec<AuditLog> = entries
            .into_iter()
            .filter(|e| (self.filter)(e))
            .collect();

        if filtered.is_empty() {
            Ok(())
        } else {
            self.inner.log_batch(filtered).await
        }
    }

    async fn query(&self, filter: AuditFilter) -> AuditResult<Vec<AuditLog>> {
        self.inner.query(filter).await
    }

    async fn flush(&self) -> AuditResult<()> {
        self.inner.flush().await
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn supports_query(&self) -> bool {
        self.inner.supports_query()
    }

    async fn health_check(&self) -> bool {
        self.inner.health_check().await
    }
}

impl<F> std::fmt::Debug for FilteringLogger<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilteringLogger")
            .field("name", &self.name)
            .field("inner", &self.inner.name())
            .finish()
    }
}

// =============================================================================
// Tee Logger
// =============================================================================

/// A logger that writes to two loggers simultaneously.
///
/// Unlike `CompositeAuditLogger`, this is optimized for exactly two loggers
/// and provides type-safe access to both.
pub struct TeeLogger<A, B> {
    primary: A,
    secondary: B,
    name: String,
}

impl<A, B> TeeLogger<A, B>
where
    A: AuditLogger,
    B: AuditLogger,
{
    /// Creates a new tee logger.
    pub fn new(primary: A, secondary: B) -> Self {
        Self {
            primary,
            secondary,
            name: "tee".to_string(),
        }
    }

    /// Sets the name of this logger.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Returns a reference to the primary logger.
    pub fn primary(&self) -> &A {
        &self.primary
    }

    /// Returns a reference to the secondary logger.
    pub fn secondary(&self) -> &B {
        &self.secondary
    }
}

#[async_trait]
impl<A, B> AuditLogger for TeeLogger<A, B>
where
    A: AuditLogger,
    B: AuditLogger,
{
    async fn log(&self, entry: AuditLog) -> AuditResult<()> {
        // Log to both, collecting errors
        let primary_result = self.primary.log(entry.clone()).await;
        let secondary_result = self.secondary.log(entry).await;

        match (primary_result, secondary_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) => Err(e),
            (Ok(()), Err(e)) => Err(e),
            (Err(e1), Err(e2)) => Err(AuditError::batch_failed(
                format!("{}: {}; {}: {}", self.primary.name(), e1, self.secondary.name(), e2),
                2,
            )),
        }
    }

    async fn query(&self, filter: AuditFilter) -> AuditResult<Vec<AuditLog>> {
        // Try primary first, then secondary
        if self.primary.supports_query() {
            self.primary.query(filter).await
        } else if self.secondary.supports_query() {
            self.secondary.query(filter).await
        } else {
            Err(AuditError::query_not_supported("TeeLogger"))
        }
    }

    async fn flush(&self) -> AuditResult<()> {
        let primary_result = self.primary.flush().await;
        let secondary_result = self.secondary.flush().await;

        match (primary_result, secondary_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(e),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn supports_query(&self) -> bool {
        self.primary.supports_query() || self.secondary.supports_query()
    }

    async fn health_check(&self) -> bool {
        self.primary.health_check().await && self.secondary.health_check().await
    }
}

impl<A, B> std::fmt::Debug for TeeLogger<A, B>
where
    A: AuditLogger,
    B: AuditLogger,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeeLogger")
            .field("name", &self.name)
            .field("primary", &self.primary.name())
            .field("secondary", &self.secondary.name())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        types::{ActionResult, AuditAction, AuditResource},
        InMemoryAuditLogger,
    };

    #[tokio::test]
    async fn test_composite_logger() {
        let logger1 = InMemoryAuditLogger::new();
        let logger2 = InMemoryAuditLogger::new();

        let logger1_clone = logger1.clone();
        let logger2_clone = logger2.clone();

        let composite = CompositeAuditLogger::new()
            .add(logger1)
            .add(logger2);

        let log = AuditLog::new(
            AuditAction::Write,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        );

        composite.log(log).await.unwrap();
        composite.flush().await.unwrap();

        // Both loggers should have the entry
        assert_eq!(logger1_clone.entries().len(), 1);
        assert_eq!(logger2_clone.entries().len(), 1);
    }

    #[tokio::test]
    async fn test_composite_batch() {
        let logger1 = InMemoryAuditLogger::new();
        let logger2 = InMemoryAuditLogger::new();

        let logger1_clone = logger1.clone();
        let logger2_clone = logger2.clone();

        let composite = CompositeAuditLogger::new()
            .add(logger1)
            .add(logger2);

        let logs: Vec<AuditLog> = (0..5)
            .map(|i| {
                AuditLog::new(
                    AuditAction::Write,
                    AuditResource::device(format!("plc-{:03}", i)),
                    ActionResult::Success,
                )
            })
            .collect();

        composite.log_batch(logs).await.unwrap();

        assert_eq!(logger1_clone.entries().len(), 5);
        assert_eq!(logger2_clone.entries().len(), 5);
    }

    #[tokio::test]
    async fn test_filtering_logger() {
        let inner = InMemoryAuditLogger::new();
        let inner_clone = inner.clone();

        let filtered = FilteringLogger::new(inner, |log| {
            log.action.is_security_sensitive()
        });

        // Log a non-security event
        let non_security = AuditLog::new(
            AuditAction::Read,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        );
        filtered.log(non_security).await.unwrap();

        // Log a security event
        let security = AuditLog::new(
            AuditAction::Login,
            AuditResource::user("admin"),
            ActionResult::Success,
        );
        filtered.log(security).await.unwrap();

        // Only security event should be logged
        assert_eq!(inner_clone.entries().len(), 1);
        assert_eq!(inner_clone.entries()[0].action, AuditAction::Login);
    }

    #[tokio::test]
    async fn test_tee_logger() {
        let primary = InMemoryAuditLogger::new();
        let secondary = InMemoryAuditLogger::new();

        let primary_clone = primary.clone();
        let secondary_clone = secondary.clone();

        let tee = TeeLogger::new(primary, secondary);

        let log = AuditLog::new(
            AuditAction::Write,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        );

        tee.log(log).await.unwrap();

        assert_eq!(primary_clone.entries().len(), 1);
        assert_eq!(secondary_clone.entries().len(), 1);
    }

    #[tokio::test]
    async fn test_composite_query() {
        let logger1 = InMemoryAuditLogger::new();
        let logger2 = InMemoryAuditLogger::new();

        // Add entry to logger1 (first logger with query support)
        logger1
            .log(AuditLog::new(
                AuditAction::Write,
                AuditResource::device("plc-001"),
                ActionResult::Success,
            ))
            .await
            .unwrap();

        let composite = CompositeAuditLogger::new()
            .add(logger1)
            .add(logger2);

        // Query should work since InMemoryAuditLogger supports querying
        // Composite queries the first logger that supports querying
        let results = composite.query(AuditFilter::default()).await.unwrap();
        assert_eq!(results.len(), 1);
    }
}
