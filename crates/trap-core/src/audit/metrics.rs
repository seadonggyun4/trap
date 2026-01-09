// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Audit logging metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::RwLock;

use super::error::AuditResult;
use super::types::{AuditFilter, AuditLog};
use super::AuditLogger;

// =============================================================================
// Audit Metrics
// =============================================================================

/// Metrics for audit logging operations.
#[derive(Debug, Default)]
pub struct AuditMetrics {
    /// Total entries logged.
    pub entries_logged: AtomicU64,
    /// Total entries by action.
    entries_by_action: RwLock<std::collections::HashMap<String, u64>>,
    /// Total entries by severity.
    entries_by_severity: RwLock<std::collections::HashMap<String, u64>>,
    /// Total entries by result.
    entries_by_result: RwLock<std::collections::HashMap<String, u64>>,
    /// Total log errors.
    pub log_errors: AtomicU64,
    /// Total query errors.
    pub query_errors: AtomicU64,
    /// Total flush operations.
    pub flush_operations: AtomicU64,
    /// Total bytes written (if available).
    pub bytes_written: AtomicU64,
    /// Last log timestamp (epoch millis).
    pub last_log_timestamp: AtomicU64,
    /// Average log duration (microseconds).
    avg_log_duration_us: AtomicU64,
    /// Log duration count (for averaging).
    log_duration_count: AtomicU64,
}

impl AuditMetrics {
    /// Creates new metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a logged entry.
    pub fn record_entry(&self, log: &AuditLog) {
        self.entries_logged.fetch_add(1, Ordering::Relaxed);

        // Update action counts
        {
            let mut by_action = self.entries_by_action.write();
            *by_action.entry(log.action.to_string()).or_insert(0) += 1;
        }

        // Update severity counts
        {
            let mut by_severity = self.entries_by_severity.write();
            *by_severity.entry(log.severity.to_string()).or_insert(0) += 1;
        }

        // Update result counts
        {
            let mut by_result = self.entries_by_result.write();
            *by_result.entry(log.result.as_str().to_string()).or_insert(0) += 1;
        }

        // Update last timestamp
        self.last_log_timestamp.store(
            log.timestamp.timestamp_millis() as u64,
            Ordering::Relaxed,
        );
    }

    /// Records a log duration.
    pub fn record_duration(&self, duration: Duration) {
        let us = duration.as_micros() as u64;

        // Simple moving average
        let count = self.log_duration_count.fetch_add(1, Ordering::Relaxed);
        let current_avg = self.avg_log_duration_us.load(Ordering::Relaxed);

        // Calculate new average
        let new_avg = if count == 0 {
            us
        } else {
            // Weighted average: old_avg * (n-1)/n + new_val / n
            (current_avg * count + us) / (count + 1)
        };

        self.avg_log_duration_us.store(new_avg, Ordering::Relaxed);
    }

    /// Records a log error.
    pub fn record_log_error(&self) {
        self.log_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a query error.
    pub fn record_query_error(&self) {
        self.query_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a flush operation.
    pub fn record_flush(&self) {
        self.flush_operations.fetch_add(1, Ordering::Relaxed);
    }

    /// Records bytes written.
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Returns the average log duration.
    pub fn avg_log_duration(&self) -> Duration {
        Duration::from_micros(self.avg_log_duration_us.load(Ordering::Relaxed))
    }

    /// Returns counts by action.
    pub fn counts_by_action(&self) -> std::collections::HashMap<String, u64> {
        self.entries_by_action.read().clone()
    }

    /// Returns counts by severity.
    pub fn counts_by_severity(&self) -> std::collections::HashMap<String, u64> {
        self.entries_by_severity.read().clone()
    }

    /// Returns counts by result.
    pub fn counts_by_result(&self) -> std::collections::HashMap<String, u64> {
        self.entries_by_result.read().clone()
    }

    /// Returns a snapshot of the metrics.
    pub fn snapshot(&self) -> AuditMetricsSnapshot {
        AuditMetricsSnapshot {
            entries_logged: self.entries_logged.load(Ordering::Relaxed),
            log_errors: self.log_errors.load(Ordering::Relaxed),
            query_errors: self.query_errors.load(Ordering::Relaxed),
            flush_operations: self.flush_operations.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            avg_log_duration_us: self.avg_log_duration_us.load(Ordering::Relaxed),
            entries_by_action: self.entries_by_action.read().clone(),
            entries_by_severity: self.entries_by_severity.read().clone(),
            entries_by_result: self.entries_by_result.read().clone(),
        }
    }

    /// Resets all metrics.
    pub fn reset(&self) {
        self.entries_logged.store(0, Ordering::Relaxed);
        self.log_errors.store(0, Ordering::Relaxed);
        self.query_errors.store(0, Ordering::Relaxed);
        self.flush_operations.store(0, Ordering::Relaxed);
        self.bytes_written.store(0, Ordering::Relaxed);
        self.avg_log_duration_us.store(0, Ordering::Relaxed);
        self.log_duration_count.store(0, Ordering::Relaxed);
        self.entries_by_action.write().clear();
        self.entries_by_severity.write().clear();
        self.entries_by_result.write().clear();
    }
}

/// Snapshot of audit metrics.
#[derive(Debug, Clone)]
pub struct AuditMetricsSnapshot {
    /// Total entries logged.
    pub entries_logged: u64,
    /// Total log errors.
    pub log_errors: u64,
    /// Total query errors.
    pub query_errors: u64,
    /// Total flush operations.
    pub flush_operations: u64,
    /// Total bytes written.
    pub bytes_written: u64,
    /// Average log duration in microseconds.
    pub avg_log_duration_us: u64,
    /// Counts by action.
    pub entries_by_action: std::collections::HashMap<String, u64>,
    /// Counts by severity.
    pub entries_by_severity: std::collections::HashMap<String, u64>,
    /// Counts by result.
    pub entries_by_result: std::collections::HashMap<String, u64>,
}

// =============================================================================
// Metered Audit Logger
// =============================================================================

/// A wrapper that collects metrics for an audit logger.
pub struct AuditMetricsCollector {
    inner: Arc<dyn AuditLogger>,
    metrics: Arc<AuditMetrics>,
    name: String,
}

impl AuditMetricsCollector {
    /// Creates a new metrics collecting wrapper.
    pub fn new<L: AuditLogger + 'static>(inner: L) -> Self {
        Self {
            inner: Arc::new(inner),
            metrics: Arc::new(AuditMetrics::new()),
            name: "metered".to_string(),
        }
    }

    /// Creates a new metrics collecting wrapper with shared metrics.
    pub fn with_metrics<L: AuditLogger + 'static>(
        inner: L,
        metrics: Arc<AuditMetrics>,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            metrics,
            name: "metered".to_string(),
        }
    }

    /// Sets the name of this logger.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Returns the metrics.
    pub fn metrics(&self) -> &Arc<AuditMetrics> {
        &self.metrics
    }

    /// Returns a snapshot of the metrics.
    pub fn snapshot(&self) -> AuditMetricsSnapshot {
        self.metrics.snapshot()
    }
}

#[async_trait]
impl AuditLogger for AuditMetricsCollector {
    async fn log(&self, entry: AuditLog) -> AuditResult<()> {
        let start = Instant::now();

        // Record the entry
        self.metrics.record_entry(&entry);

        // Forward to inner logger
        let result = self.inner.log(entry).await;

        // Record duration
        self.metrics.record_duration(start.elapsed());

        // Record error if any
        if result.is_err() {
            self.metrics.record_log_error();
        }

        result
    }

    async fn log_batch(&self, entries: Vec<AuditLog>) -> AuditResult<()> {
        let start = Instant::now();

        // Record each entry
        for entry in &entries {
            self.metrics.record_entry(entry);
        }

        // Forward to inner logger
        let result = self.inner.log_batch(entries).await;

        // Record duration
        self.metrics.record_duration(start.elapsed());

        // Record error if any
        if result.is_err() {
            self.metrics.record_log_error();
        }

        result
    }

    async fn query(&self, filter: AuditFilter) -> AuditResult<Vec<AuditLog>> {
        let result = self.inner.query(filter).await;

        if result.is_err() {
            self.metrics.record_query_error();
        }

        result
    }

    async fn flush(&self) -> AuditResult<()> {
        self.metrics.record_flush();
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

impl std::fmt::Debug for AuditMetricsCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditMetricsCollector")
            .field("name", &self.name)
            .field("inner", &self.inner.name())
            .field("entries_logged", &self.metrics.entries_logged.load(Ordering::Relaxed))
            .finish()
    }
}

// =============================================================================
// Prometheus Integration
// =============================================================================

/// Registers audit metrics with a Prometheus registry.
#[allow(dead_code)]
pub fn register_prometheus_metrics(
    registry: &prometheus::Registry,
    _metrics: &Arc<AuditMetrics>,
) -> Result<(), prometheus::Error> {
    use prometheus::{Counter, Gauge, IntCounter, Opts};

    let entries_total = IntCounter::with_opts(Opts::new(
        "trap_audit_entries_total",
        "Total number of audit log entries",
    ))?;

    let log_errors_total = IntCounter::with_opts(Opts::new(
        "trap_audit_log_errors_total",
        "Total number of audit log errors",
    ))?;

    let bytes_written_total = Counter::with_opts(Opts::new(
        "trap_audit_bytes_written_total",
        "Total bytes written to audit log",
    ))?;

    let avg_duration_gauge = Gauge::with_opts(Opts::new(
        "trap_audit_log_duration_seconds",
        "Average audit log write duration",
    ))?;

    registry.register(Box::new(entries_total))?;
    registry.register(Box::new(log_errors_total))?;
    registry.register(Box::new(bytes_written_total))?;
    registry.register(Box::new(avg_duration_gauge))?;

    Ok(())
}

// =============================================================================
// Rate Limiting Logger
// =============================================================================

/// A logger that rate limits entries to prevent flooding.
pub struct RateLimitedLogger {
    inner: Arc<dyn AuditLogger>,
    /// Maximum entries per second.
    max_per_second: u64,
    /// Current count.
    current_count: AtomicU64,
    /// Window start time (epoch seconds).
    window_start: AtomicU64,
    /// Dropped entries count.
    dropped: AtomicU64,
    /// Name.
    name: String,
}

impl RateLimitedLogger {
    /// Creates a new rate-limited logger.
    pub fn new<L: AuditLogger + 'static>(inner: L, max_per_second: u64) -> Self {
        Self {
            inner: Arc::new(inner),
            max_per_second,
            current_count: AtomicU64::new(0),
            window_start: AtomicU64::new(Self::current_epoch_second()),
            dropped: AtomicU64::new(0),
            name: "rate_limited".to_string(),
        }
    }

    fn current_epoch_second() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn check_rate_limit(&self) -> bool {
        let current_second = Self::current_epoch_second();
        let window = self.window_start.load(Ordering::Relaxed);

        // Reset if we're in a new window
        if current_second != window {
            self.window_start.store(current_second, Ordering::Relaxed);
            self.current_count.store(0, Ordering::Relaxed);
        }

        let count = self.current_count.fetch_add(1, Ordering::Relaxed);
        count < self.max_per_second
    }

    /// Returns the number of dropped entries.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl AuditLogger for RateLimitedLogger {
    async fn log(&self, entry: AuditLog) -> AuditResult<()> {
        if self.check_rate_limit() {
            self.inner.log(entry).await
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("Audit log rate limited, dropping entry");
            Ok(())
        }
    }

    async fn log_batch(&self, entries: Vec<AuditLog>) -> AuditResult<()> {
        let mut allowed = Vec::new();
        let mut dropped = 0;

        for entry in entries {
            if self.check_rate_limit() {
                allowed.push(entry);
            } else {
                dropped += 1;
            }
        }

        if dropped > 0 {
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
            tracing::warn!(dropped = dropped, "Audit log rate limited");
        }

        if !allowed.is_empty() {
            self.inner.log_batch(allowed).await
        } else {
            Ok(())
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

impl std::fmt::Debug for RateLimitedLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitedLogger")
            .field("max_per_second", &self.max_per_second)
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
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

    #[test]
    fn test_metrics_basic() {
        let metrics = AuditMetrics::new();

        let log = AuditLog::new(
            AuditAction::Write,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        );

        metrics.record_entry(&log);

        assert_eq!(metrics.entries_logged.load(Ordering::Relaxed), 1);

        let by_action = metrics.counts_by_action();
        assert_eq!(by_action.get("write"), Some(&1));
    }

    #[test]
    fn test_metrics_duration() {
        let metrics = AuditMetrics::new();

        metrics.record_duration(Duration::from_micros(100));
        metrics.record_duration(Duration::from_micros(200));

        // Average should be 150
        let avg = metrics.avg_log_duration();
        assert!(avg.as_micros() > 0);
    }

    #[tokio::test]
    async fn test_metered_logger() {
        let inner = InMemoryAuditLogger::new();
        let metered = AuditMetricsCollector::new(inner);

        let log = AuditLog::new(
            AuditAction::Write,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        );

        metered.log(log).await.unwrap();

        let snapshot = metered.snapshot();
        assert_eq!(snapshot.entries_logged, 1);
        assert_eq!(snapshot.log_errors, 0);
    }

    #[tokio::test]
    async fn test_rate_limited_logger() {
        let inner = InMemoryAuditLogger::new();
        let inner_clone = inner.clone();
        let rate_limited = RateLimitedLogger::new(inner, 5);

        // Log 10 entries quickly
        for i in 0..10 {
            let log = AuditLog::new(
                AuditAction::Write,
                AuditResource::device(format!("plc-{:03}", i)),
                ActionResult::Success,
            );
            rate_limited.log(log).await.unwrap();
        }

        // Should have dropped some entries
        assert!(rate_limited.dropped_count() > 0);
        assert!(inner_clone.len() < 10);
    }
}
