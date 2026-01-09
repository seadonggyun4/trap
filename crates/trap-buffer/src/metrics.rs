// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Prometheus metrics for the buffer subsystem.
//!
//! This module provides comprehensive metrics for monitoring buffer operations:
//!
//! - **Storage Metrics**: Items stored, dropped, current size
//! - **Flush Metrics**: Flush count, duration, success/failure rates
//! - **Circuit Breaker Metrics**: State changes, open duration
//! - **Upstream Metrics**: Latency, error rates
//!
//! # Metrics Overview
//!
//! | Metric | Type | Description |
//! |--------|------|-------------|
//! | `trap_buffer_items_stored_total` | Counter | Total items stored |
//! | `trap_buffer_items_flushed_total` | Counter | Total items flushed |
//! | `trap_buffer_items_dropped_total` | Counter | Total items dropped |
//! | `trap_buffer_current_items` | Gauge | Current items in buffer |
//! | `trap_buffer_current_bytes` | Gauge | Current bytes in buffer |
//! | `trap_buffer_flush_total` | Counter | Total flush operations |
//! | `trap_buffer_flush_duration_seconds` | Histogram | Flush duration |
//! | `trap_buffer_flush_errors_total` | Counter | Flush errors by type |
//! | `trap_buffer_circuit_breaker_state` | Gauge | Circuit breaker state |
//! | `trap_buffer_upstream_latency_seconds` | Histogram | Upstream latency |

use once_cell::sync::Lazy;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_histogram, Counter,
    CounterVec, Gauge, Histogram,
};

use crate::traits::BufferStats;

// =============================================================================
// Metric Definitions
// =============================================================================

/// Total items stored in the buffer (cumulative).
static ITEMS_STORED_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "trap_buffer_items_stored_total",
        "Total number of items stored in the buffer"
    )
    .expect("Failed to register items_stored_total metric")
});

/// Total items flushed to upstream (cumulative).
static ITEMS_FLUSHED_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "trap_buffer_items_flushed_total",
        "Total number of items successfully flushed to upstream"
    )
    .expect("Failed to register items_flushed_total metric")
});

/// Total items dropped due to capacity constraints.
static ITEMS_DROPPED_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "trap_buffer_items_dropped_total",
        "Total number of items dropped due to buffer capacity"
    )
    .expect("Failed to register items_dropped_total metric")
});

/// Current number of items in the buffer.
static CURRENT_ITEMS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "trap_buffer_current_items",
        "Current number of items in the buffer"
    )
    .expect("Failed to register current_items metric")
});

/// Current size of the buffer in bytes.
static CURRENT_BYTES: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "trap_buffer_current_bytes",
        "Current size of the buffer in bytes"
    )
    .expect("Failed to register current_bytes metric")
});

/// Total flush operations (successful + failed).
static FLUSH_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "trap_buffer_flush_total",
        "Total number of flush operations attempted"
    )
    .expect("Failed to register flush_total metric")
});

/// Successful flush operations.
static FLUSH_SUCCESS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "trap_buffer_flush_success_total",
        "Total number of successful flush operations"
    )
    .expect("Failed to register flush_success_total metric")
});

/// Flush duration histogram.
static FLUSH_DURATION: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "trap_buffer_flush_duration_seconds",
        "Duration of flush operations in seconds",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("Failed to register flush_duration metric")
});

/// Flush errors by error type.
static FLUSH_ERRORS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "trap_buffer_flush_errors_total",
        "Total number of flush errors by type",
        &["error_type"]
    )
    .expect("Failed to register flush_errors metric")
});

/// Circuit breaker state (0=Closed, 1=Open, 2=HalfOpen).
static CIRCUIT_BREAKER_STATE: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "trap_buffer_circuit_breaker_state",
        "Current circuit breaker state (0=Closed, 1=Open, 2=HalfOpen)"
    )
    .expect("Failed to register circuit_breaker_state metric")
});

/// Circuit breaker state changes.
static CIRCUIT_BREAKER_TRANSITIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "trap_buffer_circuit_breaker_transitions_total",
        "Total circuit breaker state transitions",
        &["from", "to"]
    )
    .expect("Failed to register circuit_breaker_transitions metric")
});

/// Upstream request latency histogram.
static UPSTREAM_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "trap_buffer_upstream_latency_seconds",
        "Latency of upstream requests in seconds",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("Failed to register upstream_latency metric")
});

/// Upstream request errors by status code.
static UPSTREAM_ERRORS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "trap_buffer_upstream_errors_total",
        "Total upstream request errors by status code",
        &["status_code"]
    )
    .expect("Failed to register upstream_errors metric")
});

/// Buffer fill ratio (0.0 to 1.0).
static FILL_RATIO: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "trap_buffer_fill_ratio",
        "Buffer fill ratio (0.0 to 1.0)"
    )
    .expect("Failed to register fill_ratio metric")
});

/// Retry attempts per flush.
static RETRY_ATTEMPTS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "trap_buffer_retry_attempts",
        "Number of retry attempts per flush operation",
        vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    )
    .expect("Failed to register retry_attempts metric")
});

// =============================================================================
// Metrics Collector
// =============================================================================

/// Collects and records buffer metrics.
///
/// This struct provides a high-level interface for updating Prometheus metrics
/// related to buffer operations.
#[derive(Debug, Default)]
pub struct BufferMetricsCollector {
    /// Whether metrics collection is enabled.
    enabled: bool,
}

impl BufferMetricsCollector {
    /// Creates a new metrics collector.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Creates a disabled metrics collector (no-op).
    pub fn disabled() -> Self {
        Self { enabled: false }
    }

    /// Returns whether metrics collection is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Records items stored.
    pub fn record_items_stored(&self, count: u64) {
        if !self.enabled {
            return;
        }
        ITEMS_STORED_TOTAL.inc_by(count as f64);
    }

    /// Records items flushed.
    pub fn record_items_flushed(&self, count: u64) {
        if !self.enabled {
            return;
        }
        ITEMS_FLUSHED_TOTAL.inc_by(count as f64);
    }

    /// Records items dropped.
    pub fn record_items_dropped(&self, count: u64) {
        if !self.enabled {
            return;
        }
        ITEMS_DROPPED_TOTAL.inc_by(count as f64);
    }

    /// Updates current buffer stats.
    pub fn update_current_stats(&self, items: u64, bytes: u64, max_items: u64) {
        if !self.enabled {
            return;
        }
        CURRENT_ITEMS.set(items as f64);
        CURRENT_BYTES.set(bytes as f64);

        let fill_ratio = if max_items > 0 {
            items as f64 / max_items as f64
        } else {
            0.0
        };
        FILL_RATIO.set(fill_ratio);
    }

    /// Records a flush attempt.
    pub fn record_flush_attempt(&self) {
        if !self.enabled {
            return;
        }
        FLUSH_TOTAL.inc();
    }

    /// Records a successful flush.
    pub fn record_flush_success(&self, duration_secs: f64) {
        if !self.enabled {
            return;
        }
        FLUSH_SUCCESS_TOTAL.inc();
        FLUSH_DURATION.observe(duration_secs);
    }

    /// Records a flush error.
    pub fn record_flush_error(&self, error_type: &str) {
        if !self.enabled {
            return;
        }
        FLUSH_ERRORS.with_label_values(&[error_type]).inc();
    }

    /// Records circuit breaker state.
    pub fn record_circuit_state(&self, state: CircuitBreakerState) {
        if !self.enabled {
            return;
        }
        CIRCUIT_BREAKER_STATE.set(state.as_f64());
    }

    /// Records a circuit breaker state transition.
    pub fn record_circuit_transition(&self, from: CircuitBreakerState, to: CircuitBreakerState) {
        if !self.enabled {
            return;
        }
        CIRCUIT_BREAKER_TRANSITIONS
            .with_label_values(&[from.as_str(), to.as_str()])
            .inc();
    }

    /// Records upstream request latency.
    pub fn record_upstream_latency(&self, duration_secs: f64) {
        if !self.enabled {
            return;
        }
        UPSTREAM_LATENCY.observe(duration_secs);
    }

    /// Records an upstream error.
    pub fn record_upstream_error(&self, status_code: &str) {
        if !self.enabled {
            return;
        }
        UPSTREAM_ERRORS.with_label_values(&[status_code]).inc();
    }

    /// Records retry attempts for a flush operation.
    pub fn record_retry_attempts(&self, attempts: u32) {
        if !self.enabled {
            return;
        }
        RETRY_ATTEMPTS.observe(attempts as f64);
    }

    /// Updates all stats from a BufferStats snapshot.
    pub fn update_from_stats(&self, stats: &BufferStats, max_items: u64) {
        if !self.enabled {
            return;
        }

        // Note: These are cumulative counters in the stats but Prometheus counters
        // are also cumulative, so we need to track deltas. For simplicity, we use
        // gauges for the "current" values and let the caller manage counter increments.

        CURRENT_ITEMS.set(stats.current_items as f64);
        CURRENT_BYTES.set(stats.current_bytes as f64);

        let fill_ratio = if max_items > 0 {
            stats.current_items as f64 / max_items as f64
        } else {
            0.0
        };
        FILL_RATIO.set(fill_ratio);
    }
}

// =============================================================================
// Circuit Breaker State
// =============================================================================

/// Circuit breaker states for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Circuit is closed (normal operation).
    Closed,
    /// Circuit is open (blocking requests).
    Open,
    /// Circuit is half-open (testing recovery).
    HalfOpen,
}

impl CircuitBreakerState {
    /// Returns the state as a float for Prometheus gauge.
    pub fn as_f64(&self) -> f64 {
        match self {
            CircuitBreakerState::Closed => 0.0,
            CircuitBreakerState::Open => 1.0,
            CircuitBreakerState::HalfOpen => 2.0,
        }
    }

    /// Returns the state as a string for labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitBreakerState::Closed => "closed",
            CircuitBreakerState::Open => "open",
            CircuitBreakerState::HalfOpen => "half_open",
        }
    }
}

impl From<trap_core::driver::CircuitState> for CircuitBreakerState {
    fn from(state: trap_core::driver::CircuitState) -> Self {
        match state {
            trap_core::driver::CircuitState::Closed => CircuitBreakerState::Closed,
            trap_core::driver::CircuitState::Open => CircuitBreakerState::Open,
            trap_core::driver::CircuitState::HalfOpen => CircuitBreakerState::HalfOpen,
        }
    }
}

// =============================================================================
// Metric Timer
// =============================================================================

/// A timer for measuring operation duration.
///
/// Records the duration when dropped.
pub struct MetricTimer<'a> {
    collector: &'a BufferMetricsCollector,
    start: std::time::Instant,
    metric_type: MetricTimerType,
}

/// Type of metric being timed.
pub enum MetricTimerType {
    /// Flush operation.
    Flush,
    /// Upstream request.
    Upstream,
}

impl<'a> MetricTimer<'a> {
    /// Creates a new timer for flush operations.
    pub fn flush(collector: &'a BufferMetricsCollector) -> Self {
        Self {
            collector,
            start: std::time::Instant::now(),
            metric_type: MetricTimerType::Flush,
        }
    }

    /// Creates a new timer for upstream requests.
    pub fn upstream(collector: &'a BufferMetricsCollector) -> Self {
        Self {
            collector,
            start: std::time::Instant::now(),
            metric_type: MetricTimerType::Upstream,
        }
    }

    /// Observes the elapsed time and records the metric.
    pub fn observe(self) {
        // observe is called in drop
    }

    /// Observes with a success flag.
    pub fn observe_with_result(self, success: bool) {
        let duration = self.start.elapsed().as_secs_f64();

        match self.metric_type {
            MetricTimerType::Flush => {
                if success {
                    self.collector.record_flush_success(duration);
                } else {
                    self.collector.record_flush_error("failed");
                }
            }
            MetricTimerType::Upstream => {
                self.collector.record_upstream_latency(duration);
                if !success {
                    self.collector.record_upstream_error("failed");
                }
            }
        }

        // Prevent drop from being called
        std::mem::forget(self);
    }
}

impl<'a> Drop for MetricTimer<'a> {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();

        match self.metric_type {
            MetricTimerType::Flush => {
                self.collector.record_flush_success(duration);
            }
            MetricTimerType::Upstream => {
                self.collector.record_upstream_latency(duration);
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_disabled() {
        let collector = BufferMetricsCollector::disabled();
        assert!(!collector.is_enabled());

        // These should be no-ops
        collector.record_items_stored(100);
        collector.record_items_flushed(50);
        collector.record_flush_attempt();
    }

    #[test]
    fn test_metrics_collector_enabled() {
        let collector = BufferMetricsCollector::new(true);
        assert!(collector.is_enabled());

        collector.record_items_stored(100);
        collector.record_items_flushed(50);
        collector.record_items_dropped(5);
        collector.update_current_stats(45, 4500, 100);
        collector.record_flush_attempt();
        collector.record_flush_success(0.5);
        collector.record_flush_error("timeout");
    }

    #[test]
    fn test_circuit_breaker_state() {
        assert_eq!(CircuitBreakerState::Closed.as_f64(), 0.0);
        assert_eq!(CircuitBreakerState::Open.as_f64(), 1.0);
        assert_eq!(CircuitBreakerState::HalfOpen.as_f64(), 2.0);

        assert_eq!(CircuitBreakerState::Closed.as_str(), "closed");
        assert_eq!(CircuitBreakerState::Open.as_str(), "open");
        assert_eq!(CircuitBreakerState::HalfOpen.as_str(), "half_open");
    }

    #[test]
    fn test_circuit_breaker_state_conversion() {
        use trap_core::driver::CircuitState;

        let closed: CircuitBreakerState = CircuitState::Closed.into();
        assert_eq!(closed, CircuitBreakerState::Closed);

        let open: CircuitBreakerState = CircuitState::Open.into();
        assert_eq!(open, CircuitBreakerState::Open);

        let half_open: CircuitBreakerState = CircuitState::HalfOpen.into();
        assert_eq!(half_open, CircuitBreakerState::HalfOpen);
    }

    #[test]
    fn test_metric_timer() {
        let collector = BufferMetricsCollector::new(true);

        // Timer that auto-records on drop
        {
            let _timer = MetricTimer::flush(&collector);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Timer with explicit result
        {
            let timer = MetricTimer::upstream(&collector);
            std::thread::sleep(std::time::Duration::from_millis(1));
            timer.observe_with_result(true);
        }
    }
}
