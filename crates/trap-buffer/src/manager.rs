// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Buffer Manager with Circuit Breaker and Exponential Backoff.
//!
//! This module provides the `BufferManager` which orchestrates:
//!
//! - **Automatic Periodic Flushing**: Configurable interval for sending data upstream
//! - **Circuit Breaker Integration**: Prevents cascading failures during outages
//! - **Exponential Backoff**: Gradual retry delays with jitter to prevent thundering herd
//! - **Graceful Shutdown**: Final flush attempt before shutdown
//! - **Comprehensive Metrics**: Prometheus-compatible metrics for observability
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      BufferManager                               │
//! │                                                                  │
//! │  ┌──────────────┐    ┌─────────────────┐    ┌───────────────┐   │
//! │  │ OfflineBuffer│───▶│   Flush Loop    │───▶│ UpstreamSink  │   │
//! │  │ (RocksDB/Mem)│    │ (periodic task) │    │ (HTTP client) │   │
//! │  └──────────────┘    └────────┬────────┘    └───────────────┘   │
//! │                               │                                  │
//! │                    ┌──────────▼──────────┐                       │
//! │                    │   CircuitBreaker    │                       │
//! │                    │ + ExponentialBackoff│                       │
//! │                    └─────────────────────┘                       │
//! │                                                                  │
//! │  ┌─────────────────────────────────────────────────────────┐    │
//! │  │                    Metrics                               │    │
//! │  │ • items_stored  • items_flushed  • flush_duration       │    │
//! │  │ • flush_errors  • circuit_state  • buffer_size          │    │
//! │  └─────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_buffer::{BufferManager, BufferManagerConfig, MemoryBuffer, BufferConfig};
//! use trap_buffer::upstream::HttpUpstreamSink;
//!
//! let buffer = MemoryBuffer::new(BufferConfig::for_testing());
//! let upstream = HttpUpstreamSink::new("http://localhost:8080/api/v1/data");
//!
//! let manager = BufferManager::new(
//!     buffer,
//!     upstream,
//!     BufferManagerConfig::default(),
//! );
//!
//! // Start the flush loop
//! let handle = manager.start().await;
//!
//! // Store data (goes through manager to buffer)
//! manager.store(data_point).await?;
//!
//! // Graceful shutdown
//! manager.shutdown().await;
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use trap_core::circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitError, CountBasedStrategy, LoggingEventHandler,
};
use trap_core::error::BufferError;
use trap_core::types::DataPoint;

use crate::traits::{BufferStats, OfflineBuffer};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the buffer manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferManagerConfig {
    /// Interval between flush attempts.
    #[serde(default = "default_flush_interval")]
    #[serde(with = "duration_secs")]
    pub flush_interval: Duration,

    /// Maximum batch size per flush.
    #[serde(default = "default_flush_batch_size")]
    pub flush_batch_size: usize,

    /// Maximum number of retry attempts per flush.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Base delay for exponential backoff.
    #[serde(default = "default_retry_base_delay")]
    #[serde(with = "duration_millis")]
    pub retry_base_delay: Duration,

    /// Maximum delay for exponential backoff.
    #[serde(default = "default_max_retry_delay")]
    #[serde(with = "duration_secs")]
    pub max_retry_delay: Duration,

    /// Jitter factor for retries (0.0 to 1.0).
    #[serde(default = "default_jitter")]
    pub jitter: f64,

    /// Circuit breaker configuration.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,

    /// Upstream URL for flushing data.
    pub upstream_url: String,

    /// Request timeout for upstream calls.
    #[serde(default = "default_request_timeout")]
    #[serde(with = "duration_secs")]
    pub request_timeout: Duration,

    /// Whether to enable metrics collection.
    #[serde(default = "default_enable_metrics")]
    pub enable_metrics: bool,
}

fn default_flush_interval() -> Duration {
    Duration::from_secs(5)
}

fn default_flush_batch_size() -> usize {
    1000
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_base_delay() -> Duration {
    Duration::from_millis(100)
}

fn default_max_retry_delay() -> Duration {
    Duration::from_secs(30)
}

fn default_jitter() -> f64 {
    0.3
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_enable_metrics() -> bool {
    true
}

mod duration_secs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

impl Default for BufferManagerConfig {
    fn default() -> Self {
        Self {
            flush_interval: default_flush_interval(),
            flush_batch_size: default_flush_batch_size(),
            max_retries: default_max_retries(),
            retry_base_delay: default_retry_base_delay(),
            max_retry_delay: default_max_retry_delay(),
            jitter: default_jitter(),
            circuit_breaker: CircuitBreakerConfig::default(),
            upstream_url: "http://localhost:8080/api/v1/data".to_string(),
            request_timeout: default_request_timeout(),
            enable_metrics: default_enable_metrics(),
        }
    }
}

impl BufferManagerConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> BufferManagerConfigBuilder {
        BufferManagerConfigBuilder::default()
    }

    /// Creates a configuration for testing.
    pub fn for_testing() -> Self {
        Self {
            flush_interval: Duration::from_millis(100),
            flush_batch_size: 10,
            max_retries: 2,
            retry_base_delay: Duration::from_millis(10),
            max_retry_delay: Duration::from_millis(100),
            jitter: 0.0,
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 3,
                reset_timeout: Duration::from_millis(500),
                ..Default::default()
            },
            upstream_url: "http://localhost:9999/test".to_string(),
            request_timeout: Duration::from_secs(5),
            enable_metrics: false,
        }
    }
}

/// Builder for BufferManagerConfig.
#[derive(Debug, Default)]
pub struct BufferManagerConfigBuilder {
    config: BufferManagerConfig,
}

impl BufferManagerConfigBuilder {
    /// Sets the flush interval.
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.config.flush_interval = interval;
        self
    }

    /// Sets the flush batch size.
    pub fn flush_batch_size(mut self, size: usize) -> Self {
        self.config.flush_batch_size = size;
        self
    }

    /// Sets the maximum retry attempts.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.config.max_retries = retries;
        self
    }

    /// Sets the retry base delay.
    pub fn retry_base_delay(mut self, delay: Duration) -> Self {
        self.config.retry_base_delay = delay;
        self
    }

    /// Sets the maximum retry delay.
    pub fn max_retry_delay(mut self, delay: Duration) -> Self {
        self.config.max_retry_delay = delay;
        self
    }

    /// Sets the jitter factor.
    pub fn jitter(mut self, jitter: f64) -> Self {
        self.config.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    /// Sets the upstream URL.
    pub fn upstream_url(mut self, url: impl Into<String>) -> Self {
        self.config.upstream_url = url.into();
        self
    }

    /// Sets the circuit breaker configuration.
    pub fn circuit_breaker(mut self, config: CircuitBreakerConfig) -> Self {
        self.config.circuit_breaker = config;
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> BufferManagerConfig {
        self.config
    }
}

// =============================================================================
// Upstream Sink Trait
// =============================================================================

/// Trait for upstream data sinks.
///
/// Implementations send buffered data to upstream systems.
#[async_trait]
pub trait UpstreamSink: Send + Sync {
    /// Sends a batch of data points to the upstream.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all data was sent successfully
    /// - `Err(BufferError)` if the send failed
    async fn send(&self, data: &[DataPoint]) -> Result<(), BufferError>;

    /// Returns the name of this sink for logging/metrics.
    fn name(&self) -> &str;

    /// Returns true if the sink is currently healthy.
    fn is_healthy(&self) -> bool {
        true
    }
}

// =============================================================================
// HTTP Upstream Sink
// =============================================================================

/// HTTP-based upstream sink.
///
/// Sends data points as JSON to an HTTP endpoint.
#[derive(Debug)]
pub struct HttpUpstreamSink {
    /// HTTP client.
    client: reqwest::Client,

    /// Upstream URL.
    url: String,
}

impl HttpUpstreamSink {
    /// Creates a new HTTP upstream sink.
    pub fn new(url: impl Into<String>, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(10)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            url: url.into(),
        }
    }

    /// Creates with default timeout.
    pub fn with_default_timeout(url: impl Into<String>) -> Self {
        Self::new(url, Duration::from_secs(30))
    }
}

#[async_trait]
impl UpstreamSink for HttpUpstreamSink {
    async fn send(&self, data: &[DataPoint]) -> Result<(), BufferError> {
        if data.is_empty() {
            return Ok(());
        }

        let response = self
            .client
            .post(&self.url)
            .json(&data)
            .send()
            .await
            .map_err(|e| BufferError::upstream_failed(format!("HTTP request failed: {}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(BufferError::upstream_failed(format!(
                "Upstream returned error: {} - {}",
                status, body
            )))
        }
    }

    fn name(&self) -> &str {
        "http"
    }
}

// =============================================================================
// Mock Upstream Sink (for testing)
// =============================================================================

/// A mock upstream sink for testing.
#[derive(Debug)]
pub struct MockUpstreamSink {
    /// Number of successful sends.
    pub send_count: AtomicU64,

    /// Number of items sent.
    pub items_sent: AtomicU64,

    /// Whether to fail sends.
    pub should_fail: AtomicBool,

    /// Failure message.
    pub failure_message: String,
}

impl MockUpstreamSink {
    /// Creates a new mock sink that succeeds.
    pub fn new() -> Self {
        Self {
            send_count: AtomicU64::new(0),
            items_sent: AtomicU64::new(0),
            should_fail: AtomicBool::new(false),
            failure_message: "Mock failure".to_string(),
        }
    }

    /// Creates a mock sink that always fails.
    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            send_count: AtomicU64::new(0),
            items_sent: AtomicU64::new(0),
            should_fail: AtomicBool::new(true),
            failure_message: message.into(),
        }
    }

    /// Sets whether the sink should fail.
    pub fn set_should_fail(&self, fail: bool) {
        self.should_fail.store(fail, Ordering::Relaxed);
    }

    /// Returns the number of sends.
    pub fn send_count(&self) -> u64 {
        self.send_count.load(Ordering::Relaxed)
    }

    /// Returns the number of items sent.
    pub fn items_sent(&self) -> u64 {
        self.items_sent.load(Ordering::Relaxed)
    }
}

impl Default for MockUpstreamSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UpstreamSink for MockUpstreamSink {
    async fn send(&self, data: &[DataPoint]) -> Result<(), BufferError> {
        if self.should_fail.load(Ordering::Relaxed) {
            return Err(BufferError::upstream_failed(&self.failure_message));
        }

        self.send_count.fetch_add(1, Ordering::Relaxed);
        self.items_sent.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    fn name(&self) -> &str {
        "mock"
    }
}

// =============================================================================
// Buffer Manager Metrics
// =============================================================================

/// Metrics for the buffer manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferManagerMetrics {
    /// Total flush attempts.
    pub flush_attempts: u64,
    /// Successful flushes.
    pub flush_successes: u64,
    /// Failed flushes.
    pub flush_failures: u64,
    /// Total items flushed.
    pub items_flushed: u64,
    /// Total bytes flushed.
    pub bytes_flushed: u64,
    /// Average flush duration (microseconds).
    pub avg_flush_duration_us: u64,
    /// Last flush timestamp.
    pub last_flush_time: Option<DateTime<Utc>>,
    /// Circuit breaker state.
    pub circuit_state: String,
    /// Current buffer stats.
    pub buffer_stats: BufferStats,
}

/// Internal metrics tracking.
#[derive(Debug)]
struct MetricsInner {
    flush_attempts: AtomicU64,
    flush_successes: AtomicU64,
    flush_failures: AtomicU64,
    items_flushed: AtomicU64,
    bytes_flushed: AtomicU64,
    total_flush_duration_us: AtomicU64,
    last_flush_time: std::sync::RwLock<Option<DateTime<Utc>>>,
}

impl Default for MetricsInner {
    fn default() -> Self {
        Self {
            flush_attempts: AtomicU64::new(0),
            flush_successes: AtomicU64::new(0),
            flush_failures: AtomicU64::new(0),
            items_flushed: AtomicU64::new(0),
            bytes_flushed: AtomicU64::new(0),
            total_flush_duration_us: AtomicU64::new(0),
            last_flush_time: std::sync::RwLock::new(None),
        }
    }
}

impl MetricsInner {
    fn record_flush_attempt(&self) {
        self.flush_attempts.fetch_add(1, Ordering::Relaxed);
    }

    fn record_flush_success(&self, items: u64, bytes: u64, duration_us: u64) {
        self.flush_successes.fetch_add(1, Ordering::Relaxed);
        self.items_flushed.fetch_add(items, Ordering::Relaxed);
        self.bytes_flushed.fetch_add(bytes, Ordering::Relaxed);
        self.total_flush_duration_us.fetch_add(duration_us, Ordering::Relaxed);

        if let Ok(mut last) = self.last_flush_time.write() {
            *last = Some(Utc::now());
        }
    }

    fn record_flush_failure(&self) {
        self.flush_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self, buffer_stats: BufferStats, circuit_state: &str) -> BufferManagerMetrics {
        let flush_successes = self.flush_successes.load(Ordering::Relaxed);
        let total_duration = self.total_flush_duration_us.load(Ordering::Relaxed);
        let avg_duration = if flush_successes > 0 {
            total_duration / flush_successes
        } else {
            0
        };

        let last_flush = self.last_flush_time.read().ok().and_then(|g| *g);

        BufferManagerMetrics {
            flush_attempts: self.flush_attempts.load(Ordering::Relaxed),
            flush_successes,
            flush_failures: self.flush_failures.load(Ordering::Relaxed),
            items_flushed: self.items_flushed.load(Ordering::Relaxed),
            bytes_flushed: self.bytes_flushed.load(Ordering::Relaxed),
            avg_flush_duration_us: avg_duration,
            last_flush_time: last_flush,
            circuit_state: circuit_state.to_string(),
            buffer_stats,
        }
    }
}

// =============================================================================
// Buffer Manager
// =============================================================================

/// Manages buffer operations with automatic flushing, circuit breaker, and backoff.
///
/// The `BufferManager` wraps an `OfflineBuffer` and provides:
///
/// - Automatic periodic flushing to upstream
/// - Circuit breaker protection for upstream calls
/// - Exponential backoff with jitter for retries
/// - Comprehensive metrics
/// - Graceful shutdown
pub struct BufferManager<B, S>
where
    B: OfflineBuffer + 'static,
    S: UpstreamSink + 'static,
{
    /// The underlying buffer.
    buffer: Arc<B>,

    /// The upstream sink.
    upstream: Arc<S>,

    /// Configuration.
    config: BufferManagerConfig,

    /// Circuit breaker for upstream calls.
    circuit_breaker: Arc<CircuitBreaker<CountBasedStrategy, LoggingEventHandler>>,

    /// Metrics tracking.
    metrics: Arc<MetricsInner>,

    /// Shutdown signal.
    shutdown: Arc<Notify>,

    /// Whether the manager is running.
    running: Arc<AtomicBool>,
}

impl<B, S> BufferManager<B, S>
where
    B: OfflineBuffer + 'static,
    S: UpstreamSink + 'static,
{
    /// Creates a new buffer manager.
    pub fn new(buffer: B, upstream: S, config: BufferManagerConfig) -> Self {
        let circuit_breaker = CircuitBreaker::new(config.circuit_breaker.clone());

        Self {
            buffer: Arc::new(buffer),
            upstream: Arc::new(upstream),
            config,
            circuit_breaker: Arc::new(circuit_breaker),
            metrics: Arc::new(MetricsInner::default()),
            shutdown: Arc::new(Notify::new()),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates a new buffer manager with shared components.
    pub fn with_shared(
        buffer: Arc<B>,
        upstream: Arc<S>,
        config: BufferManagerConfig,
    ) -> Self {
        let circuit_breaker = CircuitBreaker::new(config.circuit_breaker.clone());

        Self {
            buffer,
            upstream,
            config,
            circuit_breaker: Arc::new(circuit_breaker),
            metrics: Arc::new(MetricsInner::default()),
            shutdown: Arc::new(Notify::new()),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts the flush loop in the background.
    ///
    /// Returns a `JoinHandle` that can be used to wait for the loop to finish.
    pub fn start(&self) -> JoinHandle<()> {
        self.running.store(true, Ordering::SeqCst);

        let buffer = self.buffer.clone();
        let upstream = self.upstream.clone();
        let config = self.config.clone();
        let circuit_breaker = self.circuit_breaker.clone();
        let metrics = self.metrics.clone();
        let shutdown = self.shutdown.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            info!(
                interval_ms = config.flush_interval.as_millis() as u64,
                batch_size = config.flush_batch_size,
                "Buffer flush loop started"
            );

            let mut interval = tokio::time::interval(config.flush_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !running.load(Ordering::SeqCst) {
                            break;
                        }

                        Self::flush_once(
                            &buffer,
                            &upstream,
                            &config,
                            &circuit_breaker,
                            &metrics,
                        ).await;
                    }
                    _ = shutdown.notified() => {
                        info!("Buffer flush loop shutting down");

                        // Final flush attempt
                        Self::flush_once(
                            &buffer,
                            &upstream,
                            &config,
                            &circuit_breaker,
                            &metrics,
                        ).await;

                        break;
                    }
                }
            }

            running.store(false, Ordering::SeqCst);
            info!("Buffer flush loop stopped");
        })
    }

    /// Performs a single flush operation with retry logic.
    async fn flush_once(
        buffer: &Arc<B>,
        upstream: &Arc<S>,
        config: &BufferManagerConfig,
        circuit_breaker: &Arc<CircuitBreaker<CountBasedStrategy, LoggingEventHandler>>,
        metrics: &Arc<MetricsInner>,
    ) {
        // Check if there's anything to flush
        if buffer.is_empty() {
            return;
        }

        metrics.record_flush_attempt();

        // Peek at the data first
        let data = match buffer.peek(config.flush_batch_size).await {
            Ok(data) if data.is_empty() => return,
            Ok(data) => data,
            Err(e) => {
                error!(error = %e, "Failed to peek buffer");
                metrics.record_flush_failure();
                return;
            }
        };

        let item_count = data.len();
        let start_time = std::time::Instant::now();

        // Try to send with circuit breaker and exponential backoff
        let result = Self::send_with_retry(
            &data,
            upstream,
            config,
            circuit_breaker,
        ).await;

        let duration_us = start_time.elapsed().as_micros() as u64;

        match result {
            Ok(()) => {
                // Successfully sent - now remove from buffer
                match buffer.pop(item_count).await {
                    Ok(removed) => {
                        let bytes = removed.len() as u64 * 100; // Estimate
                        metrics.record_flush_success(removed.len() as u64, bytes, duration_us);

                        debug!(
                            items = removed.len(),
                            duration_ms = duration_us / 1000,
                            "Flush completed successfully"
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to pop from buffer after successful send");
                        // Data was sent but not removed - may result in duplicates
                        // This is acceptable for our use case (at-least-once delivery)
                    }
                }
            }
            Err(e) => {
                metrics.record_flush_failure();

                match e {
                    FlushError::CircuitOpen => {
                        debug!("Flush skipped: circuit breaker is open");
                    }
                    FlushError::UpstreamFailed(msg) => {
                        warn!(error = %msg, "Flush failed after retries");
                    }
                }
            }
        }
    }

    /// Sends data with exponential backoff and circuit breaker.
    async fn send_with_retry(
        data: &[DataPoint],
        upstream: &Arc<S>,
        config: &BufferManagerConfig,
        circuit_breaker: &Arc<CircuitBreaker<CountBasedStrategy, LoggingEventHandler>>,
    ) -> Result<(), FlushError> {
        let mut attempt = 0u32;

        loop {
            attempt += 1;

            // Check circuit breaker state before calling
            let result = circuit_breaker
                .call(|| async {
                    upstream.send(data).await
                })
                .await;

            match result {
                Ok(()) => return Ok(()),
                Err(CircuitError::Open) | Err(CircuitError::HalfOpenAtCapacity) => {
                    return Err(FlushError::CircuitOpen);
                }
                Err(CircuitError::Inner(e)) => {
                    let error_msg = e.to_string();

                    if attempt >= config.max_retries {
                        return Err(FlushError::UpstreamFailed(error_msg));
                    }

                    // Calculate backoff delay with jitter
                    let delay = Self::calculate_backoff(attempt, config);

                    debug!(
                        attempt = attempt,
                        max_attempts = config.max_retries,
                        delay_ms = delay.as_millis() as u64,
                        "Retrying flush after delay"
                    );

                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Calculates exponential backoff delay with jitter.
    fn calculate_backoff(attempt: u32, config: &BufferManagerConfig) -> Duration {
        let base_ms = config.retry_base_delay.as_millis() as f64;
        let multiplied = base_ms * 2.0f64.powi(attempt.saturating_sub(1) as i32);
        let capped = multiplied.min(config.max_retry_delay.as_millis() as f64);

        // Add jitter
        let jitter_range = capped * config.jitter;
        let jitter = if jitter_range > 0.0 {
            let random: f64 = rand::random();
            (random * 2.0 - 1.0) * jitter_range
        } else {
            0.0
        };

        let final_delay = (capped + jitter).max(0.0);
        Duration::from_millis(final_delay as u64)
    }

    /// Triggers a shutdown of the flush loop.
    ///
    /// This will signal the flush loop to stop and perform a final flush.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.shutdown.notify_one();
    }

    /// Stores a data point in the buffer.
    ///
    /// This is a convenience method that delegates to the underlying buffer.
    pub async fn store(&self, data: DataPoint) -> Result<(), BufferError> {
        self.buffer.store(data).await
    }

    /// Stores multiple data points in the buffer.
    pub async fn store_batch(&self, data: Vec<DataPoint>) -> Result<(), BufferError> {
        self.buffer.store_batch(data).await
    }

    /// Returns the current number of items in the buffer (O(1)).
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns true if the buffer is empty (O(1)).
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns the buffer statistics.
    pub fn buffer_stats(&self) -> BufferStats {
        self.buffer.stats()
    }

    /// Returns the manager metrics.
    pub fn metrics(&self) -> BufferManagerMetrics {
        let circuit_state = format!("{:?}", self.circuit_breaker.current_state());
        self.metrics.snapshot(self.buffer.stats(), &circuit_state)
    }

    /// Returns true if the flush loop is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Returns a reference to the underlying buffer.
    pub fn buffer(&self) -> &B {
        &self.buffer
    }

    /// Returns a reference to the upstream sink.
    pub fn upstream(&self) -> &S {
        &self.upstream
    }

    /// Returns a reference to the circuit breaker.
    pub fn circuit_breaker(&self) -> &CircuitBreaker<CountBasedStrategy, LoggingEventHandler> {
        &self.circuit_breaker
    }

    /// Manually triggers a flush operation.
    pub async fn flush_now(&self) {
        Self::flush_once(
            &self.buffer,
            &self.upstream,
            &self.config,
            &self.circuit_breaker,
            &self.metrics,
        ).await;
    }

    /// Resets the circuit breaker to closed state.
    pub fn reset_circuit_breaker(&self) {
        self.circuit_breaker.reset();
    }
}

impl<B, S> std::fmt::Debug for BufferManager<B, S>
where
    B: OfflineBuffer + 'static,
    S: UpstreamSink + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferManager")
            .field("buffer_len", &self.len())
            .field("running", &self.is_running())
            .field("circuit_state", &self.circuit_breaker.current_state())
            .finish()
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during flush operations.
#[derive(Debug)]
enum FlushError {
    /// Circuit breaker is open.
    CircuitOpen,
    /// Upstream failed after all retries.
    UpstreamFailed(String),
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryBuffer;
    use crate::traits::BufferConfig;
    use trap_core::types::{DataQuality, DeviceId, TagId, Value};

    fn create_test_data_point(value: f64) -> DataPoint {
        DataPoint::new(
            DeviceId::new("test-device"),
            TagId::new("test-tag"),
            Value::Float64(value),
            DataQuality::Good,
        )
    }

    #[tokio::test]
    async fn test_buffer_manager_store() {
        let buffer = MemoryBuffer::new(BufferConfig::for_testing());
        let upstream = MockUpstreamSink::new();
        let config = BufferManagerConfig::for_testing();

        let manager = BufferManager::new(buffer, upstream, config);

        manager.store(create_test_data_point(42.0)).await.unwrap();

        assert_eq!(manager.len(), 1);
    }

    #[tokio::test]
    async fn test_buffer_manager_batch_store() {
        let buffer = MemoryBuffer::new(BufferConfig::for_testing());
        let upstream = MockUpstreamSink::new();
        let config = BufferManagerConfig::for_testing();

        let manager = BufferManager::new(buffer, upstream, config);

        let points: Vec<DataPoint> = (0..100)
            .map(|i| create_test_data_point(i as f64))
            .collect();

        manager.store_batch(points).await.unwrap();

        assert_eq!(manager.len(), 100);
    }

    #[tokio::test]
    async fn test_buffer_manager_flush_now() {
        let buffer = MemoryBuffer::new(BufferConfig::for_testing());
        let upstream = Arc::new(MockUpstreamSink::new());
        let config = BufferManagerConfig::for_testing();

        let manager = BufferManager::with_shared(
            Arc::new(buffer),
            upstream.clone(),
            config,
        );

        // Store some data
        for i in 0..5 {
            manager.store(create_test_data_point(i as f64)).await.unwrap();
        }

        assert_eq!(manager.len(), 5);

        // Flush
        manager.flush_now().await;

        // Buffer should be empty
        assert_eq!(manager.len(), 0);

        // Upstream should have received the data
        assert_eq!(upstream.send_count(), 1);
        assert_eq!(upstream.items_sent(), 5);
    }

    #[tokio::test]
    async fn test_buffer_manager_flush_with_failure() {
        let buffer = MemoryBuffer::new(BufferConfig::for_testing());
        let upstream = Arc::new(MockUpstreamSink::failing("Test failure"));
        let config = BufferManagerConfig::builder()
            .flush_batch_size(10)
            .max_retries(2)
            .retry_base_delay(Duration::from_millis(1))
            .build();

        let manager = BufferManager::with_shared(
            Arc::new(buffer),
            upstream.clone(),
            config,
        );

        // Store some data
        for i in 0..5 {
            manager.store(create_test_data_point(i as f64)).await.unwrap();
        }

        // Flush (should fail)
        manager.flush_now().await;

        // Data should still be in buffer (flush failed)
        assert_eq!(manager.len(), 5);

        // Metrics should show failure
        let metrics = manager.metrics();
        assert!(metrics.flush_failures > 0);
    }

    #[tokio::test]
    async fn test_buffer_manager_circuit_breaker() {
        let buffer = MemoryBuffer::new(BufferConfig::for_testing());
        let upstream = Arc::new(MockUpstreamSink::failing("Test failure"));
        let config = BufferManagerConfig::builder()
            .flush_batch_size(10)
            .max_retries(1)
            .retry_base_delay(Duration::from_millis(1))
            .circuit_breaker(CircuitBreakerConfig {
                failure_threshold: 2,
                reset_timeout: Duration::from_secs(60),
                ..Default::default()
            })
            .build();

        let manager = BufferManager::with_shared(
            Arc::new(buffer),
            upstream.clone(),
            config,
        );

        // Store data and flush multiple times to trip circuit breaker
        for _ in 0..3 {
            manager.store(create_test_data_point(1.0)).await.unwrap();
            manager.flush_now().await;
        }

        // Circuit breaker should be open
        use trap_core::driver::CircuitState;
        assert_eq!(manager.circuit_breaker.current_state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn test_buffer_manager_metrics() {
        let buffer = MemoryBuffer::new(BufferConfig::for_testing());
        let upstream = Arc::new(MockUpstreamSink::new());
        let config = BufferManagerConfig::for_testing();

        let manager = BufferManager::with_shared(
            Arc::new(buffer),
            upstream.clone(),
            config,
        );

        // Store and flush
        for i in 0..10 {
            manager.store(create_test_data_point(i as f64)).await.unwrap();
        }
        manager.flush_now().await;

        let metrics = manager.metrics();
        assert_eq!(metrics.flush_attempts, 1);
        assert_eq!(metrics.flush_successes, 1);
        assert_eq!(metrics.items_flushed, 10);
    }

    #[tokio::test]
    async fn test_buffer_manager_start_stop() {
        let buffer = MemoryBuffer::new(BufferConfig::for_testing());
        let upstream = MockUpstreamSink::new();
        let config = BufferManagerConfig::builder()
            .flush_interval(Duration::from_millis(50))
            .build();

        let manager = BufferManager::new(buffer, upstream, config);

        // Start flush loop
        let handle = manager.start();

        assert!(manager.is_running());

        // Let it run briefly
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Shutdown
        manager.shutdown();

        // Wait for the loop to finish
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;

        assert!(!manager.is_running());
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        let config = BufferManagerConfig::builder()
            .retry_base_delay(Duration::from_millis(100))
            .max_retry_delay(Duration::from_secs(30))
            .jitter(0.0) // No jitter for deterministic test
            .build();

        let delay1 = BufferManager::<MemoryBuffer, MockUpstreamSink>::calculate_backoff(1, &config);
        let delay2 = BufferManager::<MemoryBuffer, MockUpstreamSink>::calculate_backoff(2, &config);
        let delay3 = BufferManager::<MemoryBuffer, MockUpstreamSink>::calculate_backoff(3, &config);

        assert_eq!(delay1, Duration::from_millis(100)); // 100 * 2^0
        assert_eq!(delay2, Duration::from_millis(200)); // 100 * 2^1
        assert_eq!(delay3, Duration::from_millis(400)); // 100 * 2^2
    }

    #[test]
    fn test_backoff_capped_at_max() {
        let config = BufferManagerConfig::builder()
            .retry_base_delay(Duration::from_millis(100))
            .max_retry_delay(Duration::from_millis(500))
            .jitter(0.0)
            .build();

        let delay = BufferManager::<MemoryBuffer, MockUpstreamSink>::calculate_backoff(10, &config);

        assert_eq!(delay, Duration::from_millis(500));
    }

    #[test]
    fn test_config_builder() {
        let config = BufferManagerConfig::builder()
            .flush_interval(Duration::from_secs(10))
            .flush_batch_size(500)
            .max_retries(5)
            .upstream_url("http://example.com/data")
            .jitter(0.2)
            .build();

        assert_eq!(config.flush_interval, Duration::from_secs(10));
        assert_eq!(config.flush_batch_size, 500);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.upstream_url, "http://example.com/data");
        assert_eq!(config.jitter, 0.2);
    }

    #[test]
    fn test_mock_upstream_sink() {
        let sink = MockUpstreamSink::new();
        assert!(!sink.should_fail.load(Ordering::Relaxed));

        sink.set_should_fail(true);
        assert!(sink.should_fail.load(Ordering::Relaxed));
    }
}
