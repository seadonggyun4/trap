// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Buffer traits and interfaces.
//!
//! This module defines the core abstraction for offline buffering with
//! **O(1) counter performance** - a critical requirement for high-throughput
//! industrial data collection.
//!
//! # Design Principles
//!
//! - **O(1) Len**: The `len()` and `is_empty()` methods MUST return in constant
//!   time using atomic counters, not by scanning the underlying storage.
//! - **Lock-Free Statistics**: All counter operations use atomic types.
//! - **Async First**: All I/O operations are async for non-blocking performance.
//! - **Batch Operations**: Optimized for batch insert/retrieve patterns.
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_buffer::{OfflineBuffer, BufferConfig};
//!
//! let buffer = RocksDbBuffer::open(BufferConfig::default()).await?;
//!
//! // Store data points
//! buffer.store(data_point).await?;
//!
//! // O(1) count check - no DB scan!
//! let count = buffer.len();
//!
//! // Retrieve and remove
//! let batch = buffer.pop(100).await?;
//! ```

use std::fmt::Debug;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use trap_core::error::BufferError;
use trap_core::types::DataPoint;

// =============================================================================
// Buffer Configuration
// =============================================================================

/// Configuration for the offline buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferConfig {
    /// Path to the buffer storage directory.
    #[serde(default = "default_buffer_path")]
    pub path: String,

    /// Maximum buffer size in bytes.
    #[serde(default = "default_max_size_bytes")]
    pub max_size_bytes: u64,

    /// Maximum number of items in the buffer.
    #[serde(default = "default_max_items")]
    pub max_items: u64,

    /// Default batch size for flush operations.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Whether to sync writes to disk immediately.
    #[serde(default)]
    pub sync_writes: bool,

    /// Enable compression (LZ4).
    #[serde(default = "default_compression")]
    pub compression: bool,

    /// Time-to-live for buffered data.
    #[serde(default = "default_ttl")]
    #[serde(with = "duration_secs")]
    pub ttl: Duration,

    /// Write buffer size for RocksDB (in bytes).
    #[serde(default = "default_write_buffer_size")]
    pub write_buffer_size: usize,

    /// Block cache size for RocksDB (in bytes).
    #[serde(default = "default_block_cache_size")]
    pub block_cache_size: usize,
}

fn default_buffer_path() -> String {
    "/var/lib/trap/buffer".to_string()
}

fn default_max_size_bytes() -> u64 {
    1024 * 1024 * 1024 // 1 GB
}

fn default_max_items() -> u64 {
    10_000_000 // 10 million
}

fn default_batch_size() -> usize {
    1000
}

fn default_compression() -> bool {
    true
}

fn default_ttl() -> Duration {
    Duration::from_secs(7 * 24 * 60 * 60) // 7 days
}

fn default_write_buffer_size() -> usize {
    64 * 1024 * 1024 // 64 MB
}

fn default_block_cache_size() -> usize {
    128 * 1024 * 1024 // 128 MB
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

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            path: default_buffer_path(),
            max_size_bytes: default_max_size_bytes(),
            max_items: default_max_items(),
            batch_size: default_batch_size(),
            sync_writes: false,
            compression: default_compression(),
            ttl: default_ttl(),
            write_buffer_size: default_write_buffer_size(),
            block_cache_size: default_block_cache_size(),
        }
    }
}

impl BufferConfig {
    /// Creates a new buffer configuration builder.
    pub fn builder() -> BufferConfigBuilder {
        BufferConfigBuilder::default()
    }

    /// Creates a configuration for testing (in-memory, small limits).
    pub fn for_testing() -> Self {
        Self {
            path: "/tmp/trap-buffer-test".to_string(),
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            max_items: 100_000,
            batch_size: 100,
            sync_writes: false,
            compression: false,
            ttl: Duration::from_secs(3600), // 1 hour
            write_buffer_size: 4 * 1024 * 1024,
            block_cache_size: 8 * 1024 * 1024,
        }
    }

    /// Creates a high-performance configuration.
    pub fn high_performance() -> Self {
        Self {
            path: default_buffer_path(),
            max_size_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            max_items: 100_000_000,                   // 100 million
            batch_size: 5000,
            sync_writes: false,
            compression: true,
            ttl: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            write_buffer_size: 256 * 1024 * 1024,        // 256 MB
            block_cache_size: 512 * 1024 * 1024,         // 512 MB
        }
    }
}

/// Builder for BufferConfig.
#[derive(Debug, Default)]
pub struct BufferConfigBuilder {
    config: BufferConfig,
}

impl BufferConfigBuilder {
    /// Sets the storage path.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.config.path = path.into();
        self
    }

    /// Sets the maximum size in bytes.
    pub fn max_size_bytes(mut self, size: u64) -> Self {
        self.config.max_size_bytes = size;
        self
    }

    /// Sets the maximum number of items.
    pub fn max_items(mut self, items: u64) -> Self {
        self.config.max_items = items;
        self
    }

    /// Sets the batch size.
    pub fn batch_size(mut self, size: usize) -> Self {
        self.config.batch_size = size;
        self
    }

    /// Sets whether to sync writes.
    pub fn sync_writes(mut self, sync: bool) -> Self {
        self.config.sync_writes = sync;
        self
    }

    /// Sets whether to enable compression.
    pub fn compression(mut self, enabled: bool) -> Self {
        self.config.compression = enabled;
        self
    }

    /// Sets the TTL.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.config.ttl = ttl;
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> BufferConfig {
        self.config
    }
}

// =============================================================================
// Buffer Statistics
// =============================================================================

/// Lock-free buffer statistics using atomic types.
///
/// All operations on this struct are O(1) and lock-free.
#[derive(Debug)]
pub struct BufferStatsInner {
    /// Total items stored (cumulative).
    pub items_stored: AtomicU64,
    /// Total items flushed to upstream (cumulative).
    pub items_flushed: AtomicU64,
    /// Total items dropped due to capacity (cumulative).
    pub items_dropped: AtomicU64,
    /// Total bytes written (cumulative).
    pub bytes_written: AtomicU64,
    /// Total bytes flushed (cumulative).
    pub bytes_flushed: AtomicU64,
    /// Number of successful flush operations.
    pub flush_count: AtomicU64,
    /// Number of failed flush operations.
    pub flush_errors: AtomicU64,
    /// Oldest item timestamp (unix nanos).
    pub oldest_timestamp: AtomicI64,
    /// Newest item timestamp (unix nanos).
    pub newest_timestamp: AtomicI64,
    /// Last flush timestamp (unix nanos).
    pub last_flush_timestamp: AtomicI64,
    /// Current item count (live counter).
    pub current_items: AtomicU64,
    /// Current size in bytes (live counter).
    pub current_bytes: AtomicU64,
}

impl Default for BufferStatsInner {
    fn default() -> Self {
        Self::new()
    }
}

impl BufferStatsInner {
    /// Creates new statistics with all counters at zero.
    pub fn new() -> Self {
        Self {
            items_stored: AtomicU64::new(0),
            items_flushed: AtomicU64::new(0),
            items_dropped: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            bytes_flushed: AtomicU64::new(0),
            flush_count: AtomicU64::new(0),
            flush_errors: AtomicU64::new(0),
            oldest_timestamp: AtomicI64::new(0),
            newest_timestamp: AtomicI64::new(0),
            last_flush_timestamp: AtomicI64::new(0),
            current_items: AtomicU64::new(0),
            current_bytes: AtomicU64::new(0),
        }
    }

    /// Records a successful store operation.
    #[inline]
    pub fn record_store(&self, bytes: u64, timestamp_nanos: i64) {
        self.items_stored.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
        self.current_items.fetch_add(1, Ordering::Relaxed);
        self.current_bytes.fetch_add(bytes, Ordering::Relaxed);

        // Update newest timestamp
        let _ = self.newest_timestamp.fetch_max(timestamp_nanos, Ordering::Relaxed);

        // Update oldest timestamp if this is the first item or older
        let current_oldest = self.oldest_timestamp.load(Ordering::Relaxed);
        if current_oldest == 0 || timestamp_nanos < current_oldest {
            let _ = self.oldest_timestamp.compare_exchange(
                current_oldest,
                timestamp_nanos,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    /// Records a successful batch store operation.
    #[inline]
    pub fn record_batch_store(&self, count: u64, bytes: u64, oldest_ts: i64, newest_ts: i64) {
        self.items_stored.fetch_add(count, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
        self.current_items.fetch_add(count, Ordering::Relaxed);
        self.current_bytes.fetch_add(bytes, Ordering::Relaxed);

        // Update timestamps
        let _ = self.newest_timestamp.fetch_max(newest_ts, Ordering::Relaxed);

        let current_oldest = self.oldest_timestamp.load(Ordering::Relaxed);
        if current_oldest == 0 || oldest_ts < current_oldest {
            let _ = self.oldest_timestamp.compare_exchange(
                current_oldest,
                oldest_ts,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    /// Records a successful flush operation.
    #[inline]
    pub fn record_flush(&self, count: u64, bytes: u64) {
        self.items_flushed.fetch_add(count, Ordering::Relaxed);
        self.bytes_flushed.fetch_add(bytes, Ordering::Relaxed);
        self.flush_count.fetch_add(1, Ordering::Relaxed);
        self.current_items.fetch_sub(count, Ordering::Relaxed);
        self.current_bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.last_flush_timestamp
            .store(Utc::now().timestamp_nanos_opt().unwrap_or(0), Ordering::Relaxed);
    }

    /// Records a failed flush operation.
    #[inline]
    pub fn record_flush_error(&self) {
        self.flush_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Records dropped items due to capacity.
    #[inline]
    pub fn record_dropped(&self, count: u64, bytes: u64) {
        self.items_dropped.fetch_add(count, Ordering::Relaxed);
        self.current_items.fetch_sub(count, Ordering::Relaxed);
        self.current_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Records removal of items (e.g., from pop operation).
    #[inline]
    pub fn record_removal(&self, count: u64, bytes: u64) {
        self.current_items.fetch_sub(count, Ordering::Relaxed);
        self.current_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Returns O(1) current item count.
    #[inline]
    pub fn current_items(&self) -> u64 {
        self.current_items.load(Ordering::Relaxed)
    }

    /// Returns O(1) current byte count.
    #[inline]
    pub fn current_bytes(&self) -> u64 {
        self.current_bytes.load(Ordering::Relaxed)
    }

    /// Creates a snapshot of the statistics.
    pub fn snapshot(&self) -> BufferStats {
        let oldest_nanos = self.oldest_timestamp.load(Ordering::Relaxed);
        let newest_nanos = self.newest_timestamp.load(Ordering::Relaxed);
        let last_flush_nanos = self.last_flush_timestamp.load(Ordering::Relaxed);

        BufferStats {
            items_stored: self.items_stored.load(Ordering::Relaxed),
            items_flushed: self.items_flushed.load(Ordering::Relaxed),
            items_dropped: self.items_dropped.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            bytes_flushed: self.bytes_flushed.load(Ordering::Relaxed),
            flush_count: self.flush_count.load(Ordering::Relaxed),
            flush_errors: self.flush_errors.load(Ordering::Relaxed),
            oldest_timestamp: if oldest_nanos > 0 {
                DateTime::from_timestamp_nanos(oldest_nanos)
            } else {
                Utc::now()
            },
            newest_timestamp: if newest_nanos > 0 {
                DateTime::from_timestamp_nanos(newest_nanos)
            } else {
                Utc::now()
            },
            last_flush_timestamp: if last_flush_nanos > 0 {
                Some(DateTime::from_timestamp_nanos(last_flush_nanos))
            } else {
                None
            },
            current_items: self.current_items.load(Ordering::Relaxed),
            current_bytes: self.current_bytes.load(Ordering::Relaxed),
        }
    }

    /// Resets all counters (for testing).
    pub fn reset(&self) {
        self.items_stored.store(0, Ordering::Relaxed);
        self.items_flushed.store(0, Ordering::Relaxed);
        self.items_dropped.store(0, Ordering::Relaxed);
        self.bytes_written.store(0, Ordering::Relaxed);
        self.bytes_flushed.store(0, Ordering::Relaxed);
        self.flush_count.store(0, Ordering::Relaxed);
        self.flush_errors.store(0, Ordering::Relaxed);
        self.oldest_timestamp.store(0, Ordering::Relaxed);
        self.newest_timestamp.store(0, Ordering::Relaxed);
        self.last_flush_timestamp.store(0, Ordering::Relaxed);
        self.current_items.store(0, Ordering::Relaxed);
        self.current_bytes.store(0, Ordering::Relaxed);
    }
}

/// Immutable snapshot of buffer statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferStats {
    /// Total items stored (cumulative).
    pub items_stored: u64,
    /// Total items flushed to upstream (cumulative).
    pub items_flushed: u64,
    /// Total items dropped due to capacity (cumulative).
    pub items_dropped: u64,
    /// Total bytes written (cumulative).
    pub bytes_written: u64,
    /// Total bytes flushed (cumulative).
    pub bytes_flushed: u64,
    /// Number of successful flush operations.
    pub flush_count: u64,
    /// Number of failed flush operations.
    pub flush_errors: u64,
    /// Oldest item timestamp.
    pub oldest_timestamp: DateTime<Utc>,
    /// Newest item timestamp.
    pub newest_timestamp: DateTime<Utc>,
    /// Last successful flush timestamp.
    pub last_flush_timestamp: Option<DateTime<Utc>>,
    /// Current item count.
    pub current_items: u64,
    /// Current size in bytes.
    pub current_bytes: u64,
}

impl BufferStats {
    /// Returns the fill ratio (0.0 to 1.0) based on item count.
    pub fn fill_ratio_items(&self, max_items: u64) -> f64 {
        if max_items == 0 {
            return 0.0;
        }
        self.current_items as f64 / max_items as f64
    }

    /// Returns the fill ratio (0.0 to 1.0) based on bytes.
    pub fn fill_ratio_bytes(&self, max_bytes: u64) -> f64 {
        if max_bytes == 0 {
            return 0.0;
        }
        self.current_bytes as f64 / max_bytes as f64
    }

    /// Returns the data age (time since oldest item).
    pub fn data_age(&self) -> chrono::Duration {
        Utc::now() - self.oldest_timestamp
    }

    /// Returns the time since last flush.
    pub fn time_since_last_flush(&self) -> Option<chrono::Duration> {
        self.last_flush_timestamp.map(|ts| Utc::now() - ts)
    }

    /// Returns the flush success rate.
    pub fn flush_success_rate(&self) -> f64 {
        let total = self.flush_count + self.flush_errors;
        if total == 0 {
            return 1.0;
        }
        self.flush_count as f64 / total as f64
    }
}

// =============================================================================
// Offline Buffer Trait
// =============================================================================

/// The core trait for offline data buffering.
///
/// This trait defines the interface for persistent data storage with
/// **O(1) counter performance** requirements.
///
/// # Implementation Requirements
///
/// - `len()` and `is_empty()` MUST be O(1) using atomic counters
/// - All methods are async for non-blocking I/O
/// - Implementations must be thread-safe (`Send + Sync`)
/// - Batch operations should be optimized for throughput
///
/// # Key Design Decisions
///
/// 1. **Separate peek/pop**: Allows inspecting data before committing removal
/// 2. **Batch operations**: Critical for high-throughput scenarios
/// 3. **Statistics tracking**: Built-in observability
/// 4. **TTL support**: Automatic cleanup of old data
#[async_trait]
pub trait OfflineBuffer: Send + Sync + Debug {
    /// Stores a single data point in the buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the data was stored successfully
    /// - `Err(BufferError::CapacityExceeded)` if the buffer is full and
    ///   the data could not be stored (after potential eviction)
    /// - `Err(BufferError::StoreFailed)` for other storage failures
    async fn store(&self, data: DataPoint) -> Result<(), BufferError>;

    /// Stores multiple data points in a single batch operation.
    ///
    /// This is more efficient than calling `store()` multiple times.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all data was stored successfully
    /// - `Err(BufferError)` if any storage operation failed
    async fn store_batch(&self, data: Vec<DataPoint>) -> Result<(), BufferError>;

    /// Peeks at items in the buffer without removing them.
    ///
    /// Items are returned in FIFO order (oldest first).
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of items to return
    ///
    /// # Returns
    ///
    /// A vector of data points (may be fewer than `limit` if buffer has less)
    async fn peek(&self, limit: usize) -> Result<Vec<DataPoint>, BufferError>;

    /// Removes and returns items from the buffer.
    ///
    /// Items are returned in FIFO order (oldest first).
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of items to remove
    ///
    /// # Returns
    ///
    /// A vector of data points that were removed
    async fn pop(&self, count: usize) -> Result<Vec<DataPoint>, BufferError>;

    /// Returns the current number of items in the buffer.
    ///
    /// # Performance
    ///
    /// **MUST be O(1)** - implemented using atomic counters, not by
    /// scanning the underlying storage.
    fn len(&self) -> usize;

    /// Returns `true` if the buffer is empty.
    ///
    /// # Performance
    ///
    /// **MUST be O(1)** - implemented using atomic counters.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all data from the buffer.
    ///
    /// # Warning
    ///
    /// This operation is irreversible and will delete all buffered data.
    async fn clear(&self) -> Result<(), BufferError>;

    /// Returns the current disk/memory usage in bytes.
    async fn disk_usage(&self) -> Result<u64, BufferError>;

    /// Returns the current buffer statistics.
    ///
    /// # Performance
    ///
    /// Should be O(1) - returns a snapshot of atomic counters.
    fn stats(&self) -> BufferStats;

    /// Flushes any pending writes to persistent storage.
    ///
    /// For RocksDB, this ensures WAL is synced to disk.
    async fn sync(&self) -> Result<(), BufferError>;

    /// Compacts the underlying storage (if applicable).
    ///
    /// This can help reclaim space after many deletions.
    async fn compact(&self) -> Result<(), BufferError>;

    /// Returns the configuration used by this buffer.
    fn config(&self) -> &BufferConfig;
}

// =============================================================================
// Buffer Factory
// =============================================================================

/// Factory trait for creating buffer instances.
///
/// This allows for dependency injection and testing.
#[async_trait]
pub trait BufferFactory: Send + Sync {
    /// Creates a new buffer instance with the given configuration.
    async fn create(&self, config: BufferConfig) -> Result<Box<dyn OfflineBuffer>, BufferError>;

    /// Returns the name of this factory.
    fn name(&self) -> &str;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_config_defaults() {
        let config = BufferConfig::default();
        assert_eq!(config.max_size_bytes, 1024 * 1024 * 1024);
        assert_eq!(config.max_items, 10_000_000);
        assert_eq!(config.batch_size, 1000);
        assert!(config.compression);
        assert!(!config.sync_writes);
    }

    #[test]
    fn test_buffer_config_builder() {
        let config = BufferConfig::builder()
            .path("/tmp/test")
            .max_size_bytes(500_000_000)
            .max_items(1_000_000)
            .batch_size(500)
            .compression(false)
            .build();

        assert_eq!(config.path, "/tmp/test");
        assert_eq!(config.max_size_bytes, 500_000_000);
        assert_eq!(config.max_items, 1_000_000);
        assert_eq!(config.batch_size, 500);
        assert!(!config.compression);
    }

    #[test]
    fn test_buffer_config_presets() {
        let test_config = BufferConfig::for_testing();
        assert!(test_config.max_size_bytes < BufferConfig::default().max_size_bytes);

        let perf_config = BufferConfig::high_performance();
        assert!(perf_config.max_size_bytes > BufferConfig::default().max_size_bytes);
    }

    #[test]
    fn test_buffer_stats_inner_store() {
        let stats = BufferStatsInner::new();

        stats.record_store(100, 1000);
        assert_eq!(stats.current_items(), 1);
        assert_eq!(stats.current_bytes(), 100);

        stats.record_store(200, 2000);
        assert_eq!(stats.current_items(), 2);
        assert_eq!(stats.current_bytes(), 300);
    }

    #[test]
    fn test_buffer_stats_inner_flush() {
        let stats = BufferStatsInner::new();

        stats.record_store(100, 1000);
        stats.record_store(200, 2000);
        assert_eq!(stats.current_items(), 2);

        stats.record_flush(1, 100);
        assert_eq!(stats.current_items(), 1);
        assert_eq!(stats.current_bytes(), 200);
    }

    #[test]
    fn test_buffer_stats_snapshot() {
        let stats = BufferStatsInner::new();
        stats.record_store(100, 1000);
        stats.record_flush(1, 100);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.items_stored, 1);
        assert_eq!(snapshot.items_flushed, 1);
        assert_eq!(snapshot.current_items, 0);
    }

    #[test]
    fn test_buffer_stats_fill_ratio() {
        let snapshot = BufferStats {
            items_stored: 100,
            items_flushed: 50,
            items_dropped: 0,
            bytes_written: 1000,
            bytes_flushed: 500,
            flush_count: 5,
            flush_errors: 1,
            oldest_timestamp: Utc::now(),
            newest_timestamp: Utc::now(),
            last_flush_timestamp: Some(Utc::now()),
            current_items: 50,
            current_bytes: 500,
        };

        assert_eq!(snapshot.fill_ratio_items(100), 0.5);
        assert_eq!(snapshot.fill_ratio_bytes(1000), 0.5);
    }

    #[test]
    fn test_buffer_stats_flush_success_rate() {
        let snapshot = BufferStats {
            items_stored: 0,
            items_flushed: 0,
            items_dropped: 0,
            bytes_written: 0,
            bytes_flushed: 0,
            flush_count: 8,
            flush_errors: 2,
            oldest_timestamp: Utc::now(),
            newest_timestamp: Utc::now(),
            last_flush_timestamp: None,
            current_items: 0,
            current_bytes: 0,
        };

        assert_eq!(snapshot.flush_success_rate(), 0.8);
    }

    #[test]
    fn test_buffer_stats_inner_reset() {
        let stats = BufferStatsInner::new();
        stats.record_store(100, 1000);
        stats.record_store(200, 2000);

        stats.reset();

        assert_eq!(stats.current_items(), 0);
        assert_eq!(stats.current_bytes(), 0);
    }

    #[test]
    fn test_buffer_stats_inner_batch_store() {
        let stats = BufferStatsInner::new();

        stats.record_batch_store(10, 1000, 100, 200);
        assert_eq!(stats.current_items(), 10);
        assert_eq!(stats.current_bytes(), 1000);
    }

    #[test]
    fn test_buffer_stats_inner_dropped() {
        let stats = BufferStatsInner::new();

        stats.record_store(100, 1000);
        stats.record_store(100, 1000);
        assert_eq!(stats.current_items(), 2);

        stats.record_dropped(1, 100);
        assert_eq!(stats.current_items(), 1);
        assert_eq!(stats.items_dropped.load(Ordering::Relaxed), 1);
    }
}
