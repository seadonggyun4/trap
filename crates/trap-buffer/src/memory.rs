// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! In-memory buffer implementation for testing.
//!
//! This module provides a thread-safe, in-memory buffer that implements
//! the `OfflineBuffer` trait. It's primarily intended for testing and
//! development scenarios where persistence is not required.
//!
//! # Features
//!
//! - **O(1) Counter Performance**: Uses atomic counters for `len()` and `is_empty()`
//! - **Thread-Safe**: Uses `parking_lot::RwLock` for minimal contention
//! - **FIFO Ordering**: Maintains insertion order using `VecDeque`
//! - **No Persistence**: Data is lost when the buffer is dropped
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_buffer::{MemoryBuffer, BufferConfig};
//!
//! let buffer = MemoryBuffer::new(BufferConfig::for_testing());
//!
//! buffer.store(data_point).await?;
//!
//! // O(1) length check
//! println!("Items: {}", buffer.len());
//! ```

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::debug;

use trap_core::error::BufferError;
use trap_core::types::DataPoint;

use crate::traits::{BufferConfig, BufferStats, BufferStatsInner, OfflineBuffer};

// =============================================================================
// Memory Buffer Entry
// =============================================================================

/// A buffered entry with size tracking.
#[derive(Debug, Clone)]
struct BufferEntry {
    /// The data point.
    data: DataPoint,
    /// Serialized size in bytes (for statistics).
    size_bytes: u64,
}

// =============================================================================
// Memory Buffer
// =============================================================================

/// An in-memory buffer implementation.
///
/// This buffer stores data in memory using a `VecDeque` for FIFO ordering.
/// It provides O(1) `len()` performance using atomic counters.
///
/// # Thread Safety
///
/// This struct is `Send + Sync`. The internal queue is protected by a
/// `parking_lot::RwLock`, and counters use atomic operations.
///
/// # Memory Management
///
/// When capacity is exceeded, oldest items are evicted (FIFO).
/// Memory is not reclaimed until the buffer is dropped or cleared.
#[derive(Debug)]
pub struct MemoryBuffer {
    /// The data queue (FIFO).
    queue: RwLock<VecDeque<BufferEntry>>,

    /// Buffer configuration.
    config: BufferConfig,

    /// O(1) item count (atomic counter).
    item_count: AtomicU64,

    /// O(1) byte count (atomic counter).
    byte_count: AtomicU64,

    /// Lock-free statistics.
    stats: BufferStatsInner,
}

impl MemoryBuffer {
    /// Creates a new in-memory buffer with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Buffer configuration
    ///
    /// # Returns
    ///
    /// A new `MemoryBuffer` instance.
    pub fn new(config: BufferConfig) -> Self {
        Self {
            queue: RwLock::new(VecDeque::with_capacity(
                (config.max_items as usize).min(100_000),
            )),
            config,
            item_count: AtomicU64::new(0),
            byte_count: AtomicU64::new(0),
            stats: BufferStatsInner::new(),
        }
    }

    /// Creates a new in-memory buffer with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(BufferConfig::for_testing())
    }

    /// Estimates the serialized size of a data point.
    fn estimate_size(data: &DataPoint) -> u64 {
        // Rough estimate based on typical serialization overhead
        let base_size = std::mem::size_of::<DataPoint>() as u64;
        let string_overhead = data.device_id.as_str().len() as u64 + data.tag_id.as_str().len() as u64;

        base_size + string_overhead + 64 // Add some overhead for serialization format
    }

    /// Evicts oldest items to make room for new data.
    fn evict_if_needed(&self, queue: &mut VecDeque<BufferEntry>, required_bytes: u64) {
        let current_items = self.item_count.load(Ordering::Relaxed);
        let current_bytes = self.byte_count.load(Ordering::Relaxed);

        // Check if eviction is needed
        if current_items < self.config.max_items
            && current_bytes + required_bytes <= self.config.max_size_bytes
        {
            return;
        }

        // Calculate how many items to evict
        let min_evict = (self.config.max_items / 10).max(1);
        let items_over = current_items.saturating_sub(self.config.max_items.saturating_sub(1));
        let items_to_evict = items_over.max(min_evict) as usize;

        debug!(
            items_to_evict = items_to_evict,
            current_items = current_items,
            max_items = self.config.max_items,
            "Evicting items from memory buffer"
        );

        let mut evicted_count = 0u64;
        let mut evicted_bytes = 0u64;

        for _ in 0..items_to_evict {
            if let Some(entry) = queue.pop_front() {
                evicted_count += 1;
                evicted_bytes += entry.size_bytes;
            } else {
                break;
            }
        }

        // Update counters
        self.item_count.fetch_sub(evicted_count, Ordering::Relaxed);
        self.byte_count.fetch_sub(evicted_bytes, Ordering::Relaxed);
        self.stats.record_dropped(evicted_count, evicted_bytes);
    }
}

#[async_trait]
impl OfflineBuffer for MemoryBuffer {
    async fn store(&self, data: DataPoint) -> Result<(), BufferError> {
        let size_bytes = Self::estimate_size(&data);
        let timestamp_nanos = data.timestamp.timestamp_nanos_opt().unwrap_or(0);

        let entry = BufferEntry { data, size_bytes };

        {
            let mut queue = self.queue.write();

            // Evict if needed
            self.evict_if_needed(&mut queue, size_bytes);

            // Add new entry
            queue.push_back(entry);
        }

        // Update counters (O(1) atomic operations)
        self.item_count.fetch_add(1, Ordering::Relaxed);
        self.byte_count.fetch_add(size_bytes, Ordering::Relaxed);
        self.stats.record_store(size_bytes, timestamp_nanos);

        Ok(())
    }

    async fn store_batch(&self, data: Vec<DataPoint>) -> Result<(), BufferError> {
        if data.is_empty() {
            return Ok(());
        }

        let entries: Vec<BufferEntry> = data
            .into_iter()
            .map(|d| {
                let size_bytes = Self::estimate_size(&d);
                BufferEntry {
                    data: d,
                    size_bytes,
                }
            })
            .collect();

        let count = entries.len() as u64;
        let total_bytes: u64 = entries.iter().map(|e| e.size_bytes).sum();

        let oldest_ts = entries
            .first()
            .and_then(|e| e.data.timestamp.timestamp_nanos_opt())
            .unwrap_or(0);
        let newest_ts = entries
            .last()
            .and_then(|e| e.data.timestamp.timestamp_nanos_opt())
            .unwrap_or(0);

        {
            let mut queue = self.queue.write();

            // Evict if needed
            self.evict_if_needed(&mut queue, total_bytes);

            // Add all entries
            for entry in entries {
                queue.push_back(entry);
            }
        }

        // Update counters
        self.item_count.fetch_add(count, Ordering::Relaxed);
        self.byte_count.fetch_add(total_bytes, Ordering::Relaxed);
        self.stats.record_batch_store(count, total_bytes, oldest_ts, newest_ts);

        Ok(())
    }

    async fn peek(&self, limit: usize) -> Result<Vec<DataPoint>, BufferError> {
        let queue = self.queue.read();

        let results: Vec<DataPoint> = queue
            .iter()
            .take(limit)
            .map(|e| e.data.clone())
            .collect();

        Ok(results)
    }

    async fn pop(&self, count: usize) -> Result<Vec<DataPoint>, BufferError> {
        if count == 0 {
            return Ok(vec![]);
        }

        let mut results = Vec::with_capacity(count);
        let mut removed_bytes = 0u64;

        {
            let mut queue = self.queue.write();

            for _ in 0..count {
                if let Some(entry) = queue.pop_front() {
                    removed_bytes += entry.size_bytes;
                    results.push(entry.data);
                } else {
                    break;
                }
            }
        }

        let removed_count = results.len() as u64;

        // Update counters
        self.item_count.fetch_sub(removed_count, Ordering::Relaxed);
        self.byte_count.fetch_sub(removed_bytes, Ordering::Relaxed);
        self.stats.record_removal(removed_count, removed_bytes);

        Ok(results)
    }

    /// Returns the current item count in O(1) time.
    #[inline]
    fn len(&self) -> usize {
        self.item_count.load(Ordering::Relaxed) as usize
    }

    async fn clear(&self) -> Result<(), BufferError> {
        {
            let mut queue = self.queue.write();
            queue.clear();
        }

        // Reset counters
        self.item_count.store(0, Ordering::Relaxed);
        self.byte_count.store(0, Ordering::Relaxed);
        self.stats.reset();

        Ok(())
    }

    async fn disk_usage(&self) -> Result<u64, BufferError> {
        // Return the tracked byte count (in-memory size)
        Ok(self.byte_count.load(Ordering::Relaxed))
    }

    fn stats(&self) -> BufferStats {
        self.stats.snapshot()
    }

    async fn sync(&self) -> Result<(), BufferError> {
        // No-op for memory buffer (no persistence)
        Ok(())
    }

    async fn compact(&self) -> Result<(), BufferError> {
        // Shrink the VecDeque to fit
        {
            let mut queue = self.queue.write();
            queue.shrink_to_fit();
        }
        Ok(())
    }

    fn config(&self) -> &BufferConfig {
        &self.config
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use trap_core::types::{DataQuality, DeviceId, TagId, Value};

    fn create_test_data_point(value: f64) -> DataPoint {
        DataPoint::new(
            DeviceId::new("test-device"),
            TagId::new("test-tag"),
            Value::Float64(value),
            DataQuality::Good,
        )
    }

    fn create_test_buffer() -> MemoryBuffer {
        MemoryBuffer::new(BufferConfig::builder()
            .max_items(1000)
            .max_size_bytes(1024 * 1024)
            .build())
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let buffer = create_test_buffer();

        let point = create_test_data_point(42.0);
        buffer.store(point.clone()).await.unwrap();

        assert_eq!(buffer.len(), 1);
        assert!(!buffer.is_empty());

        let retrieved = buffer.peek(1).await.unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].value.as_f64(), Some(42.0));
    }

    #[tokio::test]
    async fn test_batch_store() {
        let buffer = create_test_buffer();

        let points: Vec<DataPoint> = (0..100)
            .map(|i| create_test_data_point(i as f64))
            .collect();

        buffer.store_batch(points).await.unwrap();

        assert_eq!(buffer.len(), 100);
    }

    #[tokio::test]
    async fn test_pop_removes_items() {
        let buffer = create_test_buffer();

        for i in 0..10 {
            buffer.store(create_test_data_point(i as f64)).await.unwrap();
        }

        assert_eq!(buffer.len(), 10);

        let popped = buffer.pop(5).await.unwrap();
        assert_eq!(popped.len(), 5);
        assert_eq!(buffer.len(), 5);
    }

    #[tokio::test]
    async fn test_fifo_ordering() {
        let buffer = create_test_buffer();

        for i in 0..5 {
            buffer.store(create_test_data_point(i as f64)).await.unwrap();
        }

        let retrieved = buffer.pop(5).await.unwrap();

        // Should be in FIFO order (oldest first)
        for (i, point) in retrieved.iter().enumerate() {
            assert_eq!(point.value.as_f64(), Some(i as f64));
        }
    }

    #[tokio::test]
    async fn test_clear() {
        let buffer = create_test_buffer();

        for i in 0..10 {
            buffer.store(create_test_data_point(i as f64)).await.unwrap();
        }

        assert_eq!(buffer.len(), 10);

        buffer.clear().await.unwrap();

        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
    }

    #[tokio::test]
    async fn test_o1_len_performance() {
        let buffer = create_test_buffer();

        // Store many items
        let points: Vec<DataPoint> = (0..500)
            .map(|i| create_test_data_point(i as f64))
            .collect();
        buffer.store_batch(points).await.unwrap();

        // len() should be O(1) - just an atomic load
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = buffer.len();
        }
        let elapsed = start.elapsed();

        // Should be extremely fast (microseconds, not milliseconds)
        assert!(
            elapsed.as_millis() < 10,
            "len() took too long: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_stats() {
        let buffer = create_test_buffer();

        buffer.store(create_test_data_point(1.0)).await.unwrap();
        buffer.store(create_test_data_point(2.0)).await.unwrap();

        let stats = buffer.stats();
        assert_eq!(stats.items_stored, 2);
        assert_eq!(stats.current_items, 2);
        assert!(stats.bytes_written > 0);
    }

    #[tokio::test]
    async fn test_eviction_on_capacity() {
        let buffer = MemoryBuffer::new(BufferConfig::builder()
            .max_items(10) // Very small limit
            .max_size_bytes(1024 * 1024)
            .build());

        // Store more than max_items
        for i in 0..20 {
            buffer.store(create_test_data_point(i as f64)).await.unwrap();
        }

        // Should have evicted some items
        let stats = buffer.stats();
        assert!(stats.items_dropped > 0);
    }

    #[tokio::test]
    async fn test_empty_batch_store() {
        let buffer = create_test_buffer();

        buffer.store_batch(vec![]).await.unwrap();

        assert_eq!(buffer.len(), 0);
    }

    #[tokio::test]
    async fn test_pop_empty_buffer() {
        let buffer = create_test_buffer();

        let popped = buffer.pop(10).await.unwrap();

        assert!(popped.is_empty());
    }

    #[tokio::test]
    async fn test_peek_empty_buffer() {
        let buffer = create_test_buffer();

        let peeked = buffer.peek(10).await.unwrap();

        assert!(peeked.is_empty());
    }

    #[tokio::test]
    async fn test_disk_usage() {
        let buffer = create_test_buffer();

        let initial_usage = buffer.disk_usage().await.unwrap();
        assert_eq!(initial_usage, 0);

        buffer.store(create_test_data_point(42.0)).await.unwrap();

        let usage = buffer.disk_usage().await.unwrap();
        assert!(usage > 0);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        use std::sync::Arc;

        let buffer = Arc::new(create_test_buffer());
        let mut handles = vec![];

        // Spawn multiple writers
        for i in 0..10 {
            let buf = buffer.clone();
            handles.push(tokio::spawn(async move {
                for j in 0..100 {
                    buf.store(create_test_data_point((i * 100 + j) as f64))
                        .await
                        .unwrap();
                }
            }));
        }

        // Wait for all writers
        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(buffer.len(), 1000);
    }

    #[tokio::test]
    async fn test_compact() {
        let buffer = create_test_buffer();

        // Store and then remove many items
        for i in 0..100 {
            buffer.store(create_test_data_point(i as f64)).await.unwrap();
        }
        buffer.pop(90).await.unwrap();

        // Compact should succeed
        buffer.compact().await.unwrap();

        assert_eq!(buffer.len(), 10);
    }

    #[tokio::test]
    async fn test_peek_does_not_remove() {
        let buffer = create_test_buffer();

        for i in 0..5 {
            buffer.store(create_test_data_point(i as f64)).await.unwrap();
        }

        // Peek twice - should return same data
        let peek1 = buffer.peek(5).await.unwrap();
        let peek2 = buffer.peek(5).await.unwrap();

        assert_eq!(peek1.len(), 5);
        assert_eq!(peek2.len(), 5);
        assert_eq!(buffer.len(), 5); // Count unchanged
    }
}
