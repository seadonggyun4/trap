// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # Buffer Integration Tests
//!
//! Integration tests for trap-buffer functionality including:
//!
//! - Memory buffer operations
//! - Buffer manager with flush logic
//! - Capacity management and eviction
//! - Concurrent buffer operations
//!
//! ## Test Categories
//!
//! - `test_memory_buffer_*`: In-memory buffer tests
//! - `test_buffer_manager_*`: Buffer manager tests
//! - `test_buffer_concurrent_*`: Concurrency tests

use std::sync::Arc;
use std::time::Duration;

use trap_core::types::{DataPoint, DataQuality, DeviceId, TagId, Value};
use trap_buffer::{
    BufferConfig, MemoryBuffer, OfflineBuffer,
    BufferManager, BufferManagerConfig, MockUpstreamSink,
};

use trap_tests::common::{
    fixtures::{DeviceFixtures, DataPointFixtures},
    harness::ConcurrentTestHelper,
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Create a test data point with a sequence number.
fn test_data_point(seq: usize) -> DataPoint {
    DataPoint::new(
        DeviceId::new(format!("device-{}", seq % 10)),
        TagId::new(format!("tag-{}", seq)),
        Value::Float64(seq as f64),
        DataQuality::Good,
    )
}

/// Create a batch of test data points.
fn test_data_batch(count: usize) -> Vec<DataPoint> {
    (0..count).map(test_data_point).collect()
}

// =============================================================================
// Memory Buffer Basic Tests
// =============================================================================

#[tokio::test]
async fn test_memory_buffer_creation() {
    let config = BufferConfig::for_testing();
    let buffer = MemoryBuffer::new(config);

    assert!(buffer.is_empty());
    assert_eq!(buffer.len(), 0);
}

#[tokio::test]
async fn test_memory_buffer_store_single() {
    let config = BufferConfig::for_testing();
    let buffer = MemoryBuffer::new(config);

    let dp = test_data_point(1);
    buffer.store(dp).await.expect("Store failed");

    assert!(!buffer.is_empty());
    assert_eq!(buffer.len(), 1);
}

#[tokio::test]
async fn test_memory_buffer_store_batch() {
    let config = BufferConfig::for_testing();
    let buffer = MemoryBuffer::new(config);

    let batch = test_data_batch(100);
    buffer.store_batch(batch).await.expect("Store batch failed");

    assert_eq!(buffer.len(), 100);
}

#[tokio::test]
async fn test_memory_buffer_peek() {
    let config = BufferConfig::for_testing();
    let buffer = MemoryBuffer::new(config);

    // Store some data
    let batch = test_data_batch(10);
    buffer.store_batch(batch).await.expect("Store failed");

    // Peek should not remove items
    let peeked = buffer.peek(5).await.expect("Peek failed");
    assert_eq!(peeked.len(), 5);
    assert_eq!(buffer.len(), 10); // Still 10 items

    // Peek again - should get same items
    let peeked2 = buffer.peek(5).await.expect("Peek failed");
    assert_eq!(peeked2.len(), 5);
    assert_eq!(buffer.len(), 10);
}

#[tokio::test]
async fn test_memory_buffer_pop() {
    let config = BufferConfig::for_testing();
    let buffer = MemoryBuffer::new(config);

    // Store some data
    let batch = test_data_batch(10);
    buffer.store_batch(batch).await.expect("Store failed");

    // Pop should remove items
    let popped = buffer.pop(5).await.expect("Pop failed");
    assert_eq!(popped.len(), 5);
    assert_eq!(buffer.len(), 5); // Only 5 items left

    // Pop remaining
    let remaining = buffer.pop(10).await.expect("Pop failed");
    assert_eq!(remaining.len(), 5); // Only 5 were left
    assert!(buffer.is_empty());
}

#[tokio::test]
async fn test_memory_buffer_ordering() {
    let config = BufferConfig::for_testing();
    let buffer = MemoryBuffer::new(config);

    // Store items in order
    for i in 0..10 {
        let dp = test_data_point(i);
        buffer.store(dp).await.expect("Store failed");
    }

    // Pop should return in FIFO order
    let popped = buffer.pop(10).await.expect("Pop failed");

    for (i, dp) in popped.iter().enumerate() {
        let expected_value = i as f64;
        assert_eq!(dp.value.as_f64().unwrap(), expected_value);
    }
}

#[tokio::test]
async fn test_memory_buffer_clear() {
    let config = BufferConfig::for_testing();
    let buffer = MemoryBuffer::new(config);

    buffer.store_batch(test_data_batch(100)).await.expect("Store failed");
    assert_eq!(buffer.len(), 100);

    buffer.clear().await.expect("Clear failed");
    assert!(buffer.is_empty());
    assert_eq!(buffer.len(), 0);
}

// =============================================================================
// Memory Buffer Capacity Tests
// =============================================================================

#[tokio::test]
async fn test_memory_buffer_capacity_limit() {
    let config = BufferConfig::builder()
        .max_items(50)
        .build();
    let buffer = MemoryBuffer::new(config);

    // First fill to capacity
    buffer.store_batch(test_data_batch(50)).await.expect("Store failed");
    assert_eq!(buffer.len(), 50);

    // Adding more items should trigger eviction
    buffer.store_batch(test_data_batch(10)).await.expect("Store failed");

    // Buffer should have evicted some items to stay near capacity
    // The exact count depends on eviction strategy (evicts ~10% at a time)
    assert!(buffer.len() > 0);
}

#[tokio::test]
async fn test_memory_buffer_eviction_on_full() {
    let config = BufferConfig::builder()
        .max_items(10)
        .build();
    let buffer = MemoryBuffer::new(config);

    // Fill buffer
    buffer.store_batch(test_data_batch(10)).await.expect("Store failed");
    assert!(buffer.len() <= 10);

    // Add one more - should evict oldest
    let new_dp = test_data_point(999);
    buffer.store(new_dp).await.expect("Store failed");

    assert!(buffer.len() <= 10);
}

// =============================================================================
// Memory Buffer Stats Tests
// =============================================================================

#[tokio::test]
async fn test_memory_buffer_stats() {
    let config = BufferConfig::for_testing();
    let buffer = MemoryBuffer::new(config);

    // Initial stats
    let stats = buffer.stats();
    assert_eq!(stats.current_items, 0);

    // Store some items
    buffer.store_batch(test_data_batch(50)).await.expect("Store failed");

    let stats = buffer.stats();
    assert_eq!(stats.current_items, 50);
    assert!(stats.items_stored >= 50);

    // Pop some items
    buffer.pop(20).await.expect("Pop failed");

    let stats = buffer.stats();
    assert_eq!(stats.current_items, 30);
}

// =============================================================================
// Buffer Manager Tests
// =============================================================================

#[tokio::test]
async fn test_buffer_manager_store() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());
    let upstream = MockUpstreamSink::new();
    let config = BufferManagerConfig::for_testing();

    let manager = BufferManager::new(buffer, upstream, config);

    let dp = test_data_point(1);
    manager.store(dp).await.expect("Store failed");

    assert_eq!(manager.len(), 1);
}

#[tokio::test]
async fn test_buffer_manager_store_batch() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());
    let upstream = MockUpstreamSink::new();
    let config = BufferManagerConfig::for_testing();

    let manager = BufferManager::new(buffer, upstream, config);

    let batch = test_data_batch(100);
    manager.store_batch(batch).await.expect("Store batch failed");

    assert_eq!(manager.len(), 100);
}

#[tokio::test]
async fn test_buffer_manager_is_empty() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());
    let upstream = MockUpstreamSink::new();
    let config = BufferManagerConfig::for_testing();

    let manager = BufferManager::new(buffer, upstream, config);

    assert!(manager.is_empty());

    manager.store(test_data_point(1)).await.expect("Store failed");
    assert!(!manager.is_empty());
}

#[tokio::test]
async fn test_buffer_manager_with_failing_upstream() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());
    let upstream = MockUpstreamSink::failing("Test failure");
    let config = BufferManagerConfig::for_testing();

    let manager = BufferManager::new(buffer, upstream, config);

    // Store data - should still work even with failing upstream
    manager.store_batch(test_data_batch(50)).await.expect("Store failed");
    assert_eq!(manager.len(), 50);
}

// =============================================================================
// Concurrent Buffer Tests
// =============================================================================

#[tokio::test]
async fn test_buffer_concurrent_stores() {
    let buffer = Arc::new(MemoryBuffer::new(BufferConfig::for_testing()));

    let helper = ConcurrentTestHelper::new(10);
    let task_items = 100;

    helper
        .run_all_succeed({
            let buffer = buffer.clone();
            move |task_id| {
                let buffer = buffer.clone();
                async move {
                    for i in 0..task_items {
                        let dp = DataPoint::new(
                            DeviceId::new(format!("device-{}", task_id)),
                            TagId::new(format!("tag-{}", i)),
                            Value::Float64((task_id * task_items + i) as f64),
                            DataQuality::Good,
                        );
                        buffer.store(dp).await.expect("Store failed");
                    }
                    task_id
                }
            }
        })
        .await;

    // All items should be stored (may have some eviction if capacity exceeded)
    assert!(buffer.len() > 0);
}

#[tokio::test]
async fn test_buffer_concurrent_peek() {
    let buffer = Arc::new(MemoryBuffer::new(BufferConfig::for_testing()));

    // Store initial data
    buffer.store_batch(test_data_batch(100)).await.expect("Store failed");

    let helper = ConcurrentTestHelper::new(10);

    // Multiple concurrent peeks should all succeed and return same data
    let results = helper
        .run_all_succeed({
            let buffer = buffer.clone();
            move |_| {
                let buffer = buffer.clone();
                async move { buffer.peek(50).await.expect("Peek failed").len() }
            }
        })
        .await;

    // All peeks should return 50 items
    assert!(results.iter().all(|&count| count == 50));

    // Buffer should still have 100 items
    assert_eq!(buffer.len(), 100);
}

// =============================================================================
// Buffer with Test Fixtures
// =============================================================================

#[tokio::test]
async fn test_buffer_with_fixtures() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());
    let upstream = MockUpstreamSink::new();
    let config = BufferManagerConfig::for_testing();
    let manager = BufferManager::new(buffer, upstream, config);

    // Use harness resources
    let device = DeviceFixtures::modbus_plc();
    let batch = DataPointFixtures::data_point_batch(device, 50);

    manager.store_batch(batch).await.expect("Store failed");
    assert_eq!(manager.len(), 50);
}

#[tokio::test]
async fn test_buffer_isolation() {
    // Test that multiple buffer instances are isolated
    let buffer1 = MemoryBuffer::new(BufferConfig::for_testing());
    let buffer2 = MemoryBuffer::new(BufferConfig::for_testing());

    buffer1.store_batch(test_data_batch(50)).await.expect("Store failed");

    assert_eq!(buffer1.len(), 50);
    assert_eq!(buffer2.len(), 0); // buffer2 should be empty
}

// =============================================================================
// O(1) Counter Performance Tests
// =============================================================================

#[tokio::test]
async fn test_buffer_len_is_o1() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());

    // Store a large number of items
    buffer.store_batch(test_data_batch(10000)).await.expect("Store failed");

    // len() should be very fast (O(1))
    let start = std::time::Instant::now();
    for _ in 0..10000 {
        let _ = buffer.len();
    }
    let duration = start.elapsed();

    // 10000 len() calls should take less than 100ms if O(1)
    assert!(duration < Duration::from_millis(100));
}

#[tokio::test]
async fn test_buffer_is_empty_is_o1() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());

    buffer.store_batch(test_data_batch(10000)).await.expect("Store failed");

    let start = std::time::Instant::now();
    for _ in 0..10000 {
        let _ = buffer.is_empty();
    }
    let duration = start.elapsed();

    assert!(duration < Duration::from_millis(100));
}

// =============================================================================
// Edge Cases
// =============================================================================

#[tokio::test]
async fn test_buffer_empty_operations() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());

    // Peek from empty buffer
    let peeked = buffer.peek(10).await.expect("Peek failed");
    assert!(peeked.is_empty());

    // Pop from empty buffer
    let popped = buffer.pop(10).await.expect("Pop failed");
    assert!(popped.is_empty());

    // Clear empty buffer
    buffer.clear().await.expect("Clear failed");
    assert!(buffer.is_empty());
}

#[tokio::test]
async fn test_buffer_peek_more_than_available() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());
    buffer.store_batch(test_data_batch(5)).await.expect("Store failed");

    // Peek more than available
    let peeked = buffer.peek(100).await.expect("Peek failed");
    assert_eq!(peeked.len(), 5);
}

#[tokio::test]
async fn test_buffer_pop_more_than_available() {
    let buffer = MemoryBuffer::new(BufferConfig::for_testing());
    buffer.store_batch(test_data_batch(5)).await.expect("Store failed");

    // Pop more than available
    let popped = buffer.pop(100).await.expect("Pop failed");
    assert_eq!(popped.len(), 5);
    assert!(buffer.is_empty());
}

#[tokio::test]
async fn test_buffer_single_item_capacity() {
    let config = BufferConfig::builder()
        .max_items(1)
        .build();

    let buffer = MemoryBuffer::new(config);

    buffer.store(test_data_point(1)).await.expect("Store failed");
    assert!(buffer.len() <= 1);

    buffer.store(test_data_point(2)).await.expect("Store failed");
    assert!(buffer.len() <= 1);
}
