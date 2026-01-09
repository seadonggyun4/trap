// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # trap-buffer
//!
//! Offline buffering and data persistence for TRAP industrial protocol gateway.
//!
//! This crate provides persistent storage for data points when the upstream
//! connection is unavailable, ensuring no data loss during network outages.
//!
//! ## Features
//!
//! - **O(1) Counter Performance**: `len()` and `is_empty()` return in constant time
//!   using atomic counters, not by scanning the database.
//!
//! - **RocksDB Backend**: High-performance persistent storage with LZ4 compression,
//!   Bloom filters, and automatic compaction.
//!
//! - **Memory Backend**: In-memory storage for testing and development.
//!
//! - **Buffer Manager**: Orchestrates automatic flushing with circuit breaker
//!   protection and exponential backoff retry logic.
//!
//! - **Prometheus Metrics**: Comprehensive metrics for monitoring buffer operations.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      BufferManager                               │
//! │                                                                  │
//! │  ┌──────────────┐    ┌─────────────────┐    ┌───────────────┐   │
//! │  │OfflineBuffer │───▶│   Flush Loop    │───▶│ UpstreamSink  │   │
//! │  │(RocksDB/Mem) │    │ (periodic task) │    │ (HTTP client) │   │
//! │  └──────────────┘    └────────┬────────┘    └───────────────┘   │
//! │         │                     │                                  │
//! │         │ O(1)     ┌──────────▼──────────┐                       │
//! │         │ len()    │   CircuitBreaker    │                       │
//! │         │          │ + ExponentialBackoff│                       │
//! │         ▼          └─────────────────────┘                       │
//! │  ┌─────────────┐                                                 │
//! │  │ AtomicU64   │   ┌─────────────────────────────────────────┐  │
//! │  │ Counters    │   │           Prometheus Metrics            │  │
//! │  └─────────────┘   └─────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ### Using RocksDB Buffer
//!
//! ```rust,ignore
//! use trap_buffer::{RocksDbBuffer, BufferConfig, OfflineBuffer};
//! use trap_core::types::{DataPoint, DeviceId, TagId, Value, DataQuality};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a RocksDB buffer
//!     let config = BufferConfig::builder()
//!         .path("/var/lib/trap/buffer")
//!         .max_items(1_000_000)
//!         .compression(true)
//!         .build();
//!
//!     let buffer = RocksDbBuffer::open(config).await?;
//!
//!     // Store a data point
//!     let point = DataPoint::new(
//!         DeviceId::new("plc-001"),
//!         TagId::new("temperature"),
//!         Value::Float64(25.5),
//!         DataQuality::Good,
//!     );
//!     buffer.store(point).await?;
//!
//!     // O(1) count check - no DB scan!
//!     println!("Items in buffer: {}", buffer.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Using Buffer Manager
//!
//! ```rust,ignore
//! use trap_buffer::{
//!     BufferManager, BufferManagerConfig, MemoryBuffer, BufferConfig,
//!     HttpUpstreamSink,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create buffer and upstream sink
//!     let buffer = MemoryBuffer::new(BufferConfig::for_testing());
//!     let upstream = HttpUpstreamSink::new("http://localhost:8080/api/v1/data", Duration::from_secs(30));
//!
//!     // Create manager with automatic flushing
//!     let config = BufferManagerConfig::builder()
//!         .flush_interval(Duration::from_secs(5))
//!         .flush_batch_size(1000)
//!         .upstream_url("http://localhost:8080/api/v1/data")
//!         .build();
//!
//!     let manager = BufferManager::new(buffer, upstream, config);
//!
//!     // Start the flush loop
//!     let handle = manager.start();
//!
//!     // Store data through the manager
//!     manager.store(data_point).await?;
//!
//!     // Graceful shutdown
//!     manager.shutdown();
//!     handle.await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Module Overview
//!
//! - [`traits`]: Core traits and configuration types (`OfflineBuffer`, `BufferConfig`)
//! - [`rocksdb`]: RocksDB-based persistent buffer implementation
//! - [`memory`]: In-memory buffer for testing
//! - [`manager`]: Buffer manager with flush loop and circuit breaker
//! - [`metrics`]: Prometheus metrics for buffer operations
//!
//! ## Performance Characteristics
//!
//! | Operation | Complexity | Notes |
//! |-----------|------------|-------|
//! | `store()` | O(log n) | RocksDB write |
//! | `store_batch()` | O(m log n) | RocksDB batch write |
//! | `peek()` | O(m) | Iterator over m items |
//! | `pop()` | O(m) | Read + delete m items |
//! | **`len()`** | **O(1)** | AtomicU64 load |
//! | **`is_empty()`** | **O(1)** | AtomicU64 load |
//!
//! ## Feature Flags
//!
//! - `rocksdb-backend` (default): Enable RocksDB persistent storage
//! - `memory-backend`: Enable in-memory storage (always available)

#![warn(missing_docs)]
#![deny(unsafe_code)]

// =============================================================================
// Modules
// =============================================================================

pub mod traits;

#[cfg(feature = "rocksdb-backend")]
pub mod rocksdb;

pub mod memory;
pub mod manager;
pub mod metrics;

// =============================================================================
// Re-exports
// =============================================================================

pub use traits::{
    BufferConfig, BufferConfigBuilder, BufferFactory, BufferStats, BufferStatsInner,
    OfflineBuffer,
};

pub use memory::MemoryBuffer;

#[cfg(feature = "rocksdb-backend")]
pub use rocksdb::RocksDbBuffer;

pub use manager::{
    BufferManager, BufferManagerConfig, BufferManagerConfigBuilder, BufferManagerMetrics,
    HttpUpstreamSink, MockUpstreamSink, UpstreamSink,
};

pub use metrics::{BufferMetricsCollector, CircuitBreakerState, MetricTimer, MetricTimerType};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// =============================================================================
// Prelude
// =============================================================================

/// A prelude module that re-exports commonly used types.
pub mod prelude {
    pub use crate::traits::{BufferConfig, BufferStats, OfflineBuffer};
    pub use crate::memory::MemoryBuffer;

    #[cfg(feature = "rocksdb-backend")]
    pub use crate::rocksdb::RocksDbBuffer;

    pub use crate::manager::{BufferManager, BufferManagerConfig, UpstreamSink};
    pub use crate::metrics::BufferMetricsCollector;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_default_config() {
        let config = BufferConfig::default();
        assert!(config.max_items > 0);
        assert!(config.max_size_bytes > 0);
    }
}
