// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! RocksDB-based persistent buffer implementation.
//!
//! This module provides a high-performance, persistent buffer backed by RocksDB
//! with **O(1) counter performance** using atomic counters.
//!
//! # Key Features
//!
//! - **Lock-Free Counters**: `len()` and `is_empty()` are O(1) using `AtomicU64`
//! - **Ordered by Timestamp**: Keys are timestamp-based for FIFO ordering
//! - **Compression**: Optional LZ4 compression for reduced disk usage
//! - **Automatic Eviction**: FIFO eviction when capacity is exceeded
//! - **Crash Recovery**: Counter reconstruction on startup
//!
//! # Key Format
//!
//! Keys are encoded as: `{timestamp_nanos:16}{random:4}` (20 bytes total)
//!
//! This ensures:
//! - Natural timestamp ordering for FIFO retrieval
//! - No collisions for same-timestamp inserts (random suffix)
//! - Efficient range scans for batch operations

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rocksdb::{
    BlockBasedOptions, DBCompressionType, IteratorMode, Options, WriteBatch, WriteOptions, DB,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use trap_core::error::BufferError;
use trap_core::types::{BadReason, DataPoint, DataQuality, DeviceId, TagId, UncertainReason, Value};

use crate::traits::{BufferConfig, BufferStats, BufferStatsInner, OfflineBuffer};

// =============================================================================
// Bincode-Compatible Storage Format
// =============================================================================

/// Internal representation for storage that avoids serde tag attributes.
/// Bincode doesn't support `#[serde(tag = "...")]` so we use a flat structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorableDataPoint {
    device_id: String,
    tag_id: String,
    value: StorableValue,
    quality: StorableQuality,
    timestamp_nanos: i64,
    source_timestamp_nanos: Option<i64>,
}

/// Bincode-compatible value representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum StorableValue {
    Bool(bool),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Float32(f32),
    Float64(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<StorableValue>),
    Struct(Vec<(String, StorableValue)>),
    DateTimeNanos(i64),
    DurationNanos(u64),
    Null,
}

/// Bincode-compatible quality representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum StorableQuality {
    Good,
    UncertainLastKnownValue,
    UncertainSubNormal,
    UncertainEngineeringUnitsExceeded,
    UncertainInitialValue,
    UncertainSensorCalibration,
    UncertainUnknown,
    BadConfigurationError,
    BadNotConnected,
    BadDeviceFailure,
    BadSensorFailure,
    BadCommunicationFailure,
    BadAccessDenied,
    BadOutOfRange,
    BadUnknown,
}

impl StorableDataPoint {
    fn from_data_point(dp: &DataPoint) -> Self {
        Self {
            device_id: dp.device_id.as_str().to_string(),
            tag_id: dp.tag_id.as_str().to_string(),
            value: StorableValue::from_value(&dp.value),
            quality: StorableQuality::from_quality(&dp.quality),
            timestamp_nanos: dp.timestamp.timestamp_nanos_opt().unwrap_or(0),
            source_timestamp_nanos: dp.source_timestamp.and_then(|ts| ts.timestamp_nanos_opt()),
        }
    }

    fn into_data_point(self) -> DataPoint {
        use chrono::{TimeZone, Utc};

        let timestamp = Utc.timestamp_nanos(self.timestamp_nanos);
        let source_timestamp = self.source_timestamp_nanos.map(|ns| Utc.timestamp_nanos(ns));

        let mut dp = DataPoint::with_timestamp(
            DeviceId::new(self.device_id),
            TagId::new(self.tag_id),
            self.value.into_value(),
            self.quality.into_quality(),
            timestamp,
        );
        dp.source_timestamp = source_timestamp;
        dp
    }
}

impl StorableValue {
    fn from_value(v: &Value) -> Self {
        match v {
            Value::Bool(b) => StorableValue::Bool(*b),
            Value::Int8(i) => StorableValue::Int8(*i),
            Value::Int16(i) => StorableValue::Int16(*i),
            Value::Int32(i) => StorableValue::Int32(*i),
            Value::Int64(i) => StorableValue::Int64(*i),
            Value::UInt8(u) => StorableValue::UInt8(*u),
            Value::UInt16(u) => StorableValue::UInt16(*u),
            Value::UInt32(u) => StorableValue::UInt32(*u),
            Value::UInt64(u) => StorableValue::UInt64(*u),
            Value::Float32(f) => StorableValue::Float32(*f),
            Value::Float64(f) => StorableValue::Float64(*f),
            Value::String(s) => StorableValue::String(s.clone()),
            Value::Bytes(b) => StorableValue::Bytes(b.clone()),
            Value::Array(arr) => StorableValue::Array(arr.iter().map(StorableValue::from_value).collect()),
            Value::Struct(fields) => StorableValue::Struct(
                fields
                    .iter()
                    .map(|(k, v)| (k.clone(), StorableValue::from_value(v)))
                    .collect(),
            ),
            Value::DateTime(dt) => StorableValue::DateTimeNanos(dt.timestamp_nanos_opt().unwrap_or(0)),
            Value::Duration(d) => StorableValue::DurationNanos(d.as_nanos() as u64),
            Value::Null => StorableValue::Null,
        }
    }

    fn into_value(self) -> Value {
        use chrono::{TimeZone, Utc};
        use std::time::Duration;

        match self {
            StorableValue::Bool(b) => Value::Bool(b),
            StorableValue::Int8(i) => Value::Int8(i),
            StorableValue::Int16(i) => Value::Int16(i),
            StorableValue::Int32(i) => Value::Int32(i),
            StorableValue::Int64(i) => Value::Int64(i),
            StorableValue::UInt8(u) => Value::UInt8(u),
            StorableValue::UInt16(u) => Value::UInt16(u),
            StorableValue::UInt32(u) => Value::UInt32(u),
            StorableValue::UInt64(u) => Value::UInt64(u),
            StorableValue::Float32(f) => Value::Float32(f),
            StorableValue::Float64(f) => Value::Float64(f),
            StorableValue::String(s) => Value::String(s),
            StorableValue::Bytes(b) => Value::Bytes(b),
            StorableValue::Array(arr) => Value::Array(arr.into_iter().map(StorableValue::into_value).collect()),
            StorableValue::Struct(fields) => Value::Struct(
                fields
                    .into_iter()
                    .map(|(k, v)| (k, StorableValue::into_value(v)))
                    .collect(),
            ),
            StorableValue::DateTimeNanos(ns) => Value::DateTime(Utc.timestamp_nanos(ns)),
            StorableValue::DurationNanos(ns) => Value::Duration(Duration::from_nanos(ns)),
            StorableValue::Null => Value::Null,
        }
    }
}

impl StorableQuality {
    fn from_quality(q: &DataQuality) -> Self {
        match q {
            DataQuality::Good => StorableQuality::Good,
            DataQuality::Uncertain(reason) => match reason {
                UncertainReason::LastKnownValue => StorableQuality::UncertainLastKnownValue,
                UncertainReason::SubNormal => StorableQuality::UncertainSubNormal,
                UncertainReason::EngineeringUnitsExceeded => StorableQuality::UncertainEngineeringUnitsExceeded,
                UncertainReason::InitialValue => StorableQuality::UncertainInitialValue,
                UncertainReason::SensorCalibration => StorableQuality::UncertainSensorCalibration,
                UncertainReason::Unknown => StorableQuality::UncertainUnknown,
            },
            DataQuality::Bad(reason) => match reason {
                BadReason::ConfigurationError => StorableQuality::BadConfigurationError,
                BadReason::NotConnected => StorableQuality::BadNotConnected,
                BadReason::DeviceFailure => StorableQuality::BadDeviceFailure,
                BadReason::SensorFailure => StorableQuality::BadSensorFailure,
                BadReason::CommunicationFailure => StorableQuality::BadCommunicationFailure,
                BadReason::AccessDenied => StorableQuality::BadAccessDenied,
                BadReason::OutOfRange => StorableQuality::BadOutOfRange,
                BadReason::Unknown => StorableQuality::BadUnknown,
            },
        }
    }

    fn into_quality(self) -> DataQuality {
        match self {
            StorableQuality::Good => DataQuality::Good,
            StorableQuality::UncertainLastKnownValue => DataQuality::Uncertain(UncertainReason::LastKnownValue),
            StorableQuality::UncertainSubNormal => DataQuality::Uncertain(UncertainReason::SubNormal),
            StorableQuality::UncertainEngineeringUnitsExceeded => {
                DataQuality::Uncertain(UncertainReason::EngineeringUnitsExceeded)
            }
            StorableQuality::UncertainInitialValue => DataQuality::Uncertain(UncertainReason::InitialValue),
            StorableQuality::UncertainSensorCalibration => DataQuality::Uncertain(UncertainReason::SensorCalibration),
            StorableQuality::UncertainUnknown => DataQuality::Uncertain(UncertainReason::Unknown),
            StorableQuality::BadConfigurationError => DataQuality::Bad(BadReason::ConfigurationError),
            StorableQuality::BadNotConnected => DataQuality::Bad(BadReason::NotConnected),
            StorableQuality::BadDeviceFailure => DataQuality::Bad(BadReason::DeviceFailure),
            StorableQuality::BadSensorFailure => DataQuality::Bad(BadReason::SensorFailure),
            StorableQuality::BadCommunicationFailure => DataQuality::Bad(BadReason::CommunicationFailure),
            StorableQuality::BadAccessDenied => DataQuality::Bad(BadReason::AccessDenied),
            StorableQuality::BadOutOfRange => DataQuality::Bad(BadReason::OutOfRange),
            StorableQuality::BadUnknown => DataQuality::Bad(BadReason::Unknown),
        }
    }
}

// =============================================================================
// Constants
// =============================================================================

/// Column family name for data storage (reserved for future multi-column family support).
#[allow(dead_code)]
const CF_DATA: &str = "data";

/// Key size: 8 bytes timestamp + 4 bytes random = 12 bytes
const KEY_SIZE: usize = 12;

// =============================================================================
// RocksDB Buffer
// =============================================================================

/// A persistent offline buffer backed by RocksDB.
///
/// This implementation provides O(1) counter performance using atomic types.
/// The buffer stores data points with timestamp-based keys for FIFO ordering.
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be safely shared across threads.
/// The RocksDB instance handles internal locking, and counters use atomic
/// operations.
///
/// # Example
///
/// ```rust,ignore
/// use trap_buffer::{RocksDbBuffer, BufferConfig};
///
/// let config = BufferConfig::builder()
///     .path("/var/lib/trap/buffer")
///     .max_items(1_000_000)
///     .build();
///
/// let buffer = RocksDbBuffer::open(config).await?;
///
/// // Store a data point
/// buffer.store(data_point).await?;
///
/// // O(1) length check
/// println!("Items: {}", buffer.len());
/// ```
#[derive(Debug)]
pub struct RocksDbBuffer {
    /// RocksDB instance.
    db: Arc<DB>,

    /// Buffer configuration.
    config: BufferConfig,

    /// O(1) item count (atomic counter).
    item_count: AtomicU64,

    /// O(1) byte count (atomic counter).
    byte_count: AtomicU64,

    /// Lock-free statistics.
    stats: BufferStatsInner,
}

impl RocksDbBuffer {
    /// Opens or creates a RocksDB buffer at the specified path.
    ///
    /// If the database already exists, counters are reconstructed by scanning
    /// the existing data on startup.
    ///
    /// # Arguments
    ///
    /// * `config` - Buffer configuration
    ///
    /// # Returns
    ///
    /// A new `RocksDbBuffer` instance or an error if the database cannot be opened.
    pub async fn open(config: BufferConfig) -> Result<Self, BufferError> {
        let path = config.path.clone();
        let db_config = config.clone();

        // Open RocksDB in a blocking task to avoid blocking the async runtime
        let db = tokio::task::spawn_blocking(move || Self::open_db(&path, &db_config))
            .await
            .map_err(|e| BufferError::database(format!("Failed to spawn blocking task: {}", e)))?
            .map_err(|e| BufferError::database(format!("Failed to open database: {}", e)))?;

        let db = Arc::new(db);

        // Reconstruct counters by scanning existing data
        let (item_count, byte_count) = Self::reconstruct_counters(&db)?;

        info!(
            path = %config.path,
            items = item_count,
            bytes = byte_count,
            "RocksDB buffer opened"
        );

        let buffer = Self {
            db,
            config,
            item_count: AtomicU64::new(item_count),
            byte_count: AtomicU64::new(byte_count),
            stats: BufferStatsInner::new(),
        };

        // Initialize stats with current counts
        buffer.stats.current_items.store(item_count, Ordering::Relaxed);
        buffer.stats.current_bytes.store(byte_count, Ordering::Relaxed);

        Ok(buffer)
    }

    /// Opens the RocksDB database with optimized settings.
    fn open_db(path: &str, config: &BufferConfig) -> Result<DB, rocksdb::Error> {
        // Ensure the directory exists
        if let Err(e) = std::fs::create_dir_all(path) {
            error!(path = %path, error = %e, "Failed to create buffer directory");
        }

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Write buffer settings
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_max_write_buffer_number(4);
        opts.set_min_write_buffer_number_to_merge(2);

        // Compression settings
        if config.compression {
            opts.set_compression_type(DBCompressionType::Lz4);
        } else {
            opts.set_compression_type(DBCompressionType::None);
        }

        // Block-based table options
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_bloom_filter(10.0, false);
        block_opts.set_cache_index_and_filter_blocks(true);
        opts.set_block_based_table_factory(&block_opts);

        // Background threads for compaction
        opts.set_max_background_jobs(4);
        opts.increase_parallelism(4);

        // Level compaction
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_num_levels(7);

        // Disable WAL for better performance (data is recoverable from upstream)
        // Note: Enable WAL if data durability is critical
        // opts.set_wal_dir(format!("{}/wal", path));

        DB::open(&opts, path)
    }

    /// Reconstructs item and byte counters by scanning the database.
    ///
    /// This is called on startup to recover the correct counts.
    fn reconstruct_counters(db: &DB) -> Result<(u64, u64), BufferError> {
        let mut item_count = 0u64;
        let mut byte_count = 0u64;

        let iter = db.iterator(IteratorMode::Start);
        for result in iter {
            match result {
                Ok((_, value)) => {
                    item_count += 1;
                    byte_count += value.len() as u64;
                }
                Err(e) => {
                    warn!(error = %e, "Error during counter reconstruction");
                }
            }
        }

        debug!(items = item_count, bytes = byte_count, "Counters reconstructed");
        Ok((item_count, byte_count))
    }

    /// Generates a unique key for a data point.
    ///
    /// Key format: {timestamp_nanos:8}{random:4}
    fn generate_key(timestamp_nanos: i64) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];

        // First 8 bytes: timestamp (big-endian for natural ordering)
        key[0..8].copy_from_slice(&timestamp_nanos.to_be_bytes());

        // Last 4 bytes: random suffix to prevent collisions
        let random: u32 = rand::random();
        key[8..12].copy_from_slice(&random.to_be_bytes());

        key
    }

    /// Extracts the timestamp from a key (reserved for future query capabilities).
    #[allow(dead_code)]
    fn extract_timestamp(key: &[u8]) -> i64 {
        if key.len() >= 8 {
            i64::from_be_bytes(key[0..8].try_into().unwrap_or([0; 8]))
        } else {
            0
        }
    }

    /// Serializes a data point to bytes using bincode-compatible format.
    fn serialize_data_point(data: &DataPoint) -> Result<Vec<u8>, BufferError> {
        let storable = StorableDataPoint::from_data_point(data);
        bincode::serialize(&storable).map_err(|e| BufferError::store_failed(format!("Serialization error: {}", e)))
    }

    /// Deserializes bytes to a data point using bincode-compatible format.
    fn deserialize_data_point(bytes: &[u8]) -> Result<DataPoint, BufferError> {
        let storable: StorableDataPoint = bincode::deserialize(bytes)
            .map_err(|e| BufferError::corrupted_data(format!("Deserialization error: {}", e)))?;
        Ok(storable.into_data_point())
    }

    /// Checks if the buffer has capacity for new data.
    ///
    /// Returns true if there's room, false if eviction is needed.
    fn has_capacity(&self, additional_bytes: u64) -> bool {
        let current_items = self.item_count.load(Ordering::Relaxed);
        let current_bytes = self.byte_count.load(Ordering::Relaxed);

        current_items < self.config.max_items && current_bytes + additional_bytes <= self.config.max_size_bytes
    }

    /// Evicts oldest items to make room for new data.
    ///
    /// Uses FIFO eviction strategy (oldest items first).
    async fn evict_if_needed(&self, required_bytes: u64) -> Result<(), BufferError> {
        let current_items = self.item_count.load(Ordering::Relaxed);
        let current_bytes = self.byte_count.load(Ordering::Relaxed);

        // Check if eviction is needed
        let items_over = current_items.saturating_sub(self.config.max_items.saturating_sub(1));
        let bytes_over = (current_bytes + required_bytes).saturating_sub(self.config.max_size_bytes);

        if items_over == 0 && bytes_over == 0 {
            return Ok(());
        }

        // Calculate how many items to evict (at least 10% of max_items for efficiency)
        let min_evict = (self.config.max_items / 10).max(1);
        let items_to_evict = items_over.max(min_evict);

        debug!(
            items_to_evict = items_to_evict,
            items_over = items_over,
            bytes_over = bytes_over,
            "Evicting items to make room"
        );

        // Collect keys to delete
        let db = self.db.clone();
        let evict_count = items_to_evict;

        let evicted = tokio::task::spawn_blocking(move || -> Result<(u64, u64), BufferError> {
            let mut batch = WriteBatch::default();
            let mut evicted_count = 0u64;
            let mut evicted_bytes = 0u64;

            let iter = db.iterator(IteratorMode::Start);
            for result in iter.take(evict_count as usize) {
                match result {
                    Ok((key, value)) => {
                        batch.delete(&key);
                        evicted_count += 1;
                        evicted_bytes += value.len() as u64;
                    }
                    Err(e) => {
                        warn!(error = %e, "Error reading key during eviction");
                    }
                }
            }

            if evicted_count > 0 {
                db.write(batch)
                    .map_err(|e| BufferError::database(format!("Failed to write eviction batch: {}", e)))?;
            }

            Ok((evicted_count, evicted_bytes))
        })
        .await
        .map_err(|e| BufferError::database(format!("Eviction task failed: {}", e)))??;

        // Update counters
        self.item_count.fetch_sub(evicted.0, Ordering::Relaxed);
        self.byte_count.fetch_sub(evicted.1, Ordering::Relaxed);
        self.stats.record_dropped(evicted.0, evicted.1);

        debug!(
            evicted_items = evicted.0,
            evicted_bytes = evicted.1,
            "Eviction completed"
        );

        Ok(())
    }
}

#[async_trait]
impl OfflineBuffer for RocksDbBuffer {
    async fn store(&self, data: DataPoint) -> Result<(), BufferError> {
        let timestamp_nanos = data.timestamp.timestamp_nanos_opt().unwrap_or(0);
        let serialized = Self::serialize_data_point(&data)?;
        let data_size = serialized.len() as u64;

        // Evict if needed
        if !self.has_capacity(data_size) {
            self.evict_if_needed(data_size).await?;
        }

        // Generate key and store
        let key = Self::generate_key(timestamp_nanos);
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            let write_opts = WriteOptions::default();
            db.put_opt(key, &serialized, &write_opts)
                .map_err(|e| BufferError::store_failed(format!("RocksDB put failed: {}", e)))
        })
        .await
        .map_err(|e| BufferError::store_failed(format!("Spawn blocking failed: {}", e)))??;

        // Update counters (O(1) atomic operations)
        self.item_count.fetch_add(1, Ordering::Relaxed);
        self.byte_count.fetch_add(data_size, Ordering::Relaxed);
        self.stats.record_store(data_size, timestamp_nanos);

        Ok(())
    }

    async fn store_batch(&self, data: Vec<DataPoint>) -> Result<(), BufferError> {
        if data.is_empty() {
            return Ok(());
        }

        // Serialize all data points
        let mut entries: Vec<([u8; KEY_SIZE], Vec<u8>)> = Vec::with_capacity(data.len());
        let mut total_bytes = 0u64;
        let mut oldest_ts = i64::MAX;
        let mut newest_ts = i64::MIN;

        for point in &data {
            let timestamp_nanos = point.timestamp.timestamp_nanos_opt().unwrap_or(0);
            let serialized = Self::serialize_data_point(point)?;
            total_bytes += serialized.len() as u64;
            oldest_ts = oldest_ts.min(timestamp_nanos);
            newest_ts = newest_ts.max(timestamp_nanos);

            let key = Self::generate_key(timestamp_nanos);
            entries.push((key, serialized));
        }

        // Evict if needed
        if !self.has_capacity(total_bytes) {
            self.evict_if_needed(total_bytes).await?;
        }

        // Write batch
        let db = self.db.clone();
        let count = entries.len() as u64;

        tokio::task::spawn_blocking(move || {
            let mut batch = WriteBatch::default();
            for (key, value) in entries {
                batch.put(key, &value);
            }

            let write_opts = WriteOptions::default();
            db.write_opt(batch, &write_opts)
                .map_err(|e| BufferError::store_failed(format!("RocksDB batch write failed: {}", e)))
        })
        .await
        .map_err(|e| BufferError::store_failed(format!("Spawn blocking failed: {}", e)))??;

        // Update counters
        self.item_count.fetch_add(count, Ordering::Relaxed);
        self.byte_count.fetch_add(total_bytes, Ordering::Relaxed);
        self.stats.record_batch_store(count, total_bytes, oldest_ts, newest_ts);

        Ok(())
    }

    async fn peek(&self, limit: usize) -> Result<Vec<DataPoint>, BufferError> {
        if limit == 0 {
            return Ok(vec![]);
        }

        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            let mut results = Vec::with_capacity(limit);
            let iter = db.iterator(IteratorMode::Start);

            for result in iter.take(limit) {
                match result {
                    Ok((_, value)) => match Self::deserialize_data_point(&value) {
                        Ok(point) => results.push(point),
                        Err(e) => {
                            warn!(error = %e, "Failed to deserialize data point during peek");
                        }
                    },
                    Err(e) => {
                        warn!(error = %e, "Iterator error during peek");
                    }
                }
            }

            Ok(results)
        })
        .await
        .map_err(|e| BufferError::database(format!("Peek task failed: {}", e)))?
    }

    async fn pop(&self, count: usize) -> Result<Vec<DataPoint>, BufferError> {
        if count == 0 {
            return Ok(vec![]);
        }

        let db = self.db.clone();

        let (results, keys_to_delete, bytes_removed) = tokio::task::spawn_blocking(move || {
            let mut results = Vec::with_capacity(count);
            let mut keys_to_delete: Vec<Box<[u8]>> = Vec::with_capacity(count);
            let mut bytes_removed = 0u64;

            let iter = db.iterator(IteratorMode::Start);

            for result in iter.take(count) {
                match result {
                    Ok((key, value)) => {
                        bytes_removed += value.len() as u64;
                        keys_to_delete.push(key);

                        match Self::deserialize_data_point(&value) {
                            Ok(point) => results.push(point),
                            Err(e) => {
                                warn!(error = %e, "Failed to deserialize data point during pop");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Iterator error during pop");
                    }
                }
            }

            // Delete the keys
            if !keys_to_delete.is_empty() {
                let mut batch = WriteBatch::default();
                for key in &keys_to_delete {
                    batch.delete(key);
                }

                if let Err(e) = db.write(batch) {
                    error!(error = %e, "Failed to delete keys during pop");
                }
            }

            Ok::<_, BufferError>((results, keys_to_delete.len(), bytes_removed))
        })
        .await
        .map_err(|e| BufferError::database(format!("Pop task failed: {}", e)))??;

        // Update counters
        let removed_count = keys_to_delete as u64;
        self.item_count.fetch_sub(removed_count, Ordering::Relaxed);
        self.byte_count.fetch_sub(bytes_removed, Ordering::Relaxed);
        self.stats.record_removal(removed_count, bytes_removed);

        Ok(results)
    }

    /// Returns the current item count in O(1) time.
    #[inline]
    fn len(&self) -> usize {
        self.item_count.load(Ordering::Relaxed) as usize
    }

    async fn clear(&self) -> Result<(), BufferError> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            let mut batch = WriteBatch::default();
            let iter = db.iterator(IteratorMode::Start);

            for (key, _) in iter.flatten() {
                batch.delete(&key);
            }

            db.write(batch)
                .map_err(|e| BufferError::database(format!("Failed to clear database: {}", e)))
        })
        .await
        .map_err(|e| BufferError::database(format!("Clear task failed: {}", e)))??;

        // Reset counters
        self.item_count.store(0, Ordering::Relaxed);
        self.byte_count.store(0, Ordering::Relaxed);
        self.stats.reset();

        info!(path = %self.config.path, "Buffer cleared");
        Ok(())
    }

    async fn disk_usage(&self) -> Result<u64, BufferError> {
        // Return the tracked byte count (more accurate than filesystem stats)
        Ok(self.byte_count.load(Ordering::Relaxed))
    }

    fn stats(&self) -> BufferStats {
        self.stats.snapshot()
    }

    async fn sync(&self) -> Result<(), BufferError> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            db.flush()
                .map_err(|e| BufferError::database(format!("Failed to flush database: {}", e)))
        })
        .await
        .map_err(|e| BufferError::database(format!("Sync task failed: {}", e)))?
    }

    async fn compact(&self) -> Result<(), BufferError> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            db.compact_range::<&[u8], &[u8]>(None, None);
            Ok::<_, BufferError>(())
        })
        .await
        .map_err(|e| BufferError::database(format!("Compact task failed: {}", e)))?
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
    use tempfile::TempDir;
    use trap_core::types::{DataQuality, DeviceId, TagId, Value};

    fn create_test_data_point(value: f64) -> DataPoint {
        DataPoint::new(
            DeviceId::new("test-device"),
            TagId::new("test-tag"),
            Value::Float64(value),
            DataQuality::Good,
        )
    }

    async fn create_test_buffer() -> (RocksDbBuffer, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = BufferConfig::builder()
            .path(temp_dir.path().to_str().unwrap())
            .max_items(1000)
            .max_size_bytes(1024 * 1024)
            .compression(false)
            .build();

        let buffer = RocksDbBuffer::open(config).await.unwrap();
        (buffer, temp_dir)
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let (buffer, _temp) = create_test_buffer().await;

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
        let (buffer, _temp) = create_test_buffer().await;

        let points: Vec<DataPoint> = (0..100).map(|i| create_test_data_point(i as f64)).collect();

        buffer.store_batch(points).await.unwrap();

        assert_eq!(buffer.len(), 100);
    }

    #[tokio::test]
    async fn test_pop_removes_items() {
        let (buffer, _temp) = create_test_buffer().await;

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
        let (buffer, _temp) = create_test_buffer().await;

        // Store with small delay to ensure different timestamps
        for i in 0..5 {
            buffer.store(create_test_data_point(i as f64)).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }

        let retrieved = buffer.pop(5).await.unwrap();

        // Should be in FIFO order (oldest first)
        for (i, point) in retrieved.iter().enumerate() {
            assert_eq!(point.value.as_f64(), Some(i as f64));
        }
    }

    #[tokio::test]
    async fn test_clear() {
        let (buffer, _temp) = create_test_buffer().await;

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
        let (buffer, _temp) = create_test_buffer().await;

        // Store many items
        let points: Vec<DataPoint> = (0..500).map(|i| create_test_data_point(i as f64)).collect();
        buffer.store_batch(points).await.unwrap();

        // len() should be O(1) - just an atomic load
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = buffer.len();
        }
        let elapsed = start.elapsed();

        // Should be extremely fast (microseconds, not milliseconds)
        assert!(elapsed.as_millis() < 10, "len() took too long: {:?}", elapsed);
    }

    #[tokio::test]
    async fn test_stats() {
        let (buffer, _temp) = create_test_buffer().await;

        buffer.store(create_test_data_point(1.0)).await.unwrap();
        buffer.store(create_test_data_point(2.0)).await.unwrap();

        let stats = buffer.stats();
        assert_eq!(stats.items_stored, 2);
        assert_eq!(stats.current_items, 2);
        assert!(stats.bytes_written > 0);
    }

    #[tokio::test]
    async fn test_eviction_on_capacity() {
        let temp_dir = TempDir::new().unwrap();
        let config = BufferConfig::builder()
            .path(temp_dir.path().to_str().unwrap())
            .max_items(10) // Very small limit
            .max_size_bytes(1024 * 1024)
            .compression(false)
            .build();

        let buffer = RocksDbBuffer::open(config).await.unwrap();

        // Store more than max_items
        for i in 0..20 {
            buffer.store(create_test_data_point(i as f64)).await.unwrap();
        }

        // Should have evicted some items
        let stats = buffer.stats();
        assert!(stats.items_dropped > 0);
    }

    #[tokio::test]
    async fn test_persistence_across_reopens() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_str().unwrap().to_string();

        // First open: store data
        {
            let config = BufferConfig::builder()
                .path(&path)
                .max_items(1000)
                .compression(false)
                .build();

            let buffer = RocksDbBuffer::open(config).await.unwrap();

            for i in 0..10 {
                buffer.store(create_test_data_point(i as f64)).await.unwrap();
            }

            assert_eq!(buffer.len(), 10);

            // Sync to ensure data is persisted
            buffer.sync().await.unwrap();
        }

        // Second open: verify data persisted
        {
            let config = BufferConfig::builder()
                .path(&path)
                .max_items(1000)
                .compression(false)
                .build();

            let buffer = RocksDbBuffer::open(config).await.unwrap();

            // Counter should be reconstructed from existing data
            assert_eq!(buffer.len(), 10);

            let retrieved = buffer.peek(10).await.unwrap();
            assert_eq!(retrieved.len(), 10);
        }
    }

    #[test]
    fn test_key_generation() {
        let timestamp = 1234567890123456789i64;
        let key = RocksDbBuffer::generate_key(timestamp);

        assert_eq!(key.len(), KEY_SIZE);

        // Verify timestamp extraction
        let extracted = RocksDbBuffer::extract_timestamp(&key);
        assert_eq!(extracted, timestamp);
    }

    #[test]
    fn test_key_ordering() {
        let key1 = RocksDbBuffer::generate_key(1000);
        let key2 = RocksDbBuffer::generate_key(2000);
        let key3 = RocksDbBuffer::generate_key(1500);

        // Older timestamps should sort first (big-endian ordering)
        assert!(key1 < key2);
        assert!(key1 < key3);
        assert!(key3 < key2);
    }

    #[tokio::test]
    async fn test_empty_batch_store() {
        let (buffer, _temp) = create_test_buffer().await;

        buffer.store_batch(vec![]).await.unwrap();

        assert_eq!(buffer.len(), 0);
    }

    #[tokio::test]
    async fn test_pop_empty_buffer() {
        let (buffer, _temp) = create_test_buffer().await;

        let popped = buffer.pop(10).await.unwrap();

        assert!(popped.is_empty());
    }

    #[tokio::test]
    async fn test_peek_empty_buffer() {
        let (buffer, _temp) = create_test_buffer().await;

        let peeked = buffer.peek(10).await.unwrap();

        assert!(peeked.is_empty());
    }

    #[tokio::test]
    async fn test_disk_usage() {
        let (buffer, _temp) = create_test_buffer().await;

        let initial_usage = buffer.disk_usage().await.unwrap();
        assert_eq!(initial_usage, 0);

        buffer.store(create_test_data_point(42.0)).await.unwrap();

        let usage = buffer.disk_usage().await.unwrap();
        assert!(usage > 0);
    }
}
