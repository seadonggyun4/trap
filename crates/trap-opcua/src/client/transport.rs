// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA transport abstraction layer.
//!
//! This module provides abstract transport traits for OPC UA communication,
//! enabling testability and flexible backend implementations.

use std::fmt;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::OpcUaResult;
use crate::types::{NodeId, OpcUaConfig, OpcUaDataType};

// =============================================================================
// TransportState
// =============================================================================

/// Connection state of the transport layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportState {
    /// Transport is not connected.
    #[default]
    Disconnected,

    /// Transport is establishing connection.
    Connecting,

    /// Transport is connected and ready.
    Connected,

    /// Transport is reconnecting after a failure.
    Reconnecting,

    /// Transport connection has failed.
    Failed,
}

impl TransportState {
    /// Returns `true` if the transport is connected.
    #[inline]
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Returns `true` if the transport is in a transitional state.
    #[inline]
    pub fn is_transitioning(&self) -> bool {
        matches!(self, Self::Connecting | Self::Reconnecting)
    }

    /// Returns `true` if the transport has failed.
    #[inline]
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }
}

impl fmt::Display for TransportState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Connected => write!(f, "Connected"),
            Self::Reconnecting => write!(f, "Reconnecting"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// =============================================================================
// ReadResult
// =============================================================================

/// Result of a node read operation.
#[derive(Debug, Clone)]
pub struct ReadResult {
    /// The node ID that was read.
    pub node_id: NodeId,

    /// The value read (if successful).
    pub value: Option<OpcUaValue>,

    /// Status code of the read operation.
    pub status_code: u32,

    /// Server timestamp.
    pub server_timestamp: Option<chrono::DateTime<chrono::Utc>>,

    /// Source timestamp.
    pub source_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

impl ReadResult {
    /// Creates a successful read result.
    pub fn success(node_id: NodeId, value: OpcUaValue) -> Self {
        Self {
            node_id,
            value: Some(value),
            status_code: 0, // Good
            server_timestamp: Some(chrono::Utc::now()),
            source_timestamp: None,
        }
    }

    /// Creates a failed read result.
    pub fn failure(node_id: NodeId, status_code: u32) -> Self {
        Self {
            node_id,
            value: None,
            status_code,
            server_timestamp: Some(chrono::Utc::now()),
            source_timestamp: None,
        }
    }

    /// Returns `true` if the read was successful.
    #[inline]
    pub fn is_good(&self) -> bool {
        self.status_code == 0
    }

    /// Returns `true` if the status is uncertain.
    #[inline]
    pub fn is_uncertain(&self) -> bool {
        self.status_code & 0x40000000 != 0 && self.status_code & 0x80000000 == 0
    }

    /// Returns `true` if the status is bad.
    #[inline]
    pub fn is_bad(&self) -> bool {
        self.status_code & 0x80000000 != 0
    }
}

// =============================================================================
// WriteResult
// =============================================================================

/// Result of a node write operation.
#[derive(Debug, Clone)]
pub struct WriteResult {
    /// The node ID that was written.
    pub node_id: NodeId,

    /// Status code of the write operation.
    pub status_code: u32,
}

impl WriteResult {
    /// Creates a successful write result.
    pub fn success(node_id: NodeId) -> Self {
        Self {
            node_id,
            status_code: 0,
        }
    }

    /// Creates a failed write result.
    pub fn failure(node_id: NodeId, status_code: u32) -> Self {
        Self {
            node_id,
            status_code,
        }
    }

    /// Returns `true` if the write was successful.
    #[inline]
    pub fn is_good(&self) -> bool {
        self.status_code == 0
    }
}

// =============================================================================
// OpcUaValue
// =============================================================================

/// OPC UA value type for transport layer.
///
/// This is a simplified value representation for the transport layer.
/// Higher-level conversions are handled by the DataConverter.
#[derive(Debug, Clone, PartialEq)]
pub enum OpcUaValue {
    /// Boolean value.
    Boolean(bool),

    /// Signed byte.
    SByte(i8),

    /// Unsigned byte.
    Byte(u8),

    /// 16-bit signed integer.
    Int16(i16),

    /// 16-bit unsigned integer.
    UInt16(u16),

    /// 32-bit signed integer.
    Int32(i32),

    /// 32-bit unsigned integer.
    UInt32(u32),

    /// 64-bit signed integer.
    Int64(i64),

    /// 64-bit unsigned integer.
    UInt64(u64),

    /// 32-bit float.
    Float(f32),

    /// 64-bit double.
    Double(f64),

    /// String value.
    String(String),

    /// Date/time value.
    DateTime(chrono::DateTime<chrono::Utc>),

    /// GUID value.
    Guid(uuid::Uuid),

    /// Byte string.
    ByteString(Vec<u8>),

    /// Array of values.
    Array(Vec<OpcUaValue>),

    /// Null value.
    Null,
}

impl OpcUaValue {
    /// Returns the data type of this value.
    pub fn data_type(&self) -> OpcUaDataType {
        match self {
            Self::Boolean(_) => OpcUaDataType::Boolean,
            Self::SByte(_) => OpcUaDataType::SByte,
            Self::Byte(_) => OpcUaDataType::Byte,
            Self::Int16(_) => OpcUaDataType::Int16,
            Self::UInt16(_) => OpcUaDataType::UInt16,
            Self::Int32(_) => OpcUaDataType::Int32,
            Self::UInt32(_) => OpcUaDataType::UInt32,
            Self::Int64(_) => OpcUaDataType::Int64,
            Self::UInt64(_) => OpcUaDataType::UInt64,
            Self::Float(_) => OpcUaDataType::Float,
            Self::Double(_) => OpcUaDataType::Double,
            Self::String(_) => OpcUaDataType::String,
            Self::DateTime(_) => OpcUaDataType::DateTime,
            Self::Guid(_) => OpcUaDataType::Guid,
            Self::ByteString(_) => OpcUaDataType::ByteString,
            Self::Array(_) | Self::Null => OpcUaDataType::Variant,
        }
    }

    /// Returns `true` if this is a null value.
    #[inline]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Attempts to get the value as a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(v) => Some(*v),
            Self::SByte(v) => Some(*v != 0),
            Self::Byte(v) => Some(*v != 0),
            Self::Int16(v) => Some(*v != 0),
            Self::UInt16(v) => Some(*v != 0),
            Self::Int32(v) => Some(*v != 0),
            Self::UInt32(v) => Some(*v != 0),
            _ => None,
        }
    }

    /// Attempts to get the value as an i64.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Boolean(v) => Some(if *v { 1 } else { 0 }),
            Self::SByte(v) => Some(*v as i64),
            Self::Byte(v) => Some(*v as i64),
            Self::Int16(v) => Some(*v as i64),
            Self::UInt16(v) => Some(*v as i64),
            Self::Int32(v) => Some(*v as i64),
            Self::UInt32(v) => Some(*v as i64),
            Self::Int64(v) => Some(*v),
            Self::UInt64(v) => i64::try_from(*v).ok(),
            Self::Float(v) => Some(*v as i64),
            Self::Double(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Attempts to get the value as an f64.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Boolean(v) => Some(if *v { 1.0 } else { 0.0 }),
            Self::SByte(v) => Some(*v as f64),
            Self::Byte(v) => Some(*v as f64),
            Self::Int16(v) => Some(*v as f64),
            Self::UInt16(v) => Some(*v as f64),
            Self::Int32(v) => Some(*v as f64),
            Self::UInt32(v) => Some(*v as f64),
            Self::Int64(v) => Some(*v as f64),
            Self::UInt64(v) => Some(*v as f64),
            Self::Float(v) => Some(*v as f64),
            Self::Double(v) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to get the value as a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(v) => Some(v),
            _ => None,
        }
    }
}

impl Default for OpcUaValue {
    fn default() -> Self {
        Self::Null
    }
}

impl fmt::Display for OpcUaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(v) => write!(f, "{}", v),
            Self::SByte(v) => write!(f, "{}", v),
            Self::Byte(v) => write!(f, "{}", v),
            Self::Int16(v) => write!(f, "{}", v),
            Self::UInt16(v) => write!(f, "{}", v),
            Self::Int32(v) => write!(f, "{}", v),
            Self::UInt32(v) => write!(f, "{}", v),
            Self::Int64(v) => write!(f, "{}", v),
            Self::UInt64(v) => write!(f, "{}", v),
            Self::Float(v) => write!(f, "{}", v),
            Self::Double(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
            Self::DateTime(v) => write!(f, "{}", v.to_rfc3339()),
            Self::Guid(v) => write!(f, "{}", v),
            Self::ByteString(v) => write!(f, "<{} bytes>", v.len()),
            Self::Array(v) => write!(f, "[{} items]", v.len()),
            Self::Null => write!(f, "null"),
        }
    }
}

// =============================================================================
// BrowseResult
// =============================================================================

/// Result of a browse operation.
#[derive(Debug, Clone)]
pub struct BrowseResult {
    /// The node ID of the browsed node.
    pub node_id: NodeId,

    /// Browse name.
    pub browse_name: String,

    /// Display name.
    pub display_name: String,

    /// Node class.
    pub node_class: u32,

    /// Reference type (e.g., HasComponent, Organizes).
    pub reference_type: Option<NodeId>,

    /// Type definition node.
    pub type_definition: Option<NodeId>,
}

// =============================================================================
// OpcUaTransport Trait
// =============================================================================

/// Abstract transport trait for OPC UA communication.
///
/// This trait defines the low-level operations for OPC UA protocol communication.
/// Implementations handle the actual network communication and protocol details.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow concurrent access
/// from multiple tasks.
#[async_trait]
pub trait OpcUaTransport: Send + Sync {
    // =========================================================================
    // Connection Management
    // =========================================================================

    /// Establishes a connection to the OPC UA server.
    ///
    /// This method should:
    /// - Establish the TCP connection
    /// - Perform endpoint discovery
    /// - Create a secure channel
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    async fn connect(&mut self) -> OpcUaResult<()>;

    /// Closes the connection to the server.
    ///
    /// This method should gracefully close the secure channel and TCP connection.
    async fn disconnect(&mut self) -> OpcUaResult<()>;

    /// Returns `true` if the transport is currently connected.
    fn is_connected(&self) -> bool;

    /// Returns the current transport state.
    fn state(&self) -> TransportState;

    /// Attempts to reconnect after a failure.
    async fn reconnect(&mut self) -> OpcUaResult<()> {
        self.disconnect().await.ok();
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.connect().await
    }

    // =========================================================================
    // Read Operations
    // =========================================================================

    /// Reads a single node value.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to read
    async fn read_value(&self, node_id: &NodeId) -> OpcUaResult<ReadResult>;

    /// Reads multiple node values in a single request.
    ///
    /// # Arguments
    ///
    /// * `node_ids` - The nodes to read
    async fn read_values(&self, node_ids: &[NodeId]) -> OpcUaResult<Vec<ReadResult>>;

    /// Reads a specific attribute of a node.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to read
    /// * `attribute_id` - The attribute to read (default: Value = 13)
    async fn read_attribute(
        &self,
        node_id: &NodeId,
        attribute_id: u32,
    ) -> OpcUaResult<ReadResult>;

    // =========================================================================
    // Write Operations
    // =========================================================================

    /// Writes a single node value.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to write
    /// * `value` - The value to write
    async fn write_value(&self, node_id: &NodeId, value: OpcUaValue) -> OpcUaResult<WriteResult>;

    /// Writes multiple node values in a single request.
    ///
    /// # Arguments
    ///
    /// * `writes` - The node/value pairs to write
    async fn write_values(
        &self,
        writes: &[(NodeId, OpcUaValue)],
    ) -> OpcUaResult<Vec<WriteResult>>;

    // =========================================================================
    // Browse Operations
    // =========================================================================

    /// Browses child nodes of a given node.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to browse from
    /// * `direction` - Browse direction (default: Forward)
    async fn browse(&self, node_id: &NodeId) -> OpcUaResult<Vec<BrowseResult>>;

    /// Browses child nodes with custom parameters.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to browse from
    /// * `direction` - Browse direction (0=Forward, 1=Inverse, 2=Both)
    /// * `node_class_mask` - Filter by node class (0 = all)
    async fn browse_filtered(
        &self,
        node_id: &NodeId,
        direction: u32,
        node_class_mask: u32,
    ) -> OpcUaResult<Vec<BrowseResult>>;

    // =========================================================================
    // Subscription Operations
    // =========================================================================

    /// Creates a subscription for data change notifications.
    ///
    /// # Arguments
    ///
    /// * `publishing_interval` - Publishing interval in milliseconds
    ///
    /// # Returns
    ///
    /// The subscription ID.
    async fn create_subscription(&self, publishing_interval: Duration) -> OpcUaResult<u32>;

    /// Deletes a subscription.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The subscription to delete
    async fn delete_subscription(&self, subscription_id: u32) -> OpcUaResult<()>;

    /// Creates monitored items for a subscription.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The subscription ID
    /// * `node_ids` - The nodes to monitor
    /// * `sampling_interval` - Sampling interval in milliseconds
    ///
    /// # Returns
    ///
    /// A vector of monitored item IDs.
    async fn create_monitored_items(
        &self,
        subscription_id: u32,
        node_ids: &[NodeId],
        sampling_interval: Duration,
    ) -> OpcUaResult<Vec<u32>>;

    /// Deletes monitored items.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - The subscription ID
    /// * `monitored_item_ids` - The monitored items to delete
    async fn delete_monitored_items(
        &self,
        subscription_id: u32,
        monitored_item_ids: &[u32],
    ) -> OpcUaResult<()>;

    // =========================================================================
    // Metadata
    // =========================================================================

    /// Returns the transport display name for logging.
    fn display_name(&self) -> String;

    /// Returns the server endpoint URL.
    fn endpoint(&self) -> &str;

    /// Returns the configuration.
    fn config(&self) -> &OpcUaConfig;
}

// =============================================================================
// TransportMetrics
// =============================================================================

/// Metrics for transport operations.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct TransportMetrics {
    /// Total number of read operations.
    pub read_count: u64,

    /// Total number of write operations.
    pub write_count: u64,

    /// Total number of browse operations.
    pub browse_count: u64,

    /// Total number of subscription operations.
    pub subscription_count: u64,

    /// Total number of errors.
    pub error_count: u64,

    /// Last successful operation time.
    pub last_success: Option<Instant>,

    /// Last error time.
    pub last_error: Option<Instant>,

    /// Total response time in microseconds.
    pub total_response_time_us: u64,
}

#[allow(dead_code)]
impl TransportMetrics {
    /// Creates new metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a successful read operation.
    pub fn record_read(&mut self, duration: Duration) {
        self.read_count += 1;
        self.total_response_time_us += duration.as_micros() as u64;
        self.last_success = Some(Instant::now());
    }

    /// Records a successful write operation.
    pub fn record_write(&mut self, duration: Duration) {
        self.write_count += 1;
        self.total_response_time_us += duration.as_micros() as u64;
        self.last_success = Some(Instant::now());
    }

    /// Records an error.
    pub fn record_error(&mut self) {
        self.error_count += 1;
        self.last_error = Some(Instant::now());
    }

    /// Returns the average response time.
    pub fn average_response_time(&self) -> Duration {
        let total_ops = self.read_count + self.write_count;
        if total_ops == 0 {
            return Duration::ZERO;
        }
        Duration::from_micros(self.total_response_time_us / total_ops)
    }

    /// Resets all metrics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_state() {
        assert!(TransportState::Connected.is_connected());
        assert!(!TransportState::Disconnected.is_connected());
        assert!(TransportState::Connecting.is_transitioning());
        assert!(TransportState::Reconnecting.is_transitioning());
        assert!(TransportState::Failed.is_failed());
    }

    #[test]
    fn test_read_result() {
        let success = ReadResult::success(
            NodeId::numeric(2, 1001),
            OpcUaValue::Double(25.5),
        );
        assert!(success.is_good());
        assert!(!success.is_bad());

        let failure = ReadResult::failure(NodeId::numeric(2, 1001), 0x80000000);
        assert!(failure.is_bad());
        assert!(!failure.is_good());
    }

    #[test]
    fn test_opcua_value() {
        let bool_val = OpcUaValue::Boolean(true);
        assert_eq!(bool_val.as_bool(), Some(true));
        assert_eq!(bool_val.data_type(), OpcUaDataType::Boolean);

        let int_val = OpcUaValue::Int32(42);
        assert_eq!(int_val.as_i64(), Some(42));
        assert_eq!(int_val.as_f64(), Some(42.0));

        let float_val = OpcUaValue::Double(3.14);
        assert!((float_val.as_f64().unwrap() - 3.14).abs() < 0.001);

        let null_val = OpcUaValue::Null;
        assert!(null_val.is_null());
    }

    #[test]
    fn test_transport_metrics() {
        let mut metrics = TransportMetrics::new();

        metrics.record_read(Duration::from_millis(10));
        metrics.record_read(Duration::from_millis(20));
        metrics.record_write(Duration::from_millis(15));
        metrics.record_error();

        assert_eq!(metrics.read_count, 2);
        assert_eq!(metrics.write_count, 1);
        assert_eq!(metrics.error_count, 1);
        assert_eq!(metrics.average_response_time(), Duration::from_millis(15));
    }
}
