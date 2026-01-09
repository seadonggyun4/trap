// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Core data types for TRAP.
//!
//! This module provides protocol-agnostic data types that form the foundation
//! of all data handling in TRAP.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::Hash;
use std::time::Duration;

// =============================================================================
// Identifiers
// =============================================================================

/// A unique identifier for a device.
///
/// Device IDs should be stable across restarts and unique within a gateway instance.
///
/// # Examples
///
/// ```
/// use trap_core::types::DeviceId;
///
/// let id = DeviceId::new("plc-001");
/// assert_eq!(id.as_str(), "plc-001");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    /// Creates a new device ID.
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the ID as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the ID and returns the inner string.
    #[inline]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for DeviceId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for DeviceId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for DeviceId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A unique identifier for a tag within a device.
///
/// Tags represent individual data points (sensors, registers, etc.) on a device.
///
/// # Examples
///
/// ```
/// use trap_core::types::TagId;
///
/// let id = TagId::new("temperature");
/// assert_eq!(id.as_str(), "temperature");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TagId(String);

impl TagId {
    /// Creates a new tag ID.
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the ID as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the ID and returns the inner string.
    #[inline]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for TagId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for TagId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for TagId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for TagId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// Value Types
// =============================================================================

/// A protocol-agnostic data value.
///
/// This enum can represent any value type supported by industrial protocols,
/// including Modbus, OPC UA, and BACnet.
///
/// # Examples
///
/// ```
/// use trap_core::types::Value;
///
/// let temp = Value::Float64(25.5);
/// assert_eq!(temp.as_f64(), Some(25.5));
///
/// let status = Value::Bool(true);
/// assert_eq!(status.as_bool(), Some(true));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Value {
    /// Boolean value
    Bool(bool),

    /// Signed 8-bit integer
    Int8(i8),

    /// Signed 16-bit integer
    Int16(i16),

    /// Signed 32-bit integer
    Int32(i32),

    /// Signed 64-bit integer
    Int64(i64),

    /// Unsigned 8-bit integer
    UInt8(u8),

    /// Unsigned 16-bit integer
    UInt16(u16),

    /// Unsigned 32-bit integer
    UInt32(u32),

    /// Unsigned 64-bit integer
    UInt64(u64),

    /// 32-bit floating point
    Float32(f32),

    /// 64-bit floating point
    Float64(f64),

    /// UTF-8 string
    String(String),

    /// Raw bytes
    Bytes(Vec<u8>),

    /// Array of values (homogeneous or heterogeneous)
    Array(Vec<Value>),

    /// Key-value structure
    Struct(Vec<(String, Value)>),

    /// Date and time with timezone
    DateTime(DateTime<Utc>),

    /// Duration
    Duration(Duration),

    /// Null/undefined value
    Null,
}

impl Value {
    /// Returns the type name of this value.
    ///
    /// # Examples
    ///
    /// ```
    /// use trap_core::types::Value;
    ///
    /// assert_eq!(Value::Float64(1.0).type_name(), "float64");
    /// assert_eq!(Value::Bool(true).type_name(), "bool");
    /// ```
    #[inline]
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::Int8(_) => "int8",
            Value::Int16(_) => "int16",
            Value::Int32(_) => "int32",
            Value::Int64(_) => "int64",
            Value::UInt8(_) => "uint8",
            Value::UInt16(_) => "uint16",
            Value::UInt32(_) => "uint32",
            Value::UInt64(_) => "uint64",
            Value::Float32(_) => "float32",
            Value::Float64(_) => "float64",
            Value::String(_) => "string",
            Value::Bytes(_) => "bytes",
            Value::Array(_) => "array",
            Value::Struct(_) => "struct",
            Value::DateTime(_) => "datetime",
            Value::Duration(_) => "duration",
            Value::Null => "null",
        }
    }

    /// Returns `true` if this is a null value.
    #[inline]
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Returns `true` if this is a numeric value (integer or float).
    #[inline]
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            Value::Int8(_)
                | Value::Int16(_)
                | Value::Int32(_)
                | Value::Int64(_)
                | Value::UInt8(_)
                | Value::UInt16(_)
                | Value::UInt32(_)
                | Value::UInt64(_)
                | Value::Float32(_)
                | Value::Float64(_)
        )
    }

    /// Attempts to convert this value to a boolean.
    #[inline]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to convert this value to an i64.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Bool(v) => Some(if *v { 1 } else { 0 }),
            Value::Int8(v) => Some(*v as i64),
            Value::Int16(v) => Some(*v as i64),
            Value::Int32(v) => Some(*v as i64),
            Value::Int64(v) => Some(*v),
            Value::UInt8(v) => Some(*v as i64),
            Value::UInt16(v) => Some(*v as i64),
            Value::UInt32(v) => Some(*v as i64),
            Value::UInt64(v) => i64::try_from(*v).ok(),
            Value::Float32(v) => Some(*v as i64),
            Value::Float64(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Attempts to convert this value to a u64.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Bool(v) => Some(if *v { 1 } else { 0 }),
            Value::Int8(v) if *v >= 0 => Some(*v as u64),
            Value::Int16(v) if *v >= 0 => Some(*v as u64),
            Value::Int32(v) if *v >= 0 => Some(*v as u64),
            Value::Int64(v) if *v >= 0 => Some(*v as u64),
            Value::UInt8(v) => Some(*v as u64),
            Value::UInt16(v) => Some(*v as u64),
            Value::UInt32(v) => Some(*v as u64),
            Value::UInt64(v) => Some(*v),
            Value::Float32(v) if *v >= 0.0 => Some(*v as u64),
            Value::Float64(v) if *v >= 0.0 => Some(*v as u64),
            _ => None,
        }
    }

    /// Attempts to convert this value to an f64.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Bool(v) => Some(if *v { 1.0 } else { 0.0 }),
            Value::Int8(v) => Some(*v as f64),
            Value::Int16(v) => Some(*v as f64),
            Value::Int32(v) => Some(*v as f64),
            Value::Int64(v) => Some(*v as f64),
            Value::UInt8(v) => Some(*v as f64),
            Value::UInt16(v) => Some(*v as f64),
            Value::UInt32(v) => Some(*v as f64),
            Value::UInt64(v) => Some(*v as f64),
            Value::Float32(v) => Some(*v as f64),
            Value::Float64(v) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to get this value as a string reference.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(v) => Some(v),
            _ => None,
        }
    }

    /// Attempts to get this value as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(v) => Some(v),
            _ => None,
        }
    }

    /// Attempts to get this value as an array reference.
    #[inline]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(v) => Some(v),
            _ => None,
        }
    }

    /// Converts this value to a JSON value.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Value::Bool(v) => serde_json::Value::Bool(*v),
            Value::Int8(v) => serde_json::json!(*v),
            Value::Int16(v) => serde_json::json!(*v),
            Value::Int32(v) => serde_json::json!(*v),
            Value::Int64(v) => serde_json::json!(*v),
            Value::UInt8(v) => serde_json::json!(*v),
            Value::UInt16(v) => serde_json::json!(*v),
            Value::UInt32(v) => serde_json::json!(*v),
            Value::UInt64(v) => serde_json::json!(*v),
            Value::Float32(v) => serde_json::json!(*v),
            Value::Float64(v) => serde_json::json!(*v),
            Value::String(v) => serde_json::Value::String(v.clone()),
            Value::Bytes(v) => serde_json::json!(v),
            Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(|v| v.to_json()).collect())
            }
            Value::Struct(fields) => {
                let map: serde_json::Map<String, serde_json::Value> =
                    fields.iter().map(|(k, v)| (k.clone(), v.to_json())).collect();
                serde_json::Value::Object(map)
            }
            Value::DateTime(dt) => serde_json::json!(dt.to_rfc3339()),
            Value::Duration(d) => serde_json::json!(d.as_secs_f64()),
            Value::Null => serde_json::Value::Null,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Bool(v) => write!(f, "{}", v),
            Value::Int8(v) => write!(f, "{}", v),
            Value::Int16(v) => write!(f, "{}", v),
            Value::Int32(v) => write!(f, "{}", v),
            Value::Int64(v) => write!(f, "{}", v),
            Value::UInt8(v) => write!(f, "{}", v),
            Value::UInt16(v) => write!(f, "{}", v),
            Value::UInt32(v) => write!(f, "{}", v),
            Value::UInt64(v) => write!(f, "{}", v),
            Value::Float32(v) => write!(f, "{}", v),
            Value::Float64(v) => write!(f, "{}", v),
            Value::String(v) => write!(f, "{}", v),
            Value::Bytes(v) => write!(f, "<{} bytes>", v.len()),
            Value::Array(v) => write!(f, "[{} elements]", v.len()),
            Value::Struct(v) => write!(f, "{{{} fields}}", v.len()),
            Value::DateTime(v) => write!(f, "{}", v.to_rfc3339()),
            Value::Duration(v) => write!(f, "{:?}", v),
            Value::Null => write!(f, "null"),
        }
    }
}

impl Default for Value {
    fn default() -> Self {
        Value::Null
    }
}

// Implement From for common types
macro_rules! impl_from_for_value {
    ($variant:ident, $type:ty) => {
        impl From<$type> for Value {
            fn from(v: $type) -> Self {
                Value::$variant(v)
            }
        }
    };
}

impl_from_for_value!(Bool, bool);
impl_from_for_value!(Int8, i8);
impl_from_for_value!(Int16, i16);
impl_from_for_value!(Int32, i32);
impl_from_for_value!(Int64, i64);
impl_from_for_value!(UInt8, u8);
impl_from_for_value!(UInt16, u16);
impl_from_for_value!(UInt32, u32);
impl_from_for_value!(UInt64, u64);
impl_from_for_value!(Float32, f32);
impl_from_for_value!(Float64, f64);
impl_from_for_value!(String, String);

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string())
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v)
    }
}

// =============================================================================
// Data Quality
// =============================================================================

/// The quality status of a data value.
///
/// This follows OPC UA quality concepts but is protocol-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(tag = "status", content = "reason")]
pub enum DataQuality {
    /// The value is good and reliable.
    #[default]
    Good,

    /// The value is uncertain but may be usable.
    Uncertain(UncertainReason),

    /// The value is bad and should not be used.
    Bad(BadReason),
}

impl DataQuality {
    /// Returns `true` if the quality is good.
    #[inline]
    pub fn is_good(&self) -> bool {
        matches!(self, DataQuality::Good)
    }

    /// Returns `true` if the quality is usable (good or uncertain).
    #[inline]
    pub fn is_usable(&self) -> bool {
        matches!(self, DataQuality::Good | DataQuality::Uncertain(_))
    }

    /// Returns `true` if the quality is bad.
    #[inline]
    pub fn is_bad(&self) -> bool {
        matches!(self, DataQuality::Bad(_))
    }

    /// Creates a bad quality with an unknown reason.
    #[inline]
    pub fn bad() -> Self {
        DataQuality::Bad(BadReason::Unknown)
    }

    /// Creates an uncertain quality with an unknown reason.
    #[inline]
    pub fn uncertain() -> Self {
        DataQuality::Uncertain(UncertainReason::Unknown)
    }
}

impl fmt::Display for DataQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataQuality::Good => write!(f, "Good"),
            DataQuality::Uncertain(reason) => write!(f, "Uncertain: {}", reason),
            DataQuality::Bad(reason) => write!(f, "Bad: {}", reason),
        }
    }
}

/// Reasons for uncertain data quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum UncertainReason {
    /// Using last known value due to communication issues.
    LastKnownValue,

    /// Sensor operating below normal range.
    SubNormal,

    /// Value exceeds engineering units but may still be valid.
    EngineeringUnitsExceeded,

    /// Initial value before first read.
    InitialValue,

    /// Sensor calibration is outdated.
    SensorCalibration,

    /// Unknown reason.
    #[default]
    Unknown,
}

impl fmt::Display for UncertainReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UncertainReason::LastKnownValue => write!(f, "LastKnownValue"),
            UncertainReason::SubNormal => write!(f, "SubNormal"),
            UncertainReason::EngineeringUnitsExceeded => write!(f, "EngineeringUnitsExceeded"),
            UncertainReason::InitialValue => write!(f, "InitialValue"),
            UncertainReason::SensorCalibration => write!(f, "SensorCalibration"),
            UncertainReason::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Reasons for bad data quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum BadReason {
    /// Configuration error in the device or tag.
    ConfigurationError,

    /// Device is not connected.
    NotConnected,

    /// Device has failed.
    DeviceFailure,

    /// Sensor has failed.
    SensorFailure,

    /// Communication failure.
    CommunicationFailure,

    /// Access denied to the value.
    AccessDenied,

    /// Value out of range.
    OutOfRange,

    /// Unknown reason.
    #[default]
    Unknown,
}

impl fmt::Display for BadReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BadReason::ConfigurationError => write!(f, "ConfigurationError"),
            BadReason::NotConnected => write!(f, "NotConnected"),
            BadReason::DeviceFailure => write!(f, "DeviceFailure"),
            BadReason::SensorFailure => write!(f, "SensorFailure"),
            BadReason::CommunicationFailure => write!(f, "CommunicationFailure"),
            BadReason::AccessDenied => write!(f, "AccessDenied"),
            BadReason::OutOfRange => write!(f, "OutOfRange"),
            BadReason::Unknown => write!(f, "Unknown"),
        }
    }
}

// =============================================================================
// DataPoint
// =============================================================================

/// A timestamped data point from a device.
///
/// This is the primary data structure used throughout TRAP for representing
/// individual readings from industrial devices.
///
/// # Examples
///
/// ```
/// use trap_core::types::{DataPoint, DeviceId, TagId, Value, DataQuality};
///
/// let point = DataPoint::new(
///     DeviceId::new("plc-001"),
///     TagId::new("temperature"),
///     Value::Float64(25.5),
///     DataQuality::Good,
/// );
///
/// assert_eq!(point.device_id.as_str(), "plc-001");
/// assert_eq!(point.quality.is_good(), true);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataPoint {
    /// The device this data came from.
    pub device_id: DeviceId,

    /// The tag/point identifier within the device.
    pub tag_id: TagId,

    /// The data value.
    pub value: Value,

    /// The quality of the data.
    pub quality: DataQuality,

    /// Server timestamp (when TRAP received the data).
    pub timestamp: DateTime<Utc>,

    /// Source timestamp (when the device produced the data, if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_timestamp: Option<DateTime<Utc>>,
}

impl DataPoint {
    /// Creates a new data point with the current timestamp.
    pub fn new(device_id: DeviceId, tag_id: TagId, value: Value, quality: DataQuality) -> Self {
        Self {
            device_id,
            tag_id,
            value,
            quality,
            timestamp: Utc::now(),
            source_timestamp: None,
        }
    }

    /// Creates a new data point with a specific timestamp.
    pub fn with_timestamp(
        device_id: DeviceId,
        tag_id: TagId,
        value: Value,
        quality: DataQuality,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            device_id,
            tag_id,
            value,
            quality,
            timestamp,
            source_timestamp: None,
        }
    }

    /// Creates a new data point with both server and source timestamps.
    pub fn with_source_timestamp(
        device_id: DeviceId,
        tag_id: TagId,
        value: Value,
        quality: DataQuality,
        timestamp: DateTime<Utc>,
        source_timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            device_id,
            tag_id,
            value,
            quality,
            timestamp,
            source_timestamp: Some(source_timestamp),
        }
    }

    /// Returns the unique key for this data point (device + tag).
    #[inline]
    pub fn key(&self) -> (&str, &str) {
        (self.device_id.as_str(), self.tag_id.as_str())
    }

    /// Returns `true` if the data quality is good.
    #[inline]
    pub fn is_good(&self) -> bool {
        self.quality.is_good()
    }

    /// Returns `true` if the data is usable (good or uncertain).
    #[inline]
    pub fn is_usable(&self) -> bool {
        self.quality.is_usable()
    }

    /// Returns the age of this data point.
    #[inline]
    pub fn age(&self) -> chrono::Duration {
        Utc::now() - self.timestamp
    }
}

impl fmt::Display for DataPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} = {} [{}] @ {}",
            self.device_id,
            self.tag_id,
            self.value,
            self.quality,
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f")
        )
    }
}

// =============================================================================
// Protocol Types
// =============================================================================

/// Supported protocol types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Modbus TCP protocol
    ModbusTcp,

    /// Modbus RTU (serial) protocol
    ModbusRtu,

    /// OPC UA protocol
    OpcUa,

    /// BACnet IP protocol
    BacNetIp,

    /// KNX IP protocol
    Knx,

    /// Unknown/generic protocol
    Unknown,
}

impl Protocol {
    /// Returns the protocol name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::ModbusTcp => "modbus-tcp",
            Protocol::ModbusRtu => "modbus-rtu",
            Protocol::OpcUa => "opcua",
            Protocol::BacNetIp => "bacnet-ip",
            Protocol::Knx => "knx",
            Protocol::Unknown => "unknown",
        }
    }

    /// Returns `true` if this is a Modbus protocol variant.
    #[inline]
    pub fn is_modbus(&self) -> bool {
        matches!(self, Protocol::ModbusTcp | Protocol::ModbusRtu)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Unknown
    }
}

// =============================================================================
// Connection State
// =============================================================================

/// The connection state of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// Device is not connected.
    #[default]
    Disconnected,

    /// Device is currently connecting.
    Connecting,

    /// Device is connected and operational.
    Connected,

    /// Device is reconnecting after a disconnection.
    Reconnecting,

    /// Device connection has failed.
    Failed,
}

impl ConnectionState {
    /// Returns `true` if the device is connected.
    #[inline]
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected)
    }

    /// Returns `true` if the device is in a transitional state.
    #[inline]
    pub fn is_transitioning(&self) -> bool {
        matches!(self, ConnectionState::Connecting | ConnectionState::Reconnecting)
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "Disconnected"),
            ConnectionState::Connecting => write!(f, "Connecting"),
            ConnectionState::Connected => write!(f, "Connected"),
            ConnectionState::Reconnecting => write!(f, "Reconnecting"),
            ConnectionState::Failed => write!(f, "Failed"),
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
    fn test_device_id() {
        let id = DeviceId::new("test-device");
        assert_eq!(id.as_str(), "test-device");
        assert_eq!(format!("{}", id), "test-device");
    }

    #[test]
    fn test_tag_id() {
        let id = TagId::new("temperature");
        assert_eq!(id.as_str(), "temperature");
        assert_eq!(format!("{}", id), "temperature");
    }

    #[test]
    fn test_value_types() {
        assert_eq!(Value::Bool(true).type_name(), "bool");
        assert_eq!(Value::Int32(42).type_name(), "int32");
        assert_eq!(Value::Float64(3.14).type_name(), "float64");
        assert_eq!(Value::String("test".into()).type_name(), "string");
        assert_eq!(Value::Null.type_name(), "null");
    }

    #[test]
    fn test_value_conversions() {
        assert_eq!(Value::Int32(42).as_i64(), Some(42));
        assert_eq!(Value::Int32(42).as_f64(), Some(42.0));
        assert_eq!(Value::Float64(3.14).as_f64(), Some(3.14));
        assert_eq!(Value::Bool(true).as_bool(), Some(true));
        assert_eq!(Value::String("test".into()).as_str(), Some("test"));
    }

    #[test]
    fn test_value_from() {
        let v: Value = 42i32.into();
        assert!(matches!(v, Value::Int32(42)));

        let v: Value = 3.14f64.into();
        assert!(matches!(v, Value::Float64(_)));

        let v: Value = "test".into();
        assert!(matches!(v, Value::String(_)));
    }

    #[test]
    fn test_data_quality() {
        assert!(DataQuality::Good.is_good());
        assert!(DataQuality::Good.is_usable());
        assert!(!DataQuality::Good.is_bad());

        let uncertain = DataQuality::Uncertain(UncertainReason::LastKnownValue);
        assert!(!uncertain.is_good());
        assert!(uncertain.is_usable());
        assert!(!uncertain.is_bad());

        let bad = DataQuality::Bad(BadReason::NotConnected);
        assert!(!bad.is_good());
        assert!(!bad.is_usable());
        assert!(bad.is_bad());
    }

    #[test]
    fn test_data_point() {
        let point = DataPoint::new(
            DeviceId::new("device1"),
            TagId::new("tag1"),
            Value::Float64(25.5),
            DataQuality::Good,
        );

        assert_eq!(point.device_id.as_str(), "device1");
        assert_eq!(point.tag_id.as_str(), "tag1");
        assert!(point.is_good());
        assert!(point.is_usable());
        assert_eq!(point.key(), ("device1", "tag1"));
    }

    #[test]
    fn test_protocol() {
        assert_eq!(Protocol::ModbusTcp.as_str(), "modbus-tcp");
        assert!(Protocol::ModbusTcp.is_modbus());
        assert!(Protocol::ModbusRtu.is_modbus());
        assert!(!Protocol::OpcUa.is_modbus());
    }

    #[test]
    fn test_connection_state() {
        assert!(!ConnectionState::Disconnected.is_connected());
        assert!(ConnectionState::Connected.is_connected());
        assert!(ConnectionState::Connecting.is_transitioning());
        assert!(ConnectionState::Reconnecting.is_transitioning());
    }

    #[test]
    fn test_value_to_json() {
        let v = Value::Float64(3.14);
        let json = v.to_json();
        assert_eq!(json.as_f64(), Some(3.14));

        let v = Value::Array(vec![Value::Int32(1), Value::Int32(2)]);
        let json = v.to_json();
        assert!(json.is_array());
    }
}
