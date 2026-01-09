// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Configuration schema definitions for TRAP.
//!
//! This module defines the complete configuration structure for TRAP,
//! including gateway settings, device configurations, security settings,
//! buffer configuration, and API settings.
//!
//! # Schema Structure
//!
//! ```text
//! TrapConfig
//! ├── gateway: GatewayConfig
//! ├── devices: Vec<DeviceConfig>
//! ├── buffer: BufferConfig
//! ├── api: ApiConfig
//! ├── security: SecurityConfig
//! └── logging: LoggingConfig
//! ```

use crate::error::{ConfigError, ConfigResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

// =============================================================================
// Constants
// =============================================================================

/// Default poll interval in milliseconds.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;

/// Default timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Default retry count.
pub const DEFAULT_RETRY_COUNT: u32 = 3;

/// Minimum poll interval in milliseconds.
pub const MIN_POLL_INTERVAL_MS: u64 = 1;

/// Maximum poll interval in milliseconds (1 hour).
pub const MAX_POLL_INTERVAL_MS: u64 = 3_600_000;

/// Default buffer max size (1GB).
pub const DEFAULT_BUFFER_MAX_SIZE: u64 = 1_073_741_824;

/// Default buffer max items (10M).
pub const DEFAULT_BUFFER_MAX_ITEMS: u64 = 10_000_000;

/// Default buffer TTL in days.
pub const DEFAULT_BUFFER_TTL_DAYS: u32 = 7;

/// Default API port.
pub const DEFAULT_API_PORT: u16 = 8080;

/// Default JWT expiration in seconds (1 hour).
pub const DEFAULT_JWT_EXPIRATION_SECS: u64 = 3600;

/// Default rate limit requests per second.
pub const DEFAULT_RATE_LIMIT_RPS: u32 = 100;

/// Default rate limit burst size.
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 50;

// =============================================================================
// Top-Level Configuration
// =============================================================================

/// The root configuration structure for TRAP.
///
/// This structure contains all configuration needed to run a TRAP instance,
/// including gateway identification, device configurations, buffer settings,
/// API settings, security configuration, and logging settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrapConfig {
    /// Gateway configuration.
    pub gateway: GatewayConfig,

    /// Device configurations.
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,

    /// Buffer configuration.
    #[serde(default)]
    pub buffer: BufferConfig,

    /// API server configuration.
    #[serde(default)]
    pub api: ApiConfig,

    /// Security configuration.
    #[serde(default)]
    pub security: SecurityConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl TrapConfig {
    /// Validates the entire configuration.
    ///
    /// This method performs comprehensive validation including:
    /// - Unique device IDs
    /// - Valid poll intervals and timeouts
    /// - Unique tag IDs within each device
    /// - Security configuration validation
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the configuration is valid
    /// * `Err(ConfigError)` if validation fails
    pub fn validate(&self) -> ConfigResult<()> {
        // Validate gateway
        self.gateway.validate()?;

        // Check for duplicate device IDs
        let mut device_ids = std::collections::HashSet::new();
        for device in &self.devices {
            if !device_ids.insert(&device.id) {
                return Err(ConfigError::duplicate_device_id(&device.id));
            }
            device.validate()?;
        }

        // Validate buffer
        self.buffer.validate()?;

        // Validate API
        self.api.validate()?;

        // Validate security
        self.security.validate()?;

        // Validate logging
        self.logging.validate()?;

        Ok(())
    }

    /// Returns a device configuration by ID.
    pub fn get_device(&self, device_id: &str) -> Option<&DeviceConfig> {
        self.devices.iter().find(|d| d.id == device_id)
    }

    /// Returns a mutable device configuration by ID.
    pub fn get_device_mut(&mut self, device_id: &str) -> Option<&mut DeviceConfig> {
        self.devices.iter_mut().find(|d| d.id == device_id)
    }
}

impl Default for TrapConfig {
    fn default() -> Self {
        Self {
            gateway: GatewayConfig::default(),
            devices: Vec::new(),
            buffer: BufferConfig::default(),
            api: ApiConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

// =============================================================================
// Gateway Configuration
// =============================================================================

/// Gateway identification and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Unique gateway identifier.
    pub id: String,

    /// Human-readable gateway name.
    #[serde(default = "default_gateway_name")]
    pub name: String,

    /// Gateway description.
    #[serde(default)]
    pub description: Option<String>,

    /// Gateway location.
    #[serde(default)]
    pub location: Option<String>,

    /// Custom metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_gateway_name() -> String {
    "TRAP Gateway".to_string()
}

impl GatewayConfig {
    /// Validates the gateway configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.id.is_empty() {
            return Err(ConfigError::validation("gateway.id", "cannot be empty"));
        }
        if self.id.len() > 64 {
            return Err(ConfigError::validation(
                "gateway.id",
                "cannot exceed 64 characters",
            ));
        }
        Ok(())
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            id: "trap-gateway-01".to_string(),
            name: default_gateway_name(),
            description: None,
            location: None,
            metadata: HashMap::new(),
        }
    }
}

// =============================================================================
// Device Configuration
// =============================================================================

/// Configuration for a single device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfig {
    /// Unique device identifier.
    pub id: String,

    /// Human-readable device name.
    pub name: String,

    /// Device description.
    #[serde(default)]
    pub description: Option<String>,

    /// Protocol configuration.
    pub protocol: ProtocolConfig,

    /// Polling interval in milliseconds.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,

    /// Operation timeout in milliseconds.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    /// Number of retries on failure.
    #[serde(default = "default_retry_count")]
    pub retry_count: u32,

    /// Tag configurations.
    #[serde(default)]
    pub tags: Vec<TagConfig>,

    /// Whether the device is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Custom metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_poll_interval() -> u64 {
    DEFAULT_POLL_INTERVAL_MS
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn default_retry_count() -> u32 {
    DEFAULT_RETRY_COUNT
}

fn default_enabled() -> bool {
    true
}

impl DeviceConfig {
    /// Validates the device configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        // Validate ID
        if self.id.is_empty() {
            return Err(ConfigError::validation("device.id", "cannot be empty"));
        }

        // Validate name
        if self.name.is_empty() {
            return Err(ConfigError::validation("device.name", "cannot be empty"));
        }

        // Validate poll interval
        if self.poll_interval_ms < MIN_POLL_INTERVAL_MS
            || self.poll_interval_ms > MAX_POLL_INTERVAL_MS
        {
            return Err(ConfigError::out_of_range(
                format!("devices.{}.poll_interval_ms", self.id),
                self.poll_interval_ms,
                MIN_POLL_INTERVAL_MS,
                MAX_POLL_INTERVAL_MS,
            ));
        }

        // Validate timeout (should be less than poll interval for proper operation)
        if self.timeout_ms == 0 {
            return Err(ConfigError::validation(
                format!("devices.{}.timeout_ms", self.id),
                "cannot be zero",
            ));
        }

        // Validate protocol
        self.protocol.validate(&self.id)?;

        // Check for duplicate tag IDs
        let mut tag_ids = std::collections::HashSet::new();
        for tag in &self.tags {
            if !tag_ids.insert(&tag.id) {
                return Err(ConfigError::duplicate_tag_id(&self.id, &tag.id));
            }
            tag.validate(&self.id)?;
        }

        Ok(())
    }

    /// Returns a tag configuration by ID.
    pub fn get_tag(&self, tag_id: &str) -> Option<&TagConfig> {
        self.tags.iter().find(|t| t.id == tag_id)
    }

    /// Returns the timeout as a Duration.
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Returns the poll interval as a Duration.
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }
}

// =============================================================================
// Protocol Configuration
// =============================================================================

/// Protocol-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProtocolConfig {
    /// Modbus TCP protocol.
    ModbusTcp(ModbusTcpConfig),

    /// Modbus RTU protocol.
    ModbusRtu(ModbusRtuConfig),

    /// OPC UA protocol.
    OpcUa(OpcUaConfig),

    /// BACnet IP protocol.
    BacNetIp(BacNetIpConfig),

    /// KNX IP protocol.
    Knx(KnxConfig),
}

impl ProtocolConfig {
    /// Validates the protocol configuration.
    pub fn validate(&self, device_id: &str) -> ConfigResult<()> {
        match self {
            ProtocolConfig::ModbusTcp(config) => config.validate(device_id),
            ProtocolConfig::ModbusRtu(config) => config.validate(device_id),
            ProtocolConfig::OpcUa(config) => config.validate(device_id),
            ProtocolConfig::BacNetIp(config) => config.validate(device_id),
            ProtocolConfig::Knx(config) => config.validate(device_id),
        }
    }

    /// Returns the protocol type name.
    pub fn protocol_type(&self) -> &'static str {
        match self {
            ProtocolConfig::ModbusTcp(_) => "modbus-tcp",
            ProtocolConfig::ModbusRtu(_) => "modbus-rtu",
            ProtocolConfig::OpcUa(_) => "opcua",
            ProtocolConfig::BacNetIp(_) => "bacnet-ip",
            ProtocolConfig::Knx(_) => "knx",
        }
    }
}

/// Modbus TCP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModbusTcpConfig {
    /// Host address.
    pub host: String,

    /// TCP port.
    #[serde(default = "default_modbus_port")]
    pub port: u16,

    /// Unit ID (slave address).
    #[serde(default = "default_unit_id")]
    pub unit_id: u8,
}

fn default_modbus_port() -> u16 {
    502
}

fn default_unit_id() -> u8 {
    1
}

impl ModbusTcpConfig {
    /// Validates the Modbus TCP configuration.
    pub fn validate(&self, device_id: &str) -> ConfigResult<()> {
        if self.host.is_empty() {
            return Err(ConfigError::invalid_protocol(
                device_id,
                "host cannot be empty",
            ));
        }
        Ok(())
    }
}

/// Modbus RTU configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModbusRtuConfig {
    /// Serial port path (e.g., /dev/ttyUSB0 or COM1).
    pub port: String,

    /// Baud rate.
    #[serde(default = "default_baud_rate")]
    pub baud_rate: u32,

    /// Data bits (5, 6, 7, or 8).
    #[serde(default = "default_data_bits")]
    pub data_bits: u8,

    /// Stop bits (1 or 2).
    #[serde(default = "default_stop_bits")]
    pub stop_bits: u8,

    /// Parity (none, odd, or even).
    #[serde(default)]
    pub parity: Parity,

    /// Unit ID (slave address).
    #[serde(default = "default_unit_id")]
    pub unit_id: u8,
}

fn default_baud_rate() -> u32 {
    9600
}

fn default_data_bits() -> u8 {
    8
}

fn default_stop_bits() -> u8 {
    1
}

impl ModbusRtuConfig {
    /// Validates the Modbus RTU configuration.
    pub fn validate(&self, device_id: &str) -> ConfigResult<()> {
        if self.port.is_empty() {
            return Err(ConfigError::invalid_protocol(
                device_id,
                "serial port cannot be empty",
            ));
        }
        if self.data_bits < 5 || self.data_bits > 8 {
            return Err(ConfigError::invalid_protocol(
                device_id,
                "data_bits must be between 5 and 8",
            ));
        }
        if self.stop_bits < 1 || self.stop_bits > 2 {
            return Err(ConfigError::invalid_protocol(
                device_id,
                "stop_bits must be 1 or 2",
            ));
        }
        Ok(())
    }
}

/// Serial parity setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Parity {
    /// No parity.
    #[default]
    None,
    /// Odd parity.
    Odd,
    /// Even parity.
    Even,
}

/// OPC UA configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpcUaConfig {
    /// OPC UA endpoint URL.
    pub endpoint_url: String,

    /// Security policy (None, Basic128Rsa15, Basic256, Basic256Sha256).
    #[serde(default)]
    pub security_policy: SecurityPolicy,

    /// Security mode (None, Sign, SignAndEncrypt).
    #[serde(default)]
    pub security_mode: SecurityMode,

    /// Username for authentication (optional).
    #[serde(default)]
    pub username: Option<SecretValue>,

    /// Password for authentication (optional).
    #[serde(default)]
    pub password: Option<SecretValue>,

    /// Certificate path (optional).
    #[serde(default)]
    pub certificate_path: Option<PathBuf>,

    /// Private key path (optional).
    #[serde(default)]
    pub private_key_path: Option<PathBuf>,
}

impl OpcUaConfig {
    /// Validates the OPC UA configuration.
    pub fn validate(&self, device_id: &str) -> ConfigResult<()> {
        if self.endpoint_url.is_empty() {
            return Err(ConfigError::invalid_protocol(
                device_id,
                "endpoint_url cannot be empty",
            ));
        }
        if !self.endpoint_url.starts_with("opc.tcp://") {
            return Err(ConfigError::invalid_protocol(
                device_id,
                "endpoint_url must start with 'opc.tcp://'",
            ));
        }
        Ok(())
    }
}

/// OPC UA security policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SecurityPolicy {
    /// No security.
    #[default]
    None,
    /// Basic128Rsa15 policy.
    Basic128Rsa15,
    /// Basic256 policy.
    Basic256,
    /// Basic256Sha256 policy.
    Basic256Sha256,
}

/// OPC UA security mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SecurityMode {
    /// No security.
    #[default]
    None,
    /// Sign messages.
    Sign,
    /// Sign and encrypt messages.
    SignAndEncrypt,
}

/// BACnet IP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacNetIpConfig {
    /// Device IP address.
    pub host: String,

    /// BACnet UDP port.
    #[serde(default = "default_bacnet_port")]
    pub port: u16,

    /// Device instance number.
    pub device_instance: u32,

    /// Network number (optional).
    #[serde(default)]
    pub network: Option<u16>,

    /// MAC address (optional).
    #[serde(default)]
    pub mac_address: Option<String>,
}

fn default_bacnet_port() -> u16 {
    47808
}

impl BacNetIpConfig {
    /// Validates the BACnet IP configuration.
    pub fn validate(&self, device_id: &str) -> ConfigResult<()> {
        if self.host.is_empty() {
            return Err(ConfigError::invalid_protocol(
                device_id,
                "host cannot be empty",
            ));
        }
        Ok(())
    }
}

/// KNX IP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnxConfig {
    /// KNX IP router/interface address.
    pub host: String,

    /// KNX UDP port.
    #[serde(default = "default_knx_port")]
    pub port: u16,

    /// Physical address of the gateway.
    #[serde(default)]
    pub physical_address: Option<String>,

    /// Connection type.
    #[serde(default)]
    pub connection_type: KnxConnectionType,
}

fn default_knx_port() -> u16 {
    3671
}

impl KnxConfig {
    /// Validates the KNX configuration.
    pub fn validate(&self, device_id: &str) -> ConfigResult<()> {
        if self.host.is_empty() {
            return Err(ConfigError::invalid_protocol(
                device_id,
                "host cannot be empty",
            ));
        }
        Ok(())
    }
}

/// KNX connection type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnxConnectionType {
    /// Tunneling connection.
    #[default]
    Tunneling,
    /// Routing connection (multicast).
    Routing,
}

// =============================================================================
// Tag Configuration
// =============================================================================

/// Configuration for a single tag (data point).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagConfig {
    /// Unique tag identifier within the device.
    pub id: String,

    /// Human-readable tag name.
    pub name: String,

    /// Protocol-specific address.
    pub address: String,

    /// Data type.
    pub data_type: DataType,

    /// Whether the tag is writable.
    #[serde(default)]
    pub writable: bool,

    /// Engineering unit (e.g., "°C", "kWh").
    #[serde(default)]
    pub unit: Option<String>,

    /// Description.
    #[serde(default)]
    pub description: Option<String>,

    /// Minimum value (for numeric types).
    #[serde(default)]
    pub min_value: Option<f64>,

    /// Maximum value (for numeric types).
    #[serde(default)]
    pub max_value: Option<f64>,

    /// Scale factor to apply to raw value.
    #[serde(default)]
    pub scale: Option<f64>,

    /// Offset to apply after scaling.
    #[serde(default)]
    pub offset: Option<f64>,

    /// Whether the tag is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Custom metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl TagConfig {
    /// Validates the tag configuration.
    pub fn validate(&self, device_id: &str) -> ConfigResult<()> {
        if self.id.is_empty() {
            return Err(ConfigError::validation(
                format!("devices.{}.tags.id", device_id),
                "cannot be empty",
            ));
        }
        if self.name.is_empty() {
            return Err(ConfigError::validation(
                format!("devices.{}.tags.{}.name", device_id, self.id),
                "cannot be empty",
            ));
        }
        if self.address.is_empty() {
            return Err(ConfigError::validation(
                format!("devices.{}.tags.{}.address", device_id, self.id),
                "cannot be empty",
            ));
        }

        // Validate min/max range
        if let (Some(min), Some(max)) = (self.min_value, self.max_value) {
            if min > max {
                return Err(ConfigError::validation(
                    format!("devices.{}.tags.{}.min_value/max_value", device_id, self.id),
                    "min_value cannot be greater than max_value",
                ));
            }
        }

        Ok(())
    }
}

/// Data type for a tag value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataType {
    /// Boolean (1 bit).
    Bool,
    /// Signed 8-bit integer.
    Int8,
    /// Signed 16-bit integer.
    Int16,
    /// Signed 32-bit integer.
    Int32,
    /// Signed 64-bit integer.
    Int64,
    /// Unsigned 8-bit integer.
    UInt8,
    /// Unsigned 16-bit integer.
    UInt16,
    /// Unsigned 32-bit integer.
    UInt32,
    /// Unsigned 64-bit integer.
    UInt64,
    /// 32-bit floating point.
    Float32,
    /// 64-bit floating point.
    Float64,
    /// UTF-8 string.
    String,
    /// Raw bytes.
    Bytes,
}

impl DataType {
    /// Returns the size in bytes (for fixed-size types).
    pub fn size(&self) -> Option<usize> {
        match self {
            DataType::Bool => Some(1),
            DataType::Int8 | DataType::UInt8 => Some(1),
            DataType::Int16 | DataType::UInt16 => Some(2),
            DataType::Int32 | DataType::UInt32 | DataType::Float32 => Some(4),
            DataType::Int64 | DataType::UInt64 | DataType::Float64 => Some(8),
            DataType::String | DataType::Bytes => None,
        }
    }

    /// Returns `true` if this is a numeric type.
    pub fn is_numeric(&self) -> bool {
        !matches!(self, DataType::Bool | DataType::String | DataType::Bytes)
    }

    /// Returns `true` if this is a floating-point type.
    pub fn is_float(&self) -> bool {
        matches!(self, DataType::Float32 | DataType::Float64)
    }
}

// =============================================================================
// Buffer Configuration
// =============================================================================

/// Offline buffer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BufferConfig {
    /// Path to the buffer storage directory.
    #[serde(default = "default_buffer_path")]
    pub path: PathBuf,

    /// Maximum buffer size in bytes.
    #[serde(default = "default_max_size")]
    pub max_size_bytes: u64,

    /// Maximum number of items to buffer.
    #[serde(default = "default_max_items")]
    pub max_items: u64,

    /// Enable LZ4 compression.
    #[serde(default)]
    pub compression: bool,

    /// Data retention in days.
    #[serde(default = "default_ttl_days")]
    pub ttl_days: u32,

    /// Flush configuration.
    #[serde(default)]
    pub flush: FlushConfig,

    /// Circuit breaker configuration.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
}

/// Default buffer path.
pub fn default_buffer_path() -> PathBuf {
    PathBuf::from("./data/buffer")
}

fn default_max_size() -> u64 {
    DEFAULT_BUFFER_MAX_SIZE
}

fn default_max_items() -> u64 {
    DEFAULT_BUFFER_MAX_ITEMS
}

fn default_ttl_days() -> u32 {
    DEFAULT_BUFFER_TTL_DAYS
}

impl BufferConfig {
    /// Validates the buffer configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.max_size_bytes == 0 {
            return Err(ConfigError::validation(
                "buffer.max_size_bytes",
                "cannot be zero",
            ));
        }
        if self.max_items == 0 {
            return Err(ConfigError::validation(
                "buffer.max_items",
                "cannot be zero",
            ));
        }
        if self.ttl_days == 0 {
            return Err(ConfigError::validation(
                "buffer.ttl_days",
                "cannot be zero",
            ));
        }
        self.flush.validate()?;
        self.circuit_breaker.validate()?;
        Ok(())
    }
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            path: default_buffer_path(),
            max_size_bytes: DEFAULT_BUFFER_MAX_SIZE,
            max_items: DEFAULT_BUFFER_MAX_ITEMS,
            compression: false,
            ttl_days: DEFAULT_BUFFER_TTL_DAYS,
            flush: FlushConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

/// Flush strategy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlushConfig {
    /// Flush interval in seconds.
    #[serde(default = "default_flush_interval")]
    pub interval_secs: u64,

    /// Number of items per flush batch.
    #[serde(default = "default_flush_batch_size")]
    pub batch_size: u32,

    /// Number of retry attempts.
    #[serde(default = "default_flush_retries")]
    pub retries: u32,

    /// Initial retry delay in milliseconds.
    #[serde(default = "default_retry_delay")]
    pub retry_delay_ms: u64,

    /// Maximum retry delay in seconds.
    #[serde(default = "default_max_retry_delay")]
    pub max_retry_delay_secs: u64,

    /// Upstream endpoint URL.
    #[serde(default)]
    pub endpoint: Option<String>,
}

fn default_flush_interval() -> u64 {
    60
}

fn default_flush_batch_size() -> u32 {
    1000
}

fn default_flush_retries() -> u32 {
    3
}

fn default_retry_delay() -> u64 {
    1000
}

fn default_max_retry_delay() -> u64 {
    60
}

impl FlushConfig {
    /// Validates the flush configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.interval_secs == 0 {
            return Err(ConfigError::validation(
                "buffer.flush.interval_secs",
                "cannot be zero",
            ));
        }
        if self.batch_size == 0 {
            return Err(ConfigError::validation(
                "buffer.flush.batch_size",
                "cannot be zero",
            ));
        }
        Ok(())
    }
}

impl Default for FlushConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_flush_interval(),
            batch_size: default_flush_batch_size(),
            retries: default_flush_retries(),
            retry_delay_ms: default_retry_delay(),
            max_retry_delay_secs: default_max_retry_delay(),
            endpoint: None,
        }
    }
}

/// Circuit breaker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Time in seconds before attempting to close the circuit.
    #[serde(default = "default_reset_timeout")]
    pub reset_timeout_secs: u64,

    /// Number of test requests in half-open state.
    #[serde(default = "default_half_open_calls")]
    pub half_open_max_calls: u32,

    /// Success rate threshold for closing (0.0 - 1.0).
    #[serde(default = "default_success_rate")]
    pub success_rate_threshold: f64,
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_reset_timeout() -> u64 {
    30
}

fn default_half_open_calls() -> u32 {
    3
}

fn default_success_rate() -> f64 {
    0.5
}

impl CircuitBreakerConfig {
    /// Validates the circuit breaker configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.failure_threshold == 0 {
            return Err(ConfigError::validation(
                "circuit_breaker.failure_threshold",
                "cannot be zero",
            ));
        }
        if self.reset_timeout_secs == 0 {
            return Err(ConfigError::validation(
                "circuit_breaker.reset_timeout_secs",
                "cannot be zero",
            ));
        }
        if self.success_rate_threshold <= 0.0 || self.success_rate_threshold > 1.0 {
            return Err(ConfigError::validation(
                "circuit_breaker.success_rate_threshold",
                "must be between 0.0 and 1.0",
            ));
        }
        Ok(())
    }

    /// Returns the reset timeout as a Duration.
    pub fn reset_timeout(&self) -> Duration {
        Duration::from_secs(self.reset_timeout_secs)
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            reset_timeout_secs: default_reset_timeout(),
            half_open_max_calls: default_half_open_calls(),
            success_rate_threshold: default_success_rate(),
        }
    }
}

// =============================================================================
// API Configuration
// =============================================================================

/// REST API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Whether the API is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Bind address.
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,

    /// Listen port.
    #[serde(default = "default_api_port")]
    pub port: u16,

    /// Base path for API routes.
    #[serde(default = "default_base_path")]
    pub base_path: String,

    /// CORS configuration.
    #[serde(default)]
    pub cors: CorsConfig,

    /// Request timeout in seconds.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,

    /// Maximum request body size in bytes.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
}

fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}

fn default_api_port() -> u16 {
    DEFAULT_API_PORT
}

fn default_base_path() -> String {
    "/api/v1".to_string()
}

fn default_request_timeout() -> u64 {
    30
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

impl ApiConfig {
    /// Validates the API configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.request_timeout_secs == 0 {
            return Err(ConfigError::validation(
                "api.request_timeout_secs",
                "cannot be zero",
            ));
        }
        if self.max_body_size == 0 {
            return Err(ConfigError::validation(
                "api.max_body_size",
                "cannot be zero",
            ));
        }
        self.cors.validate()?;
        Ok(())
    }

    /// Returns the request timeout as a Duration.
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    /// Returns the socket address.
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.bind_address, self.port)
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: default_bind_address(),
            port: DEFAULT_API_PORT,
            base_path: default_base_path(),
            cors: CorsConfig::default(),
            request_timeout_secs: default_request_timeout(),
            max_body_size: default_max_body_size(),
        }
    }
}

/// CORS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Allowed origins (use "*" for all).
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Allowed methods.
    #[serde(default = "default_methods")]
    pub allowed_methods: Vec<String>,

    /// Allowed headers.
    #[serde(default = "default_headers")]
    pub allowed_headers: Vec<String>,

    /// Allow credentials.
    #[serde(default)]
    pub allow_credentials: bool,

    /// Max age in seconds.
    #[serde(default = "default_max_age")]
    pub max_age_secs: u64,
}

fn default_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
    ]
}

fn default_headers() -> Vec<String> {
    vec![
        "Content-Type".to_string(),
        "Authorization".to_string(),
    ]
}

fn default_max_age() -> u64 {
    3600
}

impl CorsConfig {
    /// Validates the CORS configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        Ok(())
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allowed_methods: default_methods(),
            allowed_headers: default_headers(),
            allow_credentials: false,
            max_age_secs: default_max_age(),
        }
    }
}

// =============================================================================
// Security Configuration
// =============================================================================

/// Security configuration for enterprise features.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// JWT configuration.
    #[serde(default)]
    pub jwt: JwtConfig,

    /// TLS configuration.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Audit logging configuration.
    #[serde(default)]
    pub audit: AuditConfig,
}

impl SecurityConfig {
    /// Validates the security configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        self.jwt.validate()?;
        if let Some(ref tls) = self.tls {
            tls.validate()?;
        }
        self.rate_limit.validate()?;
        self.audit.validate()?;
        Ok(())
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt: JwtConfig::default(),
            tls: None,
            rate_limit: RateLimitConfig::default(),
            audit: AuditConfig::default(),
        }
    }
}

/// JWT configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    /// Whether JWT authentication is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// JWT secret key (should be encrypted with ENC: prefix).
    #[serde(default)]
    pub secret: Option<SecretValue>,

    /// Token expiration in seconds.
    #[serde(default = "default_jwt_expiration")]
    pub expiration_secs: u64,

    /// Token issuer.
    #[serde(default = "default_jwt_issuer")]
    pub issuer: String,

    /// Allowed algorithms.
    #[serde(default = "default_jwt_algorithm")]
    pub algorithm: JwtAlgorithm,

    /// Public paths that don't require authentication.
    #[serde(default = "default_public_paths")]
    pub public_paths: Vec<String>,
}

fn default_jwt_expiration() -> u64 {
    DEFAULT_JWT_EXPIRATION_SECS
}

fn default_jwt_issuer() -> String {
    "trap".to_string()
}

fn default_jwt_algorithm() -> JwtAlgorithm {
    JwtAlgorithm::HS256
}

fn default_public_paths() -> Vec<String> {
    vec![
        "/health".to_string(),
        "/ready".to_string(),
        "/api/v1/auth/login".to_string(),
    ]
}

impl JwtConfig {
    /// Validates the JWT configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.enabled && self.secret.is_none() {
            return Err(ConfigError::validation(
                "security.jwt.secret",
                "secret is required when JWT is enabled",
            ));
        }
        if self.expiration_secs == 0 {
            return Err(ConfigError::validation(
                "security.jwt.expiration_secs",
                "cannot be zero",
            ));
        }
        Ok(())
    }

    /// Returns the expiration as a Duration.
    pub fn expiration(&self) -> Duration {
        Duration::from_secs(self.expiration_secs)
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            secret: None,
            expiration_secs: DEFAULT_JWT_EXPIRATION_SECS,
            issuer: default_jwt_issuer(),
            algorithm: default_jwt_algorithm(),
            public_paths: default_public_paths(),
        }
    }
}

/// JWT signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    /// HMAC using SHA-256.
    #[default]
    HS256,
    /// HMAC using SHA-384.
    HS384,
    /// HMAC using SHA-512.
    HS512,
    /// RSA using SHA-256.
    RS256,
    /// RSA using SHA-384.
    RS384,
    /// RSA using SHA-512.
    RS512,
}

/// TLS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to the certificate file (PEM format).
    pub cert_path: PathBuf,

    /// Path to the private key file (PEM format).
    pub key_path: PathBuf,

    /// Path to the CA certificate for client verification (optional).
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,

    /// Require client certificate.
    #[serde(default)]
    pub require_client_cert: bool,

    /// Minimum TLS version.
    #[serde(default)]
    pub min_version: TlsVersion,
}

impl TlsConfig {
    /// Validates the TLS configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if !self.cert_path.exists() {
            return Err(ConfigError::file_not_found(&self.cert_path));
        }
        if !self.key_path.exists() {
            return Err(ConfigError::file_not_found(&self.key_path));
        }
        if let Some(ref ca_path) = self.ca_cert_path {
            if !ca_path.exists() {
                return Err(ConfigError::file_not_found(ca_path));
            }
        }
        Ok(())
    }
}

/// TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2.
    #[default]
    #[serde(rename = "1.2")]
    Tls12,
    /// TLS 1.3.
    #[serde(rename = "1.3")]
    Tls13,
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Requests per second (global).
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,

    /// Burst size (token bucket).
    #[serde(default = "default_burst")]
    pub burst_size: u32,

    /// Enable per-IP limiting.
    #[serde(default)]
    pub per_ip: bool,

    /// Enable per-user limiting.
    #[serde(default)]
    pub per_user: bool,
}

fn default_rps() -> u32 {
    DEFAULT_RATE_LIMIT_RPS
}

fn default_burst() -> u32 {
    DEFAULT_RATE_LIMIT_BURST
}

impl RateLimitConfig {
    /// Validates the rate limit configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.enabled && self.requests_per_second == 0 {
            return Err(ConfigError::validation(
                "security.rate_limit.requests_per_second",
                "cannot be zero when rate limiting is enabled",
            ));
        }
        Ok(())
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: DEFAULT_RATE_LIMIT_RPS,
            burst_size: DEFAULT_RATE_LIMIT_BURST,
            per_ip: false,
            per_user: false,
        }
    }
}

/// Audit logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Whether audit logging is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Audit log file path.
    #[serde(default = "default_audit_path")]
    pub path: PathBuf,

    /// Retention in days.
    #[serde(default = "default_audit_retention")]
    pub retention_days: u32,

    /// Rotation policy.
    #[serde(default)]
    pub rotation: AuditRotation,

    /// Events to log.
    #[serde(default = "default_audit_events")]
    pub events: Vec<AuditEvent>,
}

fn default_audit_path() -> PathBuf {
    PathBuf::from("./logs/audit.log")
}

fn default_audit_retention() -> u32 {
    30
}

fn default_audit_events() -> Vec<AuditEvent> {
    vec![
        AuditEvent::Login,
        AuditEvent::Logout,
        AuditEvent::Write,
        AuditEvent::ConfigChange,
    ]
}

impl AuditConfig {
    /// Validates the audit configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.enabled && self.retention_days == 0 {
            return Err(ConfigError::validation(
                "security.audit.retention_days",
                "cannot be zero when audit is enabled",
            ));
        }
        Ok(())
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_audit_path(),
            retention_days: default_audit_retention(),
            rotation: AuditRotation::default(),
            events: default_audit_events(),
        }
    }
}

/// Audit log rotation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRotation {
    /// Daily rotation.
    #[default]
    Daily,
    /// Size-based rotation.
    Size,
    /// No rotation.
    Never,
}

/// Audit event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    /// Login events.
    Login,
    /// Logout events.
    Logout,
    /// Read operations.
    Read,
    /// Write operations.
    Write,
    /// Configuration changes.
    ConfigChange,
    /// Device add/remove.
    DeviceChange,
    /// System events.
    System,
}

// =============================================================================
// Logging Configuration
// =============================================================================

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level.
    #[serde(default)]
    pub level: LogLevel,

    /// Log format.
    #[serde(default)]
    pub format: LogFormat,

    /// Log to stdout.
    #[serde(default = "default_enabled")]
    pub stdout: bool,

    /// Log file path (optional).
    #[serde(default)]
    pub file: Option<PathBuf>,

    /// Enable JSON structured logging.
    #[serde(default)]
    pub json: bool,

    /// Include span targets in logs.
    #[serde(default = "default_enabled")]
    pub with_target: bool,

    /// Include file/line in logs.
    #[serde(default)]
    pub with_file: bool,

    /// Include thread IDs in logs.
    #[serde(default)]
    pub with_thread_ids: bool,
}

impl LoggingConfig {
    /// Validates the logging configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        Ok(())
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::default(),
            format: LogFormat::default(),
            stdout: true,
            file: None,
            json: false,
            with_target: true,
            with_file: false,
            with_thread_ids: false,
        }
    }
}

/// Log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Trace level.
    Trace,
    /// Debug level.
    Debug,
    /// Info level.
    #[default]
    Info,
    /// Warning level.
    Warn,
    /// Error level.
    Error,
}

impl LogLevel {
    /// Converts to tracing Level.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

/// Log format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Pretty format for development.
    #[default]
    Pretty,
    /// Compact format.
    Compact,
    /// Full format with all details.
    Full,
    /// JSON format for production.
    Json,
}

// =============================================================================
// Secret Value
// =============================================================================

/// A potentially encrypted secret value.
///
/// Values can be plain text or encrypted with the `ENC:` prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    /// Creates a new secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns `true` if the value is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.0.starts_with("ENC:")
    }

    /// Returns the raw value (encrypted or plain).
    pub fn raw(&self) -> &str {
        &self.0
    }

    /// Returns the encrypted payload (without the ENC: prefix).
    pub fn encrypted_payload(&self) -> Option<&str> {
        if self.is_encrypted() {
            Some(&self.0[4..])
        } else {
            None
        }
    }

    /// Creates an encrypted secret value.
    pub fn encrypted(base64_ciphertext: impl Into<String>) -> Self {
        Self(format!("ENC:{}", base64_ciphertext.into()))
    }
}

impl std::fmt::Display for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_encrypted() {
            write!(f, "ENC:***")
        } else {
            write!(f, "***")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trap_config_default() {
        let config = TrapConfig::default();
        assert_eq!(config.gateway.id, "trap-gateway-01");
        assert!(config.devices.is_empty());
        assert!(config.api.enabled);
    }

    #[test]
    fn test_device_config_validation() {
        let device = DeviceConfig {
            id: "test".to_string(),
            name: "Test Device".to_string(),
            description: None,
            protocol: ProtocolConfig::ModbusTcp(ModbusTcpConfig {
                host: "127.0.0.1".to_string(),
                port: 502,
                unit_id: 1,
            }),
            poll_interval_ms: 1000,
            timeout_ms: 5000,
            retry_count: 3,
            tags: vec![],
            enabled: true,
            metadata: HashMap::new(),
        };
        assert!(device.validate().is_ok());
    }

    #[test]
    fn test_device_invalid_poll_interval() {
        let device = DeviceConfig {
            id: "test".to_string(),
            name: "Test Device".to_string(),
            description: None,
            protocol: ProtocolConfig::ModbusTcp(ModbusTcpConfig {
                host: "127.0.0.1".to_string(),
                port: 502,
                unit_id: 1,
            }),
            poll_interval_ms: 0,
            timeout_ms: 5000,
            retry_count: 3,
            tags: vec![],
            enabled: true,
            metadata: HashMap::new(),
        };
        assert!(device.validate().is_err());
    }

    #[test]
    fn test_secret_value() {
        let plain = SecretValue::new("my-secret");
        assert!(!plain.is_encrypted());
        assert_eq!(plain.raw(), "my-secret");

        let encrypted = SecretValue::encrypted("base64data");
        assert!(encrypted.is_encrypted());
        assert_eq!(encrypted.encrypted_payload(), Some("base64data"));
    }

    #[test]
    fn test_data_type() {
        assert_eq!(DataType::Int32.size(), Some(4));
        assert_eq!(DataType::Float64.size(), Some(8));
        assert_eq!(DataType::String.size(), None);
        assert!(DataType::Float32.is_float());
        assert!(!DataType::Int32.is_float());
        assert!(DataType::Int32.is_numeric());
        assert!(!DataType::Bool.is_numeric());
    }

    #[test]
    fn test_protocol_config_type() {
        let modbus = ProtocolConfig::ModbusTcp(ModbusTcpConfig {
            host: "127.0.0.1".to_string(),
            port: 502,
            unit_id: 1,
        });
        assert_eq!(modbus.protocol_type(), "modbus-tcp");

        let opcua = ProtocolConfig::OpcUa(OpcUaConfig {
            endpoint_url: "opc.tcp://localhost:4840".to_string(),
            security_policy: SecurityPolicy::None,
            security_mode: SecurityMode::None,
            username: None,
            password: None,
            certificate_path: None,
            private_key_path: None,
        });
        assert_eq!(opcua.protocol_type(), "opcua");
    }

    #[test]
    fn test_jwt_config_validation() {
        let mut jwt = JwtConfig::default();
        assert!(jwt.validate().is_ok());

        jwt.enabled = true;
        assert!(jwt.validate().is_err()); // Missing secret

        jwt.secret = Some(SecretValue::new("my-secret"));
        assert!(jwt.validate().is_ok());
    }

    #[test]
    fn test_circuit_breaker_config() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.reset_timeout_secs, 30);
        assert!(config.validate().is_ok());

        let invalid = CircuitBreakerConfig {
            failure_threshold: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_log_level() {
        assert_eq!(LogLevel::Info.as_str(), "info");
        assert_eq!(LogLevel::Debug.as_str(), "debug");
        assert_eq!(LogLevel::Error.as_str(), "error");
    }
}
