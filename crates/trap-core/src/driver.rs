// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Protocol driver abstraction layer.
//!
//! This module provides the core traits and types for protocol drivers,
//! enabling a unified interface for all supported industrial protocols.
//!
//! # Design Principles
//!
//! - **Protocol Agnostic**: All drivers implement the same interface
//! - **Async First**: All I/O operations are asynchronous
//! - **Thread Safe**: Drivers are `Send + Sync` for concurrent access
//! - **Extensible**: New protocols can be added by implementing traits
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_core::driver::{ProtocolDriver, DriverFactory, DriverRegistry};
//!
//! // Create a registry and register factories
//! let mut registry = DriverRegistry::new();
//! registry.register(Box::new(ModbusDriverFactory));
//!
//! // Create a driver from config
//! let driver = registry.create(&device_config)?;
//! ```

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::address::Address;
use crate::error::DriverError;
use crate::types::{DataPoint, Protocol, Value};

// =============================================================================
// ProtocolDriver Trait
// =============================================================================

/// The core trait that all protocol drivers must implement.
///
/// This trait provides a unified interface for connecting to industrial devices,
/// reading and writing data, and managing subscriptions.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to allow concurrent access
/// from multiple tasks. The `&self` methods should be thread-safe for
/// concurrent reads, while `&mut self` methods (connect/disconnect)
/// should be called with exclusive access.
///
/// # Lifecycle
///
/// 1. Create driver instance via factory
/// 2. Call `connect()` to establish connection
/// 3. Use `read()` / `write()` for data operations
/// 4. Optionally use `subscribe()` for push-based updates
/// 5. Call `disconnect()` when done
///
/// # Example
///
/// ```rust,ignore
/// async fn example(driver: &mut dyn ProtocolDriver) -> Result<(), DriverError> {
///     driver.connect().await?;
///
///     let value = driver.read(&address).await?;
///     println!("Read value: {:?}", value);
///
///     driver.disconnect().await?;
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait ProtocolDriver: Send + Sync {
    // =========================================================================
    // Identification
    // =========================================================================

    /// Returns the human-readable name of this driver instance.
    ///
    /// This is typically used for logging and debugging purposes.
    fn name(&self) -> &str;

    /// Returns the protocol type this driver implements.
    fn protocol(&self) -> Protocol;

    // =========================================================================
    // Connection Management
    // =========================================================================

    /// Establishes a connection to the device.
    ///
    /// This method should:
    /// - Establish the network/serial connection
    /// - Perform any protocol-specific handshake
    /// - Verify the device is responsive
    ///
    /// # Errors
    ///
    /// Returns `DriverError::ConnectionFailed` if the connection cannot be established.
    async fn connect(&mut self) -> Result<(), DriverError>;

    /// Closes the connection to the device.
    ///
    /// This method should gracefully close the connection, releasing any
    /// resources held by the driver.
    async fn disconnect(&mut self) -> Result<(), DriverError>;

    /// Returns `true` if currently connected to the device.
    fn is_connected(&self) -> bool;

    // =========================================================================
    // Data Operations
    // =========================================================================

    /// Reads a single value from the specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The protocol-specific address to read from
    ///
    /// # Errors
    ///
    /// - `DriverError::NotConnected` - Not connected to device
    /// - `DriverError::ReadFailed` - Read operation failed
    /// - `DriverError::Timeout` - Operation timed out
    /// - `DriverError::AddressNotFound` - Invalid address
    async fn read(&self, address: &Address) -> Result<Value, DriverError>;

    /// Reads multiple values in a single batch operation.
    ///
    /// The default implementation reads each address sequentially. Protocol
    /// drivers that support batch reads should override this method for
    /// better performance.
    ///
    /// # Arguments
    ///
    /// * `addresses` - The addresses to read from
    ///
    /// # Returns
    ///
    /// A vector of tuples containing the address and the result for each read.
    async fn read_batch(
        &self,
        addresses: &[Address],
    ) -> Result<Vec<(Address, Result<Value, DriverError>)>, DriverError> {
        let mut results = Vec::with_capacity(addresses.len());
        for addr in addresses {
            let result = self.read(addr).await;
            results.push((addr.clone(), result));
        }
        Ok(results)
    }

    /// Writes a value to the specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The protocol-specific address to write to
    /// * `value` - The value to write
    ///
    /// # Errors
    ///
    /// - `DriverError::NotConnected` - Not connected to device
    /// - `DriverError::WriteFailed` - Write operation failed
    /// - `DriverError::Timeout` - Operation timed out
    /// - `DriverError::Protocol` - Address is read-only
    async fn write(&self, address: &Address, value: Value) -> Result<(), DriverError>;

    /// Writes multiple values in a single batch operation.
    ///
    /// The default implementation writes each address sequentially. Protocol
    /// drivers that support batch writes should override this method.
    async fn write_batch(
        &self,
        writes: &[(Address, Value)],
    ) -> Result<Vec<(Address, Result<(), DriverError>)>, DriverError> {
        let mut results = Vec::with_capacity(writes.len());
        for (addr, value) in writes {
            let result = self.write(addr, value.clone()).await;
            results.push((addr.clone(), result));
        }
        Ok(results)
    }

    // =========================================================================
    // Subscription (Optional)
    // =========================================================================

    /// Returns `true` if this driver supports subscriptions.
    ///
    /// Protocols like OPC UA and BACnet (COV) support push-based updates,
    /// while Modbus requires polling.
    fn supports_subscription(&self) -> bool {
        false
    }

    /// Subscribes to value changes for the specified addresses.
    ///
    /// # Arguments
    ///
    /// * `addresses` - The addresses to subscribe to
    ///
    /// # Returns
    ///
    /// A `Subscription` containing an ID and a receiver channel for updates.
    ///
    /// # Errors
    ///
    /// - `DriverError::Protocol` - Subscriptions not supported
    async fn subscribe(&self, _addresses: &[Address]) -> Result<Subscription, DriverError> {
        Err(DriverError::protocol("Subscription not supported"))
    }

    /// Unsubscribes from a previously created subscription.
    async fn unsubscribe(&self, _subscription_id: &SubscriptionId) -> Result<(), DriverError> {
        Err(DriverError::protocol("Subscription not supported"))
    }

    // =========================================================================
    // Metadata (Optional)
    // =========================================================================

    /// Browses available addresses on the device.
    ///
    /// This is useful for protocols like OPC UA that support browsing
    /// the address space.
    async fn browse(&self) -> Result<Vec<AddressInfo>, DriverError> {
        Err(DriverError::protocol("Browse not supported"))
    }

    /// Gets metadata about a specific address.
    async fn get_address_info(&self, _address: &Address) -> Result<AddressInfo, DriverError> {
        Err(DriverError::protocol("Address info not supported"))
    }

    // =========================================================================
    // Health Check
    // =========================================================================

    /// Performs a health check on the connection.
    ///
    /// This method should verify that the connection is still active
    /// and the device is responsive.
    async fn health_check(&self) -> HealthStatus;
}

// =============================================================================
// Supporting Types
// =============================================================================

/// A unique identifier for a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriptionId(pub u64);

impl SubscriptionId {
    /// Creates a new subscription ID.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sub-{}", self.0)
    }
}

/// A subscription handle for receiving data updates.
pub struct Subscription {
    /// The unique subscription ID.
    pub id: SubscriptionId,
    /// Channel for receiving data point updates.
    pub receiver: mpsc::Receiver<DataPoint>,
}

impl Subscription {
    /// Creates a new subscription with the given ID and receiver.
    pub fn new(id: SubscriptionId, receiver: mpsc::Receiver<DataPoint>) -> Self {
        Self { id, receiver }
    }
}

/// Metadata about an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// The address.
    pub address: Address,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// The expected data type.
    pub data_type: DataType,
    /// Whether the address is writable.
    pub writable: bool,
    /// Engineering unit (e.g., "°C", "kWh").
    pub unit: Option<String>,
}

/// Data type for address metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataType {
    /// Boolean
    Bool,
    /// 8-bit signed integer
    Int8,
    /// 16-bit signed integer
    Int16,
    /// 32-bit signed integer
    Int32,
    /// 64-bit signed integer
    Int64,
    /// 8-bit unsigned integer
    UInt8,
    /// 16-bit unsigned integer
    UInt16,
    /// 32-bit unsigned integer
    UInt32,
    /// 64-bit unsigned integer
    UInt64,
    /// 32-bit float
    Float32,
    /// 64-bit float
    Float64,
    /// String
    String,
    /// Byte array
    Bytes,
    /// Date/time
    DateTime,
    /// Unknown type
    Unknown,
}

impl Default for DataType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DataType::Bool => "bool",
            DataType::Int8 => "int8",
            DataType::Int16 => "int16",
            DataType::Int32 => "int32",
            DataType::Int64 => "int64",
            DataType::UInt8 => "uint8",
            DataType::UInt16 => "uint16",
            DataType::UInt32 => "uint32",
            DataType::UInt64 => "uint64",
            DataType::Float32 => "float32",
            DataType::Float64 => "float64",
            DataType::String => "string",
            DataType::Bytes => "bytes",
            DataType::DateTime => "datetime",
            DataType::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

// =============================================================================
// Health Status
// =============================================================================

/// Health status of a driver connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Whether the connection is healthy.
    pub healthy: bool,
    /// Last measured latency (if available).
    pub latency: Option<Duration>,
    /// Last successful operation time.
    pub last_success: Option<DateTime<Utc>>,
    /// Last error message (if any).
    pub last_error: Option<String>,
    /// Current circuit breaker state.
    pub circuit_state: CircuitState,
}

impl HealthStatus {
    /// Creates a healthy status.
    pub fn healthy() -> Self {
        Self {
            healthy: true,
            latency: None,
            last_success: Some(Utc::now()),
            last_error: None,
            circuit_state: CircuitState::Closed,
        }
    }

    /// Creates an unhealthy status with an error message.
    pub fn unhealthy(error: impl Into<String>) -> Self {
        Self {
            healthy: false,
            latency: None,
            last_success: None,
            last_error: Some(error.into()),
            circuit_state: CircuitState::Open,
        }
    }

    /// Sets the latency.
    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// Sets the circuit state.
    pub fn with_circuit_state(mut self, state: CircuitState) -> Self {
        self.circuit_state = state;
        self
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            healthy: false,
            latency: None,
            last_success: None,
            last_error: None,
            circuit_state: CircuitState::Closed,
        }
    }
}

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Circuit is closed, requests pass through normally.
    #[default]
    Closed,
    /// Circuit is open, requests fail fast.
    Open,
    /// Circuit is half-open, testing if the service recovered.
    HalfOpen,
}

impl CircuitState {
    /// Returns the numeric representation.
    pub fn as_u8(&self) -> u8 {
        match self {
            CircuitState::Closed => 0,
            CircuitState::Open => 1,
            CircuitState::HalfOpen => 2,
        }
    }
}

impl From<u8> for CircuitState {
    fn from(v: u8) -> Self {
        match v {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "Closed"),
            CircuitState::Open => write!(f, "Open"),
            CircuitState::HalfOpen => write!(f, "HalfOpen"),
        }
    }
}

// =============================================================================
// Driver Factory
// =============================================================================

/// Configuration for creating a driver instance.
///
/// This is a simplified config structure. The actual implementation
/// will use the full DeviceConfig from trap-config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverConfig {
    /// Unique device identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Protocol to use.
    pub protocol: Protocol,
    /// Protocol-specific configuration.
    pub protocol_config: serde_json::Value,
    /// Connection timeout.
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
    /// Number of retry attempts.
    #[serde(default = "default_retries")]
    pub retries: u32,
}

fn default_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_retries() -> u32 {
    3
}

/// A factory for creating protocol drivers.
///
/// Each protocol implementation should provide a factory that can
/// create driver instances from configuration.
pub trait DriverFactory: Send + Sync {
    /// Returns the protocol type this factory creates drivers for.
    fn protocol(&self) -> Protocol;

    /// Creates a new driver instance from the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `DriverError` if the configuration is invalid or the
    /// driver cannot be created.
    fn create(&self, config: &DriverConfig) -> Result<Box<dyn ProtocolDriver>, DriverError>;
}

// =============================================================================
// Driver Registry
// =============================================================================

/// A registry of driver factories.
///
/// The registry maps protocol types to their factories, enabling dynamic
/// driver creation based on configuration.
pub struct DriverRegistry {
    factories: HashMap<Protocol, Box<dyn DriverFactory>>,
}

impl DriverRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Registers a driver factory.
    ///
    /// If a factory for the same protocol already exists, it will be replaced.
    pub fn register(&mut self, factory: Box<dyn DriverFactory>) {
        let protocol = factory.protocol();
        self.factories.insert(protocol, factory);
        tracing::debug!(?protocol, "Registered driver factory");
    }

    /// Unregisters a driver factory.
    pub fn unregister(&mut self, protocol: Protocol) -> Option<Box<dyn DriverFactory>> {
        self.factories.remove(&protocol)
    }

    /// Creates a driver from the given configuration.
    ///
    /// # Errors
    ///
    /// - `DriverError::Protocol` - No factory registered for the protocol
    /// - Other errors from the factory
    pub fn create(&self, config: &DriverConfig) -> Result<Box<dyn ProtocolDriver>, DriverError> {
        let factory = self.factories.get(&config.protocol).ok_or_else(|| {
            DriverError::protocol(format!("No factory registered for {:?}", config.protocol))
        })?;

        factory.create(config)
    }

    /// Returns the list of supported protocols.
    pub fn supported_protocols(&self) -> Vec<Protocol> {
        self.factories.keys().copied().collect()
    }

    /// Returns `true` if a factory is registered for the given protocol.
    pub fn supports(&self, protocol: Protocol) -> bool {
        self.factories.contains_key(&protocol)
    }

    /// Returns the number of registered factories.
    pub fn len(&self) -> usize {
        self.factories.len()
    }

    /// Returns `true` if no factories are registered.
    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}

impl Default for DriverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DriverRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriverRegistry")
            .field("protocols", &self.supported_protocols())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A mock driver for testing.
    struct MockDriver {
        name: String,
        connected: AtomicBool,
    }

    impl MockDriver {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                connected: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl ProtocolDriver for MockDriver {
        fn name(&self) -> &str {
            &self.name
        }

        fn protocol(&self) -> Protocol {
            Protocol::Unknown
        }

        async fn connect(&mut self) -> Result<(), DriverError> {
            self.connected.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn disconnect(&mut self) -> Result<(), DriverError> {
            self.connected.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::SeqCst)
        }

        async fn read(&self, _address: &Address) -> Result<Value, DriverError> {
            if !self.is_connected() {
                return Err(DriverError::NotConnected);
            }
            Ok(Value::Float64(42.0))
        }

        async fn write(&self, _address: &Address, _value: Value) -> Result<(), DriverError> {
            if !self.is_connected() {
                return Err(DriverError::NotConnected);
            }
            Ok(())
        }

        async fn health_check(&self) -> HealthStatus {
            if self.is_connected() {
                HealthStatus::healthy()
            } else {
                HealthStatus::unhealthy("Not connected")
            }
        }
    }

    #[tokio::test]
    async fn test_mock_driver_lifecycle() {
        let mut driver = MockDriver::new("test-driver");

        assert!(!driver.is_connected());
        assert_eq!(driver.name(), "test-driver");

        driver.connect().await.unwrap();
        assert!(driver.is_connected());

        let health = driver.health_check().await;
        assert!(health.healthy);

        driver.disconnect().await.unwrap();
        assert!(!driver.is_connected());
    }

    #[tokio::test]
    async fn test_read_requires_connection() {
        use crate::address::GenericAddress;
        let driver = MockDriver::new("test");
        let address = Address::Generic(GenericAddress::new("test", "test-addr"));

        let result = driver.read(&address).await;
        assert!(matches!(result, Err(DriverError::NotConnected)));
    }

    #[test]
    fn test_circuit_state() {
        assert_eq!(CircuitState::Closed.as_u8(), 0);
        assert_eq!(CircuitState::Open.as_u8(), 1);
        assert_eq!(CircuitState::HalfOpen.as_u8(), 2);

        assert_eq!(CircuitState::from(0), CircuitState::Closed);
        assert_eq!(CircuitState::from(1), CircuitState::Open);
        assert_eq!(CircuitState::from(2), CircuitState::HalfOpen);
        assert_eq!(CircuitState::from(99), CircuitState::Closed);
    }

    #[test]
    fn test_health_status() {
        let healthy = HealthStatus::healthy();
        assert!(healthy.healthy);
        assert!(healthy.last_success.is_some());

        let unhealthy = HealthStatus::unhealthy("Connection refused");
        assert!(!unhealthy.healthy);
        assert_eq!(unhealthy.last_error, Some("Connection refused".to_string()));
    }

    #[test]
    fn test_driver_registry() {
        let registry = DriverRegistry::new();
        assert!(registry.is_empty());
        assert!(!registry.supports(Protocol::ModbusTcp));
        assert!(registry.supported_protocols().is_empty());
    }

    #[test]
    fn test_subscription_id() {
        let id = SubscriptionId::new(123);
        assert_eq!(id.0, 123);
        assert_eq!(format!("{}", id), "sub-123");
    }

    #[test]
    fn test_data_type_display() {
        assert_eq!(format!("{}", DataType::Float64), "float64");
        assert_eq!(format!("{}", DataType::Bool), "bool");
        assert_eq!(format!("{}", DataType::Unknown), "unknown");
    }
}
