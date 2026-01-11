// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Modbus protocol driver implementation.
//!
//! This module provides the [`ModbusDriver`] which implements the
//! [`ProtocolDriver`] trait from `trap-core`, enabling seamless integration
//! with the TRAP gateway system.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::{Mutex, RwLock};

use trap_core::driver::{
    AddressInfo, CircuitState, DataType, DriverConfig, DriverFactory, HealthStatus,
    ProtocolDriver, Subscription, SubscriptionId,
};
use trap_core::error::DriverError;
use trap_core::types::{Protocol, Value};
use trap_core::Address;

use crate::client::{
    ModbusClient, ModbusRtuTransport, ModbusTcpTransport, RetryConfig, TransportState, TypedValue,
};
use crate::error::ModbusError;
use crate::types::{ModbusConfig, ModbusDataAddress, ModbusRtuConfig, ModbusTcpConfig, TagMapping};

// =============================================================================
// ModbusDriver
// =============================================================================

/// Modbus protocol driver implementing `trap_core::ProtocolDriver`.
///
/// This driver provides:
/// - Full Modbus TCP support via `tokio-modbus`
/// - Configurable retry and timeout behavior
/// - Health monitoring with circuit breaker pattern
/// - Tag-based addressing for easy configuration
///
/// # Example
///
/// ```rust,ignore
/// use trap_modbus::driver::ModbusDriver;
/// use trap_modbus::types::ModbusTcpConfig;
///
/// let config = ModbusTcpConfig::builder()
///     .host("192.168.1.100")
///     .port(502)
///     .unit_id(1)
///     .build()?;
///
/// let mut driver = ModbusDriver::tcp(config, "plc-01".to_string());
/// driver.connect().await?;
///
/// let value = driver.read(&address).await?;
/// ```
pub struct ModbusDriver {
    /// Driver name/identifier.
    name: String,
    /// Modbus configuration.
    config: ModbusConfig,
    /// Tag mappings.
    tag_mappings: Arc<RwLock<HashMap<String, TagMapping>>>,
    /// The underlying client.
    client: Arc<Mutex<Option<ModbusClientHandle>>>,
    /// Health status.
    health: Arc<RwLock<HealthStatus>>,
    /// Retry configuration.
    retry_config: RetryConfig,
}

/// Handle to the underlying Modbus client.
enum ModbusClientHandle {
    /// TCP client.
    Tcp(ModbusClient<ModbusTcpTransport>),
    /// RTU client.
    Rtu(ModbusClient<ModbusRtuTransport>),
}

impl ModbusClientHandle {
    async fn connect(&self) -> Result<(), ModbusError> {
        match self {
            Self::Tcp(client) => client.connect().await,
            Self::Rtu(client) => client.connect().await,
        }
    }

    async fn disconnect(&self) -> Result<(), ModbusError> {
        match self {
            Self::Tcp(client) => client.disconnect().await,
            Self::Rtu(client) => client.disconnect().await,
        }
    }

    async fn is_connected(&self) -> bool {
        match self {
            Self::Tcp(client) => client.is_connected().await,
            Self::Rtu(client) => client.is_connected().await,
        }
    }

    async fn state(&self) -> TransportState {
        match self {
            Self::Tcp(client) => client.state().await,
            Self::Rtu(client) => client.state().await,
        }
    }

    async fn read_typed(&self, addr: &ModbusDataAddress) -> Result<TypedValue, ModbusError> {
        match self {
            Self::Tcp(client) => client.read_typed(addr).await,
            Self::Rtu(client) => client.read_typed(addr).await,
        }
    }

    async fn write_typed(
        &self,
        addr: &ModbusDataAddress,
        value: TypedValue,
    ) -> Result<(), ModbusError> {
        match self {
            Self::Tcp(client) => client.write_typed(addr, value).await,
            Self::Rtu(client) => client.write_typed(addr, value).await,
        }
    }
}

impl ModbusDriver {
    /// Creates a new TCP Modbus driver.
    pub fn tcp(config: ModbusTcpConfig, name: String) -> Self {
        Self {
            name,
            config: ModbusConfig::Tcp(config),
            tag_mappings: Arc::new(RwLock::new(HashMap::new())),
            client: Arc::new(Mutex::new(None)),
            health: Arc::new(RwLock::new(HealthStatus::default())),
            retry_config: RetryConfig::default(),
        }
    }

    /// Creates a new RTU Modbus driver.
    pub fn rtu(config: ModbusRtuConfig, name: String) -> Self {
        Self {
            name,
            config: ModbusConfig::Rtu(config),
            tag_mappings: Arc::new(RwLock::new(HashMap::new())),
            client: Arc::new(Mutex::new(None)),
            health: Arc::new(RwLock::new(HealthStatus::default())),
            retry_config: RetryConfig::default(),
        }
    }

    /// Creates a driver from unified config.
    pub fn from_config(config: ModbusConfig, name: String) -> Self {
        Self {
            name,
            config,
            tag_mappings: Arc::new(RwLock::new(HashMap::new())),
            client: Arc::new(Mutex::new(None)),
            health: Arc::new(RwLock::new(HealthStatus::default())),
            retry_config: RetryConfig::default(),
        }
    }

    /// Sets the retry configuration.
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Adds a tag mapping.
    pub async fn add_tag_mapping(&self, mapping: TagMapping) {
        let mut mappings = self.tag_mappings.write().await;
        mappings.insert(mapping.tag_id.clone(), mapping);
    }

    /// Adds multiple tag mappings.
    pub async fn add_tag_mappings(&self, mappings: impl IntoIterator<Item = TagMapping>) {
        let mut tag_mappings = self.tag_mappings.write().await;
        for mapping in mappings {
            tag_mappings.insert(mapping.tag_id.clone(), mapping);
        }
    }

    /// Removes a tag mapping.
    pub async fn remove_tag_mapping(&self, tag_id: &str) -> Option<TagMapping> {
        let mut mappings = self.tag_mappings.write().await;
        mappings.remove(tag_id)
    }

    /// Gets a tag mapping by ID.
    pub async fn get_tag_mapping(&self, tag_id: &str) -> Option<TagMapping> {
        let mappings = self.tag_mappings.read().await;
        mappings.get(tag_id).cloned()
    }

    /// Returns all tag mappings.
    pub async fn tag_mappings(&self) -> Vec<TagMapping> {
        let mappings = self.tag_mappings.read().await;
        mappings.values().cloned().collect()
    }

    /// Returns the configuration.
    pub fn config(&self) -> &ModbusConfig {
        &self.config
    }

    /// Converts a trap_core::Address to ModbusDataAddress.
    fn address_to_modbus(&self, address: &Address) -> Result<ModbusDataAddress, DriverError> {
        match address {
            Address::Modbus(modbus_addr) => {
                use trap_core::address::ModbusRegisterType;

                let register_type = match modbus_addr.register_type {
                    ModbusRegisterType::Coil => crate::types::RegisterType::Coil,
                    ModbusRegisterType::DiscreteInput => crate::types::RegisterType::DiscreteInput,
                    ModbusRegisterType::HoldingRegister => {
                        crate::types::RegisterType::HoldingRegister
                    }
                    ModbusRegisterType::InputRegister => crate::types::RegisterType::InputRegister,
                };

                Ok(ModbusDataAddress {
                    register_type,
                    address: modbus_addr.address,
                    count: modbus_addr.count,
                    data_type: crate::types::ModbusDataType::UInt16,
                    byte_order: crate::types::ByteOrder::BigEndian,
                    bit_position: None,
                    scale: None,
                    offset: None,
                })
            }
            Address::Generic(generic) => {
                // Try to parse as Modbus notation
                let addr_str = &generic.address;
                addr_str
                    .parse::<ModbusDataAddress>()
                    .map_err(|e| DriverError::address_not_found(format!("{}: {}", addr_str, e)))
            }
            _ => Err(DriverError::protocol(format!(
                "Unsupported address type for Modbus: {:?}",
                address
            ))),
        }
    }

    /// Updates health status after a successful operation.
    async fn record_success(&self, latency: std::time::Duration) {
        let mut health = self.health.write().await;
        health.healthy = true;
        health.latency = Some(latency);
        health.last_success = Some(Utc::now());
        health.last_error = None;
        health.circuit_state = CircuitState::Closed;
    }

    /// Updates health status after a failed operation.
    async fn record_error(&self, error: &str) {
        let mut health = self.health.write().await;
        health.healthy = false;
        health.last_error = Some(error.to_string());

        // Simple circuit breaker logic
        if health.circuit_state == CircuitState::Closed {
            health.circuit_state = CircuitState::HalfOpen;
        } else {
            health.circuit_state = CircuitState::Open;
        }
    }
}

#[async_trait]
impl ProtocolDriver for ModbusDriver {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> Protocol {
        match &self.config {
            ModbusConfig::Tcp(_) => Protocol::ModbusTcp,
            ModbusConfig::Rtu(_) => Protocol::ModbusRtu,
        }
    }

    async fn connect(&mut self) -> Result<(), DriverError> {
        let mut client_guard = self.client.lock().await;

        // Create client based on config
        let client = match &self.config {
            ModbusConfig::Tcp(tcp_config) => {
                let transport = ModbusTcpTransport::new(tcp_config.clone());
                let modbus_client =
                    ModbusClient::with_retry(transport, self.retry_config.clone())
                        .with_byte_order(tcp_config.byte_order);
                ModbusClientHandle::Tcp(modbus_client)
            }
            ModbusConfig::Rtu(rtu_config) => {
                let transport = ModbusRtuTransport::new(rtu_config.clone());
                let modbus_client =
                    ModbusClient::with_retry(transport, self.retry_config.clone())
                        .with_byte_order(rtu_config.byte_order);
                ModbusClientHandle::Rtu(modbus_client)
            }
        };

        // Connect
        client.connect().await.map_err(|e| {
            let driver_error: DriverError = e.into();
            driver_error
        })?;

        *client_guard = Some(client);

        tracing::info!(
            driver = %self.name,
            protocol = ?self.protocol(),
            "Modbus driver connected"
        );

        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), DriverError> {
        let mut client_guard = self.client.lock().await;

        if let Some(client) = client_guard.as_ref() {
            client.disconnect().await.map_err(|e| {
                let driver_error: DriverError = e.into();
                driver_error
            })?;
        }

        *client_guard = None;

        tracing::info!(driver = %self.name, "Modbus driver disconnected");

        Ok(())
    }

    fn is_connected(&self) -> bool {
        // This is a synchronous check, so we can't await the mutex
        // We'll rely on the health status instead
        if let Ok(health) = self.health.try_read() {
            health.healthy
        } else {
            false
        }
    }

    async fn read(&self, address: &Address) -> Result<Value, DriverError> {
        let start = Instant::now();

        let client_guard = self.client.lock().await;
        let client = client_guard
            .as_ref()
            .ok_or(DriverError::NotConnected)?;

        let modbus_addr = self.address_to_modbus(address)?;

        let typed_value = client.read_typed(&modbus_addr).await.map_err(|e| {
            let error_str = e.to_string();
            // Record error asynchronously in background
            let health = self.health.clone();
            tokio::spawn(async move {
                let mut h = health.write().await;
                h.healthy = false;
                h.last_error = Some(error_str);
            });
            let driver_error: DriverError = e.into();
            driver_error
        })?;

        self.record_success(start.elapsed()).await;

        Ok(typed_value.to_core_value())
    }

    async fn write(&self, address: &Address, value: Value) -> Result<(), DriverError> {
        let start = Instant::now();

        let client_guard = self.client.lock().await;
        let client = client_guard
            .as_ref()
            .ok_or(DriverError::NotConnected)?;

        let modbus_addr = self.address_to_modbus(address)?;
        let typed_value = TypedValue::from_core_value(&value);

        client
            .write_typed(&modbus_addr, typed_value)
            .await
            .map_err(|e| {
                let error_str = e.to_string();
                let health = self.health.clone();
                tokio::spawn(async move {
                    let mut h = health.write().await;
                    h.healthy = false;
                    h.last_error = Some(error_str);
                });
                let driver_error: DriverError = e.into();
                driver_error
            })?;

        self.record_success(start.elapsed()).await;

        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let health = self.health.read().await;
        health.clone()
    }

    fn supports_subscription(&self) -> bool {
        // Modbus doesn't support native subscriptions
        false
    }

    async fn subscribe(&self, _addresses: &[Address]) -> Result<Subscription, DriverError> {
        Err(DriverError::protocol(
            "Modbus does not support subscriptions - use polling instead",
        ))
    }

    async fn unsubscribe(&self, _subscription_id: &SubscriptionId) -> Result<(), DriverError> {
        Err(DriverError::protocol("Modbus does not support subscriptions"))
    }

    async fn browse(&self) -> Result<Vec<AddressInfo>, DriverError> {
        // Return configured tag mappings as browseable addresses
        let mappings = self.tag_mappings.read().await;

        let infos: Vec<AddressInfo> = mappings
            .values()
            .map(|m| AddressInfo {
                address: m.address.to_address(),
                name: m.effective_name().to_string(),
                description: m.description.clone(),
                data_type: match m.address.data_type {
                    crate::types::ModbusDataType::Bool => DataType::Bool,
                    crate::types::ModbusDataType::Int8 => DataType::Int8,
                    crate::types::ModbusDataType::UInt8 => DataType::UInt8,
                    crate::types::ModbusDataType::Int16 => DataType::Int16,
                    crate::types::ModbusDataType::UInt16 => DataType::UInt16,
                    crate::types::ModbusDataType::Int32 => DataType::Int32,
                    crate::types::ModbusDataType::UInt32 => DataType::UInt32,
                    crate::types::ModbusDataType::Int64 => DataType::Int64,
                    crate::types::ModbusDataType::UInt64 => DataType::UInt64,
                    crate::types::ModbusDataType::Float32 => DataType::Float32,
                    crate::types::ModbusDataType::Float64 => DataType::Float64,
                    crate::types::ModbusDataType::String => DataType::String,
                    crate::types::ModbusDataType::Bytes => DataType::Bytes,
                },
                writable: m.is_writable(),
                unit: m.unit.clone(),
            })
            .collect();

        Ok(infos)
    }
}

impl std::fmt::Debug for ModbusDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModbusDriver")
            .field("name", &self.name)
            .field("protocol", &self.protocol())
            .finish()
    }
}

// =============================================================================
// ModbusDriverFactory
// =============================================================================

/// Factory for creating Modbus drivers.
pub struct ModbusDriverFactory;

impl ModbusDriverFactory {
    /// Creates a new factory.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ModbusDriverFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverFactory for ModbusDriverFactory {
    fn protocol(&self) -> Protocol {
        Protocol::ModbusTcp
    }

    fn create(&self, config: &DriverConfig) -> Result<Box<dyn ProtocolDriver>, DriverError> {
        // Parse Modbus-specific config from JSON
        let modbus_config: ModbusTcpConfig =
            serde_json::from_value(config.protocol_config.clone()).map_err(|e| {
                DriverError::protocol(format!("Invalid Modbus configuration: {}", e))
            })?;

        let driver = ModbusDriver::tcp(modbus_config, config.name.clone());

        Ok(Box::new(driver))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_creation() {
        let config = ModbusTcpConfig::builder()
            .host("127.0.0.1")
            .port(502)
            .unit_id(1)
            .build()
            .unwrap();

        let driver = ModbusDriver::tcp(config, "test-driver".to_string());

        assert_eq!(driver.name(), "test-driver");
        assert_eq!(driver.protocol(), Protocol::ModbusTcp);
        assert!(!driver.supports_subscription());
    }

    #[tokio::test]
    async fn test_tag_mappings() {
        let config = ModbusTcpConfig::builder()
            .host("127.0.0.1")
            .port(502)
            .build()
            .unwrap();

        let driver = ModbusDriver::tcp(config, "test".to_string());

        let mapping = TagMapping::new(
            "temperature",
            ModbusDataAddress::holding_register(100)
                .with_data_type(crate::types::ModbusDataType::Float32)
                .with_count(2),
        )
        .with_name("Room Temperature")
        .with_unit("°C");

        driver.add_tag_mapping(mapping.clone()).await;

        let retrieved = driver.get_tag_mapping("temperature").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().tag_id, "temperature");

        let all = driver.tag_mappings().await;
        assert_eq!(all.len(), 1);

        driver.remove_tag_mapping("temperature").await;
        assert!(driver.get_tag_mapping("temperature").await.is_none());
    }

    #[test]
    fn test_factory() {
        let factory = ModbusDriverFactory::new();
        assert_eq!(factory.protocol(), Protocol::ModbusTcp);
    }

    #[test]
    fn test_address_conversion() {
        let config = ModbusTcpConfig::builder()
            .host("127.0.0.1")
            .port(502)
            .build()
            .unwrap();

        let driver = ModbusDriver::tcp(config, "test".to_string());

        // Test Modbus address
        let modbus_addr = trap_core::Address::Modbus(trap_core::address::ModbusAddress {
            register_type: trap_core::address::ModbusRegisterType::HoldingRegister,
            address: 100,
            count: 2,
            is_tcp: true,
            unit_id: 1,
        });

        let result = driver.address_to_modbus(&modbus_addr);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.address, 100);
        assert_eq!(addr.count, 2);

        // Test Generic address with parseable format
        let generic_addr = trap_core::Address::Generic(trap_core::address::GenericAddress {
            protocol: "modbus".to_string(),
            address: "HR:200".to_string(),
        });

        let result = driver.address_to_modbus(&generic_addr);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.address, 200);
    }
}
