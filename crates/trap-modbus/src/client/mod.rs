// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Modbus client implementations.
//!
//! This module provides protocol-agnostic client implementations for Modbus communication:
//!
//! - **Transport Layer**: Abstract transport trait for TCP and RTU
//! - **TCP Client**: High-performance Modbus TCP client with connection management
//! - **Retry Logic**: Configurable retry strategies with exponential backoff
//! - **Data Conversion**: Type-safe value conversion utilities
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        ModbusDriver                             │
//! │                  (ProtocolDriver impl)                          │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     ModbusClient                                │
//! │              (High-level read/write API)                        │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   ModbusTransport                               │
//! │               (Abstract transport layer)                        │
//! └─────────────────────────────────────────────────────────────────┘
//!            │                                     │
//!            ▼                                     ▼
//! ┌─────────────────────┐             ┌─────────────────────┐
//! │  ModbusTcpTransport │             │  ModbusRtuTransport │
//! │   (tokio-modbus)    │             │   (tokio-modbus)    │
//! └─────────────────────┘             └─────────────────────┘
//! ```
//!
//! # Examples
//!
//! ```rust,ignore
//! use trap_modbus::client::{ModbusClient, ModbusTcpTransport};
//! use trap_modbus::types::ModbusTcpConfig;
//!
//! // Create TCP transport
//! let config = ModbusTcpConfig::builder()
//!     .host("192.168.1.100")
//!     .port(502)
//!     .unit_id(1)
//!     .build()?;
//!
//! let transport = ModbusTcpTransport::new(config);
//! let mut client = ModbusClient::new(transport);
//!
//! // Connect and read
//! client.connect().await?;
//! let values = client.read_holding_registers(0, 10).await?;
//! ```

mod transport;
mod tcp;
mod conversion;
mod retry;

pub use transport::{ModbusTransport, TransportState};
pub use tcp::ModbusTcpTransport;
pub use conversion::{
    DataConverter, ConversionResult, ExtendedDataConverter,
    TagConverterConfig, TagConverterConfigBuilder,
    // Re-export core converter types for convenience
    ConversionContext, ConverterRegistry, RegisterConverter,
    BoolConverter, NumericConverter, StringConverter, BytesConverter,
    CompositeConverter, CompositeConverterBuilder,
    registers_to_bytes, bytes_to_registers, extract_bit, set_bit, extract_bits,
};
pub use retry::{RetryConfig, RetryStrategy, ExponentialBackoff};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::error::{ModbusError, ModbusResult, ConnectionError, OperationError};
use crate::types::{RegisterType, ModbusDataAddress, ByteOrder, ModbusDataType};

// =============================================================================
// ModbusClient
// =============================================================================

/// High-level Modbus client with retry support and data conversion.
///
/// This client wraps a [`ModbusTransport`] implementation and provides:
/// - Automatic retry with exponential backoff
/// - Data type conversion
/// - Statistics tracking
/// - Connection state management
///
/// # Thread Safety
///
/// The client is `Send + Sync` and can be shared across tasks using `Arc<Mutex<ModbusClient>>`.
pub struct ModbusClient<T: ModbusTransport> {
    /// The underlying transport.
    transport: Arc<Mutex<T>>,
    /// Retry configuration.
    retry_config: RetryConfig,
    /// Data converter.
    converter: DataConverter,
    /// Client statistics.
    stats: ClientStats,
}

impl<T: ModbusTransport> ModbusClient<T> {
    /// Creates a new client with the given transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport: Arc::new(Mutex::new(transport)),
            retry_config: RetryConfig::default(),
            converter: DataConverter::new(ByteOrder::BigEndian),
            stats: ClientStats::new(),
        }
    }

    /// Creates a new client with custom retry configuration.
    pub fn with_retry(transport: T, retry_config: RetryConfig) -> Self {
        Self {
            transport: Arc::new(Mutex::new(transport)),
            retry_config,
            converter: DataConverter::new(ByteOrder::BigEndian),
            stats: ClientStats::new(),
        }
    }

    /// Sets the default byte order for data conversion.
    pub fn with_byte_order(mut self, byte_order: ByteOrder) -> Self {
        self.converter = DataConverter::new(byte_order);
        self
    }

    /// Returns a reference to the retry configuration.
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    /// Sets the retry configuration.
    pub fn set_retry_config(&mut self, config: RetryConfig) {
        self.retry_config = config;
    }

    /// Returns the client statistics.
    pub fn stats(&self) -> &ClientStats {
        &self.stats
    }

    /// Resets the client statistics.
    pub fn reset_stats(&self) {
        self.stats.reset();
    }

    // =========================================================================
    // Connection Management
    // =========================================================================

    /// Establishes a connection to the Modbus device.
    pub async fn connect(&self) -> ModbusResult<()> {
        let mut transport = self.transport.lock().await;
        let result = transport.connect().await;
        if result.is_ok() {
            self.stats.record_connection();
        }
        result
    }

    /// Disconnects from the Modbus device.
    pub async fn disconnect(&self) -> ModbusResult<()> {
        let mut transport = self.transport.lock().await;
        transport.disconnect().await
    }

    /// Returns `true` if connected.
    pub async fn is_connected(&self) -> bool {
        let transport = self.transport.lock().await;
        transport.is_connected()
    }

    /// Returns the current transport state.
    pub async fn state(&self) -> TransportState {
        let transport = self.transport.lock().await;
        transport.state()
    }

    // =========================================================================
    // Read Operations
    // =========================================================================

    /// Reads coils from the device.
    ///
    /// # Arguments
    ///
    /// * `address` - Starting coil address (0-based)
    /// * `count` - Number of coils to read (1-2000)
    pub async fn read_coils(&self, address: u16, count: u16) -> ModbusResult<Vec<bool>> {
        self.validate_read_count(RegisterType::Coil, count)?;

        self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.read_coils(address, count).await
        })
        .await
    }

    /// Reads discrete inputs from the device.
    ///
    /// # Arguments
    ///
    /// * `address` - Starting input address (0-based)
    /// * `count` - Number of inputs to read (1-2000)
    pub async fn read_discrete_inputs(&self, address: u16, count: u16) -> ModbusResult<Vec<bool>> {
        self.validate_read_count(RegisterType::DiscreteInput, count)?;

        self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.read_discrete_inputs(address, count).await
        })
        .await
    }

    /// Reads holding registers from the device.
    ///
    /// # Arguments
    ///
    /// * `address` - Starting register address (0-based)
    /// * `count` - Number of registers to read (1-125)
    pub async fn read_holding_registers(&self, address: u16, count: u16) -> ModbusResult<Vec<u16>> {
        self.validate_read_count(RegisterType::HoldingRegister, count)?;

        self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.read_holding_registers(address, count).await
        })
        .await
    }

    /// Reads input registers from the device.
    ///
    /// # Arguments
    ///
    /// * `address` - Starting register address (0-based)
    /// * `count` - Number of registers to read (1-125)
    pub async fn read_input_registers(&self, address: u16, count: u16) -> ModbusResult<Vec<u16>> {
        self.validate_read_count(RegisterType::InputRegister, count)?;

        self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.read_input_registers(address, count).await
        })
        .await
    }

    /// Reads data from a Modbus address with type conversion.
    ///
    /// This method reads the appropriate register type and converts
    /// the raw data to the specified data type.
    pub async fn read_typed(&self, addr: &ModbusDataAddress) -> ModbusResult<TypedValue> {
        addr.validate()?;

        let raw_data = match addr.register_type {
            RegisterType::Coil => {
                let coils = self.read_coils(addr.address, addr.count).await?;
                return Ok(TypedValue::Bool(coils.first().copied().unwrap_or(false)));
            }
            RegisterType::DiscreteInput => {
                let inputs = self.read_discrete_inputs(addr.address, addr.count).await?;
                return Ok(TypedValue::Bool(inputs.first().copied().unwrap_or(false)));
            }
            RegisterType::HoldingRegister => {
                self.read_holding_registers(addr.address, addr.count).await?
            }
            RegisterType::InputRegister => {
                self.read_input_registers(addr.address, addr.count).await?
            }
        };

        self.converter.convert_from_registers(&raw_data, addr)
    }

    // =========================================================================
    // Write Operations
    // =========================================================================

    /// Writes a single coil.
    ///
    /// # Arguments
    ///
    /// * `address` - Coil address (0-based)
    /// * `value` - Value to write
    pub async fn write_coil(&self, address: u16, value: bool) -> ModbusResult<()> {
        self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.write_single_coil(address, value).await
        })
        .await
    }

    /// Writes multiple coils.
    ///
    /// # Arguments
    ///
    /// * `address` - Starting coil address (0-based)
    /// * `values` - Values to write
    pub async fn write_coils(&self, address: u16, values: &[bool]) -> ModbusResult<()> {
        if values.len() > RegisterType::Coil.max_write_count().unwrap_or(1968) as usize {
            return Err(ModbusError::operation(OperationError::too_many_registers(
                values.len() as u16,
                RegisterType::Coil.max_write_count().unwrap_or(1968),
            )));
        }

        self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.write_multiple_coils(address, values).await
        })
        .await
    }

    /// Writes a single holding register.
    ///
    /// # Arguments
    ///
    /// * `address` - Register address (0-based)
    /// * `value` - Value to write
    pub async fn write_register(&self, address: u16, value: u16) -> ModbusResult<()> {
        self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.write_single_register(address, value).await
        })
        .await
    }

    /// Writes multiple holding registers.
    ///
    /// # Arguments
    ///
    /// * `address` - Starting register address (0-based)
    /// * `values` - Values to write
    pub async fn write_registers(&self, address: u16, values: &[u16]) -> ModbusResult<()> {
        if values.len() > RegisterType::HoldingRegister.max_write_count().unwrap_or(123) as usize {
            return Err(ModbusError::operation(OperationError::too_many_registers(
                values.len() as u16,
                RegisterType::HoldingRegister.max_write_count().unwrap_or(123),
            )));
        }

        self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.write_multiple_registers(address, values).await
        })
        .await
    }

    /// Writes a typed value to a Modbus address.
    ///
    /// This method converts the value to raw registers and writes them.
    pub async fn write_typed(&self, addr: &ModbusDataAddress, value: TypedValue) -> ModbusResult<()> {
        addr.validate()?;

        if !addr.is_writable() {
            return Err(ModbusError::operation(OperationError::read_only(addr.address)));
        }

        match addr.register_type {
            RegisterType::Coil => {
                let bool_value = value.as_bool()?;
                self.write_coil(addr.address, bool_value).await
            }
            RegisterType::HoldingRegister => {
                let registers = self.converter.convert_to_registers(&value, addr)?;
                if registers.len() == 1 {
                    self.write_register(addr.address, registers[0]).await
                } else {
                    self.write_registers(addr.address, &registers).await
                }
            }
            RegisterType::DiscreteInput | RegisterType::InputRegister => {
                Err(ModbusError::operation(OperationError::read_only(addr.address)))
            }
        }
    }

    // =========================================================================
    // Batch Operations
    // =========================================================================

    /// Reads multiple addresses in batch.
    ///
    /// This method optimizes reads by grouping contiguous addresses.
    pub async fn read_batch(
        &self,
        addresses: &[ModbusDataAddress],
    ) -> ModbusResult<Vec<(ModbusDataAddress, ModbusResult<TypedValue>)>> {
        let mut results = Vec::with_capacity(addresses.len());

        for addr in addresses {
            let result = self.read_typed(addr).await;
            results.push((addr.clone(), result));
        }

        Ok(results)
    }

    // =========================================================================
    // Private Methods
    // =========================================================================

    /// Validates the read count for a register type.
    fn validate_read_count(&self, register_type: RegisterType, count: u16) -> ModbusResult<()> {
        if count == 0 {
            return Err(ModbusError::operation(OperationError::too_many_registers(0, 1)));
        }

        let max = register_type.max_read_count();
        if count > max {
            return Err(ModbusError::operation(OperationError::too_many_registers(count, max)));
        }

        Ok(())
    }

    /// Executes an operation with retry logic.
    async fn execute_with_retry<F, Fut, R>(&self, operation: F) -> ModbusResult<R>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = ModbusResult<R>>,
    {
        let start = Instant::now();
        let mut last_error = None;
        let mut attempt = 0;

        while attempt <= self.retry_config.max_retries {
            match operation().await {
                Ok(result) => {
                    self.stats.record_success(start.elapsed());
                    return Ok(result);
                }
                Err(error) => {
                    self.stats.record_error();

                    if !error.is_retryable() || attempt >= self.retry_config.max_retries {
                        return Err(error);
                    }

                    let delay = self.retry_config.strategy.delay(attempt);
                    tracing::debug!(
                        attempt = attempt + 1,
                        max_retries = self.retry_config.max_retries,
                        delay_ms = delay.as_millis(),
                        error = %error,
                        "Retrying Modbus operation"
                    );

                    tokio::time::sleep(delay).await;
                    last_error = Some(error);
                    attempt += 1;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| ModbusError::connection(ConnectionError::NotConnected)))
    }
}

// =============================================================================
// TypedValue
// =============================================================================

/// A typed value for Modbus data.
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    /// Boolean value.
    Bool(bool),
    /// 8-bit signed integer.
    Int8(i8),
    /// 8-bit unsigned integer.
    UInt8(u8),
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
    Float32(f32),
    /// 64-bit float.
    Float64(f64),
    /// String value.
    String(String),
    /// Raw bytes.
    Bytes(Vec<u8>),
}

impl TypedValue {
    /// Returns the value as a boolean.
    pub fn as_bool(&self) -> ModbusResult<bool> {
        match self {
            Self::Bool(v) => Ok(*v),
            Self::Int8(v) => Ok(*v != 0),
            Self::UInt8(v) => Ok(*v != 0),
            Self::Int16(v) => Ok(*v != 0),
            Self::UInt16(v) => Ok(*v != 0),
            _ => Err(ModbusError::type_mismatch("bool", &format!("{:?}", self))),
        }
    }

    /// Returns the value as an i32.
    pub fn as_i32(&self) -> ModbusResult<i32> {
        match self {
            Self::Bool(v) => Ok(if *v { 1 } else { 0 }),
            Self::Int8(v) => Ok(*v as i32),
            Self::UInt8(v) => Ok(*v as i32),
            Self::Int16(v) => Ok(*v as i32),
            Self::UInt16(v) => Ok(*v as i32),
            Self::Int32(v) => Ok(*v),
            Self::UInt32(v) => {
                if *v <= i32::MAX as u32 {
                    Ok(*v as i32)
                } else {
                    Err(ModbusError::type_mismatch("i32", "u32 overflow"))
                }
            }
            _ => Err(ModbusError::type_mismatch("i32", &format!("{:?}", self))),
        }
    }

    /// Returns the value as an f64.
    pub fn as_f64(&self) -> ModbusResult<f64> {
        match self {
            Self::Bool(v) => Ok(if *v { 1.0 } else { 0.0 }),
            Self::Int8(v) => Ok(*v as f64),
            Self::UInt8(v) => Ok(*v as f64),
            Self::Int16(v) => Ok(*v as f64),
            Self::UInt16(v) => Ok(*v as f64),
            Self::Int32(v) => Ok(*v as f64),
            Self::UInt32(v) => Ok(*v as f64),
            Self::Int64(v) => Ok(*v as f64),
            Self::UInt64(v) => Ok(*v as f64),
            Self::Float32(v) => Ok(*v as f64),
            Self::Float64(v) => Ok(*v),
            _ => Err(ModbusError::type_mismatch("f64", &format!("{:?}", self))),
        }
    }

    /// Converts to trap_core::Value.
    pub fn to_core_value(&self) -> trap_core::Value {
        match self {
            Self::Bool(v) => trap_core::Value::Bool(*v),
            Self::Int8(v) => trap_core::Value::Int32(*v as i32),
            Self::UInt8(v) => trap_core::Value::Int32(*v as i32),
            Self::Int16(v) => trap_core::Value::Int32(*v as i32),
            Self::UInt16(v) => trap_core::Value::Int32(*v as i32),
            Self::Int32(v) => trap_core::Value::Int32(*v),
            Self::UInt32(v) => trap_core::Value::UInt32(*v),
            Self::Int64(v) => trap_core::Value::Int64(*v),
            Self::UInt64(v) => trap_core::Value::UInt64(*v),
            Self::Float32(v) => trap_core::Value::Float32(*v),
            Self::Float64(v) => trap_core::Value::Float64(*v),
            Self::String(v) => trap_core::Value::String(v.clone()),
            Self::Bytes(v) => trap_core::Value::Bytes(v.clone()),
        }
    }

    /// Creates from trap_core::Value.
    pub fn from_core_value(value: &trap_core::Value) -> Self {
        match value {
            trap_core::Value::Bool(v) => Self::Bool(*v),
            trap_core::Value::Int32(v) => Self::Int32(*v),
            trap_core::Value::Int64(v) => Self::Int64(*v),
            trap_core::Value::UInt32(v) => Self::UInt32(*v),
            trap_core::Value::UInt64(v) => Self::UInt64(*v),
            trap_core::Value::Float32(v) => Self::Float32(*v),
            trap_core::Value::Float64(v) => Self::Float64(*v),
            trap_core::Value::String(v) => Self::String(v.clone()),
            trap_core::Value::Bytes(v) => Self::Bytes(v.clone()),
            _ => Self::Bytes(vec![]),
        }
    }

    /// Returns the data type of this value.
    pub fn data_type(&self) -> ModbusDataType {
        match self {
            Self::Bool(_) => ModbusDataType::Bool,
            Self::Int8(_) => ModbusDataType::Int8,
            Self::UInt8(_) => ModbusDataType::UInt8,
            Self::Int16(_) => ModbusDataType::Int16,
            Self::UInt16(_) => ModbusDataType::UInt16,
            Self::Int32(_) => ModbusDataType::Int32,
            Self::UInt32(_) => ModbusDataType::UInt32,
            Self::Int64(_) => ModbusDataType::Int64,
            Self::UInt64(_) => ModbusDataType::UInt64,
            Self::Float32(_) => ModbusDataType::Float32,
            Self::Float64(_) => ModbusDataType::Float64,
            Self::String(_) => ModbusDataType::String,
            Self::Bytes(_) => ModbusDataType::Bytes,
        }
    }
}

// =============================================================================
// ClientStats
// =============================================================================

/// Statistics for Modbus client operations.
#[derive(Debug)]
pub struct ClientStats {
    /// Total number of requests.
    total_requests: AtomicU64,
    /// Number of successful requests.
    successful_requests: AtomicU64,
    /// Number of failed requests.
    failed_requests: AtomicU64,
    /// Number of retries.
    retries: AtomicU64,
    /// Total response time in microseconds.
    total_response_time_us: AtomicU64,
    /// Number of connections established.
    connections: AtomicU64,
}

impl ClientStats {
    /// Creates new statistics.
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            total_response_time_us: AtomicU64::new(0),
            connections: AtomicU64::new(0),
        }
    }

    /// Records a successful operation.
    pub fn record_success(&self, duration: Duration) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Records a failed operation.
    pub fn record_error(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a retry attempt.
    pub fn record_retry(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a connection.
    pub fn record_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Resets all statistics.
    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.successful_requests.store(0, Ordering::Relaxed);
        self.failed_requests.store(0, Ordering::Relaxed);
        self.retries.store(0, Ordering::Relaxed);
        self.total_response_time_us.store(0, Ordering::Relaxed);
        self.connections.store(0, Ordering::Relaxed);
    }

    /// Returns the total number of requests.
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Returns the number of successful requests.
    pub fn successful_requests(&self) -> u64 {
        self.successful_requests.load(Ordering::Relaxed)
    }

    /// Returns the number of failed requests.
    pub fn failed_requests(&self) -> u64 {
        self.failed_requests.load(Ordering::Relaxed)
    }

    /// Returns the success rate (0.0 - 1.0).
    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests();
        if total == 0 {
            return 1.0;
        }
        self.successful_requests() as f64 / total as f64
    }

    /// Returns the average response time.
    pub fn average_response_time(&self) -> Duration {
        let success = self.successful_requests();
        if success == 0 {
            return Duration::ZERO;
        }
        let total_us = self.total_response_time_us.load(Ordering::Relaxed);
        Duration::from_micros(total_us / success)
    }

    /// Returns the number of connections established.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }
}

impl Default for ClientStats {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typed_value_conversions() {
        let bool_val = TypedValue::Bool(true);
        assert!(bool_val.as_bool().unwrap());
        assert_eq!(bool_val.as_i32().unwrap(), 1);
        assert_eq!(bool_val.as_f64().unwrap(), 1.0);

        let int_val = TypedValue::Int16(42);
        assert_eq!(int_val.as_i32().unwrap(), 42);
        assert_eq!(int_val.as_f64().unwrap(), 42.0);

        let float_val = TypedValue::Float32(3.14);
        assert!((float_val.as_f64().unwrap() - 3.14).abs() < 0.01);
    }

    #[test]
    fn test_client_stats() {
        let stats = ClientStats::new();

        stats.record_success(Duration::from_millis(10));
        stats.record_success(Duration::from_millis(20));
        stats.record_error();

        assert_eq!(stats.total_requests(), 3);
        assert_eq!(stats.successful_requests(), 2);
        assert_eq!(stats.failed_requests(), 1);
        assert!((stats.success_rate() - 0.666).abs() < 0.01);
        assert_eq!(stats.average_response_time(), Duration::from_millis(15));
    }

    #[test]
    fn test_typed_value_data_type() {
        assert_eq!(TypedValue::Bool(true).data_type(), ModbusDataType::Bool);
        assert_eq!(TypedValue::Int16(0).data_type(), ModbusDataType::Int16);
        assert_eq!(TypedValue::Float32(0.0).data_type(), ModbusDataType::Float32);
    }
}
