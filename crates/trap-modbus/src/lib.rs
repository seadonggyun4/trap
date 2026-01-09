// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # trap-modbus
//!
//! Modbus TCP/RTU protocol driver for TRAP industrial IoT gateway.
//!
//! This crate provides a comprehensive Modbus implementation with:
//!
//! - **Modbus TCP**: Ethernet-based Modbus communication using `tokio-modbus`
//! - **Modbus RTU**: Serial port-based Modbus communication (planned)
//! - **All register types**: Coil, Discrete Input, Holding Register, Input Register
//! - **Data type conversion**: Raw registers to meaningful values with byte order support
//! - **Auto-reconnection**: Automatic recovery from connection failures
//! - **Retry logic**: Configurable exponential backoff with jitter
//! - **Protocol driver**: Implements `trap_core::ProtocolDriver` for gateway integration
//!
//! ## Architecture
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
//! │   (tokio-modbus)    │             │      (planned)      │
//! └─────────────────────┘             └─────────────────────┘
//! ```
//!
//! ## Features
//!
//! - `tcp` (default): Enable Modbus TCP support
//! - `rtu` (default): Enable Modbus RTU support
//!
//! ## Quick Start
//!
//! ### Using the Client API
//!
//! ```rust,ignore
//! use trap_modbus::client::{ModbusClient, ModbusTcpTransport};
//! use trap_modbus::types::{ModbusTcpConfig, ModbusDataAddress, ModbusDataType};
//!
//! // Create TCP transport
//! let config = ModbusTcpConfig::builder()
//!     .host("192.168.1.100")
//!     .port(502)
//!     .unit_id(1)
//!     .build()?;
//!
//! let transport = ModbusTcpTransport::new(config);
//! let client = ModbusClient::new(transport);
//!
//! // Connect
//! client.connect().await?;
//!
//! // Read holding registers
//! let values = client.read_holding_registers(0, 10).await?;
//!
//! // Read with type conversion
//! let addr = ModbusDataAddress::holding_register(100)
//!     .with_count(2)
//!     .with_data_type(ModbusDataType::Float32);
//! let typed_value = client.read_typed(&addr).await?;
//! ```
//!
//! ### Using the Protocol Driver
//!
//! ```rust,ignore
//! use trap_modbus::driver::ModbusDriver;
//! use trap_modbus::types::ModbusTcpConfig;
//! use trap_core::driver::ProtocolDriver;
//!
//! let config = ModbusTcpConfig::builder()
//!     .host("192.168.1.100")
//!     .port(502)
//!     .build()?;
//!
//! let mut driver = ModbusDriver::tcp(config, "plc-01".to_string());
//! driver.connect().await?;
//!
//! // Read using trap_core::Address
//! let address = trap_core::Address::Generic(
//!     trap_core::address::GenericAddress::new("modbus", "HR:100:2:float32")
//! );
//! let value = driver.read(&address).await?;
//! ```
//!
//! ### Error Handling
//!
//! ```rust,ignore
//! use trap_modbus::error::{ModbusError, ModbusResult};
//!
//! fn handle_error(result: ModbusResult<()>) {
//!     if let Err(error) = result {
//!         if error.is_retryable() {
//!             println!("Will retry after {:?}", error.suggested_retry_delay());
//!         }
//!         for hint in error.recovery_hints() {
//!             println!("Hint: {}", hint);
//!         }
//!     }
//! }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]

// =============================================================================
// Modules
// =============================================================================

pub mod client;
pub mod driver;
pub mod error;
pub mod types;

// =============================================================================
// Re-exports - Error Module
// =============================================================================

pub use error::{
    // Main error type
    ModbusError,
    ModbusResult,
    // Error categories
    ConfigurationError,
    ConnectionError,
    ConversionError,
    OperationError,
    ProtocolError,
    TimeoutError,
    // Error metadata
    ErrorCode,
    ErrorSeverity,
    // Extension traits
    ModbusErrorContext,
};

// =============================================================================
// Re-exports - Types Module
// =============================================================================

pub use types::{
    // Register types
    ByteOrder,
    ModbusDataType,
    RegisterType,
    // Address
    ModbusDataAddress,
    // Configuration
    ModbusConfig,
    ModbusRtuConfig,
    ModbusRtuConfigBuilder,
    ModbusTcpConfig,
    ModbusTcpConfigBuilder,
    // Serial port settings
    DataBits,
    Parity,
    StopBits,
    // Tag mapping
    TagMapping,
};

// =============================================================================
// Re-exports - Client Module
// =============================================================================

pub use client::{
    // Client
    ModbusClient,
    ClientStats,
    TypedValue,
    // Transport
    ModbusTransport,
    TransportState,
    ModbusTcpTransport,
    // Conversion
    DataConverter,
    ConversionResult,
    // Retry
    RetryConfig,
    RetryStrategy,
    ExponentialBackoff,
};

// =============================================================================
// Re-exports - Driver Module
// =============================================================================

pub use driver::{
    ModbusDriver,
    ModbusDriverFactory,
};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name.
pub const NAME: &str = env!("CARGO_PKG_NAME");
