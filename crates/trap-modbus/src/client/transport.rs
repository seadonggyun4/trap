// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Abstract transport layer for Modbus communication.
//!
//! This module defines the [`ModbusTransport`] trait that provides a
//! unified interface for both TCP and RTU transports.

use async_trait::async_trait;
use std::fmt;

use crate::error::ModbusResult;

// =============================================================================
// TransportState
// =============================================================================

/// Connection state of a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportState {
    /// Transport is disconnected.
    Disconnected,
    /// Transport is connecting.
    Connecting,
    /// Transport is connected and ready.
    Connected,
    /// Transport is reconnecting after a failure.
    Reconnecting,
    /// Transport encountered an error.
    Error,
}

impl TransportState {
    /// Returns `true` if the transport is connected.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Returns `true` if the transport can accept operations.
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Returns `true` if the transport is in a transitional state.
    pub fn is_transitional(&self) -> bool {
        matches!(self, Self::Connecting | Self::Reconnecting)
    }
}

impl fmt::Display for TransportState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Disconnected => "disconnected",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::Error => "error",
        };
        write!(f, "{}", s)
    }
}

impl Default for TransportState {
    fn default() -> Self {
        Self::Disconnected
    }
}

// =============================================================================
// ModbusTransport Trait
// =============================================================================

/// Abstract transport layer for Modbus communication.
///
/// This trait provides a unified interface for both TCP and RTU transports,
/// abstracting away the underlying connection details.
///
/// # Implementors
///
/// - [`ModbusTcpTransport`](super::tcp::ModbusTcpTransport): Modbus TCP transport
/// - `ModbusRtuTransport`: Modbus RTU transport (future)
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow use from multiple tasks.
/// However, operations typically require exclusive access via `&mut self`.
///
/// # Example
///
/// ```rust,ignore
/// use trap_modbus::client::{ModbusTransport, ModbusTcpTransport};
///
/// async fn read_data<T: ModbusTransport>(transport: &T) -> ModbusResult<Vec<u16>> {
///     transport.read_holding_registers(0, 10).await
/// }
/// ```
#[async_trait]
pub trait ModbusTransport: Send + Sync {
    // =========================================================================
    // Connection Management
    // =========================================================================

    /// Establishes a connection to the Modbus device.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    async fn connect(&mut self) -> ModbusResult<()>;

    /// Disconnects from the Modbus device.
    ///
    /// This method should gracefully close the connection.
    async fn disconnect(&mut self) -> ModbusResult<()>;

    /// Returns `true` if the transport is connected.
    fn is_connected(&self) -> bool;

    /// Returns the current transport state.
    fn state(&self) -> TransportState;

    // =========================================================================
    // Read Operations (Function Codes 1-4)
    // =========================================================================

    /// Reads coils (FC 01).
    ///
    /// # Arguments
    ///
    /// * `address` - Starting coil address (0-based)
    /// * `count` - Number of coils to read
    async fn read_coils(&self, address: u16, count: u16) -> ModbusResult<Vec<bool>>;

    /// Reads discrete inputs (FC 02).
    ///
    /// # Arguments
    ///
    /// * `address` - Starting input address (0-based)
    /// * `count` - Number of inputs to read
    async fn read_discrete_inputs(&self, address: u16, count: u16) -> ModbusResult<Vec<bool>>;

    /// Reads holding registers (FC 03).
    ///
    /// # Arguments
    ///
    /// * `address` - Starting register address (0-based)
    /// * `count` - Number of registers to read
    async fn read_holding_registers(&self, address: u16, count: u16) -> ModbusResult<Vec<u16>>;

    /// Reads input registers (FC 04).
    ///
    /// # Arguments
    ///
    /// * `address` - Starting register address (0-based)
    /// * `count` - Number of registers to read
    async fn read_input_registers(&self, address: u16, count: u16) -> ModbusResult<Vec<u16>>;

    // =========================================================================
    // Write Operations (Function Codes 5, 6, 15, 16)
    // =========================================================================

    /// Writes a single coil (FC 05).
    ///
    /// # Arguments
    ///
    /// * `address` - Coil address (0-based)
    /// * `value` - Value to write
    async fn write_single_coil(&self, address: u16, value: bool) -> ModbusResult<()>;

    /// Writes a single holding register (FC 06).
    ///
    /// # Arguments
    ///
    /// * `address` - Register address (0-based)
    /// * `value` - Value to write
    async fn write_single_register(&self, address: u16, value: u16) -> ModbusResult<()>;

    /// Writes multiple coils (FC 15).
    ///
    /// # Arguments
    ///
    /// * `address` - Starting coil address (0-based)
    /// * `values` - Values to write
    async fn write_multiple_coils(&self, address: u16, values: &[bool]) -> ModbusResult<()>;

    /// Writes multiple holding registers (FC 16).
    ///
    /// # Arguments
    ///
    /// * `address` - Starting register address (0-based)
    /// * `values` - Values to write
    async fn write_multiple_registers(&self, address: u16, values: &[u16]) -> ModbusResult<()>;

    // =========================================================================
    // Optional Operations
    // =========================================================================

    /// Reads and writes multiple registers (FC 23).
    ///
    /// This is an optional operation that some devices may not support.
    ///
    /// # Default Implementation
    ///
    /// Returns `NotSupported` error.
    async fn read_write_multiple_registers(
        &self,
        _read_address: u16,
        _read_count: u16,
        _write_address: u16,
        _write_values: &[u16],
    ) -> ModbusResult<Vec<u16>> {
        Err(crate::error::ModbusError::operation(
            crate::error::OperationError::not_supported("read_write_multiple_registers (FC 23)"),
        ))
    }

    /// Masks a write register (FC 22).
    ///
    /// # Default Implementation
    ///
    /// Returns `NotSupported` error.
    async fn mask_write_register(
        &self,
        _address: u16,
        _and_mask: u16,
        _or_mask: u16,
    ) -> ModbusResult<()> {
        Err(crate::error::ModbusError::operation(
            crate::error::OperationError::not_supported("mask_write_register (FC 22)"),
        ))
    }

    // =========================================================================
    // Metadata
    // =========================================================================

    /// Returns the unit ID (slave address).
    fn unit_id(&self) -> u8;

    /// Returns a display name for this transport.
    fn display_name(&self) -> String;
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

        assert!(TransportState::Connected.is_operational());
        assert!(!TransportState::Connecting.is_operational());

        assert!(TransportState::Connecting.is_transitional());
        assert!(TransportState::Reconnecting.is_transitional());
        assert!(!TransportState::Connected.is_transitional());
    }

    #[test]
    fn test_transport_state_display() {
        assert_eq!(TransportState::Connected.to_string(), "connected");
        assert_eq!(TransportState::Disconnected.to_string(), "disconnected");
    }
}
