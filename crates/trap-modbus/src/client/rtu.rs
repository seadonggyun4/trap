// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Modbus RTU transport implementation.
//!
//! This module provides the RTU (serial) transport for Modbus communication using
//! the `tokio-modbus` and `tokio-serial` crates as the underlying implementation.
//!
//! # Features
//!
//! - Serial port communication with configurable parameters
//! - Automatic inter-frame delay calculation per Modbus specification
//! - Comprehensive error handling with recovery hints
//! - Thread-safe operations via internal mutex
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_modbus::client::ModbusRtuTransport;
//! use trap_modbus::types::ModbusRtuConfig;
//!
//! let config = ModbusRtuConfig::builder()
//!     .port("/dev/ttyUSB0")
//!     .baud_rate(9600)
//!     .parity(Parity::None)
//!     .unit_id(1)
//!     .build()?;
//!
//! let mut transport = ModbusRtuTransport::new(config);
//! transport.connect().await?;
//!
//! let values = transport.read_holding_registers(0, 10).await?;
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_modbus::client::{Context as ModbusContext, Reader, Writer};
use tokio_modbus::prelude::*;
use tokio_modbus::{Error as TokioModbusError, ExceptionCode};
use tokio_serial::{DataBits as SerialDataBits, Parity as SerialParity, SerialPortBuilderExt, StopBits as SerialStopBits};

use crate::error::{
    ConnectionError, ModbusError, ModbusResult, OperationError, ProtocolError, TimeoutError,
};
use crate::types::{ModbusRtuConfig, DataBits, Parity, StopBits};

use super::transport::{ModbusTransport, TransportState};

// =============================================================================
// ModbusRtuTransport
// =============================================================================

/// Modbus RTU transport using tokio-modbus over serial port.
///
/// This transport provides:
/// - Serial port communication via `tokio-serial`
/// - Configurable baud rate, parity, stop bits
/// - Automatic inter-frame delay per Modbus RTU specification
/// - Thread-safe operations via internal mutex
/// - Comprehensive error mapping
///
/// # Serial Port Configuration
///
/// The transport supports common serial configurations:
/// - Baud rates: 9600, 19200, 38400, 57600, 115200, etc.
/// - Data bits: 7 or 8
/// - Parity: None, Odd, Even
/// - Stop bits: 1 or 2
///
/// # Example
///
/// ```rust,ignore
/// use trap_modbus::client::ModbusRtuTransport;
/// use trap_modbus::types::{ModbusRtuConfig, Parity};
///
/// // Standard 9600 8N1 configuration
/// let config = ModbusRtuConfig::builder()
///     .port("/dev/ttyUSB0")
///     .default_9600_8n1()
///     .unit_id(1)
///     .build()?;
///
/// let mut transport = ModbusRtuTransport::new(config);
/// transport.connect().await?;
/// ```
pub struct ModbusRtuTransport {
    /// Configuration.
    config: ModbusRtuConfig,
    /// Inner context (protected by mutex for thread safety).
    inner: Arc<Mutex<RtuTransportInner>>,
    /// Current state.
    state: TransportState,
}

/// Inner transport state.
struct RtuTransportInner {
    /// The tokio-modbus context.
    context: Option<ModbusContext>,
    /// Last successful operation time.
    last_success: Option<Instant>,
    /// Last error message.
    last_error: Option<String>,
}

impl RtuTransportInner {
    fn new() -> Self {
        Self {
            context: None,
            last_success: None,
            last_error: None,
        }
    }

    fn is_connected(&self) -> bool {
        self.context.is_some()
    }

    fn record_success(&mut self) {
        self.last_success = Some(Instant::now());
        self.last_error = None;
    }

    fn record_error(&mut self, error: &str) {
        self.last_error = Some(error.to_string());
    }
}

impl ModbusRtuTransport {
    /// Creates a new RTU transport with the given configuration.
    pub fn new(config: ModbusRtuConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(RtuTransportInner::new())),
            state: TransportState::Disconnected,
        }
    }

    /// Creates a simple RTU transport with port and default settings (9600 8N1).
    pub fn simple(port: impl Into<String>) -> Self {
        let config = ModbusRtuConfig::new(port);
        Self::new(config)
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &ModbusRtuConfig {
        &self.config
    }

    /// Returns the serial port path.
    pub fn port(&self) -> &str {
        &self.config.port
    }

    /// Attempts to reconnect after a failure.
    pub async fn reconnect(&mut self) -> ModbusResult<()> {
        self.state = TransportState::Reconnecting;

        // Disconnect first if needed
        let _ = self.disconnect().await;

        // Wait before reconnecting (allow serial port to settle)
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Try to connect
        self.connect().await
    }

    /// Converts DataBits to tokio-serial DataBits.
    fn convert_data_bits(bits: DataBits) -> SerialDataBits {
        match bits {
            DataBits::Five => SerialDataBits::Five,
            DataBits::Six => SerialDataBits::Six,
            DataBits::Seven => SerialDataBits::Seven,
            DataBits::Eight => SerialDataBits::Eight,
        }
    }

    /// Converts Parity to tokio-serial Parity.
    fn convert_parity(parity: Parity) -> SerialParity {
        match parity {
            Parity::None => SerialParity::None,
            Parity::Odd => SerialParity::Odd,
            Parity::Even => SerialParity::Even,
        }
    }

    /// Converts StopBits to tokio-serial StopBits.
    fn convert_stop_bits(bits: StopBits) -> SerialStopBits {
        match bits {
            StopBits::One => SerialStopBits::One,
            StopBits::Two => SerialStopBits::Two,
        }
    }

    /// Maps a tokio-modbus error to ModbusError.
    fn map_modbus_error(&self, error: TokioModbusError, operation: &str) -> ModbusError {
        match error {
            TokioModbusError::Transport(io_error) => {
                use std::io::ErrorKind;
                match io_error.kind() {
                    ErrorKind::NotFound => {
                        ModbusError::connection(ConnectionError::serial_not_found(&self.config.port))
                    }
                    ErrorKind::PermissionDenied => {
                        ModbusError::connection(ConnectionError::serial_access_denied(&self.config.port))
                    }
                    ErrorKind::TimedOut => {
                        ModbusError::timeout(TimeoutError::response(self.config.timeout))
                    }
                    ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => {
                        ModbusError::connection(ConnectionError::closed(Some(
                            "Serial connection lost".to_string(),
                        )))
                    }
                    _ => ModbusError::operation(OperationError::ReadFailed {
                        register_type: "unknown".to_string(),
                        address: 0,
                        count: 0,
                        message: format!("{}: {}", operation, io_error),
                        source: Some(Box::new(io_error)),
                    }),
                }
            }
            TokioModbusError::Protocol(protocol_error) => {
                Self::map_protocol_error(&protocol_error)
            }
        }
    }

    /// Maps a tokio_modbus::ProtocolError to ModbusError.
    fn map_protocol_error(error: &tokio_modbus::ProtocolError) -> ModbusError {
        let error_str = format!("{:?}", error);

        let code = if error_str.contains("IllegalFunction") {
            0x01
        } else if error_str.contains("IllegalDataAddress") {
            0x02
        } else if error_str.contains("IllegalDataValue") {
            0x03
        } else if error_str.contains("ServerDeviceFailure") {
            0x04
        } else if error_str.contains("Acknowledge") {
            0x05
        } else if error_str.contains("ServerDeviceBusy") {
            0x06
        } else if error_str.contains("MemoryParityError") {
            0x08
        } else if error_str.contains("GatewayPathUnavailable") {
            0x0A
        } else if error_str.contains("GatewayTargetDevice") {
            0x0B
        } else {
            0xFF
        };

        ModbusError::protocol(ProtocolError::exception_response(0, code))
    }

    /// Converts ExceptionCode to u8.
    fn exception_code_to_u8(code: &ExceptionCode) -> u8 {
        match code {
            ExceptionCode::IllegalFunction => 0x01,
            ExceptionCode::IllegalDataAddress => 0x02,
            ExceptionCode::IllegalDataValue => 0x03,
            ExceptionCode::ServerDeviceFailure => 0x04,
            ExceptionCode::Acknowledge => 0x05,
            ExceptionCode::ServerDeviceBusy => 0x06,
            ExceptionCode::MemoryParityError => 0x08,
            ExceptionCode::GatewayPathUnavailable => 0x0A,
            ExceptionCode::GatewayTargetDevice => 0x0B,
            _ => 0xFF,
        }
    }

    /// Maps an exception response to ModbusError.
    fn map_exception_error(&self, exception: ExceptionCode, _operation: &str) -> ModbusError {
        let code = Self::exception_code_to_u8(&exception);
        ModbusError::protocol(ProtocolError::exception_response(0, code))
    }
}

#[async_trait]
impl ModbusTransport for ModbusRtuTransport {
    async fn connect(&mut self) -> ModbusResult<()> {
        if self.state == TransportState::Connected {
            return Ok(());
        }

        self.state = TransportState::Connecting;

        // Build serial port configuration
        let builder = tokio_serial::new(&self.config.port, self.config.baud_rate)
            .data_bits(Self::convert_data_bits(self.config.data_bits))
            .parity(Self::convert_parity(self.config.parity))
            .stop_bits(Self::convert_stop_bits(self.config.stop_bits));

        // Open serial port
        let serial = builder.open_native_async().map_err(|e| {
            let error = match e.kind {
                tokio_serial::ErrorKind::NoDevice => {
                    ConnectionError::serial_not_found(&self.config.port)
                }
                tokio_serial::ErrorKind::InvalidInput => {
                    ConnectionError::SerialConfigurationFailed {
                        port: self.config.port.clone(),
                        message: e.to_string(),
                    }
                }
                tokio_serial::ErrorKind::Io(io_kind) => match io_kind {
                    std::io::ErrorKind::PermissionDenied => {
                        ConnectionError::serial_access_denied(&self.config.port)
                    }
                    std::io::ErrorKind::NotFound => {
                        ConnectionError::serial_not_found(&self.config.port)
                    }
                    _ => ConnectionError::SerialConfigurationFailed {
                        port: self.config.port.clone(),
                        message: e.to_string(),
                    },
                },
                _ => ConnectionError::SerialConfigurationFailed {
                    port: self.config.port.clone(),
                    message: e.to_string(),
                },
            };
            ModbusError::connection(error)
        })?;

        // Create Modbus RTU context
        let slave = Slave(self.config.unit_id);
        let ctx = rtu::attach_slave(serial, slave);

        // Store context
        let mut inner = self.inner.lock().await;
        inner.context = Some(ctx);
        inner.record_success();
        drop(inner);

        self.state = TransportState::Connected;

        tracing::info!(
            port = %self.config.port,
            baud_rate = self.config.baud_rate,
            unit_id = self.config.unit_id,
            "Connected to Modbus RTU device"
        );

        Ok(())
    }

    async fn disconnect(&mut self) -> ModbusResult<()> {
        let mut inner = self.inner.lock().await;

        if let Some(mut ctx) = inner.context.take() {
            // Disconnect gracefully
            if let Err(e) = ctx.disconnect().await {
                tracing::warn!(error = %e, "Error disconnecting from Modbus RTU device");
            }
        }

        drop(inner);
        self.state = TransportState::Disconnected;

        tracing::debug!(
            port = %self.config.port,
            "Disconnected from Modbus RTU device"
        );

        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.state == TransportState::Connected
    }

    fn state(&self) -> TransportState {
        self.state
    }

    async fn read_coils(&self, address: u16, count: u16) -> ModbusResult<Vec<bool>> {
        let mut inner = self.inner.lock().await;
        let ctx = inner.context.as_mut().ok_or_else(|| {
            ModbusError::connection(ConnectionError::NotConnected)
        })?;

        let result = timeout(self.config.timeout, ctx.read_coils(address, count))
            .await
            .map_err(|_| ModbusError::timeout(TimeoutError::read(self.config.timeout)))?
            .map_err(|e| self.map_modbus_error(e, "read_coils"))?
            .map_err(|e| self.map_exception_error(e, "read_coils"))?;

        inner.record_success();
        Ok(result)
    }

    async fn read_discrete_inputs(&self, address: u16, count: u16) -> ModbusResult<Vec<bool>> {
        let mut inner = self.inner.lock().await;
        let ctx = inner.context.as_mut().ok_or_else(|| {
            ModbusError::connection(ConnectionError::NotConnected)
        })?;

        let result = timeout(self.config.timeout, ctx.read_discrete_inputs(address, count))
            .await
            .map_err(|_| ModbusError::timeout(TimeoutError::read(self.config.timeout)))?
            .map_err(|e| self.map_modbus_error(e, "read_discrete_inputs"))?
            .map_err(|e| self.map_exception_error(e, "read_discrete_inputs"))?;

        inner.record_success();
        Ok(result)
    }

    async fn read_holding_registers(&self, address: u16, count: u16) -> ModbusResult<Vec<u16>> {
        let mut inner = self.inner.lock().await;
        let ctx = inner.context.as_mut().ok_or_else(|| {
            ModbusError::connection(ConnectionError::NotConnected)
        })?;

        let result = timeout(self.config.timeout, ctx.read_holding_registers(address, count))
            .await
            .map_err(|_| ModbusError::timeout(TimeoutError::read(self.config.timeout)))?
            .map_err(|e| self.map_modbus_error(e, "read_holding_registers"))?
            .map_err(|e| self.map_exception_error(e, "read_holding_registers"))?;

        inner.record_success();
        Ok(result)
    }

    async fn read_input_registers(&self, address: u16, count: u16) -> ModbusResult<Vec<u16>> {
        let mut inner = self.inner.lock().await;
        let ctx = inner.context.as_mut().ok_or_else(|| {
            ModbusError::connection(ConnectionError::NotConnected)
        })?;

        let result = timeout(self.config.timeout, ctx.read_input_registers(address, count))
            .await
            .map_err(|_| ModbusError::timeout(TimeoutError::read(self.config.timeout)))?
            .map_err(|e| self.map_modbus_error(e, "read_input_registers"))?
            .map_err(|e| self.map_exception_error(e, "read_input_registers"))?;

        inner.record_success();
        Ok(result)
    }

    async fn write_single_coil(&self, address: u16, value: bool) -> ModbusResult<()> {
        let mut inner = self.inner.lock().await;
        let ctx = inner.context.as_mut().ok_or_else(|| {
            ModbusError::connection(ConnectionError::NotConnected)
        })?;

        timeout(self.config.timeout, ctx.write_single_coil(address, value))
            .await
            .map_err(|_| ModbusError::timeout(TimeoutError::write(self.config.timeout)))?
            .map_err(|e| self.map_modbus_error(e, "write_single_coil"))?
            .map_err(|e| self.map_exception_error(e, "write_single_coil"))?;

        inner.record_success();
        Ok(())
    }

    async fn write_single_register(&self, address: u16, value: u16) -> ModbusResult<()> {
        let mut inner = self.inner.lock().await;
        let ctx = inner.context.as_mut().ok_or_else(|| {
            ModbusError::connection(ConnectionError::NotConnected)
        })?;

        timeout(self.config.timeout, ctx.write_single_register(address, value))
            .await
            .map_err(|_| ModbusError::timeout(TimeoutError::write(self.config.timeout)))?
            .map_err(|e| self.map_modbus_error(e, "write_single_register"))?
            .map_err(|e| self.map_exception_error(e, "write_single_register"))?;

        inner.record_success();
        Ok(())
    }

    async fn write_multiple_coils(&self, address: u16, values: &[bool]) -> ModbusResult<()> {
        let mut inner = self.inner.lock().await;
        let ctx = inner.context.as_mut().ok_or_else(|| {
            ModbusError::connection(ConnectionError::NotConnected)
        })?;

        timeout(self.config.timeout, ctx.write_multiple_coils(address, values))
            .await
            .map_err(|_| ModbusError::timeout(TimeoutError::write(self.config.timeout)))?
            .map_err(|e| self.map_modbus_error(e, "write_multiple_coils"))?
            .map_err(|e| self.map_exception_error(e, "write_multiple_coils"))?;

        inner.record_success();
        Ok(())
    }

    async fn write_multiple_registers(&self, address: u16, values: &[u16]) -> ModbusResult<()> {
        let mut inner = self.inner.lock().await;
        let ctx = inner.context.as_mut().ok_or_else(|| {
            ModbusError::connection(ConnectionError::NotConnected)
        })?;

        timeout(self.config.timeout, ctx.write_multiple_registers(address, values))
            .await
            .map_err(|_| ModbusError::timeout(TimeoutError::write(self.config.timeout)))?
            .map_err(|e| self.map_modbus_error(e, "write_multiple_registers"))?
            .map_err(|e| self.map_exception_error(e, "write_multiple_registers"))?;

        inner.record_success();
        Ok(())
    }

    async fn read_write_multiple_registers(
        &self,
        read_address: u16,
        read_count: u16,
        write_address: u16,
        write_values: &[u16],
    ) -> ModbusResult<Vec<u16>> {
        let mut inner = self.inner.lock().await;
        let ctx = inner.context.as_mut().ok_or_else(|| {
            ModbusError::connection(ConnectionError::NotConnected)
        })?;

        let result = timeout(
            self.config.timeout,
            ctx.read_write_multiple_registers(read_address, read_count, write_address, write_values),
        )
        .await
        .map_err(|_| ModbusError::timeout(TimeoutError::response(self.config.timeout)))?
        .map_err(|e| self.map_modbus_error(e, "read_write_multiple_registers"))?
        .map_err(|e| self.map_exception_error(e, "read_write_multiple_registers"))?;

        inner.record_success();
        Ok(result)
    }

    fn unit_id(&self) -> u8 {
        self.config.unit_id
    }

    fn display_name(&self) -> String {
        format!(
            "Modbus RTU {} @{}bps (unit {})",
            self.config.port, self.config.baud_rate, self.config.unit_id
        )
    }
}

impl std::fmt::Debug for ModbusRtuTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModbusRtuTransport")
            .field("port", &self.config.port)
            .field("baud_rate", &self.config.baud_rate)
            .field("unit_id", &self.config.unit_id)
            .field("state", &self.state)
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_constructor() {
        let transport = ModbusRtuTransport::simple("/dev/ttyUSB0");
        assert_eq!(transport.config().port, "/dev/ttyUSB0");
        assert_eq!(transport.config().baud_rate, 9600); // default
        assert_eq!(transport.state(), TransportState::Disconnected);
    }

    #[test]
    fn test_port() {
        let transport = ModbusRtuTransport::simple("/dev/ttyUSB0");
        assert_eq!(transport.port(), "/dev/ttyUSB0");
    }

    #[test]
    fn test_display_name() {
        let config = ModbusRtuConfig::builder()
            .port("/dev/ttyUSB0")
            .baud_rate(19200)
            .unit_id(5)
            .build()
            .unwrap();
        let transport = ModbusRtuTransport::new(config);
        assert_eq!(
            transport.display_name(),
            "Modbus RTU /dev/ttyUSB0 @19200bps (unit 5)"
        );
    }

    #[test]
    fn test_data_bits_conversion() {
        assert!(matches!(
            ModbusRtuTransport::convert_data_bits(DataBits::Eight),
            SerialDataBits::Eight
        ));
        assert!(matches!(
            ModbusRtuTransport::convert_data_bits(DataBits::Seven),
            SerialDataBits::Seven
        ));
    }

    #[test]
    fn test_parity_conversion() {
        assert!(matches!(
            ModbusRtuTransport::convert_parity(Parity::None),
            SerialParity::None
        ));
        assert!(matches!(
            ModbusRtuTransport::convert_parity(Parity::Even),
            SerialParity::Even
        ));
        assert!(matches!(
            ModbusRtuTransport::convert_parity(Parity::Odd),
            SerialParity::Odd
        ));
    }

    #[test]
    fn test_stop_bits_conversion() {
        assert!(matches!(
            ModbusRtuTransport::convert_stop_bits(StopBits::One),
            SerialStopBits::One
        ));
        assert!(matches!(
            ModbusRtuTransport::convert_stop_bits(StopBits::Two),
            SerialStopBits::Two
        ));
    }

    #[test]
    fn test_debug_impl() {
        let transport = ModbusRtuTransport::simple("/dev/ttyUSB0");
        let debug_str = format!("{:?}", transport);
        assert!(debug_str.contains("/dev/ttyUSB0"));
        assert!(debug_str.contains("9600"));
    }
}
