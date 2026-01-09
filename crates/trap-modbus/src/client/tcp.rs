// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Modbus TCP transport implementation.
//!
//! This module provides the TCP transport for Modbus communication using
//! the `tokio-modbus` crate as the underlying implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_modbus::client::{Context as ModbusContext, Reader, Writer};
use tokio_modbus::prelude::*;
use tokio_modbus::{Error as TokioModbusError, ExceptionCode};

use crate::error::{
    ConnectionError, ModbusError, ModbusResult, OperationError, ProtocolError, TimeoutError,
};
use crate::types::ModbusTcpConfig;

use super::transport::{ModbusTransport, TransportState};

// =============================================================================
// ModbusTcpTransport
// =============================================================================

/// Modbus TCP transport using tokio-modbus.
///
/// This transport provides:
/// - Connection management with configurable timeouts
/// - Automatic reconnection support
/// - Thread-safe operations via internal mutex
/// - Comprehensive error mapping
///
/// # Example
///
/// ```rust,ignore
/// use trap_modbus::client::ModbusTcpTransport;
/// use trap_modbus::types::ModbusTcpConfig;
///
/// let config = ModbusTcpConfig::builder()
///     .host("192.168.1.100")
///     .port(502)
///     .unit_id(1)
///     .build()?;
///
/// let mut transport = ModbusTcpTransport::new(config);
/// transport.connect().await?;
///
/// let values = transport.read_holding_registers(0, 10).await?;
/// ```
pub struct ModbusTcpTransport {
    /// Configuration.
    config: ModbusTcpConfig,
    /// Inner context (protected by mutex for thread safety).
    inner: Arc<Mutex<TcpTransportInner>>,
    /// Current state.
    state: TransportState,
}

/// Inner transport state.
struct TcpTransportInner {
    /// The tokio-modbus context.
    context: Option<ModbusContext>,
    /// Last successful operation time.
    last_success: Option<Instant>,
    /// Last error message.
    last_error: Option<String>,
}

impl TcpTransportInner {
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

impl ModbusTcpTransport {
    /// Creates a new TCP transport with the given configuration.
    pub fn new(config: ModbusTcpConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(TcpTransportInner::new())),
            state: TransportState::Disconnected,
        }
    }

    /// Creates a simple TCP transport with host and port.
    pub fn simple(host: impl Into<String>, port: u16) -> Self {
        let config = ModbusTcpConfig::with_port(host, port);
        Self::new(config)
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &ModbusTcpConfig {
        &self.config
    }

    /// Returns the socket address.
    pub fn socket_addr(&self) -> String {
        self.config.socket_addr()
    }

    /// Attempts to reconnect after a failure.
    pub async fn reconnect(&mut self) -> ModbusResult<()> {
        self.state = TransportState::Reconnecting;

        // Disconnect first if needed
        let _ = self.disconnect().await;

        // Wait before reconnecting
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Try to connect
        self.connect().await
    }

    /// Resolves the socket address.
    async fn resolve_address(&self) -> ModbusResult<SocketAddr> {
        let addr_str = self.config.socket_addr();

        // Try to parse as IP:port first
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            return Ok(addr);
        }

        // Try DNS resolution
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str)
            .await
            .map_err(|e| {
                ModbusError::connection(ConnectionError::DnsResolutionFailed {
                    hostname: self.config.host.clone(),
                    source: Some(e),
                })
            })?
            .collect();

        addrs.into_iter().next().ok_or_else(|| {
            ModbusError::connection(ConnectionError::dns_failed(&self.config.host))
        })
    }

    /// Maps a tokio-modbus error to ModbusError.
    fn map_modbus_error(&self, error: TokioModbusError, operation: &str) -> ModbusError {
        match error {
            TokioModbusError::Transport(io_error) => {
                use std::io::ErrorKind;
                match io_error.kind() {
                    ErrorKind::ConnectionRefused => {
                        ModbusError::connection(ConnectionError::refused(&self.config.host, self.config.port))
                    }
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => {
                        ModbusError::connection(ConnectionError::closed(Some(io_error.to_string())))
                    }
                    ErrorKind::TimedOut => {
                        ModbusError::timeout(TimeoutError::response(self.config.operation_timeout))
                    }
                    ErrorKind::NotConnected => ModbusError::connection(ConnectionError::NotConnected),
                    ErrorKind::BrokenPipe => {
                        ModbusError::connection(ConnectionError::closed(Some("Broken pipe".to_string())))
                    }
                    _ => {
                        ModbusError::operation(OperationError::ReadFailed {
                            register_type: "unknown".to_string(),
                            address: 0,
                            count: 0,
                            message: format!("{}: {}", operation, io_error),
                            source: Some(Box::new(io_error)),
                        })
                    }
                }
            }
            TokioModbusError::Protocol(protocol_error) => {
                Self::map_protocol_error(&protocol_error)
            }
        }
    }

    /// Maps a tokio_modbus::ProtocolError to ModbusError.
    fn map_protocol_error(error: &tokio_modbus::ProtocolError) -> ModbusError {
        // tokio_modbus::ProtocolError contains exception details
        // We need to extract the exception code from it
        let error_str = format!("{:?}", error);

        // Try to extract exception code from debug representation
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

    /// Parses Modbus exception code from error string.
    fn parse_exception_code(error_str: &str) -> Option<u8> {
        // Common patterns: "Exception code: 2", "exception: 0x02"
        let patterns = [
            ("exception code:", 10),
            ("exception:", 10),
            ("Exception code:", 10),
            ("Exception:", 10),
        ];

        for (pattern, _) in patterns {
            if let Some(idx) = error_str.find(pattern) {
                let start = idx + pattern.len();
                let remainder = &error_str[start..].trim_start();

                // Try hex format
                if remainder.starts_with("0x") || remainder.starts_with("0X") {
                    if let Ok(code) = u8::from_str_radix(&remainder[2..].chars().take(2).collect::<String>(), 16) {
                        return Some(code);
                    }
                }

                // Try decimal format
                if let Ok(code) = remainder.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u8>() {
                    return Some(code);
                }
            }
        }

        None
    }
}

#[async_trait]
impl ModbusTransport for ModbusTcpTransport {
    async fn connect(&mut self) -> ModbusResult<()> {
        if self.state == TransportState::Connected {
            return Ok(());
        }

        self.state = TransportState::Connecting;

        // Resolve address
        let socket_addr = self.resolve_address().await?;

        // Connect with timeout
        let connect_future = async {
            let stream = TcpStream::connect(socket_addr).await.map_err(|e| {
                ModbusError::connection(ConnectionError::refused_with(
                    &self.config.host,
                    self.config.port,
                    e,
                ))
            })?;

            // Configure TCP socket
            stream.set_nodelay(self.config.tcp_nodelay).ok();

            // Create Modbus TCP context
            let slave = Slave(self.config.unit_id);
            let ctx = tcp::attach_slave(stream, slave);

            Ok::<_, ModbusError>(ctx)
        };

        let ctx = timeout(self.config.connect_timeout, connect_future)
            .await
            .map_err(|_| {
                ModbusError::connection(ConnectionError::timed_out(
                    &self.config.host,
                    self.config.port,
                    self.config.connect_timeout,
                ))
            })??;

        // Store context
        let mut inner = self.inner.lock().await;
        inner.context = Some(ctx);
        inner.record_success();
        drop(inner);

        self.state = TransportState::Connected;

        tracing::info!(
            host = %self.config.host,
            port = self.config.port,
            unit_id = self.config.unit_id,
            "Connected to Modbus TCP device"
        );

        Ok(())
    }

    async fn disconnect(&mut self) -> ModbusResult<()> {
        let mut inner = self.inner.lock().await;

        if let Some(mut ctx) = inner.context.take() {
            // Disconnect gracefully
            if let Err(e) = ctx.disconnect().await {
                tracing::warn!(error = %e, "Error disconnecting from Modbus device");
            }
        }

        drop(inner);
        self.state = TransportState::Disconnected;

        tracing::debug!(
            host = %self.config.host,
            port = self.config.port,
            "Disconnected from Modbus TCP device"
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

        let result = timeout(self.config.operation_timeout, ctx.read_coils(address, count))
            .await
            .map_err(|_| ModbusError::timeout(TimeoutError::read(self.config.operation_timeout)))?
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

        let result = timeout(
            self.config.operation_timeout,
            ctx.read_discrete_inputs(address, count),
        )
        .await
        .map_err(|_| ModbusError::timeout(TimeoutError::read(self.config.operation_timeout)))?
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

        let result = timeout(
            self.config.operation_timeout,
            ctx.read_holding_registers(address, count),
        )
        .await
        .map_err(|_| ModbusError::timeout(TimeoutError::read(self.config.operation_timeout)))?
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

        let result = timeout(
            self.config.operation_timeout,
            ctx.read_input_registers(address, count),
        )
        .await
        .map_err(|_| ModbusError::timeout(TimeoutError::read(self.config.operation_timeout)))?
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

        timeout(
            self.config.operation_timeout,
            ctx.write_single_coil(address, value),
        )
        .await
        .map_err(|_| ModbusError::timeout(TimeoutError::write(self.config.operation_timeout)))?
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

        timeout(
            self.config.operation_timeout,
            ctx.write_single_register(address, value),
        )
        .await
        .map_err(|_| ModbusError::timeout(TimeoutError::write(self.config.operation_timeout)))?
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

        timeout(
            self.config.operation_timeout,
            ctx.write_multiple_coils(address, values),
        )
        .await
        .map_err(|_| ModbusError::timeout(TimeoutError::write(self.config.operation_timeout)))?
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

        timeout(
            self.config.operation_timeout,
            ctx.write_multiple_registers(address, values),
        )
        .await
        .map_err(|_| ModbusError::timeout(TimeoutError::write(self.config.operation_timeout)))?
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
            self.config.operation_timeout,
            ctx.read_write_multiple_registers(
                read_address,
                read_count,
                write_address,
                write_values,
            ),
        )
        .await
        .map_err(|_| {
            ModbusError::timeout(TimeoutError::response(self.config.operation_timeout))
        })?
        .map_err(|e| self.map_modbus_error(e, "read_write_multiple_registers"))?
        .map_err(|e| self.map_exception_error(e, "read_write_multiple_registers"))?;

        inner.record_success();
        Ok(result)
    }

    fn unit_id(&self) -> u8 {
        self.config.unit_id
    }

    fn display_name(&self) -> String {
        format!("Modbus TCP {}:{} (unit {})", self.config.host, self.config.port, self.config.unit_id)
    }
}

impl std::fmt::Debug for ModbusTcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModbusTcpTransport")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
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
        let transport = ModbusTcpTransport::simple("127.0.0.1", 502);
        assert_eq!(transport.config().host, "127.0.0.1");
        assert_eq!(transport.config().port, 502);
        assert_eq!(transport.state(), TransportState::Disconnected);
    }

    #[test]
    fn test_socket_addr() {
        let transport = ModbusTcpTransport::simple("192.168.1.100", 502);
        assert_eq!(transport.socket_addr(), "192.168.1.100:502");
    }

    #[test]
    fn test_display_name() {
        let config = ModbusTcpConfig::builder()
            .host("plc.local")
            .port(502)
            .unit_id(5)
            .build()
            .unwrap();
        let transport = ModbusTcpTransport::new(config);
        assert_eq!(transport.display_name(), "Modbus TCP plc.local:502 (unit 5)");
    }

    #[test]
    fn test_parse_exception_code() {
        assert_eq!(ModbusTcpTransport::parse_exception_code("Exception code: 2"), Some(2));
        assert_eq!(ModbusTcpTransport::parse_exception_code("exception: 0x02"), Some(2));
        assert_eq!(ModbusTcpTransport::parse_exception_code("no exception"), None);
    }

    #[test]
    fn test_debug_impl() {
        let transport = ModbusTcpTransport::simple("127.0.0.1", 502);
        let debug_str = format!("{:?}", transport);
        assert!(debug_str.contains("127.0.0.1"));
        assert!(debug_str.contains("502"));
    }
}
