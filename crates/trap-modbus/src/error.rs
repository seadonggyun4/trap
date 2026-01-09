// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Modbus protocol error types with comprehensive diagnostics.
//!
//! This module provides a rich error type hierarchy for Modbus operations,
//! designed for:
//!
//! - **Extensibility**: Easy to add new error variants
//! - **Diagnostics**: Detailed error information for debugging
//! - **Recovery**: Hints for error recovery and retry strategies
//! - **Interoperability**: Seamless conversion to `trap_core::DriverError`
//!
//! # Error Categories
//!
//! ```text
//! ModbusError
//! ├── Connection    - TCP/RTU connection issues
//! ├── Protocol      - Modbus protocol violations
//! ├── Operation     - Read/write operation failures
//! ├── Conversion    - Data type conversion errors
//! └── Configuration - Invalid settings
//! ```
//!
//! # Examples
//!
//! ```
//! use trap_modbus::error::{ModbusError, ConnectionError, ErrorSeverity};
//!
//! let error = ModbusError::connection(ConnectionError::refused("192.168.1.100", 502));
//!
//! // Check if error is retryable
//! if error.is_retryable() {
//!     println!("Will retry after {:?}", error.suggested_retry_delay());
//! }
//!
//! // Get recovery hints
//! for hint in error.recovery_hints() {
//!     println!("Hint: {}", hint);
//! }
//! ```

use std::fmt;
use std::io;
use std::time::Duration;
use thiserror::Error;
use tracing::Level;

// =============================================================================
// ModbusError - Main Error Type
// =============================================================================

/// The main error type for Modbus operations.
///
/// This enum categorizes errors by their domain, making it easy to handle
/// specific error types while maintaining a unified interface.
#[derive(Debug, Error)]
pub enum ModbusError {
    /// Connection-related errors (TCP/RTU).
    #[error("{0}")]
    Connection(#[from] ConnectionError),

    /// Modbus protocol errors (exception codes, framing).
    #[error("{0}")]
    Protocol(#[from] ProtocolError),

    /// Operation errors (read/write failures).
    #[error("{0}")]
    Operation(#[from] OperationError),

    /// Data conversion errors.
    #[error("{0}")]
    Conversion(#[from] ConversionError),

    /// Configuration errors.
    #[error("{0}")]
    Configuration(#[from] ConfigurationError),

    /// Timeout errors.
    #[error("{0}")]
    Timeout(#[from] TimeoutError),
}

impl ModbusError {
    // =========================================================================
    // Factory Methods
    // =========================================================================

    /// Creates a connection error.
    #[inline]
    pub fn connection(error: ConnectionError) -> Self {
        Self::Connection(error)
    }

    /// Creates a protocol error.
    #[inline]
    pub fn protocol(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }

    /// Creates an operation error.
    #[inline]
    pub fn operation(error: OperationError) -> Self {
        Self::Operation(error)
    }

    /// Creates a conversion error.
    #[inline]
    pub fn conversion(error: ConversionError) -> Self {
        Self::Conversion(error)
    }

    /// Creates a configuration error.
    #[inline]
    pub fn configuration(error: ConfigurationError) -> Self {
        Self::Configuration(error)
    }

    /// Creates a timeout error.
    #[inline]
    pub fn timeout(error: TimeoutError) -> Self {
        Self::Timeout(error)
    }

    // =========================================================================
    // Convenience Factory Methods
    // =========================================================================

    /// Creates a TCP connection refused error.
    pub fn tcp_refused(host: impl Into<String>, port: u16) -> Self {
        Self::Connection(ConnectionError::refused(host, port))
    }

    /// Creates a not connected error.
    pub fn not_connected() -> Self {
        Self::Connection(ConnectionError::NotConnected)
    }

    /// Creates a read operation timeout.
    pub fn read_timeout(duration: Duration) -> Self {
        Self::Timeout(TimeoutError::read(duration))
    }

    /// Creates a write operation timeout.
    pub fn write_timeout(duration: Duration) -> Self {
        Self::Timeout(TimeoutError::write(duration))
    }

    /// Creates an exception response error.
    pub fn exception(function_code: u8, exception_code: u8) -> Self {
        Self::Protocol(ProtocolError::exception_response(function_code, exception_code))
    }

    /// Creates a data type mismatch error.
    pub fn type_mismatch(expected: &str, actual: &str) -> Self {
        Self::Conversion(ConversionError::type_mismatch(expected, actual))
    }

    // =========================================================================
    // Error Properties
    // =========================================================================

    /// Returns `true` if this error is retryable.
    ///
    /// Retryable errors are typically transient issues that may succeed
    /// on a subsequent attempt with appropriate backoff.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Connection(e) => e.is_retryable(),
            Self::Protocol(e) => e.is_retryable(),
            Self::Operation(e) => e.is_retryable(),
            Self::Timeout(_) => true,
            Self::Conversion(_) | Self::Configuration(_) => false,
        }
    }

    /// Returns the suggested retry delay for this error.
    ///
    /// Returns `None` if the error is not retryable.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        if !self.is_retryable() {
            return None;
        }

        match self {
            Self::Connection(e) => Some(e.suggested_retry_delay()),
            Self::Protocol(e) => e.suggested_retry_delay(),
            Self::Operation(e) => e.suggested_retry_delay(),
            Self::Timeout(e) => Some(e.suggested_retry_delay()),
            _ => None,
        }
    }

    /// Returns the maximum number of retries recommended for this error.
    pub fn max_retries(&self) -> u32 {
        match self {
            Self::Connection(e) => e.max_retries(),
            Self::Protocol(e) => e.max_retries(),
            Self::Operation(_) => 3,
            Self::Timeout(_) => 2,
            _ => 0,
        }
    }

    /// Returns the severity level of this error.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::Connection(e) => e.severity(),
            Self::Protocol(e) => e.severity(),
            Self::Operation(e) => e.severity(),
            Self::Timeout(_) => ErrorSeverity::Warning,
            Self::Conversion(_) => ErrorSeverity::Error,
            Self::Configuration(_) => ErrorSeverity::Critical,
        }
    }

    /// Returns the error category for logging and metrics.
    pub fn category(&self) -> &'static str {
        match self {
            Self::Connection(_) => "connection",
            Self::Protocol(_) => "protocol",
            Self::Operation(_) => "operation",
            Self::Timeout(_) => "timeout",
            Self::Conversion(_) => "conversion",
            Self::Configuration(_) => "configuration",
        }
    }

    /// Returns a unique error code for this error.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Connection(e) => e.error_code(),
            Self::Protocol(e) => e.error_code(),
            Self::Operation(e) => e.error_code(),
            Self::Timeout(e) => e.error_code(),
            Self::Conversion(e) => e.error_code(),
            Self::Configuration(e) => e.error_code(),
        }
    }

    /// Returns recovery hints for this error.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::Connection(e) => e.recovery_hints(),
            Self::Protocol(e) => e.recovery_hints(),
            Self::Operation(e) => e.recovery_hints(),
            Self::Timeout(e) => e.recovery_hints(),
            Self::Conversion(e) => e.recovery_hints(),
            Self::Configuration(e) => e.recovery_hints(),
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Connection(e) => e.user_message(),
            Self::Protocol(e) => e.user_message(),
            Self::Operation(e) => e.user_message(),
            Self::Timeout(e) => e.user_message(),
            Self::Conversion(e) => e.user_message(),
            Self::Configuration(e) => e.user_message(),
        }
    }

    /// Returns the tracing level for this error.
    pub fn tracing_level(&self) -> Level {
        self.severity().to_tracing_level()
    }

    /// Logs this error with appropriate level and context.
    pub fn log(&self, context: &str) {
        let level = self.tracing_level();
        let code = self.error_code();

        match level {
            Level::ERROR => tracing::error!(
                error_code = %code,
                category = self.category(),
                context = context,
                retryable = self.is_retryable(),
                "{self}"
            ),
            Level::WARN => tracing::warn!(
                error_code = %code,
                category = self.category(),
                context = context,
                retryable = self.is_retryable(),
                "{self}"
            ),
            _ => tracing::debug!(
                error_code = %code,
                category = self.category(),
                context = context,
                retryable = self.is_retryable(),
                "{self}"
            ),
        }
    }
}

// =============================================================================
// ConnectionError
// =============================================================================

/// Connection-related errors for TCP and RTU.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// TCP connection refused.
    #[error("Connection refused to {host}:{port}")]
    Refused {
        /// Target host.
        host: String,
        /// Target port.
        port: u16,
        /// Underlying error.
        #[source]
        source: Option<io::Error>,
    },

    /// TCP connection timed out.
    #[error("Connection timed out to {host}:{port} after {duration:?}")]
    TimedOut {
        /// Target host.
        host: String,
        /// Target port.
        port: u16,
        /// Timeout duration.
        duration: Duration,
    },

    /// DNS resolution failed.
    #[error("Failed to resolve hostname '{hostname}'")]
    DnsResolutionFailed {
        /// The hostname that failed to resolve.
        hostname: String,
        /// Underlying error.
        #[source]
        source: Option<io::Error>,
    },

    /// Network unreachable.
    #[error("Network unreachable: {target}")]
    NetworkUnreachable {
        /// Target address.
        target: String,
    },

    /// Serial port not found (RTU).
    #[error("Serial port not found: {port}")]
    SerialPortNotFound {
        /// Port path.
        port: String,
    },

    /// Serial port access denied (RTU).
    #[error("Serial port access denied: {port}")]
    SerialPortAccessDenied {
        /// Port path.
        port: String,
    },

    /// Serial port configuration error (RTU).
    #[error("Serial port configuration failed for '{port}': {message}")]
    SerialConfigurationFailed {
        /// Port path.
        port: String,
        /// Error message.
        message: String,
    },

    /// Connection closed unexpectedly.
    #[error("Connection closed unexpectedly")]
    Closed {
        /// Reason for closure.
        reason: Option<String>,
    },

    /// Not connected.
    #[error("Not connected to Modbus device")]
    NotConnected,

    /// Generic I/O error.
    #[error("I/O error: {message}")]
    Io {
        /// Error message.
        message: String,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}

impl ConnectionError {
    /// Creates a connection refused error.
    pub fn refused(host: impl Into<String>, port: u16) -> Self {
        Self::Refused {
            host: host.into(),
            port,
            source: None,
        }
    }

    /// Creates a connection refused error with source.
    pub fn refused_with(host: impl Into<String>, port: u16, source: io::Error) -> Self {
        Self::Refused {
            host: host.into(),
            port,
            source: Some(source),
        }
    }

    /// Creates a connection timed out error.
    pub fn timed_out(host: impl Into<String>, port: u16, duration: Duration) -> Self {
        Self::TimedOut {
            host: host.into(),
            port,
            duration,
        }
    }

    /// Creates a DNS resolution failed error.
    pub fn dns_failed(hostname: impl Into<String>) -> Self {
        Self::DnsResolutionFailed {
            hostname: hostname.into(),
            source: None,
        }
    }

    /// Creates a serial port not found error.
    pub fn serial_not_found(port: impl Into<String>) -> Self {
        Self::SerialPortNotFound { port: port.into() }
    }

    /// Creates a serial port access denied error.
    pub fn serial_access_denied(port: impl Into<String>) -> Self {
        Self::SerialPortAccessDenied { port: port.into() }
    }

    /// Creates a connection closed error.
    pub fn closed(reason: Option<String>) -> Self {
        Self::Closed { reason }
    }

    /// Creates an I/O error.
    pub fn io(message: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            message: message.into(),
            source,
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Refused { .. } => true,
            Self::TimedOut { .. } => true,
            Self::DnsResolutionFailed { .. } => true,
            Self::NetworkUnreachable { .. } => true,
            Self::Closed { .. } => true,
            Self::NotConnected => true,
            Self::Io { source, .. } => {
                matches!(
                    source.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                )
            }
            Self::SerialPortNotFound { .. }
            | Self::SerialPortAccessDenied { .. }
            | Self::SerialConfigurationFailed { .. } => false,
        }
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Duration {
        match self {
            Self::Refused { .. } => Duration::from_secs(1),
            Self::TimedOut { duration, .. } => *duration,
            Self::DnsResolutionFailed { .. } => Duration::from_secs(5),
            Self::NetworkUnreachable { .. } => Duration::from_secs(10),
            Self::Closed { .. } => Duration::from_millis(500),
            Self::NotConnected => Duration::from_millis(100),
            Self::Io { .. } => Duration::from_secs(1),
            _ => Duration::from_secs(5),
        }
    }

    /// Returns the maximum number of retries.
    pub fn max_retries(&self) -> u32 {
        match self {
            Self::Refused { .. } => 5,
            Self::TimedOut { .. } => 3,
            Self::DnsResolutionFailed { .. } => 3,
            Self::NetworkUnreachable { .. } => 10,
            Self::Closed { .. } => 3,
            Self::NotConnected => 1,
            _ => 0,
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::NotConnected => ErrorSeverity::Warning,
            Self::TimedOut { .. } => ErrorSeverity::Warning,
            Self::Closed { .. } => ErrorSeverity::Warning,
            Self::SerialPortAccessDenied { .. } => ErrorSeverity::Critical,
            _ => ErrorSeverity::Error,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Refused { .. } => ErrorCode::new(1, 1),
            Self::TimedOut { .. } => ErrorCode::new(1, 2),
            Self::DnsResolutionFailed { .. } => ErrorCode::new(1, 3),
            Self::NetworkUnreachable { .. } => ErrorCode::new(1, 4),
            Self::SerialPortNotFound { .. } => ErrorCode::new(1, 5),
            Self::SerialPortAccessDenied { .. } => ErrorCode::new(1, 6),
            Self::SerialConfigurationFailed { .. } => ErrorCode::new(1, 7),
            Self::Closed { .. } => ErrorCode::new(1, 8),
            Self::NotConnected => ErrorCode::new(1, 9),
            Self::Io { .. } => ErrorCode::new(1, 10),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::Refused { .. } => vec![
                "Check if the Modbus device is powered on",
                "Verify the IP address and port are correct",
                "Check firewall rules allow the connection",
                "Ensure no other application is using the same port",
            ],
            Self::TimedOut { .. } => vec![
                "Check network connectivity to the device",
                "Increase the connection timeout setting",
                "Verify the device is not overloaded",
            ],
            Self::DnsResolutionFailed { .. } => vec![
                "Verify the hostname is correct",
                "Check DNS server configuration",
                "Try using an IP address instead",
            ],
            Self::NetworkUnreachable { .. } => vec![
                "Check network cable connections",
                "Verify network configuration",
                "Check if the device is on the same network segment",
            ],
            Self::SerialPortNotFound { .. } => vec![
                "Verify the serial port path is correct",
                "Check if the USB-to-Serial adapter is connected",
                "List available ports with 'ls /dev/tty*'",
            ],
            Self::SerialPortAccessDenied { .. } => vec![
                "Add user to the 'dialout' group on Linux",
                "Check port permissions",
                "Run with elevated privileges if necessary",
            ],
            Self::SerialConfigurationFailed { .. } => vec![
                "Verify baud rate matches device settings",
                "Check parity, stop bits, and data bits configuration",
            ],
            Self::Closed { .. } => vec![
                "The connection was closed by the device or network",
                "Retry the connection",
            ],
            Self::NotConnected => vec![
                "Call connect() before performing operations",
            ],
            Self::Io { .. } => vec![
                "Check network connectivity",
                "Retry the operation",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Refused { host, port, .. } => {
                format!("Modbus 장비({}:{})에 연결할 수 없습니다", host, port)
            }
            Self::TimedOut { host, port, .. } => {
                format!("Modbus 장비({}:{}) 연결 시간 초과", host, port)
            }
            Self::DnsResolutionFailed { hostname, .. } => {
                format!("호스트명 '{}' 조회 실패", hostname)
            }
            Self::NetworkUnreachable { target } => {
                format!("네트워크 연결 불가: {}", target)
            }
            Self::SerialPortNotFound { port } => {
                format!("시리얼 포트를 찾을 수 없음: {}", port)
            }
            Self::SerialPortAccessDenied { port } => {
                format!("시리얼 포트 접근 거부: {}", port)
            }
            Self::SerialConfigurationFailed { port, .. } => {
                format!("시리얼 포트 설정 실패: {}", port)
            }
            Self::Closed { .. } => "연결이 끊어졌습니다".to_string(),
            Self::NotConnected => "Modbus 장비에 연결되어 있지 않습니다".to_string(),
            Self::Io { .. } => "네트워크 오류가 발생했습니다".to_string(),
        }
    }
}

impl From<io::Error> for ConnectionError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => Self::Refused {
                host: "unknown".to_string(),
                port: 0,
                source: Some(error),
            },
            io::ErrorKind::TimedOut => Self::TimedOut {
                host: "unknown".to_string(),
                port: 0,
                duration: Duration::from_secs(0),
            },
            io::ErrorKind::NotFound => Self::SerialPortNotFound {
                port: "unknown".to_string(),
            },
            io::ErrorKind::PermissionDenied => Self::SerialPortAccessDenied {
                port: "unknown".to_string(),
            },
            _ => Self::Io {
                message: error.to_string(),
                source: error,
            },
        }
    }
}

// =============================================================================
// ProtocolError
// =============================================================================

/// Modbus protocol-level errors.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Modbus exception response received.
    #[error("Modbus exception: function code {function_code:#04x}, exception {exception_code} ({exception_name})")]
    ExceptionResponse {
        /// The function code that caused the exception.
        function_code: u8,
        /// The exception code.
        exception_code: u8,
        /// Human-readable exception name.
        exception_name: String,
    },

    /// Invalid function code.
    #[error("Invalid function code: {code:#04x}")]
    InvalidFunctionCode {
        /// The invalid code.
        code: u8,
    },

    /// CRC check failed (RTU).
    #[error("CRC check failed: expected {expected:#06x}, got {actual:#06x}")]
    CrcMismatch {
        /// Expected CRC.
        expected: u16,
        /// Actual CRC.
        actual: u16,
    },

    /// Frame too short.
    #[error("Frame too short: expected at least {expected} bytes, got {actual}")]
    FrameTooShort {
        /// Expected minimum bytes.
        expected: usize,
        /// Actual bytes received.
        actual: usize,
    },

    /// Frame too long.
    #[error("Frame too long: maximum {max} bytes, got {actual}")]
    FrameTooLong {
        /// Maximum allowed bytes.
        max: usize,
        /// Actual bytes received.
        actual: usize,
    },

    /// Invalid unit ID.
    #[error("Invalid unit ID: {unit_id}")]
    InvalidUnitId {
        /// The invalid unit ID.
        unit_id: u8,
    },

    /// Unit ID mismatch.
    #[error("Unit ID mismatch: expected {expected}, got {actual}")]
    UnitIdMismatch {
        /// Expected unit ID.
        expected: u8,
        /// Actual unit ID.
        actual: u8,
    },

    /// Transaction ID mismatch (TCP).
    #[error("Transaction ID mismatch: expected {expected}, got {actual}")]
    TransactionIdMismatch {
        /// Expected transaction ID.
        expected: u16,
        /// Actual transaction ID.
        actual: u16,
    },

    /// Invalid MBAP header (TCP).
    #[error("Invalid MBAP header: {message}")]
    InvalidMbapHeader {
        /// Error message.
        message: String,
    },

    /// Unexpected response.
    #[error("Unexpected response: {message}")]
    UnexpectedResponse {
        /// Error message.
        message: String,
    },
}

impl ProtocolError {
    /// Creates an exception response error.
    pub fn exception_response(function_code: u8, exception_code: u8) -> Self {
        Self::ExceptionResponse {
            function_code,
            exception_code,
            exception_name: Self::exception_name(exception_code).to_string(),
        }
    }

    /// Returns the human-readable name for an exception code.
    pub fn exception_name(code: u8) -> &'static str {
        match code {
            0x01 => "Illegal Function",
            0x02 => "Illegal Data Address",
            0x03 => "Illegal Data Value",
            0x04 => "Slave Device Failure",
            0x05 => "Acknowledge",
            0x06 => "Slave Device Busy",
            0x08 => "Memory Parity Error",
            0x0A => "Gateway Path Unavailable",
            0x0B => "Gateway Target Device Failed to Respond",
            _ => "Unknown Exception",
        }
    }

    /// Creates a CRC mismatch error.
    pub fn crc_mismatch(expected: u16, actual: u16) -> Self {
        Self::CrcMismatch { expected, actual }
    }

    /// Creates a frame too short error.
    pub fn frame_too_short(expected: usize, actual: usize) -> Self {
        Self::FrameTooShort { expected, actual }
    }

    /// Creates an invalid unit ID error.
    pub fn invalid_unit_id(unit_id: u8) -> Self {
        Self::InvalidUnitId { unit_id }
    }

    /// Creates a unit ID mismatch error.
    pub fn unit_id_mismatch(expected: u8, actual: u8) -> Self {
        Self::UnitIdMismatch { expected, actual }
    }

    /// Creates a transaction ID mismatch error.
    pub fn transaction_id_mismatch(expected: u16, actual: u16) -> Self {
        Self::TransactionIdMismatch { expected, actual }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ExceptionResponse { exception_code, .. } => {
                // Retriable exceptions
                matches!(exception_code, 0x05 | 0x06 | 0x0B)
            }
            Self::CrcMismatch { .. } => true, // Might be transient
            Self::TransactionIdMismatch { .. } => true,
            _ => false,
        }
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        match self {
            Self::ExceptionResponse { exception_code, .. } => match exception_code {
                0x05 => Some(Duration::from_millis(500)), // Acknowledge
                0x06 => Some(Duration::from_secs(1)),     // Busy
                0x0B => Some(Duration::from_secs(2)),     // Gateway failed
                _ => None,
            },
            Self::CrcMismatch { .. } => Some(Duration::from_millis(100)),
            Self::TransactionIdMismatch { .. } => Some(Duration::from_millis(100)),
            _ => None,
        }
    }

    /// Returns the maximum number of retries.
    pub fn max_retries(&self) -> u32 {
        match self {
            Self::ExceptionResponse { exception_code, .. } => match exception_code {
                0x05 => 5,  // Acknowledge
                0x06 => 10, // Busy
                0x0B => 3,  // Gateway failed
                _ => 0,
            },
            Self::CrcMismatch { .. } => 3,
            Self::TransactionIdMismatch { .. } => 2,
            _ => 0,
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::ExceptionResponse { exception_code, .. } => match exception_code {
                0x05 | 0x06 => ErrorSeverity::Warning,
                0x01..=0x03 => ErrorSeverity::Error,
                _ => ErrorSeverity::Critical,
            },
            Self::CrcMismatch { .. } => ErrorSeverity::Warning,
            Self::InvalidUnitId { .. } | Self::InvalidFunctionCode { .. } => ErrorSeverity::Error,
            _ => ErrorSeverity::Warning,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::ExceptionResponse { exception_code, .. } => ErrorCode::new(2, *exception_code),
            Self::InvalidFunctionCode { .. } => ErrorCode::new(2, 20),
            Self::CrcMismatch { .. } => ErrorCode::new(2, 21),
            Self::FrameTooShort { .. } => ErrorCode::new(2, 22),
            Self::FrameTooLong { .. } => ErrorCode::new(2, 23),
            Self::InvalidUnitId { .. } => ErrorCode::new(2, 24),
            Self::UnitIdMismatch { .. } => ErrorCode::new(2, 25),
            Self::TransactionIdMismatch { .. } => ErrorCode::new(2, 26),
            Self::InvalidMbapHeader { .. } => ErrorCode::new(2, 27),
            Self::UnexpectedResponse { .. } => ErrorCode::new(2, 28),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::ExceptionResponse { exception_code, .. } => match exception_code {
                0x01 => vec![
                    "The function code is not supported by this device",
                    "Check device documentation for supported functions",
                ],
                0x02 => vec![
                    "The register address is out of range",
                    "Verify the address configuration",
                    "Check device memory map documentation",
                ],
                0x03 => vec![
                    "The value is not valid for this register",
                    "Check value range constraints",
                ],
                0x04 => vec![
                    "The device encountered an internal error",
                    "Power cycle the device if problem persists",
                ],
                0x06 => vec![
                    "The device is busy, retry after a delay",
                ],
                _ => vec!["Check device status and documentation"],
            },
            Self::CrcMismatch { .. } => vec![
                "Check serial cable connections",
                "Verify baud rate and serial settings match",
                "Reduce communication speed if errors persist",
            ],
            Self::InvalidUnitId { .. } => vec![
                "Verify the unit ID (slave address) is correct",
                "Unit ID should be 1-247 for standard Modbus",
            ],
            _ => vec!["Check protocol configuration"],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::ExceptionResponse {
                exception_name, ..
            } => {
                format!("Modbus 예외 응답: {}", exception_name)
            }
            Self::CrcMismatch { .. } => "통신 오류 (CRC 검증 실패)".to_string(),
            Self::FrameTooShort { .. } | Self::FrameTooLong { .. } => {
                "잘못된 프레임 크기".to_string()
            }
            Self::InvalidUnitId { unit_id } => {
                format!("잘못된 유닛 ID: {}", unit_id)
            }
            Self::UnitIdMismatch { expected, actual } => {
                format!("유닛 ID 불일치 (예상: {}, 실제: {})", expected, actual)
            }
            _ => "프로토콜 오류가 발생했습니다".to_string(),
        }
    }
}

// =============================================================================
// OperationError
// =============================================================================

/// Read/write operation errors.
#[derive(Debug, Error)]
pub enum OperationError {
    /// Read operation failed.
    #[error("Read failed for {register_type} at address {address}: {message}")]
    ReadFailed {
        /// Register type.
        register_type: String,
        /// Register address.
        address: u16,
        /// Number of registers.
        count: u16,
        /// Error message.
        message: String,
        /// Underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Write operation failed.
    #[error("Write failed for {register_type} at address {address}: {message}")]
    WriteFailed {
        /// Register type.
        register_type: String,
        /// Register address.
        address: u16,
        /// Error message.
        message: String,
        /// Underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Register address out of range.
    #[error("Address out of range: {address} (valid: {min}-{max})")]
    AddressOutOfRange {
        /// The invalid address.
        address: u16,
        /// Minimum valid address.
        min: u16,
        /// Maximum valid address.
        max: u16,
    },

    /// Too many registers requested.
    #[error("Too many registers requested: {count} (maximum: {max})")]
    TooManyRegisters {
        /// Requested count.
        count: u16,
        /// Maximum allowed.
        max: u16,
    },

    /// Register is read-only.
    #[error("Register at address {address} is read-only")]
    ReadOnly {
        /// Register address.
        address: u16,
    },

    /// Operation not supported.
    #[error("Operation not supported: {operation}")]
    NotSupported {
        /// Operation name.
        operation: String,
    },
}

impl OperationError {
    /// Creates a read failed error.
    pub fn read_failed(
        register_type: impl Into<String>,
        address: u16,
        count: u16,
        message: impl Into<String>,
    ) -> Self {
        Self::ReadFailed {
            register_type: register_type.into(),
            address,
            count,
            message: message.into(),
            source: None,
        }
    }

    /// Creates a write failed error.
    pub fn write_failed(
        register_type: impl Into<String>,
        address: u16,
        message: impl Into<String>,
    ) -> Self {
        Self::WriteFailed {
            register_type: register_type.into(),
            address,
            message: message.into(),
            source: None,
        }
    }

    /// Creates an address out of range error.
    pub fn address_out_of_range(address: u16, min: u16, max: u16) -> Self {
        Self::AddressOutOfRange { address, min, max }
    }

    /// Creates a too many registers error.
    pub fn too_many_registers(count: u16, max: u16) -> Self {
        Self::TooManyRegisters { count, max }
    }

    /// Creates a read-only error.
    pub fn read_only(address: u16) -> Self {
        Self::ReadOnly { address }
    }

    /// Creates a not supported error.
    pub fn not_supported(operation: impl Into<String>) -> Self {
        Self::NotSupported {
            operation: operation.into(),
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::ReadFailed { .. } | Self::WriteFailed { .. })
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        match self {
            Self::ReadFailed { .. } | Self::WriteFailed { .. } => Some(Duration::from_millis(100)),
            _ => None,
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::ReadFailed { .. } | Self::WriteFailed { .. } => ErrorSeverity::Warning,
            Self::AddressOutOfRange { .. } | Self::TooManyRegisters { .. } => ErrorSeverity::Error,
            Self::ReadOnly { .. } => ErrorSeverity::Warning,
            Self::NotSupported { .. } => ErrorSeverity::Error,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::ReadFailed { .. } => ErrorCode::new(3, 1),
            Self::WriteFailed { .. } => ErrorCode::new(3, 2),
            Self::AddressOutOfRange { .. } => ErrorCode::new(3, 3),
            Self::TooManyRegisters { .. } => ErrorCode::new(3, 4),
            Self::ReadOnly { .. } => ErrorCode::new(3, 5),
            Self::NotSupported { .. } => ErrorCode::new(3, 6),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::ReadFailed { .. } => vec![
                "Check if the device is still connected",
                "Verify the register address is valid",
                "Retry the operation",
            ],
            Self::WriteFailed { .. } => vec![
                "Check if the device allows write operations",
                "Verify the value is within valid range",
                "Check if the register is writable",
            ],
            Self::AddressOutOfRange { .. } => vec![
                "Check the address configuration",
                "Refer to device documentation for valid address range",
            ],
            Self::TooManyRegisters { .. } => vec![
                "Split the request into smaller batches",
                "Maximum is typically 125 registers per request",
            ],
            Self::ReadOnly { .. } => vec![
                "This register cannot be written",
                "Use a different register or check device configuration",
            ],
            Self::NotSupported { .. } => vec![
                "Check device capabilities",
                "This operation may not be available on this device",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::ReadFailed { address, .. } => {
                format!("레지스터 읽기 실패 (주소: {})", address)
            }
            Self::WriteFailed { address, .. } => {
                format!("레지스터 쓰기 실패 (주소: {})", address)
            }
            Self::AddressOutOfRange { address, .. } => {
                format!("주소 범위 초과: {}", address)
            }
            Self::TooManyRegisters { count, max } => {
                format!("요청 레지스터 수 초과 ({}/{})", count, max)
            }
            Self::ReadOnly { address } => {
                format!("읽기 전용 레지스터: {}", address)
            }
            Self::NotSupported { operation } => {
                format!("지원되지 않는 기능: {}", operation)
            }
        }
    }
}

// =============================================================================
// ConversionError
// =============================================================================

/// Data type conversion errors.
#[derive(Debug, Error)]
pub enum ConversionError {
    /// Type mismatch.
    #[error("Type mismatch: expected {expected}, got {actual}")]
    TypeMismatch {
        /// Expected type.
        expected: String,
        /// Actual type.
        actual: String,
    },

    /// Not enough data.
    #[error("Not enough data: expected {expected} bytes, got {actual}")]
    InsufficientData {
        /// Expected bytes.
        expected: usize,
        /// Actual bytes.
        actual: usize,
    },

    /// Too much data.
    #[error("Too much data: expected {expected} bytes, got {actual}")]
    ExcessData {
        /// Expected bytes.
        expected: usize,
        /// Actual bytes.
        actual: usize,
    },

    /// Invalid byte order.
    #[error("Invalid byte order: {order}")]
    InvalidByteOrder {
        /// The invalid byte order.
        order: String,
    },

    /// Value overflow.
    #[error("Value overflow: {value} exceeds range for {target_type}")]
    Overflow {
        /// The value that overflowed.
        value: String,
        /// Target type.
        target_type: String,
    },

    /// Invalid string encoding.
    #[error("Invalid string encoding: {message}")]
    InvalidEncoding {
        /// Error message.
        message: String,
    },

    /// Scale factor error.
    #[error("Scale factor error: {message}")]
    ScaleError {
        /// Error message.
        message: String,
    },
}

impl ConversionError {
    /// Creates a type mismatch error.
    pub fn type_mismatch(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::TypeMismatch {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Creates an insufficient data error.
    pub fn insufficient_data(expected: usize, actual: usize) -> Self {
        Self::InsufficientData { expected, actual }
    }

    /// Creates an excess data error.
    pub fn excess_data(expected: usize, actual: usize) -> Self {
        Self::ExcessData { expected, actual }
    }

    /// Creates an overflow error.
    pub fn overflow(value: impl Into<String>, target_type: impl Into<String>) -> Self {
        Self::Overflow {
            value: value.into(),
            target_type: target_type.into(),
        }
    }

    /// Creates an invalid encoding error.
    pub fn invalid_encoding(message: impl Into<String>) -> Self {
        Self::InvalidEncoding { message: message.into() }
    }

    /// Creates a scale error.
    pub fn scale_error(message: impl Into<String>) -> Self {
        Self::ScaleError { message: message.into() }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::TypeMismatch { .. } => ErrorCode::new(4, 1),
            Self::InsufficientData { .. } => ErrorCode::new(4, 2),
            Self::ExcessData { .. } => ErrorCode::new(4, 3),
            Self::InvalidByteOrder { .. } => ErrorCode::new(4, 4),
            Self::Overflow { .. } => ErrorCode::new(4, 5),
            Self::InvalidEncoding { .. } => ErrorCode::new(4, 6),
            Self::ScaleError { .. } => ErrorCode::new(4, 7),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::TypeMismatch { .. } => vec![
                "Check the data type configuration for this register",
                "Verify the device documentation for expected data types",
            ],
            Self::InsufficientData { .. } => vec![
                "Request more registers to get complete data",
                "Check if the data type requires multiple registers",
            ],
            Self::ExcessData { .. } => vec![
                "Reduce the number of requested registers",
            ],
            Self::InvalidByteOrder { .. } => vec![
                "Check the byte order configuration",
                "Common orders: Big-Endian, Little-Endian, Mid-Big-Endian",
            ],
            Self::Overflow { .. } => vec![
                "Check if the correct data type is configured",
                "The value may need a larger data type",
            ],
            Self::InvalidEncoding { .. } => vec![
                "Check string encoding (ASCII is typical for Modbus)",
            ],
            Self::ScaleError { .. } => vec![
                "Verify scale and offset values",
                "Check for division by zero",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::TypeMismatch { expected, actual } => {
                format!("데이터 타입 불일치 (예상: {}, 실제: {})", expected, actual)
            }
            Self::InsufficientData { expected, actual } => {
                format!("데이터 부족 ({}바이트 필요, {}바이트 수신)", expected, actual)
            }
            Self::ExcessData { .. } => "데이터 초과".to_string(),
            Self::InvalidByteOrder { order } => {
                format!("잘못된 바이트 순서: {}", order)
            }
            Self::Overflow { .. } => "값 오버플로우".to_string(),
            Self::InvalidEncoding { .. } => "잘못된 문자 인코딩".to_string(),
            Self::ScaleError { .. } => "스케일 변환 오류".to_string(),
        }
    }
}

// =============================================================================
// ConfigurationError
// =============================================================================

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    /// Invalid host address.
    #[error("Invalid host address: {address}")]
    InvalidHost {
        /// The invalid address.
        address: String,
        /// Reason.
        reason: String,
    },

    /// Invalid port.
    #[error("Invalid port: {port} ({reason})")]
    InvalidPort {
        /// The invalid port.
        port: u16,
        /// Reason.
        reason: String,
    },

    /// Invalid unit ID.
    #[error("Invalid unit ID: {unit_id} (valid range: 1-247)")]
    InvalidUnitId {
        /// The invalid unit ID.
        unit_id: u8,
    },

    /// Invalid baud rate.
    #[error("Invalid baud rate: {baud_rate}")]
    InvalidBaudRate {
        /// The invalid baud rate.
        baud_rate: u32,
    },

    /// Invalid timeout.
    #[error("Invalid timeout: {duration:?} ({reason})")]
    InvalidTimeout {
        /// The invalid duration.
        duration: Duration,
        /// Reason.
        reason: String,
    },

    /// Missing required field.
    #[error("Missing required configuration: {field}")]
    MissingField {
        /// The missing field.
        field: String,
    },

    /// Invalid register address format.
    #[error("Invalid register address format: {address}")]
    InvalidAddressFormat {
        /// The invalid address.
        address: String,
        /// Reason.
        reason: String,
    },

    /// Invalid data type.
    #[error("Invalid data type: {data_type}")]
    InvalidDataType {
        /// The invalid data type.
        data_type: String,
    },
}

impl ConfigurationError {
    /// Creates an invalid host error.
    pub fn invalid_host(address: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidHost {
            address: address.into(),
            reason: reason.into(),
        }
    }

    /// Creates an invalid port error.
    pub fn invalid_port(port: u16, reason: impl Into<String>) -> Self {
        Self::InvalidPort {
            port,
            reason: reason.into(),
        }
    }

    /// Creates an invalid unit ID error.
    pub fn invalid_unit_id(unit_id: u8) -> Self {
        Self::InvalidUnitId { unit_id }
    }

    /// Creates a missing field error.
    pub fn missing_field(field: impl Into<String>) -> Self {
        Self::MissingField { field: field.into() }
    }

    /// Creates an invalid address format error.
    pub fn invalid_address_format(address: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidAddressFormat {
            address: address.into(),
            reason: reason.into(),
        }
    }

    /// Creates an invalid data type error.
    pub fn invalid_data_type(data_type: impl Into<String>) -> Self {
        Self::InvalidDataType {
            data_type: data_type.into(),
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidHost { .. } => ErrorCode::new(5, 1),
            Self::InvalidPort { .. } => ErrorCode::new(5, 2),
            Self::InvalidUnitId { .. } => ErrorCode::new(5, 3),
            Self::InvalidBaudRate { .. } => ErrorCode::new(5, 4),
            Self::InvalidTimeout { .. } => ErrorCode::new(5, 5),
            Self::MissingField { .. } => ErrorCode::new(5, 6),
            Self::InvalidAddressFormat { .. } => ErrorCode::new(5, 7),
            Self::InvalidDataType { .. } => ErrorCode::new(5, 8),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::InvalidHost { .. } => vec![
                "Use a valid IP address or hostname",
                "Example: '192.168.1.100' or 'plc.local'",
            ],
            Self::InvalidPort { .. } => vec![
                "Standard Modbus TCP port is 502",
                "Port must be between 1 and 65535",
            ],
            Self::InvalidUnitId { .. } => vec![
                "Unit ID must be between 1 and 247",
                "Unit ID 0 is broadcast (not recommended)",
            ],
            Self::InvalidBaudRate { .. } => vec![
                "Common baud rates: 9600, 19200, 38400, 57600, 115200",
            ],
            Self::InvalidTimeout { .. } => vec![
                "Timeout should be between 100ms and 30s",
            ],
            Self::MissingField { .. } => vec![
                "Check the configuration file for required fields",
            ],
            Self::InvalidAddressFormat { .. } => vec![
                "Address format: 'HR:40001' or 'IR:30001' or 'C:00001'",
                "HR=Holding Register, IR=Input Register, C=Coil, DI=Discrete Input",
            ],
            Self::InvalidDataType { .. } => vec![
                "Valid types: bool, int16, uint16, int32, uint32, float32, float64, string",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidHost { address, .. } => {
                format!("잘못된 호스트 주소: {}", address)
            }
            Self::InvalidPort { port, .. } => {
                format!("잘못된 포트 번호: {}", port)
            }
            Self::InvalidUnitId { unit_id } => {
                format!("잘못된 유닛 ID: {} (1-247 범위)", unit_id)
            }
            Self::InvalidBaudRate { baud_rate } => {
                format!("잘못된 통신 속도: {}", baud_rate)
            }
            Self::InvalidTimeout { duration, .. } => {
                format!("잘못된 타임아웃: {:?}", duration)
            }
            Self::MissingField { field } => {
                format!("필수 설정 누락: {}", field)
            }
            Self::InvalidAddressFormat { address, .. } => {
                format!("잘못된 주소 형식: {}", address)
            }
            Self::InvalidDataType { data_type } => {
                format!("잘못된 데이터 타입: {}", data_type)
            }
        }
    }
}

// =============================================================================
// TimeoutError
// =============================================================================

/// Timeout errors.
#[derive(Debug, Error)]
pub enum TimeoutError {
    /// Connection timeout.
    #[error("Connection timed out after {duration:?}")]
    Connection {
        /// Timeout duration.
        duration: Duration,
    },

    /// Read operation timeout.
    #[error("Read operation timed out after {duration:?}")]
    Read {
        /// Timeout duration.
        duration: Duration,
    },

    /// Write operation timeout.
    #[error("Write operation timed out after {duration:?}")]
    Write {
        /// Timeout duration.
        duration: Duration,
    },

    /// Response timeout.
    #[error("Response timed out after {duration:?}")]
    Response {
        /// Timeout duration.
        duration: Duration,
    },
}

impl TimeoutError {
    /// Creates a connection timeout.
    pub fn connection(duration: Duration) -> Self {
        Self::Connection { duration }
    }

    /// Creates a read timeout.
    pub fn read(duration: Duration) -> Self {
        Self::Read { duration }
    }

    /// Creates a write timeout.
    pub fn write(duration: Duration) -> Self {
        Self::Write { duration }
    }

    /// Creates a response timeout.
    pub fn response(duration: Duration) -> Self {
        Self::Response { duration }
    }

    /// Returns the timeout duration.
    pub fn duration(&self) -> Duration {
        match self {
            Self::Connection { duration }
            | Self::Read { duration }
            | Self::Write { duration }
            | Self::Response { duration } => *duration,
        }
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Duration {
        // Retry with slightly longer timeout
        self.duration().mul_f32(0.5).max(Duration::from_millis(100))
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Connection { .. } => ErrorCode::new(6, 1),
            Self::Read { .. } => ErrorCode::new(6, 2),
            Self::Write { .. } => ErrorCode::new(6, 3),
            Self::Response { .. } => ErrorCode::new(6, 4),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        vec![
            "Check network connectivity",
            "Increase the timeout value",
            "Verify the device is responding",
            "Check for network congestion",
        ]
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        let duration = self.duration();
        match self {
            Self::Connection { .. } => {
                format!("연결 시간 초과 ({:.1}초)", duration.as_secs_f64())
            }
            Self::Read { .. } => {
                format!("읽기 시간 초과 ({:.1}초)", duration.as_secs_f64())
            }
            Self::Write { .. } => {
                format!("쓰기 시간 초과 ({:.1}초)", duration.as_secs_f64())
            }
            Self::Response { .. } => {
                format!("응답 시간 초과 ({:.1}초)", duration.as_secs_f64())
            }
        }
    }
}

// =============================================================================
// ErrorSeverity
// =============================================================================

/// Error severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorSeverity {
    /// Informational - no action required.
    Info,
    /// Warning - action may be required.
    Warning,
    /// Error - action required, but recoverable.
    Error,
    /// Critical - immediate action required.
    Critical,
}

impl ErrorSeverity {
    /// Converts to tracing level.
    pub fn to_tracing_level(self) -> Level {
        match self {
            Self::Info => Level::INFO,
            Self::Warning => Level::WARN,
            Self::Error => Level::ERROR,
            Self::Critical => Level::ERROR,
        }
    }

    /// Returns the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// ErrorCode
// =============================================================================

/// Structured error code for categorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode {
    /// Category (1=connection, 2=protocol, 3=operation, 4=conversion, 5=config, 6=timeout).
    pub category: u8,
    /// Specific error within category.
    pub code: u8,
}

impl ErrorCode {
    /// Creates a new error code.
    pub const fn new(category: u8, code: u8) -> Self {
        Self { category, code }
    }

    /// Returns the full error code as a u16.
    pub fn as_u16(&self) -> u16 {
        ((self.category as u16) << 8) | (self.code as u16)
    }

    /// Creates from a u16.
    pub fn from_u16(value: u16) -> Self {
        Self {
            category: (value >> 8) as u8,
            code: (value & 0xFF) as u8,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MB-{:02X}{:02X}", self.category, self.code)
    }
}

// =============================================================================
// Conversion to trap_core::DriverError
// =============================================================================

impl From<ModbusError> for trap_core::DriverError {
    fn from(error: ModbusError) -> Self {
        match error {
            ModbusError::Connection(e) => match e {
                ConnectionError::Refused { host, port, .. } => {
                    trap_core::DriverError::connection_failed(format!(
                        "Connection refused to {}:{}",
                        host, port
                    ))
                }
                ConnectionError::TimedOut { duration, .. } => {
                    trap_core::DriverError::timeout(duration)
                }
                ConnectionError::NotConnected => trap_core::DriverError::NotConnected,
                ConnectionError::Closed { reason } => trap_core::DriverError::connection_failed(
                    reason.unwrap_or_else(|| "Connection closed".to_string()),
                ),
                other => trap_core::DriverError::connection_failed(other.to_string()),
            },
            ModbusError::Timeout(e) => trap_core::DriverError::timeout(e.duration()),
            ModbusError::Protocol(e) => {
                trap_core::DriverError::protocol(e.to_string())
            }
            ModbusError::Operation(e) => match e {
                OperationError::ReadFailed {
                    address, message, ..
                } => trap_core::DriverError::read_failed(address.to_string(), message),
                OperationError::WriteFailed {
                    address, message, ..
                } => trap_core::DriverError::write_failed(address.to_string(), message),
                OperationError::AddressOutOfRange { address, .. } => {
                    trap_core::DriverError::address_not_found(address.to_string())
                }
                other => trap_core::DriverError::protocol(other.to_string()),
            },
            ModbusError::Conversion(e) => {
                trap_core::DriverError::invalid_response(e.to_string())
            }
            ModbusError::Configuration(e) => {
                trap_core::DriverError::protocol(format!("Configuration error: {}", e))
            }
        }
    }
}

// =============================================================================
// Result Type Alias
// =============================================================================

/// A Result type with ModbusError.
pub type ModbusResult<T> = Result<T, ModbusError>;

// =============================================================================
// Error Context Extension
// =============================================================================

/// Extension trait for adding context to Modbus errors.
pub trait ModbusErrorContext<T> {
    /// Adds device context to errors.
    fn with_device(self, device_id: &str) -> Result<T, ModbusError>;

    /// Adds address context to errors.
    fn with_address(self, address: u16) -> Result<T, ModbusError>;

    /// Maps to a connection error.
    fn connection_context(self, host: &str, port: u16) -> Result<T, ModbusError>;
}

impl<T> ModbusErrorContext<T> for Result<T, ModbusError> {
    fn with_device(self, device_id: &str) -> Result<T, ModbusError> {
        self.map_err(|e| {
            tracing::debug!(device_id = device_id, error = %e, "Modbus error with device context");
            e
        })
    }

    fn with_address(self, address: u16) -> Result<T, ModbusError> {
        self.map_err(|e| {
            tracing::debug!(address = address, error = %e, "Modbus error with address context");
            e
        })
    }

    fn connection_context(self, host: &str, port: u16) -> Result<T, ModbusError> {
        self.map_err(|e| {
            tracing::debug!(host = host, port = port, error = %e, "Modbus connection error");
            e
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_error_retryable() {
        assert!(ConnectionError::refused("localhost", 502).is_retryable());
        assert!(ConnectionError::timed_out("localhost", 502, Duration::from_secs(5)).is_retryable());
        assert!(ConnectionError::NotConnected.is_retryable());
        assert!(!ConnectionError::serial_access_denied("/dev/ttyUSB0").is_retryable());
    }

    #[test]
    fn test_protocol_error_exception_names() {
        assert_eq!(ProtocolError::exception_name(0x01), "Illegal Function");
        assert_eq!(ProtocolError::exception_name(0x02), "Illegal Data Address");
        assert_eq!(ProtocolError::exception_name(0x06), "Slave Device Busy");
    }

    #[test]
    fn test_protocol_error_retryable() {
        let busy = ProtocolError::exception_response(0x03, 0x06);
        assert!(busy.is_retryable());

        let illegal = ProtocolError::exception_response(0x03, 0x01);
        assert!(!illegal.is_retryable());
    }

    #[test]
    fn test_error_code() {
        let code = ErrorCode::new(1, 5);
        assert_eq!(code.to_string(), "MB-0105");
        assert_eq!(code.as_u16(), 0x0105);

        let from_u16 = ErrorCode::from_u16(0x0305);
        assert_eq!(from_u16.category, 3);
        assert_eq!(from_u16.code, 5);
    }

    #[test]
    fn test_modbus_error_conversion_to_driver_error() {
        let modbus_error = ModbusError::not_connected();
        let driver_error: trap_core::DriverError = modbus_error.into();

        assert!(matches!(driver_error, trap_core::DriverError::NotConnected));
    }

    #[test]
    fn test_timeout_error() {
        let timeout = TimeoutError::read(Duration::from_secs(5));
        assert_eq!(timeout.duration(), Duration::from_secs(5));

        let modbus_error = ModbusError::timeout(timeout);
        assert!(modbus_error.is_retryable());
        assert!(modbus_error.suggested_retry_delay().is_some());
    }

    #[test]
    fn test_recovery_hints() {
        let error = ConnectionError::refused("localhost", 502);
        let hints = error.recovery_hints();
        assert!(!hints.is_empty());
        assert!(hints.iter().any(|h| h.contains("powered on")));
    }

    #[test]
    fn test_error_severity() {
        let warning = ConnectionError::NotConnected;
        assert_eq!(warning.severity(), ErrorSeverity::Warning);

        let critical = ConnectionError::serial_access_denied("/dev/ttyUSB0");
        assert_eq!(critical.severity(), ErrorSeverity::Critical);
    }

    #[test]
    fn test_conversion_error() {
        let error = ConversionError::type_mismatch("int32", "float32");
        assert!(error.to_string().contains("int32"));
        assert!(error.to_string().contains("float32"));

        let modbus_error = ModbusError::conversion(error);
        assert!(!modbus_error.is_retryable());
    }

    #[test]
    fn test_configuration_error() {
        let error = ConfigurationError::invalid_unit_id(0);
        assert!(error.to_string().contains("0"));
        assert!(error.to_string().contains("1-247"));

        let hints = error.recovery_hints();
        assert!(hints.iter().any(|h| h.contains("247")));
    }

    #[test]
    fn test_error_category() {
        assert_eq!(ModbusError::not_connected().category(), "connection");
        assert_eq!(
            ModbusError::exception(0x03, 0x02).category(),
            "protocol"
        );
        assert_eq!(
            ModbusError::read_timeout(Duration::from_secs(1)).category(),
            "timeout"
        );
    }

    #[test]
    fn test_user_messages() {
        let error = ModbusError::tcp_refused("192.168.1.100", 502);
        let message = error.user_message();
        assert!(message.contains("192.168.1.100"));
        assert!(message.contains("502"));
    }
}
