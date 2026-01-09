// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Unified error hierarchy for TRAP.
//!
//! This module defines a comprehensive error type system that:
//!
//! - Provides clear, descriptive error messages
//! - Supports error chaining for traceability
//! - Distinguishes between retryable and non-retryable errors
//! - Maps errors to appropriate HTTP status codes
//! - Supports structured logging
//!
//! # Error Hierarchy
//!
//! ```text
//! TrapError (root)
//! ├── ConfigError     - Configuration parsing and validation
//! ├── DriverError     - Protocol driver operations
//! ├── BufferError     - Offline buffer operations
//! ├── BusError        - Message bus operations
//! └── ApiError        - REST API errors
//! ```
//!
//! # Examples
//!
//! ```
//! use trap_core::error::{TrapError, DriverError};
//! use std::time::Duration;
//!
//! let error = DriverError::timeout(Duration::from_secs(5));
//! assert!(error.is_retryable());
//!
//! let trap_error: TrapError = error.into();
//! assert!(trap_error.is_retryable());
//! ```

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

// =============================================================================
// TrapError - Root Error Type
// =============================================================================

/// The root error type for TRAP.
///
/// All errors in TRAP can be converted to this type, providing a unified
/// error handling interface across the entire system.
#[derive(Debug, Error)]
pub enum TrapError {
    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Protocol driver error.
    #[error("Driver error: {0}")]
    Driver(#[from] DriverError),

    /// Buffer error.
    #[error("Buffer error: {0}")]
    Buffer(#[from] BufferError),

    /// Message bus error.
    #[error("Bus error: {0}")]
    Bus(#[from] BusError),

    /// API error.
    #[error("API error: {0}")]
    Api(#[from] ApiError),
}

impl TrapError {
    /// Returns `true` if this error is retryable.
    ///
    /// Retryable errors are typically transient issues that may succeed
    /// on a subsequent attempt.
    pub fn is_retryable(&self) -> bool {
        match self {
            TrapError::Driver(e) => e.is_retryable(),
            TrapError::Buffer(e) => e.is_retryable(),
            TrapError::Bus(e) => e.is_retryable(),
            _ => false,
        }
    }

    /// Returns a user-friendly error message.
    ///
    /// This message is suitable for display to end users and avoids
    /// exposing internal implementation details.
    pub fn user_message(&self) -> String {
        match self {
            TrapError::Config(e) => format!("설정 오류: {}", e.user_message()),
            TrapError::Driver(e) => format!("장비 통신 오류: {}", e.user_message()),
            TrapError::Buffer(e) => format!("데이터 저장 오류: {}", e.user_message()),
            TrapError::Bus(e) => format!("내부 통신 오류: {}", e),
            TrapError::Api(e) => e.user_message(),
        }
    }

    /// Returns the error type as a string for logging/metrics.
    pub fn error_type(&self) -> &'static str {
        match self {
            TrapError::Config(_) => "config",
            TrapError::Driver(_) => "driver",
            TrapError::Buffer(_) => "buffer",
            TrapError::Bus(_) => "bus",
            TrapError::Api(_) => "api",
        }
    }

    /// Returns the HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            TrapError::Config(_) => 400,
            TrapError::Driver(e) => e.status_code(),
            TrapError::Buffer(_) => 503,
            TrapError::Bus(_) => 503,
            TrapError::Api(e) => e.status_code(),
        }
    }
}

// =============================================================================
// ConfigError
// =============================================================================

/// Configuration-related errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to parse configuration file.
    #[error("Failed to parse config file '{path}': {message}")]
    Parse {
        /// Path to the configuration file.
        path: PathBuf,
        /// Error message.
        message: String,
        /// Line number (if available).
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Configuration validation failed.
    #[error("Validation failed for '{field}': {message}")]
    Validation {
        /// The field that failed validation.
        field: String,
        /// Error message.
        message: String,
    },

    /// Required field is missing.
    #[error("Missing required field: {field}")]
    MissingField {
        /// The missing field name.
        field: String,
    },

    /// File I/O error.
    #[error("Failed to read config file '{path}': {source}")]
    Io {
        /// Path to the file.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Invalid address format.
    #[error("Invalid address format '{address}': {message}")]
    InvalidAddress {
        /// The invalid address string.
        address: String,
        /// Error message.
        message: String,
    },

    /// Duplicate device ID.
    #[error("Duplicate device ID: {device_id}")]
    DuplicateDeviceId {
        /// The duplicated device ID.
        device_id: String,
    },

    /// Invalid encryption key.
    #[error("Invalid encryption key: {message}")]
    InvalidEncryptionKey {
        /// Error message.
        message: String,
    },

    /// Decryption failed.
    #[error("Failed to decrypt value: {message}")]
    DecryptionFailed {
        /// Error message.
        message: String,
    },
}

impl ConfigError {
    /// Creates a validation error.
    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }

    /// Creates a missing field error.
    pub fn missing_field(field: impl Into<String>) -> Self {
        Self::MissingField { field: field.into() }
    }

    /// Creates a parse error.
    pub fn parse(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::Parse {
            path: path.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Creates an invalid address error.
    pub fn invalid_address(address: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidAddress {
            address: address.into(),
            message: message.into(),
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            ConfigError::Parse { path, message, .. } => {
                format!("설정 파일 파싱 실패 ({}): {}", path.display(), message)
            }
            ConfigError::Validation { field, message } => {
                format!("설정 검증 실패 ({}): {}", field, message)
            }
            ConfigError::MissingField { field } => {
                format!("필수 설정 누락: {}", field)
            }
            ConfigError::Io { path, .. } => {
                format!("설정 파일 읽기 실패: {}", path.display())
            }
            ConfigError::InvalidAddress { address, message } => {
                format!("잘못된 주소 형식 ({}): {}", address, message)
            }
            ConfigError::DuplicateDeviceId { device_id } => {
                format!("중복된 장비 ID: {}", device_id)
            }
            ConfigError::InvalidEncryptionKey { .. } => "암호화 키가 유효하지 않습니다".to_string(),
            ConfigError::DecryptionFailed { .. } => "복호화에 실패했습니다".to_string(),
        }
    }
}

// =============================================================================
// DriverError
// =============================================================================

/// Protocol driver errors.
#[derive(Debug, Error)]
pub enum DriverError {
    /// Connection failed.
    #[error("Connection failed: {message}")]
    ConnectionFailed {
        /// Error message.
        message: String,
        /// Underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Read operation failed.
    #[error("Read failed for '{address}': {message}")]
    ReadFailed {
        /// The address that failed.
        address: String,
        /// Error message.
        message: String,
    },

    /// Write operation failed.
    #[error("Write failed for '{address}': {message}")]
    WriteFailed {
        /// The address that failed.
        address: String,
        /// Error message.
        message: String,
    },

    /// Operation timed out.
    #[error("Operation timed out after {duration:?}")]
    Timeout {
        /// The timeout duration.
        duration: Duration,
    },

    /// Device is not connected.
    #[error("Device is not connected")]
    NotConnected,

    /// Protocol-specific error.
    #[error("Protocol error: {message}")]
    Protocol {
        /// Error message.
        message: String,
    },

    /// Invalid response from device.
    #[error("Invalid response: {message}")]
    InvalidResponse {
        /// Error message.
        message: String,
    },

    /// Address not found.
    #[error("Address not found: {address}")]
    AddressNotFound {
        /// The missing address.
        address: String,
    },

    /// Device not found.
    #[error("Device not found: {device_id}")]
    DeviceNotFound {
        /// The device ID.
        device_id: String,
    },

    /// Circuit breaker is open.
    #[error("Circuit breaker is open for device '{device_id}'")]
    CircuitOpen {
        /// The device ID.
        device_id: String,
    },

    /// Subscription error.
    #[error("Subscription error: {message}")]
    Subscription {
        /// Error message.
        message: String,
    },
}

impl DriverError {
    /// Creates a connection failed error.
    pub fn connection_failed(message: impl Into<String>) -> Self {
        Self::ConnectionFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Creates a connection failed error with a source.
    pub fn connection_failed_with<E>(message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::ConnectionFailed {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Creates a read failed error.
    pub fn read_failed(address: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ReadFailed {
            address: address.into(),
            message: message.into(),
        }
    }

    /// Creates a write failed error.
    pub fn write_failed(address: impl Into<String>, message: impl Into<String>) -> Self {
        Self::WriteFailed {
            address: address.into(),
            message: message.into(),
        }
    }

    /// Creates a timeout error.
    pub fn timeout(duration: Duration) -> Self {
        Self::Timeout { duration }
    }

    /// Creates a protocol error.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol { message: message.into() }
    }

    /// Creates an invalid response error.
    pub fn invalid_response(message: impl Into<String>) -> Self {
        Self::InvalidResponse { message: message.into() }
    }

    /// Creates an address not found error.
    pub fn address_not_found(address: impl Into<String>) -> Self {
        Self::AddressNotFound { address: address.into() }
    }

    /// Creates a device not found error.
    pub fn device_not_found(device_id: impl Into<String>) -> Self {
        Self::DeviceNotFound {
            device_id: device_id.into(),
        }
    }

    /// Creates a circuit open error.
    pub fn circuit_open(device_id: impl Into<String>) -> Self {
        Self::CircuitOpen {
            device_id: device_id.into(),
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            DriverError::Timeout { .. }
                | DriverError::ConnectionFailed { .. }
                | DriverError::NotConnected
                | DriverError::CircuitOpen { .. }
        )
    }

    /// Returns the HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            DriverError::NotConnected | DriverError::CircuitOpen { .. } => 503,
            DriverError::Timeout { .. } => 504,
            DriverError::AddressNotFound { .. } | DriverError::DeviceNotFound { .. } => 404,
            DriverError::WriteFailed { .. } => 500,
            _ => 500,
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            DriverError::ConnectionFailed { .. } => "장비 연결에 실패했습니다".to_string(),
            DriverError::ReadFailed { address, .. } => format!("데이터 읽기 실패 ({})", address),
            DriverError::WriteFailed { address, .. } => format!("데이터 쓰기 실패 ({})", address),
            DriverError::Timeout { duration } => {
                format!("응답 시간 초과 ({:.1}초)", duration.as_secs_f64())
            }
            DriverError::NotConnected => "장비가 연결되어 있지 않습니다".to_string(),
            DriverError::Protocol { message } => format!("프로토콜 오류: {}", message),
            DriverError::InvalidResponse { .. } => "잘못된 응답을 받았습니다".to_string(),
            DriverError::AddressNotFound { address } => format!("주소를 찾을 수 없습니다: {}", address),
            DriverError::DeviceNotFound { device_id } => {
                format!("장비를 찾을 수 없습니다: {}", device_id)
            }
            DriverError::CircuitOpen { device_id } => {
                format!("장비 보호 모드 활성화됨: {}", device_id)
            }
            DriverError::Subscription { .. } => "구독 오류가 발생했습니다".to_string(),
        }
    }

    /// Adds device context to the error.
    pub fn with_device(self, device_id: &str) -> Self {
        match self {
            DriverError::ConnectionFailed { message, source } => DriverError::ConnectionFailed {
                message: format!("[{}] {}", device_id, message),
                source,
            },
            DriverError::ReadFailed { address, message } => DriverError::ReadFailed {
                address: format!("{}:{}", device_id, address),
                message,
            },
            DriverError::WriteFailed { address, message } => DriverError::WriteFailed {
                address: format!("{}:{}", device_id, address),
                message,
            },
            other => other,
        }
    }

    /// Returns the error type for logging/metrics.
    pub fn error_type(&self) -> &'static str {
        match self {
            DriverError::ConnectionFailed { .. } => "connection_failed",
            DriverError::ReadFailed { .. } => "read_failed",
            DriverError::WriteFailed { .. } => "write_failed",
            DriverError::Timeout { .. } => "timeout",
            DriverError::NotConnected => "not_connected",
            DriverError::Protocol { .. } => "protocol",
            DriverError::InvalidResponse { .. } => "invalid_response",
            DriverError::AddressNotFound { .. } => "address_not_found",
            DriverError::DeviceNotFound { .. } => "device_not_found",
            DriverError::CircuitOpen { .. } => "circuit_open",
            DriverError::Subscription { .. } => "subscription",
        }
    }
}

impl Clone for DriverError {
    fn clone(&self) -> Self {
        match self {
            DriverError::ConnectionFailed { message, .. } => DriverError::ConnectionFailed {
                message: message.clone(),
                source: None,
            },
            DriverError::ReadFailed { address, message } => DriverError::ReadFailed {
                address: address.clone(),
                message: message.clone(),
            },
            DriverError::WriteFailed { address, message } => DriverError::WriteFailed {
                address: address.clone(),
                message: message.clone(),
            },
            DriverError::Timeout { duration } => DriverError::Timeout { duration: *duration },
            DriverError::NotConnected => DriverError::NotConnected,
            DriverError::Protocol { message } => DriverError::Protocol { message: message.clone() },
            DriverError::InvalidResponse { message } => {
                DriverError::InvalidResponse { message: message.clone() }
            }
            DriverError::AddressNotFound { address } => {
                DriverError::AddressNotFound { address: address.clone() }
            }
            DriverError::DeviceNotFound { device_id } => {
                DriverError::DeviceNotFound { device_id: device_id.clone() }
            }
            DriverError::CircuitOpen { device_id } => {
                DriverError::CircuitOpen { device_id: device_id.clone() }
            }
            DriverError::Subscription { message } => {
                DriverError::Subscription { message: message.clone() }
            }
        }
    }
}

// =============================================================================
// BufferError
// =============================================================================

/// Buffer-related errors.
#[derive(Debug, Error)]
pub enum BufferError {
    /// Failed to store data.
    #[error("Failed to store data: {message}")]
    StoreFailed {
        /// Error message.
        message: String,
        /// Underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Failed to flush buffer.
    #[error("Failed to flush buffer: {message}")]
    FlushFailed {
        /// Error message.
        message: String,
        /// Underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Buffer capacity exceeded.
    #[error("Buffer capacity exceeded: {current}/{max} bytes")]
    CapacityExceeded {
        /// Current size.
        current: u64,
        /// Maximum size.
        max: u64,
    },

    /// Data corruption detected.
    #[error("Corrupted data: {message}")]
    CorruptedData {
        /// Error message.
        message: String,
    },

    /// Database error.
    #[error("Database error: {message}")]
    Database {
        /// Error message.
        message: String,
    },

    /// Upstream connection failed.
    #[error("Upstream connection failed: {message}")]
    UpstreamFailed {
        /// Error message.
        message: String,
    },
}

impl BufferError {
    /// Creates a store failed error.
    pub fn store_failed(message: impl Into<String>) -> Self {
        Self::StoreFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Creates a flush failed error.
    pub fn flush_failed(message: impl Into<String>) -> Self {
        Self::FlushFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Creates a capacity exceeded error.
    pub fn capacity_exceeded(current: u64, max: u64) -> Self {
        Self::CapacityExceeded { current, max }
    }

    /// Creates a corrupted data error.
    pub fn corrupted_data(message: impl Into<String>) -> Self {
        Self::CorruptedData { message: message.into() }
    }

    /// Creates a database error.
    pub fn database(message: impl Into<String>) -> Self {
        Self::Database { message: message.into() }
    }

    /// Creates an upstream failed error.
    pub fn upstream_failed(message: impl Into<String>) -> Self {
        Self::UpstreamFailed { message: message.into() }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            BufferError::StoreFailed { .. }
                | BufferError::FlushFailed { .. }
                | BufferError::UpstreamFailed { .. }
        )
    }

    /// Returns the error type for logging/metrics.
    pub fn error_type(&self) -> &'static str {
        match self {
            BufferError::StoreFailed { .. } => "store_failed",
            BufferError::FlushFailed { .. } => "flush_failed",
            BufferError::CapacityExceeded { .. } => "capacity_exceeded",
            BufferError::CorruptedData { .. } => "corrupted_data",
            BufferError::Database { .. } => "database",
            BufferError::UpstreamFailed { .. } => "upstream_failed",
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            BufferError::StoreFailed { .. } => "데이터 저장에 실패했습니다".to_string(),
            BufferError::FlushFailed { .. } => "버퍼 전송에 실패했습니다".to_string(),
            BufferError::CapacityExceeded { current, max } => {
                format!("버퍼 용량 초과 ({}/{})", current, max)
            }
            BufferError::CorruptedData { .. } => "데이터가 손상되었습니다".to_string(),
            BufferError::Database { .. } => "데이터베이스 오류가 발생했습니다".to_string(),
            BufferError::UpstreamFailed { .. } => "상위 시스템 연결에 실패했습니다".to_string(),
        }
    }
}

// =============================================================================
// BusError
// =============================================================================

/// Message bus errors.
#[derive(Debug, Error)]
pub enum BusError {
    /// Channel is closed.
    #[error("Channel is closed")]
    Closed,

    /// Receiver lagged behind.
    #[error("Receiver lagged by {count} messages")]
    Lagged {
        /// Number of missed messages.
        count: u64,
    },

    /// Failed to send message.
    #[error("Failed to send message")]
    SendFailed,

    /// Command timeout.
    #[error("Command timed out after {duration:?}")]
    CommandTimeout {
        /// Timeout duration.
        duration: Duration,
    },

    /// Response channel closed.
    #[error("Response channel closed")]
    ResponseChannelClosed,

    /// No receivers available.
    #[error("No receivers available")]
    NoReceivers,
}

impl BusError {
    /// Creates a lagged error.
    pub fn lagged(count: u64) -> Self {
        Self::Lagged { count }
    }

    /// Creates a command timeout error.
    pub fn command_timeout(duration: Duration) -> Self {
        Self::CommandTimeout { duration }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(self, BusError::Lagged { .. } | BusError::CommandTimeout { .. })
    }
}

// =============================================================================
// CommandError
// =============================================================================

/// Command bus specific errors.
///
/// These errors are used by the `CommandBus` and `CommandHandler` to indicate
/// specific command processing failures.
#[derive(Debug, Error, Clone)]
pub enum CommandError {
    /// Command channel is closed.
    #[error("Command channel closed")]
    ChannelClosed,

    /// Response channel was closed before receiving response.
    #[error("Response channel closed")]
    ResponseChannelClosed,

    /// Command timed out waiting for response.
    #[error("Command timed out after {timeout:?}")]
    Timeout {
        /// The timeout duration.
        timeout: Duration,
    },

    /// Device not found.
    #[error("Device not found: {device_id}")]
    DeviceNotFound {
        /// The device ID.
        device_id: String,
    },

    /// Driver error occurred during command processing.
    #[error("Driver error: {message}")]
    DriverError {
        /// Error message.
        message: String,
    },

    /// Command was rejected (e.g., circuit breaker open).
    #[error("Command rejected: {reason}")]
    Rejected {
        /// Rejection reason.
        reason: String,
    },

    /// Command already expired before processing.
    #[error("Command expired")]
    Expired,
}

impl CommandError {
    /// Creates a timeout error.
    pub fn timeout(timeout: Duration) -> Self {
        Self::Timeout { timeout }
    }

    /// Creates a device not found error.
    pub fn device_not_found(device_id: impl Into<String>) -> Self {
        Self::DeviceNotFound {
            device_id: device_id.into(),
        }
    }

    /// Creates a driver error.
    pub fn driver_error(message: impl Into<String>) -> Self {
        Self::DriverError {
            message: message.into(),
        }
    }

    /// Creates a rejected error.
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self::Rejected {
            reason: reason.into(),
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            CommandError::Timeout { .. } | CommandError::DriverError { .. }
        )
    }

    /// Returns the error type for logging/metrics.
    pub fn error_type(&self) -> &'static str {
        match self {
            CommandError::ChannelClosed => "channel_closed",
            CommandError::ResponseChannelClosed => "response_channel_closed",
            CommandError::Timeout { .. } => "timeout",
            CommandError::DeviceNotFound { .. } => "device_not_found",
            CommandError::DriverError { .. } => "driver_error",
            CommandError::Rejected { .. } => "rejected",
            CommandError::Expired => "expired",
        }
    }
}

impl From<DriverError> for CommandError {
    fn from(err: DriverError) -> Self {
        Self::DriverError {
            message: err.to_string(),
        }
    }
}

// =============================================================================
// ApiError
// =============================================================================

/// REST API errors.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Resource not found.
    #[error("Resource not found: {resource}")]
    NotFound {
        /// The resource that was not found.
        resource: String,
    },

    /// Bad request.
    #[error("Bad request: {message}")]
    BadRequest {
        /// Error message.
        message: String,
    },

    /// Unauthorized access.
    #[error("Unauthorized")]
    Unauthorized,

    /// Access forbidden.
    #[error("Forbidden")]
    Forbidden,

    /// Validation error.
    #[error("Validation error: {message}")]
    Validation {
        /// Error message.
        message: String,
    },

    /// Rate limit exceeded.
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Internal server error.
    #[error("Internal error: {message}")]
    Internal {
        /// Error message.
        message: String,
        /// Underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl ApiError {
    /// Creates a not found error.
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound { resource: resource.into() }
    }

    /// Creates a bad request error.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest { message: message.into() }
    }

    /// Creates a validation error.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation { message: message.into() }
    }

    /// Creates an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
            source: None,
        }
    }

    /// Creates an internal error with a source.
    pub fn internal_with<E>(message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Internal {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Returns the HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            ApiError::NotFound { .. } => 404,
            ApiError::BadRequest { .. } => 400,
            ApiError::Unauthorized => 401,
            ApiError::Forbidden => 403,
            ApiError::Validation { .. } => 422,
            ApiError::RateLimitExceeded => 429,
            ApiError::Internal { .. } => 500,
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            ApiError::NotFound { resource } => format!("{}을(를) 찾을 수 없습니다", resource),
            ApiError::BadRequest { message } => message.clone(),
            ApiError::Unauthorized => "인증이 필요합니다".to_string(),
            ApiError::Forbidden => "접근 권한이 없습니다".to_string(),
            ApiError::Validation { message } => format!("입력 검증 실패: {}", message),
            ApiError::RateLimitExceeded => "요청 한도를 초과했습니다".to_string(),
            ApiError::Internal { .. } => "서버 내부 오류가 발생했습니다".to_string(),
        }
    }
}

// =============================================================================
// Result Type Aliases
// =============================================================================

/// A Result type with TrapError.
pub type TrapResult<T> = Result<T, TrapError>;

/// A Result type with ConfigError.
pub type ConfigResult<T> = Result<T, ConfigError>;

/// A Result type with DriverError.
pub type DriverResult<T> = Result<T, DriverError>;

/// A Result type with BufferError.
pub type BufferResult<T> = Result<T, BufferError>;

/// A Result type with BusError.
pub type BusResult<T> = Result<T, BusError>;

/// A Result type with ApiError.
pub type ApiResult<T> = Result<T, ApiError>;

/// A Result type with CommandError.
pub type CommandResult<T> = Result<T, CommandError>;

// =============================================================================
// Error Context Extension
// =============================================================================

/// Extension trait for adding context to errors.
pub trait ErrorContext<T, E> {
    /// Adds context to an error.
    fn context(self, message: impl Into<String>) -> Result<T, ContextError<E>>;

    /// Adds context using a closure.
    fn with_context<F, M>(self, f: F) -> Result<T, ContextError<E>>
    where
        F: FnOnce() -> M,
        M: Into<String>;
}

impl<T, E: std::error::Error> ErrorContext<T, E> for Result<T, E> {
    fn context(self, message: impl Into<String>) -> Result<T, ContextError<E>> {
        self.map_err(|e| ContextError {
            message: message.into(),
            source: e,
        })
    }

    fn with_context<F, M>(self, f: F) -> Result<T, ContextError<E>>
    where
        F: FnOnce() -> M,
        M: Into<String>,
    {
        self.map_err(|e| ContextError {
            message: f().into(),
            source: e,
        })
    }
}

/// An error with additional context.
#[derive(Debug)]
pub struct ContextError<E> {
    message: String,
    source: E,
}

impl<E: std::error::Error> fmt::Display for ContextError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.message, self.source)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ContextError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_error_retryable() {
        assert!(DriverError::timeout(Duration::from_secs(5)).is_retryable());
        assert!(DriverError::connection_failed("test").is_retryable());
        assert!(DriverError::NotConnected.is_retryable());
        assert!(!DriverError::read_failed("addr", "error").is_retryable());
    }

    #[test]
    fn test_driver_error_status_code() {
        assert_eq!(DriverError::NotConnected.status_code(), 503);
        assert_eq!(DriverError::timeout(Duration::from_secs(1)).status_code(), 504);
        assert_eq!(DriverError::address_not_found("test").status_code(), 404);
    }

    #[test]
    fn test_trap_error_conversion() {
        let driver_error = DriverError::timeout(Duration::from_secs(5));
        let trap_error: TrapError = driver_error.into();

        assert!(trap_error.is_retryable());
        assert_eq!(trap_error.error_type(), "driver");
    }

    #[test]
    fn test_config_error() {
        let error = ConfigError::validation("port", "must be positive");
        assert!(matches!(error, ConfigError::Validation { .. }));

        let error = ConfigError::missing_field("host");
        assert!(matches!(error, ConfigError::MissingField { .. }));
    }

    #[test]
    fn test_api_error_status_code() {
        assert_eq!(ApiError::not_found("device").status_code(), 404);
        assert_eq!(ApiError::Unauthorized.status_code(), 401);
        assert_eq!(ApiError::Forbidden.status_code(), 403);
        assert_eq!(ApiError::RateLimitExceeded.status_code(), 429);
    }

    #[test]
    fn test_buffer_error() {
        let error = BufferError::capacity_exceeded(1000, 500);
        assert!(matches!(error, BufferError::CapacityExceeded { .. }));
        assert!(!error.is_retryable());

        let error = BufferError::flush_failed("network error");
        assert!(error.is_retryable());
    }

    #[test]
    fn test_driver_error_with_device() {
        let error = DriverError::connection_failed("timeout");
        let with_device = error.with_device("plc-001");

        match with_device {
            DriverError::ConnectionFailed { message, .. } => {
                assert!(message.contains("plc-001"));
            }
            _ => panic!("Expected ConnectionFailed"),
        }
    }

    #[test]
    fn test_error_context() {
        let result: Result<(), std::io::Error> =
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"));

        let with_context = result.context("Failed to load config");
        assert!(with_context.is_err());

        let error = with_context.unwrap_err();
        assert!(error.to_string().contains("Failed to load config"));
    }
}
