// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA protocol error types with comprehensive diagnostics.
//!
//! This module provides a rich error type hierarchy for OPC UA operations,
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
//! OpcUaError
//! ├── Connection    - Session and endpoint issues
//! ├── Session       - Session lifecycle errors
//! ├── Security      - Authentication and encryption errors
//! ├── Browse        - Node browsing failures
//! ├── Operation     - Read/write operation failures
//! ├── Subscription  - Subscription and monitoring errors
//! ├── Conversion    - Data type conversion errors
//! └── Configuration - Invalid settings
//! ```
//!
//! # Examples
//!
//! ```
//! use trap_opcua::error::{OpcUaError, ConnectionError, ErrorSeverity};
//!
//! let error = OpcUaError::connection(ConnectionError::refused(
//!     "opc.tcp://localhost:4840"
//! ));
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
// OpcUaError - Main Error Type
// =============================================================================

/// The main error type for OPC UA operations.
///
/// This enum categorizes errors by their domain, making it easy to handle
/// specific error types while maintaining a unified interface.
#[derive(Debug, Error)]
pub enum OpcUaError {
    /// Connection-related errors.
    #[error("{0}")]
    Connection(#[from] ConnectionError),

    /// Session lifecycle errors.
    #[error("{0}")]
    Session(#[from] SessionError),

    /// Security and authentication errors.
    #[error("{0}")]
    Security(#[from] SecurityError),

    /// Node browsing errors.
    #[error("{0}")]
    Browse(#[from] BrowseError),

    /// Read/write operation errors.
    #[error("{0}")]
    Operation(#[from] OperationError),

    /// Subscription and monitoring errors.
    #[error("{0}")]
    Subscription(#[from] SubscriptionError),

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

impl OpcUaError {
    // =========================================================================
    // Factory Methods
    // =========================================================================

    /// Creates a connection error.
    #[inline]
    pub fn connection(error: ConnectionError) -> Self {
        Self::Connection(error)
    }

    /// Creates a session error.
    #[inline]
    pub fn session(error: SessionError) -> Self {
        Self::Session(error)
    }

    /// Creates a security error.
    #[inline]
    pub fn security(error: SecurityError) -> Self {
        Self::Security(error)
    }

    /// Creates a browse error.
    #[inline]
    pub fn browse(error: BrowseError) -> Self {
        Self::Browse(error)
    }

    /// Creates an operation error.
    #[inline]
    pub fn operation(error: OperationError) -> Self {
        Self::Operation(error)
    }

    /// Creates a subscription error.
    #[inline]
    pub fn subscription(error: SubscriptionError) -> Self {
        Self::Subscription(error)
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

    /// Creates a connection refused error.
    pub fn connection_refused(endpoint: impl Into<String>) -> Self {
        Self::Connection(ConnectionError::refused(endpoint))
    }

    /// Creates a not connected error.
    pub fn not_connected() -> Self {
        Self::Connection(ConnectionError::NotConnected)
    }

    /// Creates a session creation failed error.
    pub fn session_failed(message: impl Into<String>) -> Self {
        Self::Session(SessionError::creation_failed(message))
    }

    /// Creates an authentication failed error.
    pub fn auth_failed(message: impl Into<String>) -> Self {
        Self::Security(SecurityError::authentication_failed(message))
    }

    /// Creates a node not found error.
    pub fn node_not_found(node_id: impl Into<String>) -> Self {
        Self::Browse(BrowseError::node_not_found(node_id))
    }

    /// Creates a read failed error.
    pub fn read_failed(node_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Operation(OperationError::read_failed(node_id, message))
    }

    /// Creates a write failed error.
    pub fn write_failed(node_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Operation(OperationError::write_failed(node_id, message))
    }

    /// Creates a read operation timeout.
    pub fn read_timeout(duration: Duration) -> Self {
        Self::Timeout(TimeoutError::read(duration))
    }

    /// Creates a type mismatch error.
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
            Self::Session(e) => e.is_retryable(),
            Self::Security(e) => e.is_retryable(),
            Self::Browse(e) => e.is_retryable(),
            Self::Operation(e) => e.is_retryable(),
            Self::Subscription(e) => e.is_retryable(),
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
            Self::Session(e) => e.suggested_retry_delay(),
            Self::Security(e) => e.suggested_retry_delay(),
            Self::Browse(e) => e.suggested_retry_delay(),
            Self::Operation(e) => e.suggested_retry_delay(),
            Self::Subscription(e) => e.suggested_retry_delay(),
            Self::Timeout(e) => Some(e.suggested_retry_delay()),
            _ => None,
        }
    }

    /// Returns the maximum number of retries recommended for this error.
    pub fn max_retries(&self) -> u32 {
        match self {
            Self::Connection(e) => e.max_retries(),
            Self::Session(e) => e.max_retries(),
            Self::Security(_) => 0,
            Self::Browse(_) => 2,
            Self::Operation(_) => 3,
            Self::Subscription(_) => 3,
            Self::Timeout(_) => 2,
            _ => 0,
        }
    }

    /// Returns the severity level of this error.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::Connection(e) => e.severity(),
            Self::Session(e) => e.severity(),
            Self::Security(e) => e.severity(),
            Self::Browse(e) => e.severity(),
            Self::Operation(e) => e.severity(),
            Self::Subscription(e) => e.severity(),
            Self::Timeout(_) => ErrorSeverity::Warning,
            Self::Conversion(_) => ErrorSeverity::Error,
            Self::Configuration(_) => ErrorSeverity::Critical,
        }
    }

    /// Returns the error category for logging and metrics.
    pub fn category(&self) -> &'static str {
        match self {
            Self::Connection(_) => "connection",
            Self::Session(_) => "session",
            Self::Security(_) => "security",
            Self::Browse(_) => "browse",
            Self::Operation(_) => "operation",
            Self::Subscription(_) => "subscription",
            Self::Timeout(_) => "timeout",
            Self::Conversion(_) => "conversion",
            Self::Configuration(_) => "configuration",
        }
    }

    /// Returns a unique error code for this error.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Connection(e) => e.error_code(),
            Self::Session(e) => e.error_code(),
            Self::Security(e) => e.error_code(),
            Self::Browse(e) => e.error_code(),
            Self::Operation(e) => e.error_code(),
            Self::Subscription(e) => e.error_code(),
            Self::Timeout(e) => e.error_code(),
            Self::Conversion(e) => e.error_code(),
            Self::Configuration(e) => e.error_code(),
        }
    }

    /// Returns recovery hints for this error.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::Connection(e) => e.recovery_hints(),
            Self::Session(e) => e.recovery_hints(),
            Self::Security(e) => e.recovery_hints(),
            Self::Browse(e) => e.recovery_hints(),
            Self::Operation(e) => e.recovery_hints(),
            Self::Subscription(e) => e.recovery_hints(),
            Self::Timeout(e) => e.recovery_hints(),
            Self::Conversion(e) => e.recovery_hints(),
            Self::Configuration(e) => e.recovery_hints(),
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Connection(e) => e.user_message(),
            Self::Session(e) => e.user_message(),
            Self::Security(e) => e.user_message(),
            Self::Browse(e) => e.user_message(),
            Self::Operation(e) => e.user_message(),
            Self::Subscription(e) => e.user_message(),
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

/// Connection-related errors for OPC UA.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// Connection refused.
    #[error("Connection refused to '{endpoint}'")]
    Refused {
        /// Target endpoint.
        endpoint: String,
        /// Underlying error.
        #[source]
        source: Option<io::Error>,
    },

    /// Connection timed out.
    #[error("Connection timed out to '{endpoint}' after {duration:?}")]
    TimedOut {
        /// Target endpoint.
        endpoint: String,
        /// Timeout duration.
        duration: Duration,
    },

    /// Endpoint not found.
    #[error("Endpoint not found: '{endpoint}'")]
    EndpointNotFound {
        /// The endpoint URL.
        endpoint: String,
    },

    /// Invalid endpoint URL.
    #[error("Invalid endpoint URL: '{url}' - {reason}")]
    InvalidEndpoint {
        /// The invalid URL.
        url: String,
        /// Reason.
        reason: String,
    },

    /// No suitable endpoint found.
    #[error("No suitable endpoint found with security mode '{security_mode}'")]
    NoSuitableEndpoint {
        /// Required security mode.
        security_mode: String,
    },

    /// Server not responding.
    #[error("Server not responding at '{endpoint}'")]
    ServerNotResponding {
        /// Target endpoint.
        endpoint: String,
    },

    /// Connection closed unexpectedly.
    #[error("Connection closed unexpectedly")]
    Closed {
        /// Reason for closure.
        reason: Option<String>,
    },

    /// Not connected.
    #[error("Not connected to OPC UA server")]
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
    pub fn refused(endpoint: impl Into<String>) -> Self {
        Self::Refused {
            endpoint: endpoint.into(),
            source: None,
        }
    }

    /// Creates a connection refused error with source.
    pub fn refused_with(endpoint: impl Into<String>, source: io::Error) -> Self {
        Self::Refused {
            endpoint: endpoint.into(),
            source: Some(source),
        }
    }

    /// Creates a connection timed out error.
    pub fn timed_out(endpoint: impl Into<String>, duration: Duration) -> Self {
        Self::TimedOut {
            endpoint: endpoint.into(),
            duration,
        }
    }

    /// Creates an endpoint not found error.
    pub fn endpoint_not_found(endpoint: impl Into<String>) -> Self {
        Self::EndpointNotFound {
            endpoint: endpoint.into(),
        }
    }

    /// Creates an invalid endpoint error.
    pub fn invalid_endpoint(url: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidEndpoint {
            url: url.into(),
            reason: reason.into(),
        }
    }

    /// Creates a no suitable endpoint error.
    pub fn no_suitable_endpoint(security_mode: impl Into<String>) -> Self {
        Self::NoSuitableEndpoint {
            security_mode: security_mode.into(),
        }
    }

    /// Creates a server not responding error.
    pub fn server_not_responding(endpoint: impl Into<String>) -> Self {
        Self::ServerNotResponding {
            endpoint: endpoint.into(),
        }
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
            Self::ServerNotResponding { .. } => true,
            Self::Closed { .. } => true,
            Self::NotConnected => true,
            Self::Io { source, .. } => matches!(
                source.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
            ),
            Self::EndpointNotFound { .. }
            | Self::InvalidEndpoint { .. }
            | Self::NoSuitableEndpoint { .. } => false,
        }
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Duration {
        match self {
            Self::Refused { .. } => Duration::from_secs(2),
            Self::TimedOut { duration, .. } => *duration,
            Self::ServerNotResponding { .. } => Duration::from_secs(5),
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
            Self::ServerNotResponding { .. } => 10,
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
            Self::InvalidEndpoint { .. } => ErrorSeverity::Error,
            Self::NoSuitableEndpoint { .. } => ErrorSeverity::Error,
            _ => ErrorSeverity::Error,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Refused { .. } => ErrorCode::new(1, 1),
            Self::TimedOut { .. } => ErrorCode::new(1, 2),
            Self::EndpointNotFound { .. } => ErrorCode::new(1, 3),
            Self::InvalidEndpoint { .. } => ErrorCode::new(1, 4),
            Self::NoSuitableEndpoint { .. } => ErrorCode::new(1, 5),
            Self::ServerNotResponding { .. } => ErrorCode::new(1, 6),
            Self::Closed { .. } => ErrorCode::new(1, 7),
            Self::NotConnected => ErrorCode::new(1, 8),
            Self::Io { .. } => ErrorCode::new(1, 9),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::Refused { .. } => vec![
                "Check if the OPC UA server is running",
                "Verify the endpoint URL is correct",
                "Check firewall rules allow the connection",
                "Ensure the server is accepting connections",
            ],
            Self::TimedOut { .. } => vec![
                "Check network connectivity to the server",
                "Increase the connection timeout setting",
                "Verify the server is not overloaded",
            ],
            Self::EndpointNotFound { .. } => vec![
                "Verify the server URL is correct",
                "Check if the server is running",
                "Try discovering endpoints using GetEndpoints",
            ],
            Self::InvalidEndpoint { .. } => vec![
                "Use format: opc.tcp://hostname:port/path",
                "Verify the hostname and port are correct",
            ],
            Self::NoSuitableEndpoint { .. } => vec![
                "Check available security modes on the server",
                "Try using SecurityMode::None for testing",
                "Verify your security configuration matches server capabilities",
            ],
            Self::ServerNotResponding { .. } => vec![
                "The server may be overloaded or restarting",
                "Check network connectivity",
                "Retry after a delay",
            ],
            Self::Closed { .. } => vec![
                "The connection was closed by the server",
                "Check server logs for disconnect reason",
                "Retry the connection",
            ],
            Self::NotConnected => vec!["Call connect() before performing operations"],
            Self::Io { .. } => vec!["Check network connectivity", "Retry the operation"],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Refused { endpoint, .. } => {
                format!("OPC UA 서버({})에 연결할 수 없습니다", endpoint)
            }
            Self::TimedOut { endpoint, .. } => {
                format!("OPC UA 서버({}) 연결 시간 초과", endpoint)
            }
            Self::EndpointNotFound { endpoint } => {
                format!("엔드포인트를 찾을 수 없음: {}", endpoint)
            }
            Self::InvalidEndpoint { url, .. } => {
                format!("잘못된 엔드포인트 URL: {}", url)
            }
            Self::NoSuitableEndpoint { security_mode } => {
                format!("적합한 엔드포인트 없음 (보안 모드: {})", security_mode)
            }
            Self::ServerNotResponding { endpoint } => {
                format!("서버 응답 없음: {}", endpoint)
            }
            Self::Closed { .. } => "연결이 끊어졌습니다".to_string(),
            Self::NotConnected => "OPC UA 서버에 연결되어 있지 않습니다".to_string(),
            Self::Io { .. } => "네트워크 오류가 발생했습니다".to_string(),
        }
    }
}

impl From<io::Error> for ConnectionError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => Self::Refused {
                endpoint: "unknown".to_string(),
                source: Some(error),
            },
            io::ErrorKind::TimedOut => Self::TimedOut {
                endpoint: "unknown".to_string(),
                duration: Duration::from_secs(0),
            },
            _ => Self::Io {
                message: error.to_string(),
                source: error,
            },
        }
    }
}

// =============================================================================
// SessionError
// =============================================================================

/// Session lifecycle errors.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Session creation failed.
    #[error("Failed to create session: {message}")]
    CreationFailed {
        /// Error message.
        message: String,
        /// Underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Session activation failed.
    #[error("Failed to activate session: {message}")]
    ActivationFailed {
        /// Error message.
        message: String,
    },

    /// Session expired.
    #[error("Session expired (ID: {session_id:?})")]
    Expired {
        /// Session ID.
        session_id: Option<String>,
    },

    /// Session closed by server.
    #[error("Session closed by server: {reason}")]
    ClosedByServer {
        /// Reason for closure.
        reason: String,
    },

    /// Session not activated.
    #[error("Session not activated")]
    NotActivated,

    /// Session ID mismatch.
    #[error("Session ID mismatch: expected {expected}, got {actual}")]
    IdMismatch {
        /// Expected session ID.
        expected: String,
        /// Actual session ID.
        actual: String,
    },

    /// Maximum sessions exceeded.
    #[error("Maximum number of sessions exceeded on server")]
    MaxSessionsExceeded,

    /// Session token invalid.
    #[error("Invalid session token")]
    InvalidToken,
}

impl SessionError {
    /// Creates a session creation failed error.
    pub fn creation_failed(message: impl Into<String>) -> Self {
        Self::CreationFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Creates a session creation failed error with source.
    pub fn creation_failed_with<E>(message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::CreationFailed {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Creates a session activation failed error.
    pub fn activation_failed(message: impl Into<String>) -> Self {
        Self::ActivationFailed {
            message: message.into(),
        }
    }

    /// Creates a session expired error.
    pub fn expired(session_id: Option<String>) -> Self {
        Self::Expired { session_id }
    }

    /// Creates a session closed by server error.
    pub fn closed_by_server(reason: impl Into<String>) -> Self {
        Self::ClosedByServer {
            reason: reason.into(),
        }
    }

    /// Creates a session ID mismatch error.
    pub fn id_mismatch(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::IdMismatch {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Expired { .. }
                | Self::ClosedByServer { .. }
                | Self::CreationFailed { .. }
                | Self::ActivationFailed { .. }
        )
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        match self {
            Self::Expired { .. } => Some(Duration::from_millis(100)),
            Self::ClosedByServer { .. } => Some(Duration::from_secs(1)),
            Self::CreationFailed { .. } => Some(Duration::from_secs(2)),
            Self::ActivationFailed { .. } => Some(Duration::from_secs(1)),
            _ => None,
        }
    }

    /// Returns the maximum number of retries.
    pub fn max_retries(&self) -> u32 {
        match self {
            Self::Expired { .. } => 1,
            Self::ClosedByServer { .. } => 3,
            Self::CreationFailed { .. } => 3,
            Self::ActivationFailed { .. } => 2,
            _ => 0,
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::Expired { .. } => ErrorSeverity::Warning,
            Self::NotActivated => ErrorSeverity::Warning,
            Self::MaxSessionsExceeded => ErrorSeverity::Error,
            Self::InvalidToken => ErrorSeverity::Critical,
            _ => ErrorSeverity::Error,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::CreationFailed { .. } => ErrorCode::new(2, 1),
            Self::ActivationFailed { .. } => ErrorCode::new(2, 2),
            Self::Expired { .. } => ErrorCode::new(2, 3),
            Self::ClosedByServer { .. } => ErrorCode::new(2, 4),
            Self::NotActivated => ErrorCode::new(2, 5),
            Self::IdMismatch { .. } => ErrorCode::new(2, 6),
            Self::MaxSessionsExceeded => ErrorCode::new(2, 7),
            Self::InvalidToken => ErrorCode::new(2, 8),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::CreationFailed { .. } => vec![
                "Check server connection",
                "Verify endpoint configuration",
                "Check server logs for errors",
            ],
            Self::ActivationFailed { .. } => vec![
                "Verify user credentials",
                "Check security policy compatibility",
                "Ensure certificate is trusted by server",
            ],
            Self::Expired { .. } => vec![
                "Create a new session",
                "Increase session timeout in configuration",
                "Implement session keep-alive",
            ],
            Self::ClosedByServer { .. } => vec![
                "Check server logs for reason",
                "Verify session timeout settings",
                "Create a new session",
            ],
            Self::NotActivated => vec!["Call activateSession() after creating the session"],
            Self::IdMismatch { .. } => vec!["Session state may be corrupted, reconnect"],
            Self::MaxSessionsExceeded => vec![
                "Close unused sessions",
                "Check server session limits",
                "Contact server administrator",
            ],
            Self::InvalidToken => vec!["Session token is invalid, create a new session"],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::CreationFailed { .. } => "세션 생성에 실패했습니다".to_string(),
            Self::ActivationFailed { .. } => "세션 활성화에 실패했습니다".to_string(),
            Self::Expired { .. } => "세션이 만료되었습니다".to_string(),
            Self::ClosedByServer { reason } => {
                format!("서버에 의해 세션이 종료됨: {}", reason)
            }
            Self::NotActivated => "세션이 활성화되지 않았습니다".to_string(),
            Self::IdMismatch { .. } => "세션 ID 불일치".to_string(),
            Self::MaxSessionsExceeded => "서버 세션 한도 초과".to_string(),
            Self::InvalidToken => "유효하지 않은 세션 토큰".to_string(),
        }
    }
}

// =============================================================================
// SecurityError
// =============================================================================

/// Security and authentication errors.
#[derive(Debug, Error)]
pub enum SecurityError {
    /// Authentication failed.
    #[error("Authentication failed: {message}")]
    AuthenticationFailed {
        /// Error message.
        message: String,
    },

    /// Certificate error.
    #[error("Certificate error: {message}")]
    Certificate {
        /// Error message.
        message: String,
    },

    /// Certificate not trusted.
    #[error("Server certificate not trusted: {thumbprint}")]
    CertificateNotTrusted {
        /// Certificate thumbprint.
        thumbprint: String,
    },

    /// Certificate expired.
    #[error("Certificate expired")]
    CertificateExpired {
        /// Expiration date.
        expired_at: Option<String>,
    },

    /// Private key error.
    #[error("Private key error: {message}")]
    PrivateKey {
        /// Error message.
        message: String,
    },

    /// Security policy not supported.
    #[error("Security policy not supported: {policy}")]
    PolicyNotSupported {
        /// The unsupported policy.
        policy: String,
    },

    /// Security mode not supported.
    #[error("Security mode not supported: {mode}")]
    ModeNotSupported {
        /// The unsupported mode.
        mode: String,
    },

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureInvalid,

    /// Encryption failed.
    #[error("Encryption failed: {message}")]
    EncryptionFailed {
        /// Error message.
        message: String,
    },

    /// Decryption failed.
    #[error("Decryption failed: {message}")]
    DecryptionFailed {
        /// Error message.
        message: String,
    },

    /// User access denied.
    #[error("User access denied for user '{username}'")]
    AccessDenied {
        /// Username.
        username: String,
    },
}

impl SecurityError {
    /// Creates an authentication failed error.
    pub fn authentication_failed(message: impl Into<String>) -> Self {
        Self::AuthenticationFailed {
            message: message.into(),
        }
    }

    /// Creates a certificate error.
    pub fn certificate(message: impl Into<String>) -> Self {
        Self::Certificate {
            message: message.into(),
        }
    }

    /// Creates a certificate not trusted error.
    pub fn certificate_not_trusted(thumbprint: impl Into<String>) -> Self {
        Self::CertificateNotTrusted {
            thumbprint: thumbprint.into(),
        }
    }

    /// Creates a certificate expired error.
    pub fn certificate_expired(expired_at: Option<String>) -> Self {
        Self::CertificateExpired { expired_at }
    }

    /// Creates a private key error.
    pub fn private_key(message: impl Into<String>) -> Self {
        Self::PrivateKey {
            message: message.into(),
        }
    }

    /// Creates a policy not supported error.
    pub fn policy_not_supported(policy: impl Into<String>) -> Self {
        Self::PolicyNotSupported {
            policy: policy.into(),
        }
    }

    /// Creates a mode not supported error.
    pub fn mode_not_supported(mode: impl Into<String>) -> Self {
        Self::ModeNotSupported { mode: mode.into() }
    }

    /// Creates an access denied error.
    pub fn access_denied(username: impl Into<String>) -> Self {
        Self::AccessDenied {
            username: username.into(),
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        false // Security errors typically require configuration changes
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        None
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::AuthenticationFailed { .. } => ErrorSeverity::Error,
            Self::CertificateNotTrusted { .. } => ErrorSeverity::Warning,
            Self::CertificateExpired { .. } => ErrorSeverity::Error,
            Self::AccessDenied { .. } => ErrorSeverity::Error,
            Self::SignatureInvalid => ErrorSeverity::Critical,
            _ => ErrorSeverity::Error,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::AuthenticationFailed { .. } => ErrorCode::new(3, 1),
            Self::Certificate { .. } => ErrorCode::new(3, 2),
            Self::CertificateNotTrusted { .. } => ErrorCode::new(3, 3),
            Self::CertificateExpired { .. } => ErrorCode::new(3, 4),
            Self::PrivateKey { .. } => ErrorCode::new(3, 5),
            Self::PolicyNotSupported { .. } => ErrorCode::new(3, 6),
            Self::ModeNotSupported { .. } => ErrorCode::new(3, 7),
            Self::SignatureInvalid => ErrorCode::new(3, 8),
            Self::EncryptionFailed { .. } => ErrorCode::new(3, 9),
            Self::DecryptionFailed { .. } => ErrorCode::new(3, 10),
            Self::AccessDenied { .. } => ErrorCode::new(3, 11),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::AuthenticationFailed { .. } => vec![
                "Verify username and password",
                "Check if user exists on the server",
                "Verify authentication method matches server configuration",
            ],
            Self::Certificate { .. } => vec![
                "Check certificate file exists and is readable",
                "Verify certificate format (DER or PEM)",
                "Regenerate certificate if corrupted",
            ],
            Self::CertificateNotTrusted { .. } => vec![
                "Add server certificate to trusted store",
                "Accept the certificate in your application",
                "Use SecurityMode::None for testing",
            ],
            Self::CertificateExpired { .. } => vec![
                "Renew the certificate",
                "Generate a new self-signed certificate",
                "Check system clock is correct",
            ],
            Self::PrivateKey { .. } => vec![
                "Verify private key file exists",
                "Check private key matches certificate",
                "Regenerate key pair if necessary",
            ],
            Self::PolicyNotSupported { .. } => vec![
                "Check server supported security policies",
                "Use a supported policy (Basic256Sha256 recommended)",
            ],
            Self::ModeNotSupported { .. } => vec![
                "Check server supported security modes",
                "Try SignAndEncrypt or Sign mode",
            ],
            Self::SignatureInvalid => vec![
                "Message may have been tampered with",
                "Check for network issues",
                "Reconnect to the server",
            ],
            Self::EncryptionFailed { .. } | Self::DecryptionFailed { .. } => vec![
                "Check security configuration",
                "Verify key exchange completed successfully",
            ],
            Self::AccessDenied { .. } => vec![
                "Check user permissions on the server",
                "Contact server administrator",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::AuthenticationFailed { .. } => "인증에 실패했습니다".to_string(),
            Self::Certificate { .. } => "인증서 오류가 발생했습니다".to_string(),
            Self::CertificateNotTrusted { .. } => "서버 인증서를 신뢰할 수 없습니다".to_string(),
            Self::CertificateExpired { .. } => "인증서가 만료되었습니다".to_string(),
            Self::PrivateKey { .. } => "개인 키 오류가 발생했습니다".to_string(),
            Self::PolicyNotSupported { policy } => {
                format!("지원되지 않는 보안 정책: {}", policy)
            }
            Self::ModeNotSupported { mode } => {
                format!("지원되지 않는 보안 모드: {}", mode)
            }
            Self::SignatureInvalid => "서명 검증에 실패했습니다".to_string(),
            Self::EncryptionFailed { .. } => "암호화에 실패했습니다".to_string(),
            Self::DecryptionFailed { .. } => "복호화에 실패했습니다".to_string(),
            Self::AccessDenied { username } => {
                format!("접근이 거부되었습니다 (사용자: {})", username)
            }
        }
    }
}

// =============================================================================
// BrowseError
// =============================================================================

/// Node browsing errors.
#[derive(Debug, Error)]
pub enum BrowseError {
    /// Node not found.
    #[error("Node not found: {node_id}")]
    NodeNotFound {
        /// The node ID that was not found.
        node_id: String,
    },

    /// Browse failed.
    #[error("Browse failed for node '{node_id}': {message}")]
    BrowseFailed {
        /// Node ID being browsed.
        node_id: String,
        /// Error message.
        message: String,
    },

    /// Invalid node ID format.
    #[error("Invalid node ID format: '{node_id}' - {reason}")]
    InvalidNodeId {
        /// The invalid node ID.
        node_id: String,
        /// Reason.
        reason: String,
    },

    /// Bad continuation point.
    #[error("Invalid continuation point")]
    BadContinuationPoint,

    /// Too many results.
    #[error("Too many browse results: {count} (max: {max})")]
    TooManyResults {
        /// Actual count.
        count: u32,
        /// Maximum allowed.
        max: u32,
    },

    /// Access denied for node.
    #[error("Access denied for node '{node_id}'")]
    AccessDenied {
        /// The node ID.
        node_id: String,
    },

    /// Invalid browse path.
    #[error("Invalid browse path '{path}': {reason}")]
    InvalidPath {
        /// The invalid path.
        path: String,
        /// Reason.
        reason: String,
    },

    /// Maximum depth exceeded.
    #[error("Maximum browse depth exceeded: {depth} (max: {max})")]
    MaxDepthExceeded {
        /// Current depth.
        depth: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Path not found.
    #[error("Path not found: {path}")]
    PathNotFound {
        /// The path that was not found.
        path: String,
    },
}

impl BrowseError {
    /// Creates a node not found error.
    pub fn node_not_found(node_id: impl Into<String>) -> Self {
        Self::NodeNotFound {
            node_id: node_id.into(),
        }
    }

    /// Creates a browse failed error.
    pub fn browse_failed(node_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::BrowseFailed {
            node_id: node_id.into(),
            message: message.into(),
        }
    }

    /// Creates an invalid node ID error.
    pub fn invalid_node_id(node_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidNodeId {
            node_id: node_id.into(),
            reason: reason.into(),
        }
    }

    /// Creates an access denied error.
    pub fn access_denied(node_id: impl Into<String>) -> Self {
        Self::AccessDenied {
            node_id: node_id.into(),
        }
    }

    /// Creates an invalid path error.
    pub fn invalid_path(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidPath {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Creates a max depth exceeded error.
    pub fn max_depth_exceeded(depth: usize, max: usize) -> Self {
        Self::MaxDepthExceeded { depth, max }
    }

    /// Creates a path not found error.
    pub fn path_not_found(path: impl Into<String>) -> Self {
        Self::PathNotFound {
            path: path.into(),
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::BrowseFailed { .. } | Self::BadContinuationPoint)
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        match self {
            Self::BrowseFailed { .. } => Some(Duration::from_millis(500)),
            Self::BadContinuationPoint => Some(Duration::from_millis(100)),
            _ => None,
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::NodeNotFound { .. } => ErrorSeverity::Warning,
            Self::AccessDenied { .. } => ErrorSeverity::Error,
            _ => ErrorSeverity::Warning,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::NodeNotFound { .. } => ErrorCode::new(4, 1),
            Self::BrowseFailed { .. } => ErrorCode::new(4, 2),
            Self::InvalidNodeId { .. } => ErrorCode::new(4, 3),
            Self::BadContinuationPoint => ErrorCode::new(4, 4),
            Self::TooManyResults { .. } => ErrorCode::new(4, 5),
            Self::AccessDenied { .. } => ErrorCode::new(4, 6),
            Self::InvalidPath { .. } => ErrorCode::new(4, 7),
            Self::MaxDepthExceeded { .. } => ErrorCode::new(4, 8),
            Self::PathNotFound { .. } => ErrorCode::new(4, 9),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::NodeNotFound { .. } => vec![
                "Verify the node ID is correct",
                "Use browse to discover available nodes",
                "Check if the node exists on the server",
            ],
            Self::BrowseFailed { .. } => vec![
                "Check server connection",
                "Verify browse permissions",
                "Retry the operation",
            ],
            Self::InvalidNodeId { .. } => vec![
                "Node ID format: ns=<namespace>;i=<numeric> or ns=<namespace>;s=<string>",
                "Example: ns=2;s=MyNode or ns=0;i=85",
            ],
            Self::BadContinuationPoint => vec![
                "Continuation point may have expired",
                "Restart the browse operation",
            ],
            Self::TooManyResults { .. } => vec![
                "Increase max_references_per_node",
                "Use continuation points to paginate results",
            ],
            Self::AccessDenied { .. } => vec![
                "Check user permissions for this node",
                "Contact server administrator",
            ],
            Self::InvalidPath { .. } => vec![
                "Path format: Objects/Server/Status",
                "Start with Objects, Types, Views, or Root",
            ],
            Self::MaxDepthExceeded { .. } => vec![
                "Reduce browse depth limit",
                "Use targeted browsing instead of full tree",
            ],
            Self::PathNotFound { .. } => vec![
                "Verify each segment of the path exists",
                "Use browse to discover available paths",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::NodeNotFound { node_id } => {
                format!("노드를 찾을 수 없음: {}", node_id)
            }
            Self::BrowseFailed { node_id, .. } => {
                format!("노드 탐색 실패: {}", node_id)
            }
            Self::InvalidNodeId { node_id, .. } => {
                format!("잘못된 노드 ID 형식: {}", node_id)
            }
            Self::BadContinuationPoint => "잘못된 연속 포인트".to_string(),
            Self::TooManyResults { count, max } => {
                format!("결과가 너무 많음 ({}/{})", count, max)
            }
            Self::AccessDenied { node_id } => {
                format!("노드 접근 거부: {}", node_id)
            }
            Self::InvalidPath { path, .. } => {
                format!("잘못된 탐색 경로: {}", path)
            }
            Self::MaxDepthExceeded { depth, max } => {
                format!("최대 탐색 깊이 초과: {} (최대: {})", depth, max)
            }
            Self::PathNotFound { path } => {
                format!("경로를 찾을 수 없음: {}", path)
            }
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
    #[error("Read failed for node '{node_id}': {message}")]
    ReadFailed {
        /// Node ID.
        node_id: String,
        /// Error message.
        message: String,
        /// OPC UA status code (if available).
        status_code: Option<u32>,
    },

    /// Write operation failed.
    #[error("Write failed for node '{node_id}': {message}")]
    WriteFailed {
        /// Node ID.
        node_id: String,
        /// Error message.
        message: String,
        /// OPC UA status code (if available).
        status_code: Option<u32>,
    },

    /// Bad status code in response.
    #[error("Bad status code {status_code:#010x} ({status_name}) for node '{node_id}'")]
    BadStatus {
        /// Node ID.
        node_id: String,
        /// Status code.
        status_code: u32,
        /// Status name.
        status_name: String,
    },

    /// Node is not readable.
    #[error("Node '{node_id}' is not readable")]
    NotReadable {
        /// Node ID.
        node_id: String,
    },

    /// Node is not writable.
    #[error("Node '{node_id}' is not writable")]
    NotWritable {
        /// Node ID.
        node_id: String,
    },

    /// Value out of range.
    #[error("Value out of range for node '{node_id}'")]
    ValueOutOfRange {
        /// Node ID.
        node_id: String,
    },

    /// Type mismatch.
    #[error("Type mismatch for node '{node_id}': expected {expected}, got {actual}")]
    TypeMismatch {
        /// Node ID.
        node_id: String,
        /// Expected type.
        expected: String,
        /// Actual type.
        actual: String,
    },

    /// Operation not supported.
    #[error("Operation '{operation}' not supported")]
    NotSupported {
        /// Operation name.
        operation: String,
    },
}

impl OperationError {
    /// Creates a read failed error.
    pub fn read_failed(node_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ReadFailed {
            node_id: node_id.into(),
            message: message.into(),
            status_code: None,
        }
    }

    /// Creates a read failed error with status code.
    pub fn read_failed_with_status(
        node_id: impl Into<String>,
        message: impl Into<String>,
        status_code: u32,
    ) -> Self {
        Self::ReadFailed {
            node_id: node_id.into(),
            message: message.into(),
            status_code: Some(status_code),
        }
    }

    /// Creates a write failed error.
    pub fn write_failed(node_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::WriteFailed {
            node_id: node_id.into(),
            message: message.into(),
            status_code: None,
        }
    }

    /// Creates a write failed error with status code.
    pub fn write_failed_with_status(
        node_id: impl Into<String>,
        message: impl Into<String>,
        status_code: u32,
    ) -> Self {
        Self::WriteFailed {
            node_id: node_id.into(),
            message: message.into(),
            status_code: Some(status_code),
        }
    }

    /// Creates a bad status error.
    pub fn bad_status(node_id: impl Into<String>, status_code: u32) -> Self {
        Self::BadStatus {
            node_id: node_id.into(),
            status_code,
            status_name: Self::status_code_name(status_code).to_string(),
        }
    }

    /// Creates a not readable error.
    pub fn not_readable(node_id: impl Into<String>) -> Self {
        Self::NotReadable {
            node_id: node_id.into(),
        }
    }

    /// Creates a not writable error.
    pub fn not_writable(node_id: impl Into<String>) -> Self {
        Self::NotWritable {
            node_id: node_id.into(),
        }
    }

    /// Creates a value out of range error.
    pub fn value_out_of_range(node_id: impl Into<String>) -> Self {
        Self::ValueOutOfRange {
            node_id: node_id.into(),
        }
    }

    /// Creates a type mismatch error.
    pub fn type_mismatch(
        node_id: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::TypeMismatch {
            node_id: node_id.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Creates a not supported error.
    pub fn not_supported(operation: impl Into<String>) -> Self {
        Self::NotSupported {
            operation: operation.into(),
        }
    }

    /// Returns the human-readable name for an OPC UA status code.
    pub fn status_code_name(code: u32) -> &'static str {
        // Common OPC UA status codes
        match code {
            0x0000_0000 => "Good",
            0x8000_0000 => "Bad",
            0x8001_0000 => "BadUnexpectedError",
            0x8002_0000 => "BadInternalError",
            0x8003_0000 => "BadOutOfMemory",
            0x8004_0000 => "BadResourceUnavailable",
            0x8005_0000 => "BadCommunicationError",
            0x8006_0000 => "BadEncodingError",
            0x8007_0000 => "BadDecodingError",
            0x8008_0000 => "BadEncodingLimitsExceeded",
            0x8009_0000 => "BadRequestTooLarge",
            0x800A_0000 => "BadResponseTooLarge",
            0x800B_0000 => "BadUnknownResponse",
            0x800C_0000 => "BadTimeout",
            0x800D_0000 => "BadServiceUnsupported",
            0x800E_0000 => "BadShutdown",
            0x800F_0000 => "BadServerNotConnected",
            0x8010_0000 => "BadServerHalted",
            0x8011_0000 => "BadNothingToDo",
            0x8012_0000 => "BadTooManyOperations",
            0x8013_0000 => "BadTooManyMonitoredItems",
            0x8014_0000 => "BadDataTypeIdUnknown",
            0x8015_0000 => "BadCertificateInvalid",
            0x8016_0000 => "BadSecurityChecksFailed",
            0x8017_0000 => "BadCertificateTimeInvalid",
            0x8018_0000 => "BadCertificateIssuerTimeInvalid",
            0x8019_0000 => "BadCertificateHostNameInvalid",
            0x801A_0000 => "BadCertificateUriInvalid",
            0x801B_0000 => "BadCertificateUseNotAllowed",
            0x801C_0000 => "BadCertificateIssuerUseNotAllowed",
            0x801D_0000 => "BadCertificateUntrusted",
            0x801E_0000 => "BadCertificateRevocationUnknown",
            0x801F_0000 => "BadCertificateIssuerRevocationUnknown",
            0x8020_0000 => "BadCertificateRevoked",
            0x8021_0000 => "BadCertificateIssuerRevoked",
            0x8022_0000 => "BadCertificateChainIncomplete",
            0x8023_0000 => "BadUserAccessDenied",
            0x8024_0000 => "BadIdentityTokenInvalid",
            0x8025_0000 => "BadIdentityTokenRejected",
            0x8026_0000 => "BadSecureChannelIdInvalid",
            0x8027_0000 => "BadInvalidTimestamp",
            0x8028_0000 => "BadNonceInvalid",
            0x8029_0000 => "BadSessionIdInvalid",
            0x802A_0000 => "BadSessionClosed",
            0x802B_0000 => "BadSessionNotActivated",
            0x802C_0000 => "BadSubscriptionIdInvalid",
            0x802D_0000 => "BadRequestHeaderInvalid",
            0x802E_0000 => "BadTimestampsToReturnInvalid",
            0x802F_0000 => "BadRequestCancelledByClient",
            0x8030_0000 => "BadTooManyArguments",
            0x8031_0000 => "BadLicenseExpired",
            0x8032_0000 => "BadLicenseLimitsExceeded",
            0x8033_0000 => "BadLicenseNotAvailable",
            0x8060_0000 => "BadNodeIdRejected",
            0x8061_0000 => "BadNodeIdInvalid",
            0x8062_0000 => "BadNodeIdUnknown",
            0x8063_0000 => "BadAttributeIdInvalid",
            0x8064_0000 => "BadIndexRangeInvalid",
            0x8065_0000 => "BadIndexRangeNoData",
            0x8066_0000 => "BadDataEncodingInvalid",
            0x8067_0000 => "BadDataEncodingUnsupported",
            0x8068_0000 => "BadNotReadable",
            0x8069_0000 => "BadNotWritable",
            0x806A_0000 => "BadOutOfRange",
            0x806B_0000 => "BadNotSupported",
            0x806C_0000 => "BadNotFound",
            0x806D_0000 => "BadObjectDeleted",
            0x806E_0000 => "BadNotImplemented",
            0x806F_0000 => "BadMonitoringModeInvalid",
            0x8070_0000 => "BadMonitoredItemIdInvalid",
            0x8071_0000 => "BadMonitoredItemFilterInvalid",
            0x8072_0000 => "BadMonitoredItemFilterUnsupported",
            0x8073_0000 => "BadFilterNotAllowed",
            0x8074_0000 => "BadStructureMissing",
            0x8075_0000 => "BadEventFilterInvalid",
            0x8076_0000 => "BadContentFilterInvalid",
            0x8077_0000 => "BadFilterOperatorInvalid",
            0x8078_0000 => "BadFilterOperatorUnsupported",
            0x8079_0000 => "BadFilterOperandCountMismatch",
            0x807A_0000 => "BadFilterOperandInvalid",
            0x807B_0000 => "BadFilterElementInvalid",
            0x807C_0000 => "BadFilterLiteralInvalid",
            0x807D_0000 => "BadContinuationPointInvalid",
            0x807E_0000 => "BadNoContinuationPoints",
            0x807F_0000 => "BadReferenceTypeIdInvalid",
            0x8080_0000 => "BadBrowseDirectionInvalid",
            0x8081_0000 => "BadNodeNotInView",
            0x8082_0000 => "BadNumericOverflow",
            0x8083_0000 => "BadServerUriInvalid",
            0x8084_0000 => "BadServerNameMissing",
            0x8085_0000 => "BadDiscoveryUrlMissing",
            0x8086_0000 => "BadSempahoreFileMissing",
            0x8087_0000 => "BadRequestTypeInvalid",
            0x8088_0000 => "BadSecurityModeRejected",
            0x8089_0000 => "BadSecurityPolicyRejected",
            0x808A_0000 => "BadTooManySessions",
            0x808B_0000 => "BadUserSignatureInvalid",
            0x808C_0000 => "BadApplicationSignatureInvalid",
            0x808D_0000 => "BadNoValidCertificates",
            0x808E_0000 => "BadIdentityChangeNotSupported",
            0x808F_0000 => "BadRequestCancelledByRequest",
            0x8090_0000 => "BadParentNodeIdInvalid",
            0x8091_0000 => "BadReferenceNotAllowed",
            0x8092_0000 => "BadNodeIdExists",
            0x8093_0000 => "BadNodeClassInvalid",
            0x8094_0000 => "BadBrowseNameInvalid",
            0x8095_0000 => "BadBrowseNameDuplicated",
            0x8096_0000 => "BadNodeAttributesInvalid",
            0x8097_0000 => "BadTypeDefinitionInvalid",
            0x8098_0000 => "BadSourceNodeIdInvalid",
            0x8099_0000 => "BadTargetNodeIdInvalid",
            0x809A_0000 => "BadDuplicateReferenceNotAllowed",
            0x809B_0000 => "BadInvalidSelfReference",
            0x809C_0000 => "BadReferenceLocalOnly",
            0x809D_0000 => "BadNoDeleteRights",
            0x809E_0000 => "UncertainReferenceNotDeleted",
            0x809F_0000 => "BadServerIndexInvalid",
            0x80A0_0000 => "BadViewIdUnknown",
            0x80A1_0000 => "BadViewTimestampInvalid",
            0x80A2_0000 => "BadViewParameterMismatch",
            0x80A3_0000 => "BadViewVersionInvalid",
            0x80AA_0000 => "BadWriteNotSupported",
            0x80AB_0000 => "BadTypeMismatch",
            0x80AC_0000 => "BadMethodInvalid",
            0x80AD_0000 => "BadArgumentsMissing",
            0x80B0_0000 => "BadNotExecutable",
            0x80C0_0000 => "BadConditionBranchAlreadyAcked",
            0x80C1_0000 => "BadConditionBranchAlreadyConfirmed",
            0x80C2_0000 => "BadConditionAlreadyShelved",
            0x80C3_0000 => "BadConditionNotShelved",
            0x80C4_0000 => "BadShelvingTimeOutOfRange",
            0x80D0_0000 => "BadNoData",
            0x80D1_0000 => "BadBoundNotFound",
            0x80D2_0000 => "BadBoundNotSupported",
            0x80D3_0000 => "BadDataLost",
            0x80D4_0000 => "BadDataUnavailable",
            0x80D5_0000 => "BadEntryExists",
            0x80D6_0000 => "BadNoEntryExists",
            0x80D7_0000 => "BadTimestampNotSupported",
            0x80E0_0000 => "GoodEntryInserted",
            0x80E1_0000 => "GoodEntryReplaced",
            0x80E2_0000 => "UncertainDataSubNormal",
            0x80E3_0000 => "GoodNoData",
            0x80E4_0000 => "GoodMoreData",
            0x80E5_0000 => "BadAggregateListMismatch",
            0x80E6_0000 => "BadAggregateNotSupported",
            0x80E7_0000 => "BadAggregateInvalidInputs",
            0x80E8_0000 => "BadAggregateConfigurationRejected",
            0x80E9_0000 => "GoodDataIgnored",
            0x80EA_0000 => "BadRequestNotAllowed",
            0x80EB_0000 => "BadRequestNotComplete",
            0x80EC_0000 => "GoodEdited",
            0x80ED_0000 => "GoodPostActionFailed",
            0x80EE_0000 => "UncertainDominantValueChanged",
            0x80EF_0000 => "GoodDependentValueChanged",
            0x80F0_0000 => "BadDominantValueChanged",
            0x80F1_0000 => "UncertainDependentValueChanged",
            0x80F2_0000 => "BadDependentValueChanged",
            _ => "Unknown",
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ReadFailed { status_code, .. } | Self::WriteFailed { status_code, .. } => {
                // Check if status code indicates a retryable error
                if let Some(code) = status_code {
                    // Timeout, server busy, etc.
                    matches!(
                        code,
                        0x800C_0000 // BadTimeout
                        | 0x8005_0000 // BadCommunicationError
                        | 0x800F_0000 // BadServerNotConnected
                    )
                } else {
                    true
                }
            }
            Self::BadStatus { status_code, .. } => {
                matches!(
                    status_code,
                    0x800C_0000 // BadTimeout
                    | 0x8005_0000 // BadCommunicationError
                    | 0x800F_0000 // BadServerNotConnected
                )
            }
            _ => false,
        }
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        if self.is_retryable() {
            Some(Duration::from_millis(500))
        } else {
            None
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::ReadFailed { .. } | Self::WriteFailed { .. } => ErrorSeverity::Warning,
            Self::BadStatus { .. } => ErrorSeverity::Warning,
            Self::NotReadable { .. } | Self::NotWritable { .. } => ErrorSeverity::Error,
            Self::ValueOutOfRange { .. } => ErrorSeverity::Warning,
            Self::TypeMismatch { .. } => ErrorSeverity::Error,
            Self::NotSupported { .. } => ErrorSeverity::Error,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::ReadFailed { .. } => ErrorCode::new(5, 1),
            Self::WriteFailed { .. } => ErrorCode::new(5, 2),
            Self::BadStatus { .. } => ErrorCode::new(5, 3),
            Self::NotReadable { .. } => ErrorCode::new(5, 4),
            Self::NotWritable { .. } => ErrorCode::new(5, 5),
            Self::ValueOutOfRange { .. } => ErrorCode::new(5, 6),
            Self::TypeMismatch { .. } => ErrorCode::new(5, 7),
            Self::NotSupported { .. } => ErrorCode::new(5, 8),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::ReadFailed { .. } => vec![
                "Check if the node exists",
                "Verify read permissions",
                "Check server connection",
            ],
            Self::WriteFailed { .. } => vec![
                "Check if the node is writable",
                "Verify write permissions",
                "Check value type matches node data type",
            ],
            Self::BadStatus { .. } => vec![
                "Check the OPC UA status code documentation",
                "Verify server state",
            ],
            Self::NotReadable { .. } => vec![
                "This node does not support reading",
                "Check node attributes",
            ],
            Self::NotWritable { .. } => vec![
                "This node is read-only",
                "Check node access level",
            ],
            Self::ValueOutOfRange { .. } => vec![
                "Value exceeds the valid range for this node",
                "Check node engineering units and range",
            ],
            Self::TypeMismatch { .. } => vec![
                "Check the expected data type for this node",
                "Convert value to the correct type before writing",
            ],
            Self::NotSupported { .. } => vec![
                "This operation is not supported by the server",
                "Check server capabilities",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::ReadFailed { node_id, .. } => {
                format!("노드 읽기 실패: {}", node_id)
            }
            Self::WriteFailed { node_id, .. } => {
                format!("노드 쓰기 실패: {}", node_id)
            }
            Self::BadStatus {
                node_id,
                status_name,
                ..
            } => {
                format!("노드 상태 오류 ({}): {}", node_id, status_name)
            }
            Self::NotReadable { node_id } => {
                format!("읽기 불가 노드: {}", node_id)
            }
            Self::NotWritable { node_id } => {
                format!("쓰기 불가 노드: {}", node_id)
            }
            Self::ValueOutOfRange { node_id } => {
                format!("값 범위 초과 (노드: {})", node_id)
            }
            Self::TypeMismatch {
                node_id,
                expected,
                actual,
            } => {
                format!(
                    "타입 불일치 (노드: {}, 예상: {}, 실제: {})",
                    node_id, expected, actual
                )
            }
            Self::NotSupported { operation } => {
                format!("지원되지 않는 기능: {}", operation)
            }
        }
    }
}

// =============================================================================
// SubscriptionError
// =============================================================================

/// Subscription and monitoring errors.
#[derive(Debug, Error)]
pub enum SubscriptionError {
    /// Subscription creation failed.
    #[error("Failed to create subscription: {message}")]
    CreationFailed {
        /// Error message.
        message: String,
    },

    /// Subscription not found.
    #[error("Subscription not found: {subscription_id}")]
    NotFound {
        /// Subscription ID.
        subscription_id: u32,
    },

    /// Subscription deleted.
    #[error("Subscription deleted by server: {subscription_id}")]
    Deleted {
        /// Subscription ID.
        subscription_id: u32,
    },

    /// Monitored item creation failed.
    #[error("Failed to create monitored item for node '{node_id}': {message}")]
    MonitoredItemFailed {
        /// Node ID.
        node_id: String,
        /// Error message.
        message: String,
    },

    /// Monitored item not found.
    #[error("Monitored item not found: {item_id}")]
    MonitoredItemNotFound {
        /// Monitored item ID.
        item_id: u32,
    },

    /// Too many monitored items.
    #[error("Too many monitored items: {count} (max: {max})")]
    TooManyMonitoredItems {
        /// Current count.
        count: u32,
        /// Maximum allowed.
        max: u32,
    },

    /// Publishing interval rejected.
    #[error("Publishing interval rejected: requested {requested:?}, got {actual:?}")]
    PublishingIntervalRejected {
        /// Requested interval.
        requested: Duration,
        /// Actual interval.
        actual: Duration,
    },

    /// Sampling interval rejected.
    #[error("Sampling interval rejected for node '{node_id}': requested {requested:?}, got {actual:?}")]
    SamplingIntervalRejected {
        /// Node ID.
        node_id: String,
        /// Requested interval.
        requested: Duration,
        /// Actual interval.
        actual: Duration,
    },

    /// Queue overflow.
    #[error("Queue overflow for monitored item {item_id}: lost {lost_count} notifications")]
    QueueOverflow {
        /// Monitored item ID.
        item_id: u32,
        /// Number of lost notifications.
        lost_count: u32,
    },

    /// Publish timeout.
    #[error("Publish timeout for subscription {subscription_id}")]
    PublishTimeout {
        /// Subscription ID.
        subscription_id: u32,
    },
}

impl SubscriptionError {
    /// Creates a subscription creation failed error.
    pub fn creation_failed(message: impl Into<String>) -> Self {
        Self::CreationFailed {
            message: message.into(),
        }
    }

    /// Creates a subscription not found error.
    pub fn not_found(subscription_id: u32) -> Self {
        Self::NotFound { subscription_id }
    }

    /// Creates a subscription deleted error.
    pub fn deleted(subscription_id: u32) -> Self {
        Self::Deleted { subscription_id }
    }

    /// Creates a monitored item failed error.
    pub fn monitored_item_failed(node_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::MonitoredItemFailed {
            node_id: node_id.into(),
            message: message.into(),
        }
    }

    /// Creates a monitored item not found error.
    pub fn monitored_item_not_found(item_id: u32) -> Self {
        Self::MonitoredItemNotFound { item_id }
    }

    /// Creates a too many monitored items error.
    pub fn too_many_monitored_items(count: u32, max: u32) -> Self {
        Self::TooManyMonitoredItems { count, max }
    }

    /// Creates a queue overflow error.
    pub fn queue_overflow(item_id: u32, lost_count: u32) -> Self {
        Self::QueueOverflow {
            item_id,
            lost_count,
        }
    }

    /// Creates a publish timeout error.
    pub fn publish_timeout(subscription_id: u32) -> Self {
        Self::PublishTimeout { subscription_id }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::CreationFailed { .. }
                | Self::Deleted { .. }
                | Self::MonitoredItemFailed { .. }
                | Self::PublishTimeout { .. }
        )
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        match self {
            Self::CreationFailed { .. } => Some(Duration::from_secs(1)),
            Self::Deleted { .. } => Some(Duration::from_millis(500)),
            Self::MonitoredItemFailed { .. } => Some(Duration::from_millis(500)),
            Self::PublishTimeout { .. } => Some(Duration::from_secs(1)),
            _ => None,
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::CreationFailed { .. } => ErrorSeverity::Error,
            Self::NotFound { .. } => ErrorSeverity::Warning,
            Self::Deleted { .. } => ErrorSeverity::Warning,
            Self::MonitoredItemFailed { .. } => ErrorSeverity::Warning,
            Self::TooManyMonitoredItems { .. } => ErrorSeverity::Error,
            Self::QueueOverflow { .. } => ErrorSeverity::Warning,
            Self::PublishTimeout { .. } => ErrorSeverity::Warning,
            _ => ErrorSeverity::Warning,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::CreationFailed { .. } => ErrorCode::new(6, 1),
            Self::NotFound { .. } => ErrorCode::new(6, 2),
            Self::Deleted { .. } => ErrorCode::new(6, 3),
            Self::MonitoredItemFailed { .. } => ErrorCode::new(6, 4),
            Self::MonitoredItemNotFound { .. } => ErrorCode::new(6, 5),
            Self::TooManyMonitoredItems { .. } => ErrorCode::new(6, 6),
            Self::PublishingIntervalRejected { .. } => ErrorCode::new(6, 7),
            Self::SamplingIntervalRejected { .. } => ErrorCode::new(6, 8),
            Self::QueueOverflow { .. } => ErrorCode::new(6, 9),
            Self::PublishTimeout { .. } => ErrorCode::new(6, 10),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::CreationFailed { .. } => vec![
                "Check server connection",
                "Verify subscription parameters",
                "Check server subscription limits",
            ],
            Self::NotFound { .. } | Self::Deleted { .. } => vec![
                "Subscription may have expired",
                "Create a new subscription",
            ],
            Self::MonitoredItemFailed { .. } => vec![
                "Verify node ID is correct",
                "Check node supports monitoring",
            ],
            Self::TooManyMonitoredItems { .. } => vec![
                "Remove unused monitored items",
                "Contact server administrator to increase limits",
            ],
            Self::PublishingIntervalRejected { .. } | Self::SamplingIntervalRejected { .. } => vec![
                "Server adjusted the interval to its capabilities",
                "Check server minimum/maximum interval settings",
            ],
            Self::QueueOverflow { .. } => vec![
                "Increase queue size for monitored item",
                "Process notifications faster",
                "Reduce sampling interval",
            ],
            Self::PublishTimeout { .. } => vec![
                "Check server connection",
                "Subscription may be deleted",
                "Recreate subscription",
            ],
            _ => vec!["Check subscription configuration"],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::CreationFailed { .. } => "구독 생성 실패".to_string(),
            Self::NotFound { subscription_id } => {
                format!("구독을 찾을 수 없음 (ID: {})", subscription_id)
            }
            Self::Deleted { subscription_id } => {
                format!("구독이 삭제됨 (ID: {})", subscription_id)
            }
            Self::MonitoredItemFailed { node_id, .. } => {
                format!("모니터링 항목 생성 실패: {}", node_id)
            }
            Self::MonitoredItemNotFound { item_id } => {
                format!("모니터링 항목을 찾을 수 없음 (ID: {})", item_id)
            }
            Self::TooManyMonitoredItems { count, max } => {
                format!("모니터링 항목 한도 초과 ({}/{})", count, max)
            }
            Self::PublishingIntervalRejected { actual, .. } => {
                format!("발행 간격이 조정됨: {:?}", actual)
            }
            Self::SamplingIntervalRejected { node_id, actual, .. } => {
                format!("샘플링 간격이 조정됨 ({}): {:?}", node_id, actual)
            }
            Self::QueueOverflow { lost_count, .. } => {
                format!("알림 큐 오버플로우 (손실: {})", lost_count)
            }
            Self::PublishTimeout { .. } => "발행 시간 초과".to_string(),
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

    /// Unsupported variant type.
    #[error("Unsupported OPC UA variant type: {variant_type}")]
    UnsupportedVariant {
        /// The variant type.
        variant_type: String,
    },

    /// Invalid value.
    #[error("Invalid value for type '{target_type}': {message}")]
    InvalidValue {
        /// Target type.
        target_type: String,
        /// Error message.
        message: String,
    },

    /// Value overflow.
    #[error("Value overflow: {value} exceeds range for {target_type}")]
    Overflow {
        /// The value that overflowed.
        value: String,
        /// Target type.
        target_type: String,
    },

    /// Array conversion failed.
    #[error("Array conversion failed: {message}")]
    ArrayConversionFailed {
        /// Error message.
        message: String,
    },

    /// ExtensionObject not supported.
    #[error("ExtensionObject not supported: {type_id}")]
    ExtensionObjectNotSupported {
        /// Type ID.
        type_id: String,
    },

    /// Null value.
    #[error("Unexpected null value")]
    NullValue,

    /// Invalid scale factor.
    #[error("Invalid scale factor: {message}")]
    InvalidScale {
        /// Error message.
        message: String,
    },

    /// Value out of range.
    #[error("Value {value} out of range [{min}, {max}]")]
    ValueOutOfRange {
        /// The value that is out of range.
        value: String,
        /// Minimum allowed value.
        min: String,
        /// Maximum allowed value.
        max: String,
    },

    /// Invalid format.
    #[error("Invalid format: {message}")]
    InvalidFormat {
        /// Error message.
        message: String,
    },

    /// Unsupported type.
    #[error("Unsupported type: {type_name}")]
    UnsupportedType {
        /// Type name.
        type_name: String,
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

    /// Creates an unsupported variant error.
    pub fn unsupported_variant(variant_type: impl Into<String>) -> Self {
        Self::UnsupportedVariant {
            variant_type: variant_type.into(),
        }
    }

    /// Creates an invalid value error.
    pub fn invalid_value(target_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidValue {
            target_type: target_type.into(),
            message: message.into(),
        }
    }

    /// Creates an overflow error.
    pub fn overflow(value: impl Into<String>, target_type: impl Into<String>) -> Self {
        Self::Overflow {
            value: value.into(),
            target_type: target_type.into(),
        }
    }

    /// Creates an array conversion failed error.
    pub fn array_conversion_failed(message: impl Into<String>) -> Self {
        Self::ArrayConversionFailed {
            message: message.into(),
        }
    }

    /// Creates an extension object not supported error.
    pub fn extension_object_not_supported(type_id: impl Into<String>) -> Self {
        Self::ExtensionObjectNotSupported {
            type_id: type_id.into(),
        }
    }

    /// Creates an invalid scale error.
    pub fn invalid_scale(message: impl Into<String>) -> Self {
        Self::InvalidScale {
            message: message.into(),
        }
    }

    /// Creates a value out of range error.
    pub fn value_out_of_range<T: std::fmt::Display>(value: T, min: T, max: T) -> Self {
        Self::ValueOutOfRange {
            value: value.to_string(),
            min: min.to_string(),
            max: max.to_string(),
        }
    }

    /// Creates an invalid format error.
    pub fn invalid_format(message: impl Into<String>) -> Self {
        Self::InvalidFormat {
            message: message.into(),
        }
    }

    /// Creates an unsupported type error.
    pub fn unsupported_type(type_name: impl Into<String>) -> Self {
        Self::UnsupportedType {
            type_name: type_name.into(),
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::TypeMismatch { .. } => ErrorCode::new(7, 1),
            Self::UnsupportedVariant { .. } => ErrorCode::new(7, 2),
            Self::InvalidValue { .. } => ErrorCode::new(7, 3),
            Self::Overflow { .. } => ErrorCode::new(7, 4),
            Self::ArrayConversionFailed { .. } => ErrorCode::new(7, 5),
            Self::ExtensionObjectNotSupported { .. } => ErrorCode::new(7, 6),
            Self::NullValue => ErrorCode::new(7, 7),
            Self::InvalidScale { .. } => ErrorCode::new(7, 8),
            Self::ValueOutOfRange { .. } => ErrorCode::new(7, 9),
            Self::InvalidFormat { .. } => ErrorCode::new(7, 10),
            Self::UnsupportedType { .. } => ErrorCode::new(7, 11),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::TypeMismatch { .. } => vec![
                "Check the expected data type for this node",
                "Use the appropriate conversion function",
            ],
            Self::UnsupportedVariant { .. } => vec![
                "This OPC UA data type is not supported",
                "Check trap-opcua documentation for supported types",
            ],
            Self::InvalidValue { .. } => vec![
                "Check the value format",
                "Ensure value is valid for the target type",
            ],
            Self::Overflow { .. } => vec![
                "Value exceeds the range of the target type",
                "Use a larger data type or scale the value",
            ],
            Self::ArrayConversionFailed { .. } => vec![
                "Check array element types are consistent",
                "Verify array dimensions",
            ],
            Self::ExtensionObjectNotSupported { .. } => vec![
                "Extension objects require custom handling",
                "Contact support for assistance",
            ],
            Self::NullValue => vec![
                "The value is null/empty",
                "Check if node has a value",
            ],
            Self::InvalidScale { .. } => vec![
                "Scale factor is invalid (e.g., zero)",
                "Check the scale configuration",
            ],
            Self::ValueOutOfRange { .. } => vec![
                "Value exceeds allowed range for target type",
                "Enable clamping or use a larger data type",
            ],
            Self::InvalidFormat { .. } => vec![
                "Value format is invalid",
                "Check the expected format for this type",
            ],
            Self::UnsupportedType { .. } => vec![
                "This data type is not supported by the converter",
                "Register a custom converter or use a supported type",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::TypeMismatch { expected, actual } => {
                format!("타입 불일치 (예상: {}, 실제: {})", expected, actual)
            }
            Self::UnsupportedVariant { variant_type } => {
                format!("지원되지 않는 데이터 타입: {}", variant_type)
            }
            Self::InvalidValue { target_type, .. } => {
                format!("잘못된 값 (타입: {})", target_type)
            }
            Self::Overflow { .. } => "값 오버플로우".to_string(),
            Self::ArrayConversionFailed { .. } => "배열 변환 실패".to_string(),
            Self::ExtensionObjectNotSupported { .. } => {
                "지원되지 않는 확장 객체".to_string()
            }
            Self::NullValue => "빈 값".to_string(),
            Self::InvalidScale { .. } => "잘못된 스케일 값".to_string(),
            Self::ValueOutOfRange { .. } => "값이 허용 범위를 초과".to_string(),
            Self::InvalidFormat { .. } => "잘못된 형식".to_string(),
            Self::UnsupportedType { type_name } => {
                format!("지원되지 않는 타입: {}", type_name)
            }
        }
    }
}

// =============================================================================
// ConfigurationError
// =============================================================================

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    /// Invalid endpoint URL.
    #[error("Invalid endpoint URL: {url}")]
    InvalidEndpoint {
        /// The invalid URL.
        url: String,
        /// Reason.
        reason: String,
    },

    /// Invalid node ID format.
    #[error("Invalid node ID format: {node_id}")]
    InvalidNodeId {
        /// The invalid node ID.
        node_id: String,
        /// Reason.
        reason: String,
    },

    /// Invalid security configuration.
    #[error("Invalid security configuration: {message}")]
    InvalidSecurity {
        /// Error message.
        message: String,
    },

    /// Invalid timeout value.
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

    /// Certificate file not found.
    #[error("Certificate file not found: {path}")]
    CertificateNotFound {
        /// File path.
        path: String,
    },

    /// Private key file not found.
    #[error("Private key file not found: {path}")]
    PrivateKeyNotFound {
        /// File path.
        path: String,
    },

    /// Invalid namespace index.
    #[error("Invalid namespace index: {index}")]
    InvalidNamespace {
        /// The invalid index.
        index: u16,
    },

    /// Invalid data type.
    #[error("Invalid data type: {data_type}")]
    InvalidDataType {
        /// The invalid data type.
        data_type: String,
    },

    /// Invalid security mode.
    #[error("Invalid security mode: {mode}")]
    InvalidSecurityMode {
        /// The invalid mode.
        mode: String,
    },

    /// Invalid security policy.
    #[error("Invalid security policy: {policy}")]
    InvalidSecurityPolicy {
        /// The invalid policy.
        policy: String,
    },
}

impl ConfigurationError {
    /// Creates an invalid endpoint error.
    pub fn invalid_endpoint(url: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidEndpoint {
            url: url.into(),
            reason: reason.into(),
        }
    }

    /// Creates an invalid node ID error.
    pub fn invalid_node_id(node_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidNodeId {
            node_id: node_id.into(),
            reason: reason.into(),
        }
    }

    /// Creates an invalid security error.
    pub fn invalid_security(message: impl Into<String>) -> Self {
        Self::InvalidSecurity {
            message: message.into(),
        }
    }

    /// Creates an invalid timeout error.
    pub fn invalid_timeout(duration: Duration, reason: impl Into<String>) -> Self {
        Self::InvalidTimeout {
            duration,
            reason: reason.into(),
        }
    }

    /// Creates a missing field error.
    pub fn missing_field(field: impl Into<String>) -> Self {
        Self::MissingField { field: field.into() }
    }

    /// Creates a certificate not found error.
    pub fn certificate_not_found(path: impl Into<String>) -> Self {
        Self::CertificateNotFound { path: path.into() }
    }

    /// Creates a private key not found error.
    pub fn private_key_not_found(path: impl Into<String>) -> Self {
        Self::PrivateKeyNotFound { path: path.into() }
    }

    /// Creates an invalid data type error.
    pub fn invalid_data_type(data_type: impl Into<String>) -> Self {
        Self::InvalidDataType {
            data_type: data_type.into(),
        }
    }

    /// Creates an invalid security mode error.
    pub fn invalid_security_mode(mode: impl Into<String>) -> Self {
        Self::InvalidSecurityMode { mode: mode.into() }
    }

    /// Creates an invalid security policy error.
    pub fn invalid_security_policy(policy: impl Into<String>) -> Self {
        Self::InvalidSecurityPolicy {
            policy: policy.into(),
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidEndpoint { .. } => ErrorCode::new(8, 1),
            Self::InvalidNodeId { .. } => ErrorCode::new(8, 2),
            Self::InvalidSecurity { .. } => ErrorCode::new(8, 3),
            Self::InvalidTimeout { .. } => ErrorCode::new(8, 4),
            Self::MissingField { .. } => ErrorCode::new(8, 5),
            Self::CertificateNotFound { .. } => ErrorCode::new(8, 6),
            Self::PrivateKeyNotFound { .. } => ErrorCode::new(8, 7),
            Self::InvalidNamespace { .. } => ErrorCode::new(8, 8),
            Self::InvalidDataType { .. } => ErrorCode::new(8, 9),
            Self::InvalidSecurityMode { .. } => ErrorCode::new(8, 10),
            Self::InvalidSecurityPolicy { .. } => ErrorCode::new(8, 11),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::InvalidEndpoint { .. } => vec![
                "Use format: opc.tcp://hostname:port/path",
                "Standard OPC UA port is 4840",
            ],
            Self::InvalidNodeId { .. } => vec![
                "Node ID format: ns=<namespace>;i=<numeric> or ns=<namespace>;s=<string>",
                "Example: ns=2;s=MyNode or ns=0;i=85",
            ],
            Self::InvalidSecurity { .. } => vec![
                "Check security mode and policy combination",
                "Valid modes: None, Sign, SignAndEncrypt",
                "Valid policies: None, Basic256Sha256, Aes128Sha256RsaOaep",
            ],
            Self::InvalidTimeout { .. } => vec![
                "Timeout should be between 1 second and 5 minutes",
            ],
            Self::MissingField { .. } => vec![
                "Check the configuration file for required fields",
            ],
            Self::CertificateNotFound { .. } | Self::PrivateKeyNotFound { .. } => vec![
                "Check the file path is correct",
                "Verify file permissions",
                "Generate a new certificate if needed",
            ],
            Self::InvalidNamespace { .. } => vec![
                "Namespace index must be valid for the server",
                "Use browse to discover available namespaces",
            ],
            Self::InvalidDataType { .. } => vec![
                "Valid types: Boolean, SByte, Byte, Int16, UInt16, Int32, UInt32, Int64, UInt64, Float, Double, String, DateTime, ByteString",
            ],
            Self::InvalidSecurityMode { .. } => vec![
                "Valid modes: None, Sign, SignAndEncrypt",
            ],
            Self::InvalidSecurityPolicy { .. } => vec![
                "Valid policies: None, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidEndpoint { url, .. } => {
                format!("잘못된 엔드포인트 URL: {}", url)
            }
            Self::InvalidNodeId { node_id, .. } => {
                format!("잘못된 노드 ID 형식: {}", node_id)
            }
            Self::InvalidSecurity { .. } => "잘못된 보안 설정".to_string(),
            Self::InvalidTimeout { duration, .. } => {
                format!("잘못된 타임아웃: {:?}", duration)
            }
            Self::MissingField { field } => {
                format!("필수 설정 누락: {}", field)
            }
            Self::CertificateNotFound { path } => {
                format!("인증서 파일을 찾을 수 없음: {}", path)
            }
            Self::PrivateKeyNotFound { path } => {
                format!("개인 키 파일을 찾을 수 없음: {}", path)
            }
            Self::InvalidNamespace { index } => {
                format!("잘못된 네임스페이스 인덱스: {}", index)
            }
            Self::InvalidDataType { data_type } => {
                format!("잘못된 데이터 타입: {}", data_type)
            }
            Self::InvalidSecurityMode { mode } => {
                format!("잘못된 보안 모드: {}", mode)
            }
            Self::InvalidSecurityPolicy { policy } => {
                format!("잘못된 보안 정책: {}", policy)
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

    /// Session creation timeout.
    #[error("Session creation timed out after {duration:?}")]
    Session {
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

    /// Browse operation timeout.
    #[error("Browse operation timed out after {duration:?}")]
    Browse {
        /// Timeout duration.
        duration: Duration,
    },

    /// Request timeout.
    #[error("Request timed out after {duration:?}")]
    Request {
        /// Timeout duration.
        duration: Duration,
    },
}

impl TimeoutError {
    /// Creates a connection timeout.
    pub fn connection(duration: Duration) -> Self {
        Self::Connection { duration }
    }

    /// Creates a session timeout.
    pub fn session(duration: Duration) -> Self {
        Self::Session { duration }
    }

    /// Creates a read timeout.
    pub fn read(duration: Duration) -> Self {
        Self::Read { duration }
    }

    /// Creates a write timeout.
    pub fn write(duration: Duration) -> Self {
        Self::Write { duration }
    }

    /// Creates a browse timeout.
    pub fn browse(duration: Duration) -> Self {
        Self::Browse { duration }
    }

    /// Creates a request timeout.
    pub fn request(duration: Duration) -> Self {
        Self::Request { duration }
    }

    /// Returns the timeout duration.
    pub fn duration(&self) -> Duration {
        match self {
            Self::Connection { duration }
            | Self::Session { duration }
            | Self::Read { duration }
            | Self::Write { duration }
            | Self::Browse { duration }
            | Self::Request { duration } => *duration,
        }
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Duration {
        self.duration().mul_f32(0.5).max(Duration::from_millis(500))
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Connection { .. } => ErrorCode::new(9, 1),
            Self::Session { .. } => ErrorCode::new(9, 2),
            Self::Read { .. } => ErrorCode::new(9, 3),
            Self::Write { .. } => ErrorCode::new(9, 4),
            Self::Browse { .. } => ErrorCode::new(9, 5),
            Self::Request { .. } => ErrorCode::new(9, 6),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        vec![
            "Check network connectivity",
            "Increase the timeout value",
            "Verify the server is responding",
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
            Self::Session { .. } => {
                format!("세션 생성 시간 초과 ({:.1}초)", duration.as_secs_f64())
            }
            Self::Read { .. } => {
                format!("읽기 시간 초과 ({:.1}초)", duration.as_secs_f64())
            }
            Self::Write { .. } => {
                format!("쓰기 시간 초과 ({:.1}초)", duration.as_secs_f64())
            }
            Self::Browse { .. } => {
                format!("탐색 시간 초과 ({:.1}초)", duration.as_secs_f64())
            }
            Self::Request { .. } => {
                format!("요청 시간 초과 ({:.1}초)", duration.as_secs_f64())
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
///
/// Format: `UA-XXYY` where XX is category and YY is specific error.
///
/// Categories:
/// - 1: Connection
/// - 2: Session
/// - 3: Security
/// - 4: Browse
/// - 5: Operation
/// - 6: Subscription
/// - 7: Conversion
/// - 8: Configuration
/// - 9: Timeout
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode {
    /// Category (1-9).
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
        write!(f, "UA-{:02X}{:02X}", self.category, self.code)
    }
}

// =============================================================================
// Conversion to trap_core::DriverError
// =============================================================================

impl From<OpcUaError> for trap_core::DriverError {
    fn from(error: OpcUaError) -> Self {
        match error {
            OpcUaError::Connection(e) => match e {
                ConnectionError::Refused { endpoint, .. } => {
                    trap_core::DriverError::connection_failed(format!(
                        "Connection refused to {}",
                        endpoint
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
            OpcUaError::Session(e) => {
                trap_core::DriverError::connection_failed(format!("Session error: {}", e))
            }
            OpcUaError::Security(e) => {
                trap_core::DriverError::protocol(format!("Security error: {}", e))
            }
            OpcUaError::Timeout(e) => trap_core::DriverError::timeout(e.duration()),
            OpcUaError::Browse(e) => match e {
                BrowseError::NodeNotFound { node_id } => {
                    trap_core::DriverError::address_not_found(node_id)
                }
                other => trap_core::DriverError::protocol(other.to_string()),
            },
            OpcUaError::Operation(e) => match e {
                OperationError::ReadFailed { node_id, message, .. } => {
                    trap_core::DriverError::read_failed(node_id, message)
                }
                OperationError::WriteFailed { node_id, message, .. } => {
                    trap_core::DriverError::write_failed(node_id, message)
                }
                OperationError::NotReadable { node_id } => {
                    trap_core::DriverError::protocol(format!("Node not readable: {}", node_id))
                }
                OperationError::NotWritable { node_id } => {
                    trap_core::DriverError::protocol(format!("Node not writable: {}", node_id))
                }
                other => trap_core::DriverError::protocol(other.to_string()),
            },
            OpcUaError::Subscription(e) => trap_core::DriverError::Subscription {
                message: e.to_string(),
            },
            OpcUaError::Conversion(e) => {
                trap_core::DriverError::invalid_response(e.to_string())
            }
            OpcUaError::Configuration(e) => {
                trap_core::DriverError::protocol(format!("Configuration error: {}", e))
            }
        }
    }
}

// =============================================================================
// Result Type Alias
// =============================================================================

/// A Result type with OpcUaError.
pub type OpcUaResult<T> = Result<T, OpcUaError>;

// =============================================================================
// Error Context Extension
// =============================================================================

/// Extension trait for adding context to OPC UA errors.
pub trait OpcUaErrorContext<T> {
    /// Adds endpoint context to errors.
    fn with_endpoint(self, endpoint: &str) -> Result<T, OpcUaError>;

    /// Adds node context to errors.
    fn with_node(self, node_id: &str) -> Result<T, OpcUaError>;

    /// Adds session context to errors.
    fn with_session(self, session_id: &str) -> Result<T, OpcUaError>;
}

impl<T> OpcUaErrorContext<T> for Result<T, OpcUaError> {
    fn with_endpoint(self, endpoint: &str) -> Result<T, OpcUaError> {
        self.map_err(|e| {
            tracing::debug!(endpoint = endpoint, error = %e, "OPC UA error with endpoint context");
            e
        })
    }

    fn with_node(self, node_id: &str) -> Result<T, OpcUaError> {
        self.map_err(|e| {
            tracing::debug!(node_id = node_id, error = %e, "OPC UA error with node context");
            e
        })
    }

    fn with_session(self, session_id: &str) -> Result<T, OpcUaError> {
        self.map_err(|e| {
            tracing::debug!(session_id = session_id, error = %e, "OPC UA error with session context");
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
        assert!(ConnectionError::refused("opc.tcp://localhost:4840").is_retryable());
        assert!(
            ConnectionError::timed_out("opc.tcp://localhost:4840", Duration::from_secs(5))
                .is_retryable()
        );
        assert!(ConnectionError::NotConnected.is_retryable());
        assert!(!ConnectionError::invalid_endpoint("bad-url", "invalid format").is_retryable());
    }

    #[test]
    fn test_session_error() {
        let error = SessionError::expired(Some("sess-123".to_string()));
        assert!(error.is_retryable());
        assert!(error.suggested_retry_delay().is_some());
    }

    #[test]
    fn test_security_error_not_retryable() {
        let error = SecurityError::authentication_failed("Invalid credentials");
        assert!(!error.is_retryable());
        assert!(error.suggested_retry_delay().is_none());
    }

    #[test]
    fn test_browse_error() {
        let error = BrowseError::node_not_found("ns=2;s=Unknown");
        assert!(!error.is_retryable());
        assert!(error.to_string().contains("ns=2;s=Unknown"));
    }

    #[test]
    fn test_operation_error_status_codes() {
        assert_eq!(
            OperationError::status_code_name(0x0000_0000),
            "Good"
        );
        assert_eq!(
            OperationError::status_code_name(0x8068_0000),
            "BadNotReadable"
        );
        assert_eq!(
            OperationError::status_code_name(0x8069_0000),
            "BadNotWritable"
        );
    }

    #[test]
    fn test_subscription_error() {
        let error = SubscriptionError::too_many_monitored_items(1000, 500);
        assert!(!error.is_retryable());
        assert!(error.to_string().contains("1000"));
        assert!(error.to_string().contains("500"));
    }

    #[test]
    fn test_conversion_error() {
        let error = ConversionError::type_mismatch("Int32", "String");
        assert!(error.to_string().contains("Int32"));
        assert!(error.to_string().contains("String"));
    }

    #[test]
    fn test_error_code() {
        let code = ErrorCode::new(1, 5);
        assert_eq!(code.to_string(), "UA-0105");
        assert_eq!(code.as_u16(), 0x0105);

        let from_u16 = ErrorCode::from_u16(0x0305);
        assert_eq!(from_u16.category, 3);
        assert_eq!(from_u16.code, 5);
    }

    #[test]
    fn test_opcua_error_conversion_to_driver_error() {
        let opcua_error = OpcUaError::not_connected();
        let driver_error: trap_core::DriverError = opcua_error.into();

        assert!(matches!(driver_error, trap_core::DriverError::NotConnected));
    }

    #[test]
    fn test_timeout_error() {
        let timeout = TimeoutError::read(Duration::from_secs(5));
        assert_eq!(timeout.duration(), Duration::from_secs(5));

        let opcua_error = OpcUaError::timeout(timeout);
        assert!(opcua_error.is_retryable());
        assert!(opcua_error.suggested_retry_delay().is_some());
    }

    #[test]
    fn test_recovery_hints() {
        let error = ConnectionError::refused("opc.tcp://localhost:4840");
        let hints = error.recovery_hints();
        assert!(!hints.is_empty());
        assert!(hints.iter().any(|h| h.contains("running")));
    }

    #[test]
    fn test_error_severity() {
        let warning = ConnectionError::NotConnected;
        assert_eq!(warning.severity(), ErrorSeverity::Warning);

        let error = SecurityError::authentication_failed("test");
        assert_eq!(error.severity(), ErrorSeverity::Error);
    }

    #[test]
    fn test_error_category() {
        assert_eq!(OpcUaError::not_connected().category(), "connection");
        assert_eq!(
            OpcUaError::session_failed("test").category(),
            "session"
        );
        assert_eq!(
            OpcUaError::read_timeout(Duration::from_secs(1)).category(),
            "timeout"
        );
    }

    #[test]
    fn test_user_messages() {
        let error = OpcUaError::connection_refused("opc.tcp://192.168.1.100:4840");
        let message = error.user_message();
        assert!(message.contains("192.168.1.100"));
    }

    #[test]
    fn test_configuration_error() {
        let error = ConfigurationError::invalid_node_id("bad;format", "missing namespace");
        assert!(error.to_string().contains("bad;format"));

        let hints = error.recovery_hints();
        assert!(hints.iter().any(|h| h.contains("ns=")));
    }
}
