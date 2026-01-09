// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Audit error types.

use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during audit logging.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Failed to write audit log.
    #[error("Failed to write audit log: {message}")]
    WriteFailed {
        /// Error message.
        message: String,
        /// Underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Failed to query audit logs.
    #[error("Failed to query audit logs: {message}")]
    QueryFailed {
        /// Error message.
        message: String,
    },

    /// Query not supported by this logger.
    #[error("Query not supported by this logger: {logger_type}")]
    QueryNotSupported {
        /// The type of logger that doesn't support queries.
        logger_type: String,
    },

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("Serialization error: {message}")]
    Serialization {
        /// Error message.
        message: String,
    },

    /// Logger not initialized.
    #[error("Audit logger not initialized")]
    NotInitialized,

    /// Configuration error.
    #[error("Configuration error: {message}")]
    Configuration {
        /// Error message.
        message: String,
    },

    /// File rotation error.
    #[error("File rotation error: {message}")]
    RotationFailed {
        /// Error message.
        message: String,
        /// File path.
        path: Option<PathBuf>,
    },

    /// Batch processing error.
    #[error("Batch processing error: {message}")]
    BatchFailed {
        /// Error message.
        message: String,
        /// Number of failed entries.
        failed_count: usize,
    },

    /// Channel closed.
    #[error("Audit channel closed")]
    ChannelClosed,

    /// Encryption error.
    #[error("Encryption error: {message}")]
    EncryptionFailed {
        /// Error message.
        message: String,
    },

    /// Logger is shutting down.
    #[error("Logger is shutting down")]
    ShuttingDown,
}

impl AuditError {
    /// Creates a write failed error.
    pub fn write_failed(message: impl Into<String>) -> Self {
        Self::WriteFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Creates a write failed error with source.
    pub fn write_failed_with<E>(message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::WriteFailed {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Creates a query failed error.
    pub fn query_failed(message: impl Into<String>) -> Self {
        Self::QueryFailed {
            message: message.into(),
        }
    }

    /// Creates a query not supported error.
    pub fn query_not_supported(logger_type: impl Into<String>) -> Self {
        Self::QueryNotSupported {
            logger_type: logger_type.into(),
        }
    }

    /// Creates a serialization error.
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization {
            message: message.into(),
        }
    }

    /// Creates a configuration error.
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Creates a rotation failed error.
    pub fn rotation_failed(message: impl Into<String>) -> Self {
        Self::RotationFailed {
            message: message.into(),
            path: None,
        }
    }

    /// Creates a rotation failed error with path.
    pub fn rotation_failed_at(message: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self::RotationFailed {
            message: message.into(),
            path: Some(path.into()),
        }
    }

    /// Creates a batch failed error.
    pub fn batch_failed(message: impl Into<String>, failed_count: usize) -> Self {
        Self::BatchFailed {
            message: message.into(),
            failed_count,
        }
    }

    /// Creates an encryption failed error.
    pub fn encryption_failed(message: impl Into<String>) -> Self {
        Self::EncryptionFailed {
            message: message.into(),
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AuditError::WriteFailed { .. }
                | AuditError::Io(_)
                | AuditError::BatchFailed { .. }
                | AuditError::RotationFailed { .. }
        )
    }

    /// Returns the error type for metrics/logging.
    pub fn error_type(&self) -> &'static str {
        match self {
            AuditError::WriteFailed { .. } => "write_failed",
            AuditError::QueryFailed { .. } => "query_failed",
            AuditError::QueryNotSupported { .. } => "query_not_supported",
            AuditError::Io(_) => "io_error",
            AuditError::Serialization { .. } => "serialization_error",
            AuditError::NotInitialized => "not_initialized",
            AuditError::Configuration { .. } => "configuration_error",
            AuditError::RotationFailed { .. } => "rotation_failed",
            AuditError::BatchFailed { .. } => "batch_failed",
            AuditError::ChannelClosed => "channel_closed",
            AuditError::EncryptionFailed { .. } => "encryption_failed",
            AuditError::ShuttingDown => "shutting_down",
        }
    }
}

/// Result type for audit operations.
pub type AuditResult<T> = Result<T, AuditError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = AuditError::write_failed("test error");
        assert!(matches!(err, AuditError::WriteFailed { .. }));
        assert!(err.is_retryable());

        let err = AuditError::query_not_supported("file_logger");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_error_type() {
        let err = AuditError::write_failed("test");
        assert_eq!(err.error_type(), "write_failed");

        let err = AuditError::ChannelClosed;
        assert_eq!(err.error_type(), "channel_closed");
    }
}
