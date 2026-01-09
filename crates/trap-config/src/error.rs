// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Configuration error types for trap-config.
//!
//! This module provides a comprehensive error type hierarchy for configuration
//! operations including parsing, validation, encryption, and loading.

use std::path::PathBuf;
use thiserror::Error;

/// Configuration-related errors.
///
/// This error type covers all possible failures during configuration
/// loading, parsing, validation, and encryption/decryption operations.
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
        line: Option<usize>,
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

    /// Duplicate tag ID within a device.
    #[error("Duplicate tag ID '{tag_id}' in device '{device_id}'")]
    DuplicateTagId {
        /// The device ID.
        device_id: String,
        /// The duplicated tag ID.
        tag_id: String,
    },

    /// Invalid encryption key.
    #[error("Invalid encryption key: {message}")]
    InvalidEncryptionKey {
        /// Error message.
        message: String,
    },

    /// Encryption failed.
    #[error("Failed to encrypt value: {message}")]
    EncryptionFailed {
        /// Error message.
        message: String,
    },

    /// Decryption failed.
    #[error("Failed to decrypt value: {message}")]
    DecryptionFailed {
        /// Error message.
        message: String,
    },

    /// Environment variable not found.
    #[error("Environment variable not found: {name}")]
    EnvVarNotFound {
        /// The environment variable name.
        name: String,
    },

    /// Invalid environment variable value.
    #[error("Invalid environment variable value for '{name}': {message}")]
    InvalidEnvVar {
        /// The environment variable name.
        name: String,
        /// Error message.
        message: String,
    },

    /// File not found.
    #[error("File not found: {path}")]
    FileNotFound {
        /// The path that was not found.
        path: PathBuf,
    },

    /// Invalid value type.
    #[error("Invalid value for '{field}': expected {expected}, got {actual}")]
    InvalidType {
        /// The field name.
        field: String,
        /// Expected type.
        expected: String,
        /// Actual type.
        actual: String,
    },

    /// Value out of range.
    #[error("Value out of range for '{field}': {value} (expected {min}..{max})")]
    OutOfRange {
        /// The field name.
        field: String,
        /// The actual value.
        value: String,
        /// Minimum value.
        min: String,
        /// Maximum value.
        max: String,
    },

    /// Invalid protocol configuration.
    #[error("Invalid protocol configuration for device '{device_id}': {message}")]
    InvalidProtocol {
        /// The device ID.
        device_id: String,
        /// Error message.
        message: String,
    },

    /// Unsupported configuration format.
    #[error("Unsupported configuration format: {format}")]
    UnsupportedFormat {
        /// The unsupported format.
        format: String,
    },

    /// Configuration merge error.
    #[error("Failed to merge configuration: {message}")]
    MergeError {
        /// Error message.
        message: String,
    },

    /// Serialization error.
    #[error("Serialization error: {message}")]
    Serialization {
        /// Error message.
        message: String,
    },
}

impl ConfigError {
    /// Creates a parse error.
    pub fn parse(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::Parse {
            path: path.into(),
            message: message.into(),
            line: None,
        }
    }

    /// Creates a parse error with line number.
    pub fn parse_at_line(
        path: impl Into<PathBuf>,
        message: impl Into<String>,
        line: usize,
    ) -> Self {
        Self::Parse {
            path: path.into(),
            message: message.into(),
            line: Some(line),
        }
    }

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

    /// Creates an I/O error.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Creates an invalid address error.
    pub fn invalid_address(address: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidAddress {
            address: address.into(),
            message: message.into(),
        }
    }

    /// Creates a duplicate device ID error.
    pub fn duplicate_device_id(device_id: impl Into<String>) -> Self {
        Self::DuplicateDeviceId {
            device_id: device_id.into(),
        }
    }

    /// Creates a duplicate tag ID error.
    pub fn duplicate_tag_id(device_id: impl Into<String>, tag_id: impl Into<String>) -> Self {
        Self::DuplicateTagId {
            device_id: device_id.into(),
            tag_id: tag_id.into(),
        }
    }

    /// Creates an invalid encryption key error.
    pub fn invalid_encryption_key(message: impl Into<String>) -> Self {
        Self::InvalidEncryptionKey {
            message: message.into(),
        }
    }

    /// Creates an encryption failed error.
    pub fn encryption_failed(message: impl Into<String>) -> Self {
        Self::EncryptionFailed {
            message: message.into(),
        }
    }

    /// Creates a decryption failed error.
    pub fn decryption_failed(message: impl Into<String>) -> Self {
        Self::DecryptionFailed {
            message: message.into(),
        }
    }

    /// Creates an environment variable not found error.
    pub fn env_var_not_found(name: impl Into<String>) -> Self {
        Self::EnvVarNotFound { name: name.into() }
    }

    /// Creates an invalid environment variable error.
    pub fn invalid_env_var(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidEnvVar {
            name: name.into(),
            message: message.into(),
        }
    }

    /// Creates a file not found error.
    pub fn file_not_found(path: impl Into<PathBuf>) -> Self {
        Self::FileNotFound { path: path.into() }
    }

    /// Creates an invalid type error.
    pub fn invalid_type(
        field: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::InvalidType {
            field: field.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Creates an out of range error.
    pub fn out_of_range<T: std::fmt::Display>(
        field: impl Into<String>,
        value: T,
        min: T,
        max: T,
    ) -> Self {
        Self::OutOfRange {
            field: field.into(),
            value: value.to_string(),
            min: min.to_string(),
            max: max.to_string(),
        }
    }

    /// Creates an invalid protocol error.
    pub fn invalid_protocol(device_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidProtocol {
            device_id: device_id.into(),
            message: message.into(),
        }
    }

    /// Creates an unsupported format error.
    pub fn unsupported_format(format: impl Into<String>) -> Self {
        Self::UnsupportedFormat {
            format: format.into(),
        }
    }

    /// Creates a merge error.
    pub fn merge_error(message: impl Into<String>) -> Self {
        Self::MergeError {
            message: message.into(),
        }
    }

    /// Creates a serialization error.
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization {
            message: message.into(),
        }
    }

    /// Returns a user-friendly error message in Korean.
    pub fn user_message(&self) -> String {
        match self {
            ConfigError::Parse { path, message, line } => {
                if let Some(line) = line {
                    format!(
                        "설정 파일 파싱 실패 ({}, 라인 {}): {}",
                        path.display(),
                        line,
                        message
                    )
                } else {
                    format!("설정 파일 파싱 실패 ({}): {}", path.display(), message)
                }
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
            ConfigError::DuplicateTagId { device_id, tag_id } => {
                format!("중복된 태그 ID ({}/{})", device_id, tag_id)
            }
            ConfigError::InvalidEncryptionKey { .. } => "암호화 키가 유효하지 않습니다".to_string(),
            ConfigError::EncryptionFailed { .. } => "암호화에 실패했습니다".to_string(),
            ConfigError::DecryptionFailed { .. } => "복호화에 실패했습니다".to_string(),
            ConfigError::EnvVarNotFound { name } => {
                format!("환경 변수를 찾을 수 없습니다: {}", name)
            }
            ConfigError::InvalidEnvVar { name, message } => {
                format!("잘못된 환경 변수 값 ({}): {}", name, message)
            }
            ConfigError::FileNotFound { path } => {
                format!("파일을 찾을 수 없습니다: {}", path.display())
            }
            ConfigError::InvalidType { field, expected, actual } => {
                format!(
                    "잘못된 타입 ({}): {}이 필요하지만 {}입니다",
                    field, expected, actual
                )
            }
            ConfigError::OutOfRange { field, value, min, max } => {
                format!(
                    "범위 초과 ({}): {} (허용 범위: {}..{})",
                    field, value, min, max
                )
            }
            ConfigError::InvalidProtocol { device_id, message } => {
                format!("잘못된 프로토콜 설정 ({}): {}", device_id, message)
            }
            ConfigError::UnsupportedFormat { format } => {
                format!("지원하지 않는 설정 형식: {}", format)
            }
            ConfigError::MergeError { message } => {
                format!("설정 병합 실패: {}", message)
            }
            ConfigError::Serialization { message } => {
                format!("직렬화 오류: {}", message)
            }
        }
    }

    /// Returns `true` if this error is related to missing or invalid credentials.
    pub fn is_credential_error(&self) -> bool {
        matches!(
            self,
            ConfigError::InvalidEncryptionKey { .. }
                | ConfigError::EncryptionFailed { .. }
                | ConfigError::DecryptionFailed { .. }
        )
    }

    /// Returns `true` if this error is related to file I/O.
    pub fn is_io_error(&self) -> bool {
        matches!(
            self,
            ConfigError::Io { .. } | ConfigError::FileNotFound { .. }
        )
    }

    /// Returns the error type as a string for logging/metrics.
    pub fn error_type(&self) -> &'static str {
        match self {
            ConfigError::Parse { .. } => "parse",
            ConfigError::Validation { .. } => "validation",
            ConfigError::MissingField { .. } => "missing_field",
            ConfigError::Io { .. } => "io",
            ConfigError::InvalidAddress { .. } => "invalid_address",
            ConfigError::DuplicateDeviceId { .. } => "duplicate_device_id",
            ConfigError::DuplicateTagId { .. } => "duplicate_tag_id",
            ConfigError::InvalidEncryptionKey { .. } => "invalid_encryption_key",
            ConfigError::EncryptionFailed { .. } => "encryption_failed",
            ConfigError::DecryptionFailed { .. } => "decryption_failed",
            ConfigError::EnvVarNotFound { .. } => "env_var_not_found",
            ConfigError::InvalidEnvVar { .. } => "invalid_env_var",
            ConfigError::FileNotFound { .. } => "file_not_found",
            ConfigError::InvalidType { .. } => "invalid_type",
            ConfigError::OutOfRange { .. } => "out_of_range",
            ConfigError::InvalidProtocol { .. } => "invalid_protocol",
            ConfigError::UnsupportedFormat { .. } => "unsupported_format",
            ConfigError::MergeError { .. } => "merge_error",
            ConfigError::Serialization { .. } => "serialization",
        }
    }
}

/// A Result type with ConfigError.
pub type ConfigResult<T> = Result<T, ConfigError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_error_creation() {
        let error = ConfigError::validation("port", "must be positive");
        assert!(matches!(error, ConfigError::Validation { .. }));
        assert_eq!(error.error_type(), "validation");

        let error = ConfigError::missing_field("host");
        assert!(matches!(error, ConfigError::MissingField { .. }));
        assert_eq!(error.error_type(), "missing_field");

        let error = ConfigError::invalid_address("HR:99999", "address out of range");
        assert!(matches!(error, ConfigError::InvalidAddress { .. }));
        assert_eq!(error.error_type(), "invalid_address");
    }

    #[test]
    fn test_config_error_user_message() {
        let error = ConfigError::validation("port", "must be positive");
        let msg = error.user_message();
        assert!(msg.contains("설정 검증 실패"));
        assert!(msg.contains("port"));

        let error = ConfigError::missing_field("host");
        let msg = error.user_message();
        assert!(msg.contains("필수 설정 누락"));
    }

    #[test]
    fn test_config_error_is_credential_error() {
        assert!(ConfigError::invalid_encryption_key("bad key").is_credential_error());
        assert!(ConfigError::encryption_failed("failed").is_credential_error());
        assert!(ConfigError::decryption_failed("failed").is_credential_error());
        assert!(!ConfigError::missing_field("host").is_credential_error());
    }

    #[test]
    fn test_config_error_is_io_error() {
        let error = ConfigError::io("test.yaml", std::io::Error::new(std::io::ErrorKind::NotFound, "not found"));
        assert!(error.is_io_error());
        assert!(ConfigError::file_not_found("test.yaml").is_io_error());
        assert!(!ConfigError::missing_field("host").is_io_error());
    }

    #[test]
    fn test_parse_at_line() {
        let error = ConfigError::parse_at_line("config.yaml", "invalid syntax", 42);
        match error {
            ConfigError::Parse { line, .. } => assert_eq!(line, Some(42)),
            _ => panic!("Expected Parse error"),
        }
    }

    #[test]
    fn test_out_of_range() {
        let error = ConfigError::out_of_range("poll_interval_ms", 0, 1, 3600000);
        let msg = error.user_message();
        assert!(msg.contains("범위 초과"));
        assert!(msg.contains("poll_interval_ms"));
    }
}
