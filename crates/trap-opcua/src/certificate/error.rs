// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Certificate-specific error types.
//!
//! This module provides a comprehensive error hierarchy for certificate operations,
//! separate from the main OPC UA error types for better modularity.

use std::io;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tracing::Level;

use crate::error::{ErrorCode, ErrorSeverity, OpcUaError, SecurityError};

// =============================================================================
// CertificateError - Main Certificate Error Type
// =============================================================================

/// Comprehensive error type for certificate operations.
///
/// This enum categorizes certificate-related errors by their domain:
///
/// ```text
/// CertificateError
/// ├── Generation    - Certificate creation failures
/// ├── Storage       - File I/O and persistence errors
/// ├── Validation    - Certificate verification failures
/// ├── Parsing       - Certificate/key parsing errors
/// ├── Expiration    - Certificate validity period issues
/// └── Configuration - Invalid certificate settings
/// ```
#[derive(Debug, Error)]
pub enum CertificateError {
    /// Certificate generation errors.
    #[error("{0}")]
    Generation(#[from] GenerationError),

    /// Certificate storage errors.
    #[error("{0}")]
    Storage(#[from] StorageError),

    /// Certificate validation errors.
    #[error("{0}")]
    Validation(#[from] ValidationError),

    /// Certificate parsing errors.
    #[error("{0}")]
    Parsing(#[from] ParsingError),

    /// Certificate expiration errors.
    #[error("{0}")]
    Expiration(#[from] ExpirationError),

    /// Configuration errors.
    #[error("{0}")]
    Configuration(#[from] CertConfigError),
}

impl CertificateError {
    // =========================================================================
    // Factory Methods
    // =========================================================================

    /// Creates a generation error.
    #[inline]
    pub fn generation(error: GenerationError) -> Self {
        Self::Generation(error)
    }

    /// Creates a storage error.
    #[inline]
    pub fn storage(error: StorageError) -> Self {
        Self::Storage(error)
    }

    /// Creates a validation error.
    #[inline]
    pub fn validation(error: ValidationError) -> Self {
        Self::Validation(error)
    }

    /// Creates a parsing error.
    #[inline]
    pub fn parsing(error: ParsingError) -> Self {
        Self::Parsing(error)
    }

    /// Creates an expiration error.
    #[inline]
    pub fn expiration(error: ExpirationError) -> Self {
        Self::Expiration(error)
    }

    /// Creates a configuration error.
    #[inline]
    pub fn configuration(error: CertConfigError) -> Self {
        Self::Configuration(error)
    }

    // =========================================================================
    // Convenience Factory Methods
    // =========================================================================

    /// Creates a key generation failed error.
    pub fn key_generation_failed(algorithm: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Generation(GenerationError::key_generation_failed(algorithm, message))
    }

    /// Creates a certificate creation failed error.
    pub fn cert_creation_failed(message: impl Into<String>) -> Self {
        Self::Generation(GenerationError::cert_creation_failed(message))
    }

    /// Creates a file not found error.
    pub fn file_not_found(path: impl Into<PathBuf>) -> Self {
        Self::Storage(StorageError::file_not_found(path))
    }

    /// Creates a write failed error.
    pub fn write_failed(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::Storage(StorageError::write_failed(path, message))
    }

    /// Creates a certificate expired error.
    pub fn expired(days_expired: i64) -> Self {
        Self::Expiration(ExpirationError::expired(days_expired))
    }

    /// Creates a certificate not yet valid error.
    pub fn not_yet_valid(days_until_valid: i64) -> Self {
        Self::Expiration(ExpirationError::not_yet_valid(days_until_valid))
    }

    /// Creates an invalid certificate error.
    pub fn invalid_certificate(message: impl Into<String>) -> Self {
        Self::Validation(ValidationError::invalid_certificate(message))
    }

    /// Creates a certificate not trusted error.
    pub fn not_trusted(thumbprint: impl Into<String>) -> Self {
        Self::Validation(ValidationError::not_trusted(thumbprint))
    }

    // =========================================================================
    // Error Properties
    // =========================================================================

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Generation(_) => false,
            Self::Storage(e) => e.is_retryable(),
            Self::Validation(_) => false,
            Self::Parsing(_) => false,
            Self::Expiration(_) => false,
            Self::Configuration(_) => false,
        }
    }

    /// Returns the suggested retry delay for this error.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        match self {
            Self::Storage(e) => e.suggested_retry_delay(),
            _ => None,
        }
    }

    /// Returns the severity level of this error.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::Generation(e) => e.severity(),
            Self::Storage(e) => e.severity(),
            Self::Validation(e) => e.severity(),
            Self::Parsing(e) => e.severity(),
            Self::Expiration(e) => e.severity(),
            Self::Configuration(_) => ErrorSeverity::Error,
        }
    }

    /// Returns the error category for logging and metrics.
    pub fn category(&self) -> &'static str {
        match self {
            Self::Generation(_) => "certificate_generation",
            Self::Storage(_) => "certificate_storage",
            Self::Validation(_) => "certificate_validation",
            Self::Parsing(_) => "certificate_parsing",
            Self::Expiration(_) => "certificate_expiration",
            Self::Configuration(_) => "certificate_configuration",
        }
    }

    /// Returns a unique error code for this error.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Generation(e) => e.error_code(),
            Self::Storage(e) => e.error_code(),
            Self::Validation(e) => e.error_code(),
            Self::Parsing(e) => e.error_code(),
            Self::Expiration(e) => e.error_code(),
            Self::Configuration(e) => e.error_code(),
        }
    }

    /// Returns recovery hints for this error.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::Generation(e) => e.recovery_hints(),
            Self::Storage(e) => e.recovery_hints(),
            Self::Validation(e) => e.recovery_hints(),
            Self::Parsing(e) => e.recovery_hints(),
            Self::Expiration(e) => e.recovery_hints(),
            Self::Configuration(e) => e.recovery_hints(),
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Generation(e) => e.user_message(),
            Self::Storage(e) => e.user_message(),
            Self::Validation(e) => e.user_message(),
            Self::Parsing(e) => e.user_message(),
            Self::Expiration(e) => e.user_message(),
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
                "{self}"
            ),
            Level::WARN => tracing::warn!(
                error_code = %code,
                category = self.category(),
                context = context,
                "{self}"
            ),
            _ => tracing::debug!(
                error_code = %code,
                category = self.category(),
                context = context,
                "{self}"
            ),
        }
    }
}

// =============================================================================
// GenerationError
// =============================================================================

/// Errors during certificate or key generation.
#[derive(Debug, Error)]
pub enum GenerationError {
    /// Key generation failed.
    #[error("Key generation failed ({algorithm}): {message}")]
    KeyGenerationFailed {
        /// Algorithm used.
        algorithm: String,
        /// Error message.
        message: String,
    },

    /// Certificate creation failed.
    #[error("Certificate creation failed: {message}")]
    CertCreationFailed {
        /// Error message.
        message: String,
    },

    /// Certificate signing failed.
    #[error("Certificate signing failed: {message}")]
    SigningFailed {
        /// Error message.
        message: String,
    },

    /// Invalid key size.
    #[error("Invalid key size: {size} bits (minimum: {minimum}, maximum: {maximum})")]
    InvalidKeySize {
        /// Requested key size.
        size: u32,
        /// Minimum allowed size.
        minimum: u32,
        /// Maximum allowed size.
        maximum: u32,
    },

    /// Unsupported algorithm.
    #[error("Unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm {
        /// The unsupported algorithm.
        algorithm: String,
    },

    /// Invalid subject name.
    #[error("Invalid subject name '{name}': {reason}")]
    InvalidSubjectName {
        /// The invalid name.
        name: String,
        /// Reason.
        reason: String,
    },

    /// Invalid validity period.
    #[error("Invalid validity period: {reason}")]
    InvalidValidityPeriod {
        /// Reason.
        reason: String,
    },

    /// Extension error.
    #[error("Certificate extension error: {extension} - {message}")]
    ExtensionError {
        /// Extension name.
        extension: String,
        /// Error message.
        message: String,
    },
}

impl GenerationError {
    /// Creates a key generation failed error.
    pub fn key_generation_failed(
        algorithm: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::KeyGenerationFailed {
            algorithm: algorithm.into(),
            message: message.into(),
        }
    }

    /// Creates a certificate creation failed error.
    pub fn cert_creation_failed(message: impl Into<String>) -> Self {
        Self::CertCreationFailed {
            message: message.into(),
        }
    }

    /// Creates a signing failed error.
    pub fn signing_failed(message: impl Into<String>) -> Self {
        Self::SigningFailed {
            message: message.into(),
        }
    }

    /// Creates an invalid key size error.
    pub fn invalid_key_size(size: u32, minimum: u32, maximum: u32) -> Self {
        Self::InvalidKeySize {
            size,
            minimum,
            maximum,
        }
    }

    /// Creates an unsupported algorithm error.
    pub fn unsupported_algorithm(algorithm: impl Into<String>) -> Self {
        Self::UnsupportedAlgorithm {
            algorithm: algorithm.into(),
        }
    }

    /// Creates an invalid subject name error.
    pub fn invalid_subject_name(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidSubjectName {
            name: name.into(),
            reason: reason.into(),
        }
    }

    /// Creates an invalid validity period error.
    pub fn invalid_validity_period(reason: impl Into<String>) -> Self {
        Self::InvalidValidityPeriod {
            reason: reason.into(),
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::InvalidKeySize { .. } => ErrorSeverity::Error,
            Self::UnsupportedAlgorithm { .. } => ErrorSeverity::Error,
            _ => ErrorSeverity::Critical,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::KeyGenerationFailed { .. } => ErrorCode::new(10, 1),
            Self::CertCreationFailed { .. } => ErrorCode::new(10, 2),
            Self::SigningFailed { .. } => ErrorCode::new(10, 3),
            Self::InvalidKeySize { .. } => ErrorCode::new(10, 4),
            Self::UnsupportedAlgorithm { .. } => ErrorCode::new(10, 5),
            Self::InvalidSubjectName { .. } => ErrorCode::new(10, 6),
            Self::InvalidValidityPeriod { .. } => ErrorCode::new(10, 7),
            Self::ExtensionError { .. } => ErrorCode::new(10, 8),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::KeyGenerationFailed { .. } => vec![
                "Check if cryptographic libraries are properly installed",
                "Verify system has sufficient entropy",
                "Try a different key algorithm",
            ],
            Self::CertCreationFailed { .. } => vec![
                "Verify all certificate parameters are valid",
                "Check subject name format",
            ],
            Self::SigningFailed { .. } => vec![
                "Verify private key is valid",
                "Check signing algorithm compatibility",
            ],
            Self::InvalidKeySize { minimum, maximum, .. } => vec![
                "Use a key size within the allowed range",
                "RSA: 2048, 3072, or 4096 bits recommended",
            ],
            Self::UnsupportedAlgorithm { .. } => vec![
                "Use RSA or ECDSA for OPC UA compatibility",
                "RSA-SHA256 is widely supported",
            ],
            Self::InvalidSubjectName { .. } => vec![
                "Common Name (CN) is required",
                "Use ASCII characters for compatibility",
            ],
            Self::InvalidValidityPeriod { .. } => vec![
                "Validity must be at least 1 day",
                "Maximum recommended: 365 days for security",
            ],
            Self::ExtensionError { .. } => vec![
                "Check extension parameters",
                "Verify extension is supported by OPC UA",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::KeyGenerationFailed { algorithm, .. } => {
                format!("{} 키 생성 실패", algorithm)
            }
            Self::CertCreationFailed { .. } => "인증서 생성 실패".to_string(),
            Self::SigningFailed { .. } => "인증서 서명 실패".to_string(),
            Self::InvalidKeySize { size, .. } => {
                format!("잘못된 키 크기: {} 비트", size)
            }
            Self::UnsupportedAlgorithm { algorithm } => {
                format!("지원되지 않는 알고리즘: {}", algorithm)
            }
            Self::InvalidSubjectName { name, .. } => {
                format!("잘못된 주체 이름: {}", name)
            }
            Self::InvalidValidityPeriod { .. } => "잘못된 유효 기간".to_string(),
            Self::ExtensionError { extension, .. } => {
                format!("인증서 확장 오류: {}", extension)
            }
        }
    }
}

// =============================================================================
// StorageError
// =============================================================================

/// Errors during certificate storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// File not found.
    #[error("Certificate file not found: {path}")]
    FileNotFound {
        /// File path.
        path: PathBuf,
    },

    /// Read failed.
    #[error("Failed to read certificate file '{path}': {message}")]
    ReadFailed {
        /// File path.
        path: PathBuf,
        /// Error message.
        message: String,
        /// Underlying I/O error.
        #[source]
        source: Option<io::Error>,
    },

    /// Write failed.
    #[error("Failed to write certificate file '{path}': {message}")]
    WriteFailed {
        /// File path.
        path: PathBuf,
        /// Error message.
        message: String,
        /// Underlying I/O error.
        #[source]
        source: Option<io::Error>,
    },

    /// Permission denied.
    #[error("Permission denied for certificate file: {path}")]
    PermissionDenied {
        /// File path.
        path: PathBuf,
    },

    /// Directory creation failed.
    #[error("Failed to create certificate directory '{path}': {message}")]
    DirectoryCreationFailed {
        /// Directory path.
        path: PathBuf,
        /// Error message.
        message: String,
    },

    /// Certificate already exists.
    #[error("Certificate already exists: {path}")]
    AlreadyExists {
        /// File path.
        path: PathBuf,
    },

    /// Invalid path.
    #[error("Invalid certificate path: {path} - {reason}")]
    InvalidPath {
        /// The invalid path.
        path: PathBuf,
        /// Reason.
        reason: String,
    },

    /// Storage is read-only.
    #[error("Certificate storage is read-only")]
    ReadOnly,

    /// Disk full.
    #[error("Insufficient disk space for certificate storage")]
    DiskFull,
}

impl StorageError {
    /// Creates a file not found error.
    pub fn file_not_found(path: impl Into<PathBuf>) -> Self {
        Self::FileNotFound { path: path.into() }
    }

    /// Creates a read failed error.
    pub fn read_failed(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::ReadFailed {
            path: path.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Creates a read failed error with source.
    pub fn read_failed_with(
        path: impl Into<PathBuf>,
        message: impl Into<String>,
        source: io::Error,
    ) -> Self {
        Self::ReadFailed {
            path: path.into(),
            message: message.into(),
            source: Some(source),
        }
    }

    /// Creates a write failed error.
    pub fn write_failed(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::WriteFailed {
            path: path.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Creates a write failed error with source.
    pub fn write_failed_with(
        path: impl Into<PathBuf>,
        message: impl Into<String>,
        source: io::Error,
    ) -> Self {
        Self::WriteFailed {
            path: path.into(),
            message: message.into(),
            source: Some(source),
        }
    }

    /// Creates a permission denied error.
    pub fn permission_denied(path: impl Into<PathBuf>) -> Self {
        Self::PermissionDenied { path: path.into() }
    }

    /// Creates a directory creation failed error.
    pub fn directory_creation_failed(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::DirectoryCreationFailed {
            path: path.into(),
            message: message.into(),
        }
    }

    /// Creates an already exists error.
    pub fn already_exists(path: impl Into<PathBuf>) -> Self {
        Self::AlreadyExists { path: path.into() }
    }

    /// Creates an invalid path error.
    pub fn invalid_path(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Self::InvalidPath {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::WriteFailed { .. } | Self::DirectoryCreationFailed { .. } | Self::DiskFull
        )
    }

    /// Returns the suggested retry delay.
    pub fn suggested_retry_delay(&self) -> Option<Duration> {
        if self.is_retryable() {
            Some(Duration::from_secs(1))
        } else {
            None
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::FileNotFound { .. } => ErrorSeverity::Warning,
            Self::PermissionDenied { .. } => ErrorSeverity::Error,
            Self::ReadOnly => ErrorSeverity::Error,
            Self::DiskFull => ErrorSeverity::Critical,
            _ => ErrorSeverity::Warning,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::FileNotFound { .. } => ErrorCode::new(11, 1),
            Self::ReadFailed { .. } => ErrorCode::new(11, 2),
            Self::WriteFailed { .. } => ErrorCode::new(11, 3),
            Self::PermissionDenied { .. } => ErrorCode::new(11, 4),
            Self::DirectoryCreationFailed { .. } => ErrorCode::new(11, 5),
            Self::AlreadyExists { .. } => ErrorCode::new(11, 6),
            Self::InvalidPath { .. } => ErrorCode::new(11, 7),
            Self::ReadOnly => ErrorCode::new(11, 8),
            Self::DiskFull => ErrorCode::new(11, 9),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::FileNotFound { .. } => vec![
                "Generate a new certificate",
                "Check the certificate path configuration",
            ],
            Self::ReadFailed { .. } => vec![
                "Check file permissions",
                "Verify file is not corrupted",
            ],
            Self::WriteFailed { .. } => vec![
                "Check directory permissions",
                "Ensure sufficient disk space",
            ],
            Self::PermissionDenied { .. } => vec![
                "Run with appropriate permissions",
                "Check file ownership",
            ],
            Self::DirectoryCreationFailed { .. } => vec![
                "Check parent directory permissions",
                "Verify path is valid",
            ],
            Self::AlreadyExists { .. } => vec![
                "Use force flag to overwrite",
                "Choose a different filename",
            ],
            Self::InvalidPath { .. } => vec![
                "Use absolute path",
                "Check for invalid characters",
            ],
            Self::ReadOnly => vec![
                "Use a writable storage location",
                "Check volume mount options",
            ],
            Self::DiskFull => vec![
                "Free up disk space",
                "Use a different storage location",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::FileNotFound { path } => {
                format!("인증서 파일을 찾을 수 없음: {}", path.display())
            }
            Self::ReadFailed { path, .. } => {
                format!("인증서 파일 읽기 실패: {}", path.display())
            }
            Self::WriteFailed { path, .. } => {
                format!("인증서 파일 쓰기 실패: {}", path.display())
            }
            Self::PermissionDenied { path } => {
                format!("인증서 파일 접근 거부: {}", path.display())
            }
            Self::DirectoryCreationFailed { path, .. } => {
                format!("인증서 디렉토리 생성 실패: {}", path.display())
            }
            Self::AlreadyExists { path } => {
                format!("인증서가 이미 존재함: {}", path.display())
            }
            Self::InvalidPath { path, .. } => {
                format!("잘못된 인증서 경로: {}", path.display())
            }
            Self::ReadOnly => "인증서 저장소가 읽기 전용입니다".to_string(),
            Self::DiskFull => "디스크 공간 부족".to_string(),
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => Self::FileNotFound {
                path: PathBuf::from("unknown"),
            },
            io::ErrorKind::PermissionDenied => Self::PermissionDenied {
                path: PathBuf::from("unknown"),
            },
            _ => Self::ReadFailed {
                path: PathBuf::from("unknown"),
                message: error.to_string(),
                source: Some(error),
            },
        }
    }
}

// =============================================================================
// ValidationError
// =============================================================================

/// Errors during certificate validation.
#[derive(Debug, Clone, Error)]
pub enum ValidationError {
    /// Invalid certificate.
    #[error("Invalid certificate: {message}")]
    InvalidCertificate {
        /// Error message.
        message: String,
    },

    /// Certificate not trusted.
    #[error("Certificate not trusted: {thumbprint}")]
    NotTrusted {
        /// Certificate thumbprint.
        thumbprint: String,
    },

    /// Certificate chain error.
    #[error("Certificate chain validation failed: {message}")]
    ChainError {
        /// Error message.
        message: String,
    },

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureInvalid,

    /// Key usage mismatch.
    #[error("Certificate key usage does not permit: {usage}")]
    KeyUsageMismatch {
        /// Required usage.
        usage: String,
    },

    /// Extended key usage mismatch.
    #[error("Certificate extended key usage does not permit: {usage}")]
    ExtendedKeyUsageMismatch {
        /// Required usage.
        usage: String,
    },

    /// Subject Alternative Name mismatch.
    #[error("Certificate SAN does not match hostname: {expected}")]
    SanMismatch {
        /// Expected hostname.
        expected: String,
    },

    /// Revoked certificate.
    #[error("Certificate has been revoked")]
    Revoked {
        /// Revocation reason.
        reason: Option<String>,
    },

    /// Self-signed certificate not allowed.
    #[error("Self-signed certificates are not allowed")]
    SelfSignedNotAllowed,

    /// Weak algorithm.
    #[error("Certificate uses weak algorithm: {algorithm}")]
    WeakAlgorithm {
        /// The weak algorithm.
        algorithm: String,
    },

    /// Invalid application URI.
    #[error("Application URI mismatch: expected '{expected}', got '{actual}'")]
    ApplicationUriMismatch {
        /// Expected URI.
        expected: String,
        /// Actual URI.
        actual: String,
    },
}

impl ValidationError {
    /// Creates an invalid certificate error.
    pub fn invalid_certificate(message: impl Into<String>) -> Self {
        Self::InvalidCertificate {
            message: message.into(),
        }
    }

    /// Creates a not trusted error.
    pub fn not_trusted(thumbprint: impl Into<String>) -> Self {
        Self::NotTrusted {
            thumbprint: thumbprint.into(),
        }
    }

    /// Creates a chain error.
    pub fn chain_error(message: impl Into<String>) -> Self {
        Self::ChainError {
            message: message.into(),
        }
    }

    /// Creates a key usage mismatch error.
    pub fn key_usage_mismatch(usage: impl Into<String>) -> Self {
        Self::KeyUsageMismatch {
            usage: usage.into(),
        }
    }

    /// Creates a SAN mismatch error.
    pub fn san_mismatch(expected: impl Into<String>) -> Self {
        Self::SanMismatch {
            expected: expected.into(),
        }
    }

    /// Creates a revoked error.
    pub fn revoked(reason: Option<String>) -> Self {
        Self::Revoked { reason }
    }

    /// Creates a weak algorithm error.
    pub fn weak_algorithm(algorithm: impl Into<String>) -> Self {
        Self::WeakAlgorithm {
            algorithm: algorithm.into(),
        }
    }

    /// Creates an application URI mismatch error.
    pub fn application_uri_mismatch(
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::ApplicationUriMismatch {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::NotTrusted { .. } => ErrorSeverity::Warning,
            Self::SelfSignedNotAllowed => ErrorSeverity::Warning,
            Self::Revoked { .. } => ErrorSeverity::Critical,
            Self::SignatureInvalid => ErrorSeverity::Critical,
            _ => ErrorSeverity::Error,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidCertificate { .. } => ErrorCode::new(12, 1),
            Self::NotTrusted { .. } => ErrorCode::new(12, 2),
            Self::ChainError { .. } => ErrorCode::new(12, 3),
            Self::SignatureInvalid => ErrorCode::new(12, 4),
            Self::KeyUsageMismatch { .. } => ErrorCode::new(12, 5),
            Self::ExtendedKeyUsageMismatch { .. } => ErrorCode::new(12, 6),
            Self::SanMismatch { .. } => ErrorCode::new(12, 7),
            Self::Revoked { .. } => ErrorCode::new(12, 8),
            Self::SelfSignedNotAllowed => ErrorCode::new(12, 9),
            Self::WeakAlgorithm { .. } => ErrorCode::new(12, 10),
            Self::ApplicationUriMismatch { .. } => ErrorCode::new(12, 11),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::InvalidCertificate { .. } => vec![
                "Check certificate file format",
                "Regenerate certificate if corrupted",
            ],
            Self::NotTrusted { .. } => vec![
                "Add certificate to trusted store",
                "Accept certificate explicitly",
            ],
            Self::ChainError { .. } => vec![
                "Install intermediate certificates",
                "Check CA certificate validity",
            ],
            Self::SignatureInvalid => vec![
                "Certificate may be corrupted",
                "Re-download or regenerate certificate",
            ],
            Self::KeyUsageMismatch { .. } => vec![
                "Generate certificate with appropriate key usage",
                "For OPC UA: Digital Signature, Key Encipherment, Data Encipherment",
            ],
            Self::ExtendedKeyUsageMismatch { .. } => vec![
                "Generate certificate with clientAuth and serverAuth EKU",
            ],
            Self::SanMismatch { .. } => vec![
                "Regenerate certificate with correct hostname",
                "Add hostname to Subject Alternative Names",
            ],
            Self::Revoked { .. } => vec![
                "Obtain a new certificate",
                "Contact certificate issuer",
            ],
            Self::SelfSignedNotAllowed => vec![
                "Use a CA-signed certificate",
                "Enable self-signed certificate acceptance in settings",
            ],
            Self::WeakAlgorithm { .. } => vec![
                "Regenerate certificate with SHA-256 or stronger",
                "Use RSA 2048+ or ECDSA P-256+",
            ],
            Self::ApplicationUriMismatch { .. } => vec![
                "Verify application URI matches certificate",
                "Regenerate certificate with correct application URI",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidCertificate { .. } => "유효하지 않은 인증서".to_string(),
            Self::NotTrusted { thumbprint } => {
                format!("신뢰할 수 없는 인증서: {}", thumbprint)
            }
            Self::ChainError { .. } => "인증서 체인 검증 실패".to_string(),
            Self::SignatureInvalid => "인증서 서명 검증 실패".to_string(),
            Self::KeyUsageMismatch { usage } => {
                format!("인증서 키 용도 불일치: {}", usage)
            }
            Self::ExtendedKeyUsageMismatch { usage } => {
                format!("인증서 확장 키 용도 불일치: {}", usage)
            }
            Self::SanMismatch { expected } => {
                format!("인증서 SAN 불일치: {}", expected)
            }
            Self::Revoked { .. } => "인증서가 폐기되었습니다".to_string(),
            Self::SelfSignedNotAllowed => "자체 서명 인증서는 허용되지 않습니다".to_string(),
            Self::WeakAlgorithm { algorithm } => {
                format!("취약한 알고리즘 사용: {}", algorithm)
            }
            Self::ApplicationUriMismatch { .. } => "애플리케이션 URI 불일치".to_string(),
        }
    }
}

// =============================================================================
// ParsingError
// =============================================================================

/// Errors during certificate or key parsing.
#[derive(Debug, Error)]
pub enum ParsingError {
    /// Invalid DER format.
    #[error("Invalid DER encoding: {message}")]
    InvalidDer {
        /// Error message.
        message: String,
    },

    /// Invalid PEM format.
    #[error("Invalid PEM encoding: {message}")]
    InvalidPem {
        /// Error message.
        message: String,
    },

    /// Invalid private key.
    #[error("Invalid private key: {message}")]
    InvalidPrivateKey {
        /// Error message.
        message: String,
    },

    /// Invalid public key.
    #[error("Invalid public key: {message}")]
    InvalidPublicKey {
        /// Error message.
        message: String,
    },

    /// Key mismatch.
    #[error("Private key does not match certificate public key")]
    KeyMismatch,

    /// Unsupported format.
    #[error("Unsupported certificate format: {format}")]
    UnsupportedFormat {
        /// The unsupported format.
        format: String,
    },

    /// Missing private key.
    #[error("Private key not found in file")]
    MissingPrivateKey,

    /// Missing certificate.
    #[error("Certificate not found in file")]
    MissingCertificate,

    /// Invalid thumbprint.
    #[error("Invalid certificate thumbprint: {thumbprint}")]
    InvalidThumbprint {
        /// The invalid thumbprint.
        thumbprint: String,
    },
}

impl ParsingError {
    /// Creates an invalid DER error.
    pub fn invalid_der(message: impl Into<String>) -> Self {
        Self::InvalidDer {
            message: message.into(),
        }
    }

    /// Creates an invalid PEM error.
    pub fn invalid_pem(message: impl Into<String>) -> Self {
        Self::InvalidPem {
            message: message.into(),
        }
    }

    /// Creates an invalid private key error.
    pub fn invalid_private_key(message: impl Into<String>) -> Self {
        Self::InvalidPrivateKey {
            message: message.into(),
        }
    }

    /// Creates an invalid public key error.
    pub fn invalid_public_key(message: impl Into<String>) -> Self {
        Self::InvalidPublicKey {
            message: message.into(),
        }
    }

    /// Creates an unsupported format error.
    pub fn unsupported_format(format: impl Into<String>) -> Self {
        Self::UnsupportedFormat {
            format: format.into(),
        }
    }

    /// Creates an invalid thumbprint error.
    pub fn invalid_thumbprint(thumbprint: impl Into<String>) -> Self {
        Self::InvalidThumbprint {
            thumbprint: thumbprint.into(),
        }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        ErrorSeverity::Error
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidDer { .. } => ErrorCode::new(13, 1),
            Self::InvalidPem { .. } => ErrorCode::new(13, 2),
            Self::InvalidPrivateKey { .. } => ErrorCode::new(13, 3),
            Self::InvalidPublicKey { .. } => ErrorCode::new(13, 4),
            Self::KeyMismatch => ErrorCode::new(13, 5),
            Self::UnsupportedFormat { .. } => ErrorCode::new(13, 6),
            Self::MissingPrivateKey => ErrorCode::new(13, 7),
            Self::MissingCertificate => ErrorCode::new(13, 8),
            Self::InvalidThumbprint { .. } => ErrorCode::new(13, 9),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::InvalidDer { .. } => vec![
                "Check file is in DER format",
                "Convert from PEM using: openssl x509 -in cert.pem -outform DER -out cert.der",
            ],
            Self::InvalidPem { .. } => vec![
                "Check file is in PEM format",
                "Verify BEGIN/END markers are present",
            ],
            Self::InvalidPrivateKey { .. } => vec![
                "Verify private key file integrity",
                "Check key file is not encrypted (or provide password)",
            ],
            Self::InvalidPublicKey { .. } => vec![
                "Extract public key from certificate",
                "Verify certificate file integrity",
            ],
            Self::KeyMismatch => vec![
                "Ensure private key matches certificate",
                "Generate new key pair if necessary",
            ],
            Self::UnsupportedFormat { .. } => vec![
                "Use DER or PEM format",
                "Convert using OpenSSL",
            ],
            Self::MissingPrivateKey => vec![
                "Provide separate private key file",
                "Check PKCS#12 file contains key",
            ],
            Self::MissingCertificate => vec![
                "Provide separate certificate file",
                "Check PKCS#12 file contains certificate",
            ],
            Self::InvalidThumbprint { .. } => vec![
                "Use SHA-1 or SHA-256 thumbprint",
                "Format: hexadecimal without colons",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidDer { .. } => "잘못된 DER 인코딩".to_string(),
            Self::InvalidPem { .. } => "잘못된 PEM 인코딩".to_string(),
            Self::InvalidPrivateKey { .. } => "잘못된 개인키".to_string(),
            Self::InvalidPublicKey { .. } => "잘못된 공개키".to_string(),
            Self::KeyMismatch => "개인키와 인증서가 일치하지 않습니다".to_string(),
            Self::UnsupportedFormat { format } => {
                format!("지원되지 않는 형식: {}", format)
            }
            Self::MissingPrivateKey => "개인키를 찾을 수 없음".to_string(),
            Self::MissingCertificate => "인증서를 찾을 수 없음".to_string(),
            Self::InvalidThumbprint { thumbprint } => {
                format!("잘못된 지문: {}", thumbprint)
            }
        }
    }
}

// =============================================================================
// ExpirationError
// =============================================================================

/// Errors related to certificate expiration.
#[derive(Debug, Error)]
pub enum ExpirationError {
    /// Certificate has expired.
    #[error("Certificate expired {days_expired} day(s) ago")]
    Expired {
        /// Days since expiration.
        days_expired: i64,
    },

    /// Certificate is not yet valid.
    #[error("Certificate not valid for another {days_until_valid} day(s)")]
    NotYetValid {
        /// Days until valid.
        days_until_valid: i64,
    },

    /// Certificate will expire soon.
    #[error("Certificate expires in {days_remaining} day(s)")]
    ExpiringSoon {
        /// Days until expiration.
        days_remaining: i64,
    },
}

impl ExpirationError {
    /// Creates an expired error.
    pub fn expired(days_expired: i64) -> Self {
        Self::Expired { days_expired }
    }

    /// Creates a not yet valid error.
    pub fn not_yet_valid(days_until_valid: i64) -> Self {
        Self::NotYetValid { days_until_valid }
    }

    /// Creates an expiring soon error.
    pub fn expiring_soon(days_remaining: i64) -> Self {
        Self::ExpiringSoon { days_remaining }
    }

    /// Returns the severity level.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::Expired { .. } => ErrorSeverity::Error,
            Self::NotYetValid { .. } => ErrorSeverity::Error,
            Self::ExpiringSoon { days_remaining } if *days_remaining <= 7 => ErrorSeverity::Warning,
            Self::ExpiringSoon { .. } => ErrorSeverity::Info,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Expired { .. } => ErrorCode::new(14, 1),
            Self::NotYetValid { .. } => ErrorCode::new(14, 2),
            Self::ExpiringSoon { .. } => ErrorCode::new(14, 3),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::Expired { .. } => vec![
                "Generate a new certificate",
                "Renew the certificate with your CA",
            ],
            Self::NotYetValid { .. } => vec![
                "Check system clock is correct",
                "Wait until certificate validity period begins",
            ],
            Self::ExpiringSoon { .. } => vec![
                "Plan certificate renewal",
                "Generate replacement certificate before expiration",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Expired { days_expired } => {
                format!("인증서가 {}일 전에 만료되었습니다", days_expired)
            }
            Self::NotYetValid { days_until_valid } => {
                format!("인증서가 {}일 후에 유효해집니다", days_until_valid)
            }
            Self::ExpiringSoon { days_remaining } => {
                format!("인증서가 {}일 후 만료됩니다", days_remaining)
            }
        }
    }
}

// =============================================================================
// CertConfigError
// =============================================================================

/// Certificate configuration errors.
#[derive(Debug, Error)]
pub enum CertConfigError {
    /// Missing required field.
    #[error("Missing required certificate configuration: {field}")]
    MissingField {
        /// The missing field.
        field: String,
    },

    /// Invalid value.
    #[error("Invalid certificate configuration value for '{field}': {message}")]
    InvalidValue {
        /// Field name.
        field: String,
        /// Error message.
        message: String,
    },

    /// Invalid path.
    #[error("Invalid certificate path '{field}': {path}")]
    InvalidPath {
        /// Field name.
        field: String,
        /// The invalid path.
        path: String,
    },

    /// Conflicting options.
    #[error("Conflicting certificate options: {message}")]
    ConflictingOptions {
        /// Error message.
        message: String,
    },
}

impl CertConfigError {
    /// Creates a missing field error.
    pub fn missing_field(field: impl Into<String>) -> Self {
        Self::MissingField {
            field: field.into(),
        }
    }

    /// Creates an invalid value error.
    pub fn invalid_value(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidValue {
            field: field.into(),
            message: message.into(),
        }
    }

    /// Creates an invalid path error.
    pub fn invalid_path(field: impl Into<String>, path: impl Into<String>) -> Self {
        Self::InvalidPath {
            field: field.into(),
            path: path.into(),
        }
    }

    /// Creates a conflicting options error.
    pub fn conflicting_options(message: impl Into<String>) -> Self {
        Self::ConflictingOptions {
            message: message.into(),
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingField { .. } => ErrorCode::new(15, 1),
            Self::InvalidValue { .. } => ErrorCode::new(15, 2),
            Self::InvalidPath { .. } => ErrorCode::new(15, 3),
            Self::ConflictingOptions { .. } => ErrorCode::new(15, 4),
        }
    }

    /// Returns recovery hints.
    pub fn recovery_hints(&self) -> Vec<&'static str> {
        match self {
            Self::MissingField { .. } => vec![
                "Provide the required configuration field",
                "Check configuration documentation",
            ],
            Self::InvalidValue { .. } => vec![
                "Check the value format and range",
                "Refer to configuration examples",
            ],
            Self::InvalidPath { .. } => vec![
                "Use an absolute path",
                "Verify the path exists",
            ],
            Self::ConflictingOptions { .. } => vec![
                "Review configuration options",
                "Remove conflicting settings",
            ],
        }
    }

    /// Returns a user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            Self::MissingField { field } => {
                format!("필수 인증서 설정 누락: {}", field)
            }
            Self::InvalidValue { field, message } => {
                format!("잘못된 인증서 설정 '{}': {}", field, message)
            }
            Self::InvalidPath { field, path } => {
                format!("잘못된 인증서 경로 '{}': {}", field, path)
            }
            Self::ConflictingOptions { message } => {
                format!("충돌하는 인증서 옵션: {}", message)
            }
        }
    }
}

// =============================================================================
// Result Type Alias
// =============================================================================

/// A Result type with CertificateError.
pub type CertificateResult<T> = Result<T, CertificateError>;

// =============================================================================
// Conversion to OpcUaError
// =============================================================================

impl From<CertificateError> for OpcUaError {
    fn from(error: CertificateError) -> Self {
        match error {
            CertificateError::Validation(ValidationError::NotTrusted { thumbprint }) => {
                OpcUaError::Security(SecurityError::CertificateNotTrusted { thumbprint })
            }
            CertificateError::Expiration(ExpirationError::Expired { .. }) => {
                OpcUaError::Security(SecurityError::CertificateExpired { expired_at: None })
            }
            other => OpcUaError::Security(SecurityError::Certificate {
                message: other.to_string(),
            }),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation_error() {
        let error = GenerationError::key_generation_failed("RSA", "insufficient entropy");
        assert!(error.to_string().contains("RSA"));
        assert!(error.to_string().contains("insufficient entropy"));
        assert_eq!(error.error_code(), ErrorCode::new(10, 1));
    }

    #[test]
    fn test_storage_error_retryable() {
        let error = StorageError::write_failed("/tmp/cert.pem", "disk full");
        assert!(error.is_retryable());

        let error = StorageError::permission_denied("/tmp/cert.pem");
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_validation_error_severity() {
        let error = ValidationError::not_trusted("ABC123");
        assert_eq!(error.severity(), ErrorSeverity::Warning);

        let error = ValidationError::revoked(Some("key compromise".to_string()));
        assert_eq!(error.severity(), ErrorSeverity::Critical);
    }

    #[test]
    fn test_expiration_error() {
        let error = ExpirationError::expired(30);
        assert_eq!(error.error_code(), ErrorCode::new(14, 1));
        assert!(error.to_string().contains("30"));

        let error = ExpirationError::expiring_soon(5);
        assert_eq!(error.severity(), ErrorSeverity::Warning);
    }

    #[test]
    fn test_certificate_error_conversion() {
        let error = CertificateError::not_trusted("ABC123");
        let opcua_error: OpcUaError = error.into();
        assert!(matches!(
            opcua_error,
            OpcUaError::Security(SecurityError::CertificateNotTrusted { .. })
        ));
    }

    #[test]
    fn test_recovery_hints() {
        let error = ValidationError::weak_algorithm("MD5");
        let hints = error.recovery_hints();
        assert!(!hints.is_empty());
        assert!(hints.iter().any(|h| h.contains("SHA-256")));
    }

    #[test]
    fn test_user_message() {
        let error = StorageError::file_not_found("/path/to/cert.pem");
        let msg = error.user_message();
        assert!(msg.contains("찾을 수 없음"));
    }
}
