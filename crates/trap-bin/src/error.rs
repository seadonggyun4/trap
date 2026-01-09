// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Error types for the TRAP binary.

use thiserror::Error;

/// Result type alias for trap-bin operations.
pub type BinResult<T> = Result<T, BinError>;

/// Errors that can occur in the TRAP binary.
#[derive(Debug, Error)]
pub enum BinError {
    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Initialization error.
    #[error("Initialization error: {0}")]
    Initialization(String),

    /// Runtime error.
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(String),

    /// Health check error.
    #[error("Health check failed: {0}")]
    Health(String),

    /// API error.
    #[error("API error: {0}")]
    Api(#[from] trap_api::ApiError),

    /// Config parsing error.
    #[error("Config error: {0}")]
    Config(#[from] trap_config::ConfigError),

    /// Core error.
    #[error("Core error: {0}")]
    Core(#[from] trap_core::TrapError),

    /// Generic error with context.
    #[error("{context}: {source}")]
    WithContext {
        /// The context description.
        context: String,
        /// The underlying error.
        #[source]
        source: Box<BinError>,
    },
}

impl BinError {
    /// Creates a configuration error.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Configuration(msg.into())
    }

    /// Creates an initialization error.
    pub fn init(msg: impl Into<String>) -> Self {
        Self::Initialization(msg.into())
    }

    /// Creates a runtime error.
    pub fn runtime(msg: impl Into<String>) -> Self {
        Self::Runtime(msg.into())
    }

    /// Creates an I/O error.
    pub fn io(msg: impl Into<String>) -> Self {
        Self::Io(msg.into())
    }

    /// Adds context to an error.
    pub fn with_context(self, context: impl Into<String>) -> Self {
        Self::WithContext {
            context: context.into(),
            source: Box::new(self),
        }
    }

    /// Returns the exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Configuration(_) | Self::Config(_) => 1,
            Self::Initialization(_) => 2,
            Self::Runtime(_) => 3,
            Self::Io(_) => 4,
            Self::Health(_) => 5,
            Self::Api(_) => 6,
            Self::Core(_) => 7,
            Self::WithContext { source, .. } => source.exit_code(),
        }
    }
}

impl From<std::io::Error> for BinError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<anyhow::Error> for BinError {
    fn from(err: anyhow::Error) -> Self {
        Self::Runtime(err.to_string())
    }
}

// =============================================================================
// Error Reporting
// =============================================================================

/// Reports an error with appropriate formatting.
pub fn report_error(error: &BinError) {
    eprintln!("Error: {}", error);

    // Print cause chain
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        eprintln!("  Caused by: {}", cause);
        source = cause.source();
    }
}

/// Reports an error and exits with the appropriate code.
pub fn report_error_and_exit(error: BinError) -> ! {
    report_error(&error);
    std::process::exit(error.exit_code())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = BinError::config("test error");
        assert_eq!(err.to_string(), "Configuration error: test error");
    }

    #[test]
    fn test_error_with_context() {
        let err = BinError::config("inner error").with_context("outer context");
        assert_eq!(err.to_string(), "outer context: Configuration error: inner error");
    }

    #[test]
    fn test_exit_codes() {
        assert_eq!(BinError::config("test").exit_code(), 1);
        assert_eq!(BinError::init("test").exit_code(), 2);
        assert_eq!(BinError::runtime("test").exit_code(), 3);
        assert_eq!(BinError::io("test").exit_code(), 4);
        assert_eq!(BinError::Health("test".to_string()).exit_code(), 5);
    }
}
