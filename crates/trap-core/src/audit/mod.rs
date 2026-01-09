// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Audit logging for security and compliance.
//!
//! This module provides a comprehensive, extensible audit logging system for tracking
//! all significant operations in the system, supporting both security requirements
//! and operational compliance.
//!
//! # Architecture
//!
//! The audit logging system is designed with the following principles:
//!
//! - **Extensibility**: New logger implementations can be added via the `AuditLogger` trait
//! - **Composability**: Multiple loggers can be chained using `CompositeAuditLogger`
//! - **Performance**: Async batch processing for high-throughput environments
//! - **Flexibility**: Pluggable formatters for different output formats
//! - **Observability**: Built-in metrics collection
//!
//! # Components
//!
//! - [`AuditLogger`]: Core trait for audit logger implementations
//! - [`AuditLog`]: Structured audit log entry with rich metadata
//! - [`FileAuditLogger`]: File-based logger with rotation support
//! - [`AsyncBatchAuditLogger`]: High-performance batched async logger
//! - [`CompositeAuditLogger`]: Chains multiple loggers together
//! - [`AuditFormatter`]: Trait for custom log formatting
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_core::audit::{
//!     AuditLogger, AuditLog, AuditAction, ActionResult,
//!     FileAuditLogger, AsyncBatchAuditLogger, CompositeAuditLogger,
//!     RotationConfig,
//! };
//!
//! // Create a composite logger with file and async batch logging
//! let file_logger = FileAuditLogger::new("audit.log", RotationConfig::daily())?;
//! let async_logger = AsyncBatchAuditLogger::new(file_logger)
//!     .batch_size(100)
//!     .flush_interval(Duration::from_secs(5))
//!     .build();
//!
//! // Log an operation
//! async_logger.log(AuditLog::write_operation(
//!     &device_id,
//!     &address,
//!     &value,
//!     ActionResult::Success,
//!     Some("admin"),
//!     None,
//! )).await?;
//! ```

mod error;
mod types;
mod formatter;
mod file_logger;
mod memory_logger;
mod batch_logger;
mod composite_logger;
mod metrics;

// Re-export all public types
pub use error::{AuditError, AuditResult};
pub use types::{
    ActionResult, AuditAction, AuditContext, AuditFilter, AuditLog, AuditResource,
    AuditSeverity, SensitiveValue,
};
pub use formatter::{
    AuditFormatter, JsonFormatter, CompactJsonFormatter, TextFormatter,
    CefFormatter, SyslogFormatter,
};
pub use file_logger::{FileAuditLogger, RotationConfig, RotationStrategy};
pub use memory_logger::InMemoryAuditLogger;
pub use batch_logger::{AsyncBatchAuditLogger, BatchConfig};
pub use composite_logger::{CompositeAuditLogger, FilteringLogger, TeeLogger};
pub use metrics::{AuditMetrics, AuditMetricsCollector, RateLimitedLogger};

use async_trait::async_trait;

// =============================================================================
// Core Trait
// =============================================================================

/// Trait for audit logger implementations.
///
/// This trait defines the core interface that all audit loggers must implement.
/// It is designed to be async-first and supports both logging and querying.
///
/// # Implementing a Custom Logger
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use trap_core::audit::{AuditLogger, AuditLog, AuditFilter, AuditResult};
///
/// struct MyCustomLogger {
///     // ... your fields
/// }
///
/// #[async_trait]
/// impl AuditLogger for MyCustomLogger {
///     async fn log(&self, entry: AuditLog) -> AuditResult<()> {
///         // Your implementation
///         Ok(())
///     }
///
///     async fn query(&self, filter: AuditFilter) -> AuditResult<Vec<AuditLog>> {
///         // Your implementation
///         Ok(vec![])
///     }
///
///     async fn flush(&self) -> AuditResult<()> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait AuditLogger: Send + Sync {
    /// Logs an audit entry.
    ///
    /// This method should be non-blocking where possible. For high-throughput
    /// scenarios, consider using `AsyncBatchAuditLogger` to batch writes.
    async fn log(&self, entry: AuditLog) -> AuditResult<()>;

    /// Logs multiple audit entries in a batch.
    ///
    /// The default implementation calls `log` for each entry, but implementations
    /// may override this for better performance.
    async fn log_batch(&self, entries: Vec<AuditLog>) -> AuditResult<()> {
        for entry in entries {
            self.log(entry).await?;
        }
        Ok(())
    }

    /// Queries audit logs with the given filter.
    ///
    /// Not all logger implementations support querying. File-based loggers
    /// may return an error, while database-backed loggers provide full query support.
    async fn query(&self, filter: AuditFilter) -> AuditResult<Vec<AuditLog>>;

    /// Flushes any buffered logs.
    ///
    /// This should be called before shutdown to ensure all logs are persisted.
    async fn flush(&self) -> AuditResult<()>;

    /// Returns the logger name for identification.
    fn name(&self) -> &str {
        "audit_logger"
    }

    /// Returns `true` if this logger supports querying.
    fn supports_query(&self) -> bool {
        false
    }

    /// Returns `true` if this logger is healthy.
    async fn health_check(&self) -> bool {
        true
    }
}

// =============================================================================
// No-Op Logger
// =============================================================================

/// A no-op audit logger that discards all entries.
///
/// Useful when audit logging is disabled or for testing.
#[derive(Debug, Default, Clone)]
pub struct NoOpAuditLogger;

impl NoOpAuditLogger {
    /// Creates a new no-op logger.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AuditLogger for NoOpAuditLogger {
    async fn log(&self, _entry: AuditLog) -> AuditResult<()> {
        Ok(())
    }

    async fn query(&self, _filter: AuditFilter) -> AuditResult<Vec<AuditLog>> {
        Ok(Vec::new())
    }

    async fn flush(&self) -> AuditResult<()> {
        Ok(())
    }

    fn name(&self) -> &str {
        "noop"
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for creating audit loggers with common configurations.
#[derive(Debug)]
pub struct AuditLoggerBuilder {
    file_path: Option<std::path::PathBuf>,
    rotation_config: Option<RotationConfig>,
    batch_config: Option<BatchConfig>,
    formatter: Option<Box<dyn AuditFormatter>>,
    enable_metrics: bool,
}

impl Default for AuditLoggerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLoggerBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {
            file_path: None,
            rotation_config: None,
            batch_config: None,
            formatter: None,
            enable_metrics: false,
        }
    }

    /// Sets the file path for file-based logging.
    pub fn file(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    /// Sets the rotation configuration.
    pub fn rotation(mut self, config: RotationConfig) -> Self {
        self.rotation_config = Some(config);
        self
    }

    /// Enables batch processing with the given configuration.
    pub fn batch(mut self, config: BatchConfig) -> Self {
        self.batch_config = Some(config);
        self
    }

    /// Sets a custom formatter.
    pub fn formatter(mut self, formatter: impl AuditFormatter + 'static) -> Self {
        self.formatter = Some(Box::new(formatter));
        self
    }

    /// Enables metrics collection.
    pub fn with_metrics(mut self) -> Self {
        self.enable_metrics = true;
        self
    }

    /// Builds the audit logger.
    pub fn build(self) -> AuditResult<Box<dyn AuditLogger>> {
        let file_path = self.file_path.ok_or_else(|| {
            AuditError::configuration("File path is required")
        })?;

        let rotation = self.rotation_config.unwrap_or_default();
        let file_logger = FileAuditLogger::new(&file_path, rotation)?;

        if let Some(batch_config) = self.batch_config {
            Ok(Box::new(
                AsyncBatchAuditLogger::new(file_logger, batch_config),
            ))
        } else {
            Ok(Box::new(file_logger))
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_logger() {
        let logger = NoOpAuditLogger::new();

        let log = AuditLog::new(
            AuditAction::Read,
            AuditResource::device("test-device"),
            ActionResult::Success,
        );

        assert!(logger.log(log).await.is_ok());
        assert!(logger.query(AuditFilter::default()).await.unwrap().is_empty());
        assert!(logger.flush().await.is_ok());
    }
}
