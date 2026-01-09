// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! File-based audit logger with rotation support.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Timelike, Utc};
use parking_lot::Mutex;

use super::error::{AuditError, AuditResult};
use super::formatter::{AuditFormatter, CompactJsonFormatter};
use super::types::{AuditFilter, AuditLog};
use super::AuditLogger;

// =============================================================================
// Rotation Configuration
// =============================================================================

/// Rotation configuration for file-based logging.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Rotation strategy.
    pub strategy: RotationStrategy,
    /// Maximum file size in bytes (for size-based rotation).
    pub max_size: u64,
    /// Number of files to keep.
    pub keep_files: u32,
    /// Compress rotated files.
    pub compress: bool,
}

/// Rotation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStrategy {
    /// Rotate daily at midnight UTC.
    Daily,
    /// Rotate hourly.
    Hourly,
    /// Rotate when file exceeds max size.
    Size,
    /// Never rotate.
    Never,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            strategy: RotationStrategy::Daily,
            max_size: 100 * 1024 * 1024, // 100MB
            keep_files: 30,
            compress: false,
        }
    }
}

impl RotationConfig {
    /// Creates a daily rotation config.
    pub fn daily() -> Self {
        Self {
            strategy: RotationStrategy::Daily,
            ..Default::default()
        }
    }

    /// Creates an hourly rotation config.
    pub fn hourly() -> Self {
        Self {
            strategy: RotationStrategy::Hourly,
            ..Default::default()
        }
    }

    /// Creates a size-based rotation config.
    pub fn size(max_size: u64) -> Self {
        Self {
            strategy: RotationStrategy::Size,
            max_size,
            ..Default::default()
        }
    }

    /// Creates a no-rotation config.
    pub fn never() -> Self {
        Self {
            strategy: RotationStrategy::Never,
            ..Default::default()
        }
    }

    /// Sets the number of files to keep.
    pub fn keep(mut self, count: u32) -> Self {
        self.keep_files = count;
        self
    }

    /// Enables compression for rotated files.
    pub fn with_compression(mut self) -> Self {
        self.compress = true;
        self
    }

    /// Sets the maximum file size.
    pub fn max_size(mut self, size: u64) -> Self {
        self.max_size = size;
        self
    }
}

// =============================================================================
// File Audit Logger
// =============================================================================

/// File-based audit logger.
///
/// Writes audit logs to a file in the configured format (default: JSON Lines).
/// Supports daily rotation and file retention policies.
///
/// # Example
///
/// ```rust,ignore
/// use trap_core::audit::{FileAuditLogger, RotationConfig};
///
/// let logger = FileAuditLogger::new("audit.log", RotationConfig::daily())?;
///
/// // Or with a custom formatter
/// let logger = FileAuditLogger::builder("audit.log")
///     .rotation(RotationConfig::daily().keep(7))
///     .formatter(TextFormatter::new())
///     .build()?;
/// ```
pub struct FileAuditLogger {
    /// Base path for log files.
    base_path: PathBuf,
    /// Current writer.
    writer: Arc<Mutex<BufWriter<File>>>,
    /// Formatter.
    formatter: Box<dyn AuditFormatter>,
    /// Rotation configuration.
    rotation_config: RotationConfig,
    /// Current file date (for time-based rotation).
    current_period: Mutex<RotationPeriod>,
    /// Current file size (for size-based rotation).
    current_size: AtomicU64,
    /// Total bytes written.
    total_bytes_written: AtomicU64,
    /// Total logs written.
    total_logs_written: AtomicU64,
}

/// Represents the current rotation period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RotationPeriod {
    date: NaiveDate,
    hour: u32,
}

impl RotationPeriod {
    fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self {
            date: dt.date_naive(),
            hour: dt.hour(),
        }
    }

    fn needs_rotation(&self, other: &Self, strategy: RotationStrategy) -> bool {
        match strategy {
            RotationStrategy::Daily => self.date != other.date,
            RotationStrategy::Hourly => self.date != other.date || self.hour != other.hour,
            _ => false,
        }
    }
}

impl FileAuditLogger {
    /// Creates a new file-based audit logger.
    pub fn new(path: impl AsRef<Path>, rotation_config: RotationConfig) -> AuditResult<Self> {
        Self::builder(path).rotation(rotation_config).build()
    }

    /// Creates a builder for the file audit logger.
    pub fn builder(path: impl AsRef<Path>) -> FileAuditLoggerBuilder {
        FileAuditLoggerBuilder::new(path)
    }

    /// Gets the file path for the given time.
    fn get_file_path(
        base_path: &Path,
        config: &RotationConfig,
        time: DateTime<Utc>,
    ) -> PathBuf {
        match config.strategy {
            RotationStrategy::Daily => {
                let date = time.format("%Y-%m-%d");
                Self::format_rotated_path(base_path, &date.to_string())
            }
            RotationStrategy::Hourly => {
                let datetime = time.format("%Y-%m-%d-%H");
                Self::format_rotated_path(base_path, &datetime.to_string())
            }
            RotationStrategy::Size => {
                // For size-based rotation, we use a sequence number
                // This is handled separately in check_size_rotation
                base_path.to_path_buf()
            }
            RotationStrategy::Never => base_path.to_path_buf(),
        }
    }

    fn format_rotated_path(base_path: &Path, suffix: &str) -> PathBuf {
        let stem = base_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("audit");
        let ext = base_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("log");
        let parent = base_path.parent().unwrap_or(Path::new("."));
        parent.join(format!("{}-{}.{}", stem, suffix, ext))
    }

    /// Opens a file for writing.
    fn open_file(path: &Path) -> AuditResult<File> {
        // Create directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AuditError::write_failed_with(format!("Failed to open {}", path.display()), e))
    }

    /// Checks and performs time-based rotation if needed.
    fn check_time_rotation(&self) -> AuditResult<()> {
        let now = Utc::now();
        let current = RotationPeriod::from_datetime(now);

        let mut period_guard = self.current_period.lock();

        if !period_guard.needs_rotation(&current, self.rotation_config.strategy) {
            return Ok(());
        }

        // Rotate to new file
        let new_path = Self::get_file_path(&self.base_path, &self.rotation_config, now);
        let new_file = Self::open_file(&new_path)?;

        let mut writer_guard = self.writer.lock();
        writer_guard.flush()?;
        *writer_guard = BufWriter::new(new_file);
        *period_guard = current;

        // Reset size counter
        self.current_size.store(0, Ordering::Relaxed);

        tracing::info!(path = %new_path.display(), "Rotated audit log file");

        // Cleanup old files
        self.cleanup_old_files()?;

        Ok(())
    }

    /// Checks and performs size-based rotation if needed.
    fn check_size_rotation(&self) -> AuditResult<()> {
        if self.rotation_config.strategy != RotationStrategy::Size {
            return Ok(());
        }

        let current_size = self.current_size.load(Ordering::Relaxed);
        if current_size < self.rotation_config.max_size {
            return Ok(());
        }

        // Find the next available sequence number
        let new_path = self.find_next_size_rotated_path()?;
        let new_file = Self::open_file(&new_path)?;

        let mut writer_guard = self.writer.lock();
        writer_guard.flush()?;
        *writer_guard = BufWriter::new(new_file);

        self.current_size.store(0, Ordering::Relaxed);

        tracing::info!(path = %new_path.display(), "Rotated audit log file (size limit)");

        self.cleanup_old_files()?;

        Ok(())
    }

    fn find_next_size_rotated_path(&self) -> AuditResult<PathBuf> {
        let stem = self
            .base_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("audit");
        let ext = self
            .base_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("log");
        let parent = self.base_path.parent().unwrap_or(Path::new("."));

        // Find the next sequence number
        let mut seq = 1;
        loop {
            let path = parent.join(format!("{}.{}.{}", stem, seq, ext));
            if !path.exists() {
                return Ok(path);
            }
            seq += 1;
            if seq > 10000 {
                return Err(AuditError::rotation_failed("Too many rotated files"));
            }
        }
    }

    /// Cleans up old rotated files.
    fn cleanup_old_files(&self) -> AuditResult<()> {
        if self.rotation_config.keep_files == 0 {
            return Ok(());
        }

        let parent = self.base_path.parent().unwrap_or(Path::new("."));
        let stem = self
            .base_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("audit");

        let mut files: Vec<PathBuf> = fs::read_dir(parent)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(stem) && n != stem)
                    .unwrap_or(false)
            })
            .collect();

        // Sort by modification time (oldest first)
        files.sort_by(|a, b| {
            let a_time = fs::metadata(a)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let b_time = fs::metadata(b)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            a_time.cmp(&b_time)
        });

        // Remove files exceeding the retention limit
        let files_to_remove = files.len().saturating_sub(self.rotation_config.keep_files as usize);
        for file in files.into_iter().take(files_to_remove) {
            if let Err(e) = fs::remove_file(&file) {
                tracing::warn!(
                    path = %file.display(),
                    error = %e,
                    "Failed to remove old audit log file"
                );
            } else {
                tracing::debug!(path = %file.display(), "Removed old audit log file");
            }
        }

        Ok(())
    }

    /// Writes a log entry to the file.
    fn write_entry(&self, entry: &AuditLog) -> AuditResult<()> {
        let formatted = self.formatter.format(entry)?;
        let bytes = formatted.as_bytes();

        let mut writer = self.writer.lock();
        writeln!(writer, "{}", formatted)?;

        // Update size counter
        self.current_size.fetch_add(bytes.len() as u64 + 1, Ordering::Relaxed);
        self.total_bytes_written.fetch_add(bytes.len() as u64 + 1, Ordering::Relaxed);
        self.total_logs_written.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Returns the total bytes written.
    pub fn total_bytes_written(&self) -> u64 {
        self.total_bytes_written.load(Ordering::Relaxed)
    }

    /// Returns the total logs written.
    pub fn total_logs_written(&self) -> u64 {
        self.total_logs_written.load(Ordering::Relaxed)
    }

    /// Returns the current file size.
    pub fn current_file_size(&self) -> u64 {
        self.current_size.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl AuditLogger for FileAuditLogger {
    async fn log(&self, entry: AuditLog) -> AuditResult<()> {
        // Check for rotation
        match self.rotation_config.strategy {
            RotationStrategy::Daily | RotationStrategy::Hourly => {
                self.check_time_rotation()?;
            }
            RotationStrategy::Size => {
                self.check_size_rotation()?;
            }
            RotationStrategy::Never => {}
        }

        self.write_entry(&entry)
    }

    async fn log_batch(&self, entries: Vec<AuditLog>) -> AuditResult<()> {
        // Check for rotation once before batch
        match self.rotation_config.strategy {
            RotationStrategy::Daily | RotationStrategy::Hourly => {
                self.check_time_rotation()?;
            }
            RotationStrategy::Size => {
                self.check_size_rotation()?;
            }
            RotationStrategy::Never => {}
        }

        let mut writer = self.writer.lock();
        let mut total_bytes = 0u64;

        for entry in &entries {
            let formatted = self.formatter.format(entry)?;
            let bytes = formatted.as_bytes();
            writeln!(writer, "{}", formatted)?;
            total_bytes += bytes.len() as u64 + 1;
        }

        self.current_size.fetch_add(total_bytes, Ordering::Relaxed);
        self.total_bytes_written.fetch_add(total_bytes, Ordering::Relaxed);
        self.total_logs_written.fetch_add(entries.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    async fn query(&self, _filter: AuditFilter) -> AuditResult<Vec<AuditLog>> {
        // File-based logger doesn't support efficient querying
        Err(AuditError::query_not_supported("FileAuditLogger"))
    }

    async fn flush(&self) -> AuditResult<()> {
        let mut writer = self.writer.lock();
        writer.flush()?;
        Ok(())
    }

    fn name(&self) -> &str {
        "file"
    }

    fn supports_query(&self) -> bool {
        false
    }

    async fn health_check(&self) -> bool {
        // Try to flush to verify file is writable
        let mut writer = self.writer.lock();
        writer.flush().is_ok()
    }
}

impl std::fmt::Debug for FileAuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileAuditLogger")
            .field("base_path", &self.base_path)
            .field("rotation_config", &self.rotation_config)
            .field("total_bytes_written", &self.total_bytes_written.load(Ordering::Relaxed))
            .field("total_logs_written", &self.total_logs_written.load(Ordering::Relaxed))
            .finish()
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for FileAuditLogger.
pub struct FileAuditLoggerBuilder {
    path: PathBuf,
    rotation_config: RotationConfig,
    formatter: Option<Box<dyn AuditFormatter>>,
}

impl FileAuditLoggerBuilder {
    /// Creates a new builder.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            rotation_config: RotationConfig::default(),
            formatter: None,
        }
    }

    /// Sets the rotation configuration.
    pub fn rotation(mut self, config: RotationConfig) -> Self {
        self.rotation_config = config;
        self
    }

    /// Sets the formatter.
    pub fn formatter(mut self, formatter: impl AuditFormatter + 'static) -> Self {
        self.formatter = Some(Box::new(formatter));
        self
    }

    /// Builds the logger.
    pub fn build(self) -> AuditResult<FileAuditLogger> {
        let now = Utc::now();
        let file_path = FileAuditLogger::get_file_path(&self.path, &self.rotation_config, now);
        let file = FileAuditLogger::open_file(&file_path)?;

        // Get initial file size
        let initial_size = file.metadata().map(|m| m.len()).unwrap_or(0);

        let formatter: Box<dyn AuditFormatter> =
            self.formatter.unwrap_or_else(|| Box::new(CompactJsonFormatter::new()));

        Ok(FileAuditLogger {
            base_path: self.path,
            writer: Arc::new(Mutex::new(BufWriter::new(file))),
            formatter,
            rotation_config: self.rotation_config,
            current_period: Mutex::new(RotationPeriod::from_datetime(now)),
            current_size: AtomicU64::new(initial_size),
            total_bytes_written: AtomicU64::new(0),
            total_logs_written: AtomicU64::new(0),
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{ActionResult, AuditAction, AuditResource};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_file_logger_creation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");

        let logger = FileAuditLogger::new(&path, RotationConfig::never()).unwrap();

        assert!(logger.health_check().await);
    }

    #[tokio::test]
    async fn test_file_logger_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");

        let logger = FileAuditLogger::new(&path, RotationConfig::never()).unwrap();

        let log = AuditLog::new(
            AuditAction::Write,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        );

        logger.log(log).await.unwrap();
        logger.flush().await.unwrap();

        assert!(logger.total_logs_written() > 0);
        assert!(logger.total_bytes_written() > 0);

        // Verify file content
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("plc-001"));
        assert!(content.contains("write"));
    }

    #[tokio::test]
    async fn test_file_logger_batch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");

        let logger = FileAuditLogger::new(&path, RotationConfig::never()).unwrap();

        let logs: Vec<AuditLog> = (0..10)
            .map(|i| {
                AuditLog::new(
                    AuditAction::Write,
                    AuditResource::device(format!("plc-{:03}", i)),
                    ActionResult::Success,
                )
            })
            .collect();

        logger.log_batch(logs).await.unwrap();
        logger.flush().await.unwrap();

        assert_eq!(logger.total_logs_written(), 10);

        // Verify file has 10 lines
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 10);
    }

    #[tokio::test]
    async fn test_query_not_supported() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");

        let logger = FileAuditLogger::new(&path, RotationConfig::never()).unwrap();

        let result = logger.query(AuditFilter::default()).await;
        assert!(matches!(result, Err(AuditError::QueryNotSupported { .. })));
        assert!(!logger.supports_query());
    }

    #[test]
    fn test_rotation_config() {
        let config = RotationConfig::daily().keep(7);
        assert_eq!(config.keep_files, 7);
        assert!(matches!(config.strategy, RotationStrategy::Daily));

        let size_config = RotationConfig::size(50 * 1024 * 1024);
        assert!(matches!(size_config.strategy, RotationStrategy::Size));
        assert_eq!(size_config.max_size, 50 * 1024 * 1024);
    }

    #[test]
    fn test_rotation_period() {
        use chrono::TimeZone;

        let dt1 = Utc.with_ymd_and_hms(2025, 1, 1, 10, 0, 0).unwrap();
        let dt2 = Utc.with_ymd_and_hms(2025, 1, 1, 11, 0, 0).unwrap();
        let dt3 = Utc.with_ymd_and_hms(2025, 1, 2, 10, 0, 0).unwrap();

        let p1 = RotationPeriod::from_datetime(dt1);
        let p2 = RotationPeriod::from_datetime(dt2);
        let p3 = RotationPeriod::from_datetime(dt3);

        // Same day, different hour
        assert!(!p1.needs_rotation(&p2, RotationStrategy::Daily));
        assert!(p1.needs_rotation(&p2, RotationStrategy::Hourly));

        // Different day
        assert!(p1.needs_rotation(&p3, RotationStrategy::Daily));
        assert!(p1.needs_rotation(&p3, RotationStrategy::Hourly));
    }
}
