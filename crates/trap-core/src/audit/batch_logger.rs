// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Async batch audit logger for high-throughput environments.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::error::{AuditError, AuditResult};
use super::types::{AuditFilter, AuditLog};
use super::AuditLogger;

// =============================================================================
// Batch Configuration
// =============================================================================

/// Configuration for async batch logging.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum batch size before flushing.
    pub max_batch_size: usize,
    /// Maximum time to wait before flushing.
    pub flush_interval: Duration,
    /// Channel buffer size.
    pub channel_size: usize,
    /// Whether to block on channel full.
    pub block_on_full: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            flush_interval: Duration::from_secs(5),
            channel_size: 10000,
            block_on_full: false,
        }
    }
}

impl BatchConfig {
    /// Creates a new batch config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum batch size.
    pub fn max_batch_size(mut self, size: usize) -> Self {
        self.max_batch_size = size;
        self
    }

    /// Sets the flush interval.
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }

    /// Sets the channel buffer size.
    pub fn channel_size(mut self, size: usize) -> Self {
        self.channel_size = size;
        self
    }

    /// Sets whether to block when the channel is full.
    pub fn block_on_full(mut self, block: bool) -> Self {
        self.block_on_full = block;
        self
    }
}

// =============================================================================
// Async Batch Audit Logger
// =============================================================================

/// Async batch audit logger wrapper.
///
/// Wraps another `AuditLogger` and batches writes for improved performance.
/// Entries are buffered and flushed either when the batch size is reached
/// or after the flush interval elapses.
///
/// # Example
///
/// ```rust,ignore
/// use trap_core::audit::{AsyncBatchAuditLogger, FileAuditLogger, BatchConfig, RotationConfig};
/// use std::time::Duration;
///
/// let file_logger = FileAuditLogger::new("audit.log", RotationConfig::daily())?;
///
/// let batch_logger = AsyncBatchAuditLogger::new(
///     file_logger,
///     BatchConfig::new()
///         .max_batch_size(100)
///         .flush_interval(Duration::from_secs(5)),
/// );
///
/// // Start the background worker
/// batch_logger.start();
///
/// // Use the logger
/// batch_logger.log(log_entry).await?;
///
/// // Shutdown gracefully
/// batch_logger.shutdown().await?;
/// ```
pub struct AsyncBatchAuditLogger {
    /// The underlying logger.
    inner: Arc<dyn AuditLogger>,
    /// Configuration.
    config: BatchConfig,
    /// Sender for log entries.
    sender: mpsc::Sender<BatchCommand>,
    /// Statistics.
    stats: Arc<BatchStats>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Handle to the background task.
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Commands sent to the batch worker.
enum BatchCommand {
    /// Log a single entry.
    Log(AuditLog),
    /// Log a batch of entries.
    LogBatch(Vec<AuditLog>),
    /// Flush immediately.
    Flush(tokio::sync::oneshot::Sender<AuditResult<()>>),
    /// Shutdown the worker.
    Shutdown,
}

/// Batch logger statistics.
#[derive(Debug, Default)]
struct BatchStats {
    /// Total entries received.
    entries_received: AtomicU64,
    /// Total entries written.
    entries_written: AtomicU64,
    /// Total batches flushed.
    batches_flushed: AtomicU64,
    /// Entries dropped due to full channel.
    entries_dropped: AtomicU64,
    /// Flush errors.
    flush_errors: AtomicU64,
}

impl AsyncBatchAuditLogger {
    /// Creates a new async batch logger.
    pub fn new<L: AuditLogger + 'static>(inner: L, config: BatchConfig) -> Self {
        let (sender, receiver) = mpsc::channel(config.channel_size);
        let inner: Arc<dyn AuditLogger> = Arc::new(inner);
        let stats = Arc::new(BatchStats::default());
        let shutdown = Arc::new(AtomicBool::new(false));

        let logger = Self {
            inner: inner.clone(),
            config: config.clone(),
            sender,
            stats: stats.clone(),
            shutdown: shutdown.clone(),
            handle: Mutex::new(None),
        };

        // Start background worker
        let handle = tokio::spawn(Self::worker(
            inner,
            receiver,
            config,
            stats,
            shutdown,
        ));
        *logger.handle.lock() = Some(handle);

        logger
    }

    /// Background worker that processes batches.
    async fn worker(
        inner: Arc<dyn AuditLogger>,
        mut receiver: mpsc::Receiver<BatchCommand>,
        config: BatchConfig,
        stats: Arc<BatchStats>,
        shutdown: Arc<AtomicBool>,
    ) {
        let mut batch: Vec<AuditLog> = Vec::with_capacity(config.max_batch_size);
        let mut last_flush = Instant::now();

        loop {
            // Calculate time until next flush
            let time_since_flush = last_flush.elapsed();
            let time_until_flush = config.flush_interval.saturating_sub(time_since_flush);

            tokio::select! {
                // Receive new commands
                cmd = receiver.recv() => {
                    match cmd {
                        Some(BatchCommand::Log(entry)) => {
                            batch.push(entry);
                            stats.entries_received.fetch_add(1, Ordering::Relaxed);

                            // Flush if batch is full
                            if batch.len() >= config.max_batch_size {
                                let _ = Self::flush_batch(&inner, &mut batch, &stats, &mut last_flush).await;
                            }
                        }
                        Some(BatchCommand::LogBatch(entries)) => {
                            let count = entries.len() as u64;
                            stats.entries_received.fetch_add(count, Ordering::Relaxed);
                            batch.extend(entries);

                            // Flush if batch is full
                            if batch.len() >= config.max_batch_size {
                                let _ = Self::flush_batch(&inner, &mut batch, &stats, &mut last_flush).await;
                            }
                        }
                        Some(BatchCommand::Flush(response)) => {
                            let result = Self::flush_batch(&inner, &mut batch, &stats, &mut last_flush).await;
                            let _ = response.send(result);
                        }
                        Some(BatchCommand::Shutdown) | None => {
                            // Final flush
                            let _ = Self::flush_batch(&inner, &mut batch, &stats, &mut last_flush).await;
                            break;
                        }
                    }
                }
                // Timeout - flush on interval
                _ = tokio::time::sleep(time_until_flush) => {
                    if !batch.is_empty() {
                        let _ = Self::flush_batch(&inner, &mut batch, &stats, &mut last_flush).await;
                    }
                    last_flush = Instant::now();
                }
            }

            if shutdown.load(Ordering::Relaxed) {
                // Final flush
                let _ = Self::flush_batch(&inner, &mut batch, &stats, &mut last_flush).await;
                break;
            }
        }

        tracing::debug!("Batch audit logger worker stopped");
    }

    /// Flushes the current batch.
    async fn flush_batch(
        inner: &Arc<dyn AuditLogger>,
        batch: &mut Vec<AuditLog>,
        stats: &Arc<BatchStats>,
        last_flush: &mut Instant,
    ) -> AuditResult<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let count = batch.len() as u64;
        let entries = std::mem::take(batch);

        let result = inner.log_batch(entries).await;
        *last_flush = Instant::now();

        match &result {
            Ok(()) => {
                stats.entries_written.fetch_add(count, Ordering::Relaxed);
                stats.batches_flushed.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                stats.flush_errors.fetch_add(1, Ordering::Relaxed);
                tracing::error!(error = %e, count = count, "Failed to flush audit batch");
            }
        }

        result
    }

    /// Returns the number of entries received.
    pub fn entries_received(&self) -> u64 {
        self.stats.entries_received.load(Ordering::Relaxed)
    }

    /// Returns the number of entries written.
    pub fn entries_written(&self) -> u64 {
        self.stats.entries_written.load(Ordering::Relaxed)
    }

    /// Returns the number of batches flushed.
    pub fn batches_flushed(&self) -> u64 {
        self.stats.batches_flushed.load(Ordering::Relaxed)
    }

    /// Returns the number of entries dropped.
    pub fn entries_dropped(&self) -> u64 {
        self.stats.entries_dropped.load(Ordering::Relaxed)
    }

    /// Returns the number of flush errors.
    pub fn flush_errors(&self) -> u64 {
        self.stats.flush_errors.load(Ordering::Relaxed)
    }

    /// Shuts down the logger gracefully.
    pub async fn shutdown(&self) -> AuditResult<()> {
        self.shutdown.store(true, Ordering::Relaxed);

        // Send shutdown command
        let _ = self.sender.send(BatchCommand::Shutdown).await;

        // Wait for worker to finish
        if let Some(handle) = self.handle.lock().take() {
            let _ = handle.await;
        }

        // Flush the inner logger
        self.inner.flush().await
    }
}

#[async_trait]
impl AuditLogger for AsyncBatchAuditLogger {
    async fn log(&self, entry: AuditLog) -> AuditResult<()> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(AuditError::ShuttingDown);
        }

        if self.config.block_on_full {
            self.sender
                .send(BatchCommand::Log(entry))
                .await
                .map_err(|_| AuditError::ChannelClosed)?;
        } else {
            match self.sender.try_send(BatchCommand::Log(entry)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.stats.entries_dropped.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("Audit log channel full, dropping entry");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(AuditError::ChannelClosed);
                }
            }
        }

        Ok(())
    }

    async fn log_batch(&self, entries: Vec<AuditLog>) -> AuditResult<()> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(AuditError::ShuttingDown);
        }

        let count = entries.len() as u64;

        if self.config.block_on_full {
            self.sender
                .send(BatchCommand::LogBatch(entries))
                .await
                .map_err(|_| AuditError::ChannelClosed)?;
        } else {
            match self.sender.try_send(BatchCommand::LogBatch(entries)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.stats.entries_dropped.fetch_add(count, Ordering::Relaxed);
                    tracing::warn!(count = count, "Audit log channel full, dropping batch");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(AuditError::ChannelClosed);
                }
            }
        }

        Ok(())
    }

    async fn query(&self, filter: AuditFilter) -> AuditResult<Vec<AuditLog>> {
        self.inner.query(filter).await
    }

    async fn flush(&self) -> AuditResult<()> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(AuditError::ShuttingDown);
        }

        let (tx, rx) = tokio::sync::oneshot::channel();

        self.sender
            .send(BatchCommand::Flush(tx))
            .await
            .map_err(|_| AuditError::ChannelClosed)?;

        rx.await.map_err(|_| AuditError::ChannelClosed)?
    }

    fn name(&self) -> &str {
        "async_batch"
    }

    fn supports_query(&self) -> bool {
        self.inner.supports_query()
    }

    async fn health_check(&self) -> bool {
        !self.shutdown.load(Ordering::Relaxed) && self.inner.health_check().await
    }
}

impl std::fmt::Debug for AsyncBatchAuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncBatchAuditLogger")
            .field("config", &self.config)
            .field("entries_received", &self.entries_received())
            .field("entries_written", &self.entries_written())
            .field("batches_flushed", &self.batches_flushed())
            .field("entries_dropped", &self.entries_dropped())
            .finish()
    }
}

impl Drop for AsyncBatchAuditLogger {
    fn drop(&mut self) {
        // Signal shutdown
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        types::{ActionResult, AuditAction, AuditResource},
        InMemoryAuditLogger,
    };

    #[tokio::test]
    async fn test_batch_logger_basic() {
        let inner = InMemoryAuditLogger::new();
        let inner_clone = inner.clone();

        let config = BatchConfig::new()
            .max_batch_size(10)
            .flush_interval(Duration::from_secs(1));

        let logger = AsyncBatchAuditLogger::new(inner, config);

        // Log some entries
        for i in 0..5 {
            let log = AuditLog::new(
                AuditAction::Write,
                AuditResource::device(format!("plc-{:03}", i)),
                ActionResult::Success,
            );
            logger.log(log).await.unwrap();
        }

        // Flush and verify
        logger.flush().await.unwrap();

        // Give some time for async processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(logger.entries_received(), 5);

        // Shutdown
        logger.shutdown().await.unwrap();

        // Verify entries were written
        let entries = inner_clone.entries();
        assert_eq!(entries.len(), 5);
    }

    #[tokio::test]
    async fn test_batch_logger_auto_flush_on_size() {
        let inner = InMemoryAuditLogger::new();
        let inner_clone = inner.clone();

        let config = BatchConfig::new()
            .max_batch_size(5)
            .flush_interval(Duration::from_secs(60)); // Long interval

        let logger = AsyncBatchAuditLogger::new(inner, config);

        // Log exactly batch size entries
        for i in 0..5 {
            let log = AuditLog::new(
                AuditAction::Write,
                AuditResource::device(format!("plc-{:03}", i)),
                ActionResult::Success,
            );
            logger.log(log).await.unwrap();
        }

        // Give time for batch to be processed
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should have been flushed automatically
        assert!(logger.batches_flushed() >= 1);

        logger.shutdown().await.unwrap();
        assert_eq!(inner_clone.entries().len(), 5);
    }

    #[tokio::test]
    async fn test_batch_logger_batch() {
        let inner = InMemoryAuditLogger::new();
        let inner_clone = inner.clone();

        let config = BatchConfig::new()
            .max_batch_size(100)
            .flush_interval(Duration::from_secs(1));

        let logger = AsyncBatchAuditLogger::new(inner, config);

        // Log a batch
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

        tokio::time::sleep(Duration::from_millis(100)).await;

        logger.shutdown().await.unwrap();
        assert_eq!(inner_clone.entries().len(), 10);
    }

    #[test]
    fn test_batch_config() {
        let config = BatchConfig::new()
            .max_batch_size(50)
            .flush_interval(Duration::from_secs(10))
            .channel_size(5000)
            .block_on_full(true);

        assert_eq!(config.max_batch_size, 50);
        assert_eq!(config.flush_interval, Duration::from_secs(10));
        assert_eq!(config.channel_size, 5000);
        assert!(config.block_on_full);
    }
}
