// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Command handler implementation for processing write commands.
//!
//! This module provides `CommandHandler`, which processes write commands
//! received from the `CommandBus` and dispatches them to the appropriate
//! protocol drivers.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────┐        ┌─────────────────────┐
//! │  CommandBus    │───────▶│  CommandHandler     │
//! │  (senders)     │        │  - CommandReceiver  │
//! └────────────────┘        │  - WriteHandler     │
//!                           │  - AuditLogger      │
//!                           └──────────┬──────────┘
//!                                      │
//!                           ┌──────────▼──────────┐
//!                           │  Protocol Drivers   │
//!                           │  (via WriteHandler) │
//!                           └─────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_core::handler::{CommandHandler, WriteHandler};
//! use trap_core::bus::{CommandBus, CommandReceiver};
//!
//! // Create the command channel
//! let (command_bus, command_receiver) = CommandBus::channel(256);
//!
//! // Create a custom write handler
//! struct MyWriteHandler { /* ... */ }
//!
//! impl WriteHandler for MyWriteHandler {
//!     async fn handle_write(&self, cmd: &WriteCommand) -> Result<(), DriverError> {
//!         // Dispatch to the appropriate driver
//!         Ok(())
//!     }
//! }
//!
//! // Create and run the handler
//! let handler = CommandHandler::new(command_receiver)
//!     .with_write_handler(Arc::new(MyWriteHandler { /* ... */ }));
//!
//! tokio::spawn(handler.run());
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Notify;
use tracing::{debug, error, info, instrument, warn};

use crate::bus::{CommandReceiver, WriteCommand};
use crate::error::{CommandError, DriverError};
use crate::types::DeviceId;

// =============================================================================
// WriteHandler Trait
// =============================================================================

/// Trait for handling write operations.
///
/// Implement this trait to define how write commands are dispatched
/// to protocol drivers.
#[async_trait]
pub trait WriteHandler: Send + Sync {
    /// Handles a write command.
    ///
    /// # Arguments
    ///
    /// * `cmd` - The write command to process
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The write was successful
    /// * `Err(DriverError)` - The write failed
    async fn handle_write(&self, cmd: &WriteCommand) -> Result<(), DriverError>;

    /// Checks if a device exists.
    ///
    /// Override this method to provide device validation.
    /// Default implementation always returns `true`.
    fn device_exists(&self, _device_id: &DeviceId) -> bool {
        true
    }

    /// Called before processing a command.
    ///
    /// Can be used for validation, rate limiting, etc.
    /// Return `Err` to reject the command before processing.
    async fn pre_process(&self, _cmd: &WriteCommand) -> Result<(), CommandError> {
        Ok(())
    }

    /// Called after processing a command.
    ///
    /// Can be used for metrics, logging, etc.
    async fn post_process(&self, _cmd: &WriteCommand, _result: &Result<(), DriverError>) {}
}

// =============================================================================
// NoOpWriteHandler
// =============================================================================

/// A no-op write handler that always succeeds.
///
/// Useful for testing or as a placeholder.
#[derive(Debug, Default)]
pub struct NoOpWriteHandler;

#[async_trait]
impl WriteHandler for NoOpWriteHandler {
    async fn handle_write(&self, _cmd: &WriteCommand) -> Result<(), DriverError> {
        Ok(())
    }
}

// =============================================================================
// CommandHandler
// =============================================================================

/// Handler for processing write commands from the command bus.
///
/// The `CommandHandler` receives commands from a `CommandReceiver` and
/// dispatches them to a `WriteHandler` for processing.
///
/// # Features
///
/// - Automatic timeout checking for expired commands
/// - Pre/post processing hooks via `WriteHandler`
/// - Metrics collection
/// - Graceful shutdown support
pub struct CommandHandler<W: WriteHandler> {
    /// The command receiver.
    receiver: CommandReceiver,
    /// The write handler.
    write_handler: Arc<W>,
    /// Shutdown notification.
    shutdown: Arc<Notify>,
    /// Handler metrics.
    metrics: Arc<HandlerMetrics>,
    /// Configuration.
    config: HandlerConfig,
}

/// Configuration for the command handler.
#[derive(Debug, Clone)]
pub struct HandlerConfig {
    /// Whether to skip expired commands (default: true).
    pub skip_expired: bool,
    /// Minimum remaining time to process a command (default: 100ms).
    pub min_remaining_time: Duration,
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            skip_expired: true,
            min_remaining_time: Duration::from_millis(100),
        }
    }
}

/// Metrics for the command handler.
#[derive(Debug, Default)]
pub struct HandlerMetrics {
    /// Total commands processed.
    pub commands_processed: AtomicU64,
    /// Commands that succeeded.
    pub commands_succeeded: AtomicU64,
    /// Commands that failed.
    pub commands_failed: AtomicU64,
    /// Commands skipped due to expiration.
    pub commands_expired: AtomicU64,
    /// Commands rejected in pre-processing.
    pub commands_rejected: AtomicU64,
}

impl HandlerMetrics {
    /// Creates a snapshot of the current metrics.
    pub fn snapshot(&self) -> HandlerMetricsSnapshot {
        HandlerMetricsSnapshot {
            commands_processed: self.commands_processed.load(Ordering::Relaxed),
            commands_succeeded: self.commands_succeeded.load(Ordering::Relaxed),
            commands_failed: self.commands_failed.load(Ordering::Relaxed),
            commands_expired: self.commands_expired.load(Ordering::Relaxed),
            commands_rejected: self.commands_rejected.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of handler metrics.
#[derive(Debug, Clone, Default)]
pub struct HandlerMetricsSnapshot {
    /// Total commands processed.
    pub commands_processed: u64,
    /// Commands that succeeded.
    pub commands_succeeded: u64,
    /// Commands that failed.
    pub commands_failed: u64,
    /// Commands skipped due to expiration.
    pub commands_expired: u64,
    /// Commands rejected in pre-processing.
    pub commands_rejected: u64,
}

impl<W: WriteHandler + 'static> CommandHandler<W> {
    /// Creates a new command handler with the specified receiver and write handler.
    pub fn new(receiver: CommandReceiver, write_handler: Arc<W>) -> Self {
        Self {
            receiver,
            write_handler,
            shutdown: Arc::new(Notify::new()),
            metrics: Arc::new(HandlerMetrics::default()),
            config: HandlerConfig::default(),
        }
    }

    /// Sets the handler configuration.
    pub fn with_config(mut self, config: HandlerConfig) -> Self {
        self.config = config;
        self
    }

    /// Returns a handle that can be used to signal shutdown.
    pub fn shutdown_handle(&self) -> Arc<Notify> {
        self.shutdown.clone()
    }

    /// Returns a reference to the metrics.
    pub fn metrics(&self) -> &Arc<HandlerMetrics> {
        &self.metrics
    }

    /// Runs the command handler loop.
    ///
    /// This method runs until all senders are dropped or shutdown is signaled.
    #[instrument(skip(self), name = "command_handler")]
    pub async fn run(mut self) {
        info!("Command handler started");

        loop {
            tokio::select! {
                biased;

                // Check for shutdown
                _ = self.shutdown.notified() => {
                    info!("Command handler received shutdown signal");
                    break;
                }

                // Process commands
                cmd = self.receiver.recv() => {
                    match cmd {
                        Some(command) => {
                            self.process_command(command).await;
                        }
                        None => {
                            info!("Command channel closed, handler shutting down");
                            break;
                        }
                    }
                }
            }
        }

        // Log final metrics
        let metrics = self.metrics.snapshot();
        info!(
            processed = metrics.commands_processed,
            succeeded = metrics.commands_succeeded,
            failed = metrics.commands_failed,
            expired = metrics.commands_expired,
            rejected = metrics.commands_rejected,
            "Command handler stopped"
        );
    }

    /// Processes a single command.
    #[instrument(skip(self, cmd), fields(
        command_id = %cmd.id,
        device_id = %cmd.device_id,
    ))]
    async fn process_command(&self, cmd: WriteCommand) {
        self.metrics.commands_processed.fetch_add(1, Ordering::Relaxed);

        // Check for expiration
        if self.config.skip_expired {
            match cmd.remaining_time() {
                Some(remaining) if remaining < self.config.min_remaining_time => {
                    warn!(
                        remaining_ms = remaining.as_millis() as u64,
                        "Command expired or has insufficient time"
                    );
                    self.metrics.commands_expired.fetch_add(1, Ordering::Relaxed);
                    cmd.respond_failure("Command expired");
                    return;
                }
                None => {
                    warn!("Command already timed out");
                    self.metrics.commands_expired.fetch_add(1, Ordering::Relaxed);
                    cmd.respond_failure("Command expired");
                    return;
                }
                _ => {}
            }
        }

        // Check device exists
        if !self.write_handler.device_exists(&cmd.device_id) {
            let device_id = cmd.device_id.clone();
            warn!(device_id = %device_id, "Device not found");
            self.metrics.commands_failed.fetch_add(1, Ordering::Relaxed);
            cmd.respond_failure(format!("Device not found: {}", device_id));
            return;
        }

        // Pre-processing
        if let Err(e) = self.write_handler.pre_process(&cmd).await {
            warn!(error = %e, "Command rejected in pre-processing");
            self.metrics.commands_rejected.fetch_add(1, Ordering::Relaxed);
            cmd.respond_failure(e.to_string());
            return;
        }

        // Execute the write
        debug!(
            address = %cmd.address,
            value = ?cmd.value,
            "Executing write command"
        );

        let result = self.write_handler.handle_write(&cmd).await;

        // Post-processing
        self.write_handler.post_process(&cmd, &result).await;

        // Send response
        match &result {
            Ok(()) => {
                debug!("Write command succeeded");
                self.metrics.commands_succeeded.fetch_add(1, Ordering::Relaxed);
                cmd.respond_success();
            }
            Err(e) => {
                error!(error = %e, "Write command failed");
                self.metrics.commands_failed.fetch_add(1, Ordering::Relaxed);
                cmd.respond_driver_error(e);
            }
        }
    }
}

// =============================================================================
// Builder Pattern
// =============================================================================

/// Builder for creating a command handler.
pub struct CommandHandlerBuilder {
    receiver: CommandReceiver,
    config: HandlerConfig,
}

impl CommandHandlerBuilder {
    /// Creates a new builder with the specified receiver.
    pub fn new(receiver: CommandReceiver) -> Self {
        Self {
            receiver,
            config: HandlerConfig::default(),
        }
    }

    /// Sets the handler configuration.
    pub fn config(mut self, config: HandlerConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets whether to skip expired commands.
    pub fn skip_expired(mut self, skip: bool) -> Self {
        self.config.skip_expired = skip;
        self
    }

    /// Sets the minimum remaining time for command processing.
    pub fn min_remaining_time(mut self, duration: Duration) -> Self {
        self.config.min_remaining_time = duration;
        self
    }

    /// Builds the command handler with the specified write handler.
    pub fn build<W: WriteHandler + 'static>(self, write_handler: Arc<W>) -> CommandHandler<W> {
        CommandHandler::new(self.receiver, write_handler).with_config(self.config)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, GenericAddress};
    use crate::bus::{AuditContext, CommandBus, WriteCommand};
    use crate::types::{DeviceId, Value};
    use std::sync::atomic::AtomicBool;
    use tokio::time::timeout;

    /// Mock write handler for testing.
    struct MockWriteHandler {
        should_fail: AtomicBool,
        fail_message: String,
    }

    impl MockWriteHandler {
        fn new() -> Self {
            Self {
                should_fail: AtomicBool::new(false),
                fail_message: "Mock failure".to_string(),
            }
        }

        fn set_should_fail(&self, fail: bool) {
            self.should_fail.store(fail, Ordering::Relaxed);
        }
    }

    #[async_trait]
    impl WriteHandler for MockWriteHandler {
        async fn handle_write(&self, _cmd: &WriteCommand) -> Result<(), DriverError> {
            if self.should_fail.load(Ordering::Relaxed) {
                Err(DriverError::write_failed("test", &self.fail_message))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_command_handler_success() {
        let (bus, receiver) = CommandBus::channel(16);
        let write_handler = Arc::new(MockWriteHandler::new());
        let handler = CommandHandler::new(receiver, write_handler);

        // Start handler
        let handle = tokio::spawn(handler.run());

        // Send command
        let response = bus
            .send_write(
                DeviceId::new("device1"),
                Address::Generic(GenericAddress::new("test", "addr")),
                Value::Float64(42.0),
                AuditContext::anonymous(),
                Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert!(response.success);

        // Drop bus to signal shutdown
        drop(bus);
        timeout(Duration::from_secs(1), handle).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_command_handler_failure() {
        let (bus, receiver) = CommandBus::channel(16);
        let write_handler = Arc::new(MockWriteHandler::new());
        write_handler.set_should_fail(true);

        let handler = CommandHandler::new(receiver, write_handler);

        // Start handler
        let handle = tokio::spawn(handler.run());

        // Send command
        let response = bus
            .send_write(
                DeviceId::new("device1"),
                Address::Generic(GenericAddress::new("test", "addr")),
                Value::Float64(42.0),
                AuditContext::anonymous(),
                Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert!(!response.success);
        assert!(response.error.is_some());

        drop(bus);
        timeout(Duration::from_secs(1), handle).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_command_handler_shutdown() {
        let (bus, receiver) = CommandBus::channel(16);
        let write_handler = Arc::new(MockWriteHandler::new());
        let handler = CommandHandler::new(receiver, write_handler);
        let shutdown = handler.shutdown_handle();

        // Start handler
        let handle = tokio::spawn(handler.run());

        // Signal shutdown
        shutdown.notify_one();

        // Handler should stop
        timeout(Duration::from_secs(1), handle).await.unwrap().unwrap();

        // Bus should still be valid but handler stopped
        drop(bus);
    }

    #[tokio::test]
    async fn test_command_handler_metrics() {
        let (bus, receiver) = CommandBus::channel(16);
        let write_handler = Arc::new(MockWriteHandler::new());
        let handler = CommandHandler::new(receiver, write_handler);
        let metrics = handler.metrics().clone();

        // Start handler
        let handle = tokio::spawn(handler.run());

        // Send multiple commands
        for _ in 0..3 {
            let _ = bus
                .send_write(
                    DeviceId::new("device1"),
                    Address::Generic(GenericAddress::new("test", "addr")),
                    Value::Float64(42.0),
                    AuditContext::anonymous(),
                    Duration::from_secs(5),
                )
                .await;
        }

        // Give some time for processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.commands_processed, 3);
        assert_eq!(snapshot.commands_succeeded, 3);

        drop(bus);
        timeout(Duration::from_secs(1), handle).await.unwrap().unwrap();
    }

    #[test]
    fn test_no_op_write_handler() {
        let handler = NoOpWriteHandler;
        assert!(handler.device_exists(&DeviceId::new("any")));
    }

    #[test]
    fn test_handler_config_default() {
        let config = HandlerConfig::default();
        assert!(config.skip_expired);
        assert_eq!(config.min_remaining_time, Duration::from_millis(100));
    }

    #[test]
    fn test_builder() {
        let (_, receiver) = CommandBus::channel(16);
        let builder = CommandHandlerBuilder::new(receiver)
            .skip_expired(false)
            .min_remaining_time(Duration::from_millis(50));

        let handler = builder.build(Arc::new(NoOpWriteHandler));
        assert!(!handler.config.skip_expired);
        assert_eq!(handler.config.min_remaining_time, Duration::from_millis(50));
    }
}
