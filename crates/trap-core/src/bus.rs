// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Message bus implementations for internal communication.
//!
//! This module provides two types of message buses:
//!
//! - **DataBus**: Broadcast channel for data distribution (1:N)
//! - **CommandBus**: MPSC channel for write commands (N:1)
//!
//! # Design Principles
//!
//! - DataBus uses `tokio::sync::broadcast` for efficient fan-out
//! - CommandBus uses `tokio::sync::mpsc` with oneshot response channels
//! - Both buses provide statistics and monitoring capabilities
//! - CommandBus separates sender and receiver for clean architecture
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────┐
//! │                    Message System                          │
//! │                                                            │
//! │  ┌─────────────────────────────────────────────────────┐  │
//! │  │               DataBus (broadcast)                    │  │
//! │  │         Clone 가능한 메시지만 처리                   │  │
//! │  └─────────────────────────────────────────────────────┘  │
//! │           │              │              │                  │
//! │           ▼              ▼              ▼                  │
//! │     ┌─────────┐    ┌─────────┐    ┌─────────┐             │
//! │     │ Buffer  │    │   API   │    │ Metrics │             │
//! │     └─────────┘    └─────────┘    └─────────┘             │
//! │                                                            │
//! │  ┌─────────────────────────────────────────────────────┐  │
//! │  │              CommandBus (mpsc)                       │  │
//! │  │         쓰기 명령 전용 (oneshot 응답 포함)           │  │
//! │  └─────────────────────────────────────────────────────┘  │
//! │           │                                                │
//! │           ▼                                                │
//! │     ┌─────────────┐                                        │
//! │     │  Command    │                                        │
//! │     │  Handler    │                                        │
//! │     └─────────────┘                                        │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_core::bus::{DataBus, CommandBus, WriteCommand, WriteResponse};
//!
//! // Data bus for broadcasting
//! let data_bus = DataBus::new(1024);
//! let subscriber = data_bus.subscribe();
//! data_bus.publish(DataMessage::data(point))?;
//!
//! // Command bus for write operations
//! let (command_bus, command_receiver) = CommandBus::channel(256);
//! let result = command_bus.send_write(...).await?;
//! ```

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot};
use uuid::Uuid;

use crate::address::Address;
use crate::error::{BusError, CommandError, DriverError};
use crate::message::DataMessage;
use crate::types::{DeviceId, Value};

// =============================================================================
// WriteResponse
// =============================================================================

/// Response from a write command execution.
///
/// Contains detailed information about the command execution result,
/// including timing and error information for monitoring and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResponse {
    /// The command ID this response is for.
    pub command_id: Uuid,
    /// Whether the command succeeded.
    pub success: bool,
    /// Error message if the command failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Error type for categorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    /// Time taken to process the command.
    #[serde(with = "duration_millis")]
    pub duration: Duration,
    /// When the response was created.
    pub timestamp: DateTime<Utc>,
}

impl WriteResponse {
    /// Creates a successful response.
    pub fn success(command_id: Uuid, duration: Duration) -> Self {
        Self {
            command_id,
            success: true,
            error: None,
            error_type: None,
            duration,
            timestamp: Utc::now(),
        }
    }

    /// Creates a failure response.
    pub fn failure(command_id: Uuid, error: impl Into<String>, duration: Duration) -> Self {
        Self {
            command_id,
            success: false,
            error: Some(error.into()),
            error_type: None,
            duration,
            timestamp: Utc::now(),
        }
    }

    /// Creates a failure response from a DriverError.
    pub fn from_driver_error(command_id: Uuid, error: &DriverError, duration: Duration) -> Self {
        Self {
            command_id,
            success: false,
            error: Some(error.to_string()),
            error_type: Some(error.error_type().to_string()),
            duration,
            timestamp: Utc::now(),
        }
    }

    /// Creates a failure response from a CommandError.
    pub fn from_command_error(command_id: Uuid, error: &CommandError, duration: Duration) -> Self {
        Self {
            command_id,
            success: false,
            error: Some(error.to_string()),
            error_type: Some(error.error_type().to_string()),
            duration,
            timestamp: Utc::now(),
        }
    }

    /// Sets the error type.
    pub fn with_error_type(mut self, error_type: impl Into<String>) -> Self {
        self.error_type = Some(error_type.into());
        self
    }
}

/// Serialization helper for Duration as milliseconds.
mod duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

// =============================================================================
// WriteCommand
// =============================================================================

/// A write command to be processed by the command handler.
///
/// This structure contains all information needed to perform a write operation,
/// including the response channel for returning the result.
pub struct WriteCommand {
    /// Unique command ID.
    pub id: Uuid,
    /// Target device.
    pub device_id: DeviceId,
    /// Target address.
    pub address: Address,
    /// Value to write.
    pub value: Value,
    /// Response channel.
    pub response_tx: oneshot::Sender<WriteResponse>,
    /// Audit context for logging.
    pub audit_context: AuditContext,
    /// Command timeout.
    pub timeout: Duration,
    /// When the command was created.
    pub created_at: Instant,
    /// Timestamp for logging/serialization.
    pub timestamp: DateTime<Utc>,
}

impl WriteCommand {
    /// Creates a new write command.
    pub fn new(
        device_id: DeviceId,
        address: Address,
        value: Value,
        audit_context: AuditContext,
        timeout: Duration,
    ) -> (Self, oneshot::Receiver<WriteResponse>) {
        let (tx, rx) = oneshot::channel();

        let cmd = Self {
            id: Uuid::now_v7(),
            device_id,
            address,
            value,
            response_tx: tx,
            audit_context,
            timeout,
            created_at: Instant::now(),
            timestamp: Utc::now(),
        };

        (cmd, rx)
    }

    /// Returns `true` if the command has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.created_at.elapsed() > self.timeout
    }

    /// Returns the remaining time before timeout.
    pub fn remaining_time(&self) -> Option<Duration> {
        let elapsed = self.created_at.elapsed();
        if elapsed >= self.timeout {
            None
        } else {
            Some(self.timeout - elapsed)
        }
    }

    /// Returns the elapsed time since command creation.
    pub fn elapsed(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Sends a success response.
    pub fn respond_success(self) {
        let duration = self.created_at.elapsed();
        let _ = self.response_tx.send(WriteResponse::success(self.id, duration));
    }

    /// Sends a failure response.
    pub fn respond_failure(self, error: impl Into<String>) {
        let duration = self.created_at.elapsed();
        let _ = self.response_tx.send(WriteResponse::failure(self.id, error, duration));
    }

    /// Sends a response from a DriverError.
    pub fn respond_driver_error(self, error: &DriverError) {
        let duration = self.created_at.elapsed();
        let _ = self.response_tx.send(WriteResponse::from_driver_error(self.id, error, duration));
    }
}

impl std::fmt::Debug for WriteCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteCommand")
            .field("id", &self.id)
            .field("device_id", &self.device_id)
            .field("address", &self.address)
            .field("value", &self.value)
            .field("timeout", &self.timeout)
            .field("timestamp", &self.timestamp)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Audit Context
// =============================================================================

/// Context information for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditContext {
    /// User ID (if authenticated).
    pub user_id: Option<String>,
    /// Client IP address.
    pub client_ip: Option<IpAddr>,
    /// Request ID for tracing.
    pub request_id: Uuid,
    /// User roles for RBAC.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Additional metadata.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl AuditContext {
    /// Creates a new audit context.
    pub fn new() -> Self {
        Self {
            user_id: None,
            client_ip: None,
            request_id: Uuid::now_v7(),
            roles: Vec::new(),
            metadata: serde_json::Value::Null,
        }
    }

    /// Creates an audit context with user information.
    pub fn with_user(user_id: impl Into<String>, client_ip: Option<IpAddr>) -> Self {
        Self {
            user_id: Some(user_id.into()),
            client_ip,
            request_id: Uuid::now_v7(),
            roles: Vec::new(),
            metadata: serde_json::Value::Null,
        }
    }

    /// Creates an anonymous audit context.
    pub fn anonymous() -> Self {
        Self::new()
    }

    /// Sets the user ID.
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Sets the client IP.
    pub fn client_ip(mut self, ip: IpAddr) -> Self {
        self.client_ip = Some(ip);
        self
    }

    /// Sets the roles.
    pub fn roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Adds a role.
    pub fn add_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Sets additional metadata.
    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

impl Default for AuditContext {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Bus Statistics
// =============================================================================

/// Statistics for a message bus.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BusStats {
    /// Total messages published.
    pub messages_published: u64,
    /// Total messages received.
    pub messages_received: u64,
    /// Messages dropped due to lag.
    pub messages_dropped: u64,
    /// Current number of subscribers (for DataBus).
    pub subscriber_count: u64,
    /// Total errors.
    pub errors: u64,
}

// =============================================================================
// Data Bus
// =============================================================================

/// A broadcast bus for distributing data messages.
///
/// The DataBus uses a `tokio::sync::broadcast` channel internally,
/// allowing multiple subscribers to receive all published messages.
///
/// Messages that implement `Clone` are efficiently distributed to all
/// active subscribers.
pub struct DataBus {
    /// The broadcast sender.
    sender: broadcast::Sender<DataMessage>,
    /// Channel capacity.
    capacity: usize,
    /// Statistics.
    stats: Arc<AtomicBusStats>,
}

/// Atomic statistics for lock-free updates.
#[derive(Debug, Default)]
struct AtomicBusStats {
    messages_published: AtomicU64,
    messages_dropped: AtomicU64,
    errors: AtomicU64,
}

impl DataBus {
    /// Creates a new data bus with the specified capacity.
    ///
    /// The capacity determines how many messages can be buffered
    /// before slow receivers start losing messages.
    ///
    /// # Recommended Capacity
    ///
    /// - `10000` for general use (1000 tags × 1s poll × 10s buffer)
    /// - Higher for high-frequency polling
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);

        Self {
            sender,
            capacity,
            stats: Arc::new(AtomicBusStats::default()),
        }
    }

    /// Publishes a message to all subscribers.
    ///
    /// Returns the number of receivers that will receive the message.
    /// Returns `Ok(0)` if there are no active subscribers.
    pub fn publish(&self, message: DataMessage) -> Result<usize, BusError> {
        match self.sender.send(message) {
            Ok(count) => {
                self.stats.messages_published.fetch_add(1, Ordering::Relaxed);
                Ok(count)
            }
            Err(_) => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                // No receivers - this is not necessarily an error
                // in a pub/sub system, but we track it
                Ok(0)
            }
        }
    }

    /// Publishes a message, ignoring if there are no receivers.
    pub fn try_publish(&self, message: DataMessage) {
        let _ = self.sender.send(message);
        self.stats.messages_published.fetch_add(1, Ordering::Relaxed);
    }

    /// Creates a new subscriber.
    pub fn subscribe(&self) -> DataSubscriber {
        DataSubscriber {
            receiver: self.sender.subscribe(),
            stats: self.stats.clone(),
        }
    }

    /// Returns the current number of subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Returns the channel capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns current statistics.
    pub fn stats(&self) -> BusStats {
        BusStats {
            messages_published: self.stats.messages_published.load(Ordering::Relaxed),
            messages_received: 0, // Tracked per subscriber
            messages_dropped: self.stats.messages_dropped.load(Ordering::Relaxed),
            subscriber_count: self.subscriber_count() as u64,
            errors: self.stats.errors.load(Ordering::Relaxed),
        }
    }
}

impl std::fmt::Debug for DataBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataBus")
            .field("capacity", &self.capacity)
            .field("subscriber_count", &self.subscriber_count())
            .field("messages_published", &self.stats.messages_published.load(Ordering::Relaxed))
            .finish()
    }
}

/// A subscriber to the data bus.
pub struct DataSubscriber {
    receiver: broadcast::Receiver<DataMessage>,
    stats: Arc<AtomicBusStats>,
}

impl DataSubscriber {
    /// Receives the next message.
    ///
    /// Returns `None` if the sender has been dropped.
    pub async fn recv(&mut self) -> Result<DataMessage, BusError> {
        loop {
            match self.receiver.recv().await {
                Ok(msg) => return Ok(msg),
                Err(broadcast::error::RecvError::Closed) => return Err(BusError::Closed),
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    self.stats.messages_dropped.fetch_add(count, Ordering::Relaxed);
                    tracing::warn!(count, "DataBus subscriber lagged, messages dropped");
                    // Continue receiving - don't return error for lag
                }
            }
        }
    }

    /// Tries to receive a message without blocking.
    pub fn try_recv(&mut self) -> Result<Option<DataMessage>, BusError> {
        match self.receiver.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(broadcast::error::TryRecvError::Closed) => Err(BusError::Closed),
            Err(broadcast::error::TryRecvError::Lagged(count)) => {
                self.stats.messages_dropped.fetch_add(count, Ordering::Relaxed);
                Ok(None)
            }
        }
    }

    /// Filters messages for a specific device.
    pub fn filter_device(self, device_id: DeviceId) -> DeviceFilteredSubscriber {
        DeviceFilteredSubscriber {
            subscriber: self,
            device_id,
        }
    }
}

/// A subscriber filtered by device ID.
pub struct DeviceFilteredSubscriber {
    subscriber: DataSubscriber,
    device_id: DeviceId,
}

impl DeviceFilteredSubscriber {
    /// Receives the next message matching the device filter.
    pub async fn recv(&mut self) -> Result<DataMessage, BusError> {
        loop {
            let msg = self.subscriber.recv().await?;
            if self.matches(&msg) {
                return Ok(msg);
            }
        }
    }

    fn matches(&self, msg: &DataMessage) -> bool {
        match msg.device_id() {
            Some(id) => id == &self.device_id,
            None => true, // System messages pass through
        }
    }
}

// =============================================================================
// Command Bus
// =============================================================================

/// An MPSC bus for processing write commands.
///
/// The CommandBus uses a `tokio::sync::mpsc` channel for N:1 communication,
/// where multiple senders can submit commands to a single handler.
///
/// # Usage Pattern
///
/// ```rust,ignore
/// // Create the channel pair
/// let (command_bus, command_receiver) = CommandBus::channel(256);
///
/// // Spawn the command handler with the receiver
/// tokio::spawn(async move {
///     let handler = CommandHandler::new(command_receiver, ...);
///     handler.run().await;
/// });
///
/// // Use command_bus from API handlers
/// let response = command_bus.send_write(...).await?;
/// ```
#[derive(Clone)]
pub struct CommandBus {
    /// The sender.
    sender: mpsc::Sender<WriteCommand>,
    /// Channel capacity.
    capacity: usize,
    /// Statistics.
    stats: Arc<AtomicCommandBusStats>,
}

/// Atomic statistics for command bus.
#[derive(Debug, Default)]
struct AtomicCommandBusStats {
    commands_sent: AtomicU64,
    commands_succeeded: AtomicU64,
    commands_failed: AtomicU64,
    commands_timed_out: AtomicU64,
}

impl CommandBus {
    /// Creates a new command bus channel pair.
    ///
    /// Returns a tuple of (CommandBus, CommandReceiver) where:
    /// - `CommandBus`: Can be cloned and used by multiple senders
    /// - `CommandReceiver`: Should be owned by a single command handler
    pub fn channel(capacity: usize) -> (Self, CommandReceiver) {
        let (sender, receiver) = mpsc::channel(capacity);
        let stats = Arc::new(AtomicCommandBusStats::default());

        (
            Self {
                sender,
                capacity,
                stats: stats.clone(),
            },
            CommandReceiver {
                receiver,
                stats,
            },
        )
    }

    /// Creates a command bus with an existing sender.
    ///
    /// Note: Prefer using `channel()` to create a properly paired bus and receiver.
    #[doc(hidden)]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = mpsc::channel(capacity);
        Self {
            sender,
            capacity,
            stats: Arc::new(AtomicCommandBusStats::default()),
        }
    }

    /// Sends a write command and waits for the response.
    ///
    /// This is a convenience method that creates the response channel
    /// and waits for the result.
    pub async fn send_write(
        &self,
        device_id: DeviceId,
        address: Address,
        value: Value,
        audit_context: AuditContext,
        timeout: Duration,
    ) -> Result<WriteResponse, CommandError> {
        let (cmd, rx) = WriteCommand::new(device_id, address, value, audit_context, timeout);

        self.send(cmd).await?;

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => {
                if response.success {
                    self.stats.commands_succeeded.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.commands_failed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(response)
            }
            Ok(Err(_)) => {
                self.stats.commands_failed.fetch_add(1, Ordering::Relaxed);
                Err(CommandError::ResponseChannelClosed)
            }
            Err(_) => {
                self.stats.commands_timed_out.fetch_add(1, Ordering::Relaxed);
                Err(CommandError::Timeout { timeout })
            }
        }
    }

    /// Sends a command without waiting for the response.
    ///
    /// The caller is responsible for receiving the response from the
    /// `oneshot::Receiver` returned by `WriteCommand::new()`.
    pub async fn send(&self, command: WriteCommand) -> Result<(), CommandError> {
        self.sender
            .send(command)
            .await
            .map_err(|_| CommandError::ChannelClosed)?;

        self.stats.commands_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Tries to send a command without blocking.
    pub fn try_send(&self, command: WriteCommand) -> Result<(), CommandError> {
        self.sender.try_send(command).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => CommandError::Rejected {
                reason: "Channel full".to_string(),
            },
            mpsc::error::TrySendError::Closed(_) => CommandError::ChannelClosed,
        })?;

        self.stats.commands_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Returns the channel capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns current statistics.
    pub fn stats(&self) -> CommandBusStats {
        CommandBusStats {
            commands_sent: self.stats.commands_sent.load(Ordering::Relaxed),
            commands_succeeded: self.stats.commands_succeeded.load(Ordering::Relaxed),
            commands_failed: self.stats.commands_failed.load(Ordering::Relaxed),
            commands_timed_out: self.stats.commands_timed_out.load(Ordering::Relaxed),
        }
    }

    /// Creates a command sender that can be cloned.
    pub fn sender(&self) -> CommandSender {
        CommandSender {
            sender: self.sender.clone(),
            stats: self.stats.clone(),
        }
    }
}

impl std::fmt::Debug for CommandBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandBus")
            .field("capacity", &self.capacity)
            .field("commands_sent", &self.stats.commands_sent.load(Ordering::Relaxed))
            .finish()
    }
}

/// Statistics for the command bus.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CommandBusStats {
    /// Total commands sent.
    pub commands_sent: u64,
    /// Commands that succeeded.
    pub commands_succeeded: u64,
    /// Commands that failed.
    pub commands_failed: u64,
    /// Commands that timed out.
    pub commands_timed_out: u64,
}

// =============================================================================
// Command Receiver
// =============================================================================

/// Receiver side of the command bus.
///
/// This should be owned by a single command handler task.
/// Use `CommandHandler` for a complete implementation.
pub struct CommandReceiver {
    receiver: mpsc::Receiver<WriteCommand>,
    stats: Arc<AtomicCommandBusStats>,
}

impl CommandReceiver {
    /// Receives the next command.
    ///
    /// Returns `None` when all senders have been dropped.
    pub async fn recv(&mut self) -> Option<WriteCommand> {
        self.receiver.recv().await
    }

    /// Tries to receive a command without blocking.
    pub fn try_recv(&mut self) -> Option<WriteCommand> {
        self.receiver.try_recv().ok()
    }

    /// Closes the receiver.
    ///
    /// Prevents any further commands from being sent.
    pub fn close(&mut self) {
        self.receiver.close();
    }

    /// Returns command bus statistics.
    pub fn stats(&self) -> CommandBusStats {
        CommandBusStats {
            commands_sent: self.stats.commands_sent.load(Ordering::Relaxed),
            commands_succeeded: self.stats.commands_succeeded.load(Ordering::Relaxed),
            commands_failed: self.stats.commands_failed.load(Ordering::Relaxed),
            commands_timed_out: self.stats.commands_timed_out.load(Ordering::Relaxed),
        }
    }
}

impl std::fmt::Debug for CommandReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandReceiver")
            .field("commands_sent", &self.stats.commands_sent.load(Ordering::Relaxed))
            .finish()
    }
}

// =============================================================================
// Command Sender
// =============================================================================

/// A clonable sender for the command bus.
#[derive(Clone)]
pub struct CommandSender {
    sender: mpsc::Sender<WriteCommand>,
    stats: Arc<AtomicCommandBusStats>,
}

impl CommandSender {
    /// Sends a command.
    pub async fn send(&self, command: WriteCommand) -> Result<(), CommandError> {
        self.sender
            .send(command)
            .await
            .map_err(|_| CommandError::ChannelClosed)?;

        self.stats.commands_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Sends a command and waits for the response.
    pub async fn send_write(
        &self,
        device_id: DeviceId,
        address: Address,
        value: Value,
        audit_context: AuditContext,
        timeout: Duration,
    ) -> Result<WriteResponse, CommandError> {
        let (cmd, rx) = WriteCommand::new(device_id, address, value, audit_context, timeout);

        self.send(cmd).await?;

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => {
                if response.success {
                    self.stats.commands_succeeded.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.commands_failed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(response)
            }
            Ok(Err(_)) => {
                self.stats.commands_failed.fetch_add(1, Ordering::Relaxed);
                Err(CommandError::ResponseChannelClosed)
            }
            Err(_) => {
                self.stats.commands_timed_out.fetch_add(1, Ordering::Relaxed);
                Err(CommandError::Timeout { timeout })
            }
        }
    }
}

impl std::fmt::Debug for CommandSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSender").finish_non_exhaustive()
    }
}

// =============================================================================
// Bus Handle
// =============================================================================

/// A handle containing both buses for convenient access.
#[derive(Clone)]
pub struct BusHandle {
    /// Data bus for publishing data messages.
    pub data_bus: Arc<DataBus>,
    /// Command sender for sending write commands.
    pub command_sender: CommandSender,
}

impl BusHandle {
    /// Creates a new bus handle.
    pub fn new(data_bus: Arc<DataBus>, command_sender: CommandSender) -> Self {
        Self {
            data_bus,
            command_sender,
        }
    }

    /// Publishes a data message.
    pub fn publish_data(&self, message: DataMessage) -> Result<usize, BusError> {
        self.data_bus.publish(message)
    }

    /// Sends a write command and waits for the result.
    pub async fn send_write_command(
        &self,
        device_id: DeviceId,
        address: Address,
        value: Value,
        audit_context: AuditContext,
        timeout: Duration,
    ) -> Result<WriteResponse, CommandError> {
        self.command_sender
            .send_write(device_id, address, value, audit_context, timeout)
            .await
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DataQuality, TagId};

    #[tokio::test]
    async fn test_data_bus_publish_subscribe() {
        let bus = DataBus::new(16);
        let mut subscriber = bus.subscribe();

        let point = crate::types::DataPoint::new(
            DeviceId::new("device1"),
            TagId::new("tag1"),
            Value::Float64(42.0),
            DataQuality::Good,
        );

        let msg = DataMessage::data(point);

        // Publish
        let count = bus.publish(msg.clone()).unwrap();
        assert_eq!(count, 1);

        // Receive
        let received = subscriber.recv().await.unwrap();
        assert!(received.is_data());
    }

    #[tokio::test]
    async fn test_data_bus_multiple_subscribers() {
        let bus = DataBus::new(16);
        let mut sub1 = bus.subscribe();
        let mut sub2 = bus.subscribe();

        let msg = DataMessage::System(crate::message::SystemEvent::heartbeat(1, 2));

        // Publish
        let count = bus.publish(msg).unwrap();
        assert_eq!(count, 2);

        // Both should receive
        let r1 = sub1.recv().await;
        let r2 = sub2.recv().await;
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }

    #[test]
    fn test_audit_context() {
        let ctx = AuditContext::with_user("user123", Some("192.168.1.1".parse().unwrap()));
        assert_eq!(ctx.user_id, Some("user123".to_string()));
        assert!(ctx.client_ip.is_some());
    }

    #[test]
    fn test_audit_context_builder() {
        let ctx = AuditContext::new()
            .user_id("test_user")
            .add_role("admin")
            .add_role("operator");

        assert_eq!(ctx.user_id, Some("test_user".to_string()));
        assert_eq!(ctx.roles.len(), 2);
    }

    #[tokio::test]
    async fn test_command_bus_channel() {
        use crate::address::GenericAddress;

        let (bus, mut receiver) = CommandBus::channel(16);

        let (cmd, rx) = WriteCommand::new(
            DeviceId::new("device1"),
            Address::Generic(GenericAddress::new("test", "test-addr")),
            Value::Float64(1.0),
            AuditContext::anonymous(),
            Duration::from_secs(5),
        );

        // Send command
        bus.send(cmd).await.unwrap();

        // Receive command
        let received = receiver.recv().await.unwrap();
        assert_eq!(received.device_id.as_str(), "device1");

        // Send response
        received.respond_success();

        // Receive response
        let result = rx.await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_command_bus_send_write() {
        use crate::address::GenericAddress;

        let (bus, mut receiver) = CommandBus::channel(16);

        // Spawn handler
        tokio::spawn(async move {
            while let Some(cmd) = receiver.recv().await {
                cmd.respond_success();
            }
        });

        // Send write command
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
    }

    #[test]
    fn test_write_command_timeout() {
        use crate::address::GenericAddress;
        use std::thread::sleep;

        let (cmd, _rx) = WriteCommand::new(
            DeviceId::new("device1"),
            Address::Generic(GenericAddress::new("test", "addr")),
            Value::Int32(42),
            AuditContext::anonymous(),
            Duration::from_millis(50),
        );

        assert!(!cmd.is_timed_out());

        sleep(Duration::from_millis(100));

        assert!(cmd.is_timed_out());
    }

    #[test]
    fn test_write_response() {
        let response = WriteResponse::success(Uuid::now_v7(), Duration::from_millis(100));
        assert!(response.success);
        assert!(response.error.is_none());

        let response = WriteResponse::failure(Uuid::now_v7(), "test error", Duration::from_millis(50));
        assert!(!response.success);
        assert_eq!(response.error, Some("test error".to_string()));
    }

    #[test]
    fn test_write_response_serialization() {
        let response = WriteResponse::success(Uuid::now_v7(), Duration::from_millis(123));
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("123")); // duration in millis
        assert!(json.contains("true")); // success
    }

    #[test]
    fn test_bus_stats() {
        let bus = DataBus::new(16);
        let _sub = bus.subscribe();

        bus.try_publish(DataMessage::System(crate::message::SystemEvent::heartbeat(0, 0)));
        bus.try_publish(DataMessage::System(crate::message::SystemEvent::heartbeat(0, 0)));

        let stats = bus.stats();
        assert_eq!(stats.messages_published, 2);
        assert_eq!(stats.subscriber_count, 1);
    }

    #[test]
    fn test_command_bus_stats() {
        let (bus, _receiver) = CommandBus::channel(16);
        let stats = bus.stats();
        assert_eq!(stats.commands_sent, 0);
    }

    #[test]
    fn test_write_command_debug() {
        use crate::address::GenericAddress;

        let (cmd, _) = WriteCommand::new(
            DeviceId::new("device1"),
            Address::Generic(GenericAddress::new("test", "addr")),
            Value::Int32(42),
            AuditContext::anonymous(),
            Duration::from_secs(5),
        );

        let debug_str = format!("{:?}", cmd);
        assert!(debug_str.contains("device1"));
    }
}
