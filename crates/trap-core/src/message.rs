// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Message types for the internal message bus.
//!
//! This module defines the message types used for internal communication
//! within TRAP. Messages are designed to be `Clone`-able for use with
//! broadcast channels.
//!
//! # Message Categories
//!
//! - **Data Messages**: Data points, batches, and device status updates
//! - **System Events**: System-level notifications
//! - **Error Types**: Categorized error information
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_core::message::{DataMessage, SystemEvent};
//!
//! let msg = DataMessage::Data(data_point);
//! let event = DataMessage::System(SystemEvent::ShutdownRequested);
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::driver::{CircuitState, HealthStatus};
use crate::types::{ConnectionState, DataPoint, DataQuality, DeviceId, TagId};

// =============================================================================
// Data Message
// =============================================================================

/// Messages sent through the data bus.
///
/// All variants are `Clone`-able for use with broadcast channels.
/// For large data, consider using `Arc` internally if cloning becomes expensive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataMessage {
    /// A single data point from a device.
    Data(DataPoint),

    /// A batch of data points for performance optimization.
    DataBatch(Vec<DataPoint>),

    /// Device connection status changed.
    DeviceStatus {
        /// The device whose status changed.
        device_id: DeviceId,
        /// New connection status.
        status: ConnectionStatus,
        /// Optional status message.
        message: Option<String>,
        /// When the status changed.
        timestamp: DateTime<Utc>,
    },

    /// Driver health check result.
    HealthCheck {
        /// The device that was checked.
        device_id: DeviceId,
        /// Health status result.
        status: HealthStatus,
        /// When the check was performed.
        timestamp: DateTime<Utc>,
    },

    /// An error occurred.
    Error {
        /// The device that had the error (if applicable).
        device_id: Option<DeviceId>,
        /// Error message (String for Clone compatibility).
        error: String,
        /// Error category.
        error_type: ErrorType,
        /// When the error occurred.
        timestamp: DateTime<Utc>,
    },

    /// Tag value changed significantly (for change-only reporting).
    ValueChange {
        /// The device.
        device_id: DeviceId,
        /// The tag.
        tag_id: TagId,
        /// Previous value (if available).
        old_value: Option<DataPoint>,
        /// New value.
        new_value: DataPoint,
    },

    /// Quality changed for a tag.
    QualityChange {
        /// The device.
        device_id: DeviceId,
        /// The tag.
        tag_id: TagId,
        /// Previous quality.
        old_quality: DataQuality,
        /// New quality.
        new_quality: DataQuality,
        /// When the change occurred.
        timestamp: DateTime<Utc>,
    },

    /// A system-level event.
    System(SystemEvent),
}

impl DataMessage {
    /// Creates a data message from a data point.
    pub fn data(point: DataPoint) -> Self {
        Self::Data(point)
    }

    /// Creates a batch data message.
    pub fn batch(points: Vec<DataPoint>) -> Self {
        Self::DataBatch(points)
    }

    /// Creates a device status message.
    pub fn device_status(
        device_id: DeviceId,
        status: ConnectionStatus,
        message: Option<String>,
    ) -> Self {
        Self::DeviceStatus {
            device_id,
            status,
            message,
            timestamp: Utc::now(),
        }
    }

    /// Creates an error message.
    pub fn error(
        device_id: Option<DeviceId>,
        error: impl Into<String>,
        error_type: ErrorType,
    ) -> Self {
        Self::Error {
            device_id,
            error: error.into(),
            error_type,
            timestamp: Utc::now(),
        }
    }

    /// Creates a system event message.
    pub fn system(event: SystemEvent) -> Self {
        Self::System(event)
    }

    /// Returns the timestamp of this message.
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            DataMessage::Data(p) => p.timestamp,
            DataMessage::DataBatch(batch) => batch.first().map(|p| p.timestamp).unwrap_or_else(Utc::now),
            DataMessage::DeviceStatus { timestamp, .. } => *timestamp,
            DataMessage::HealthCheck { timestamp, .. } => *timestamp,
            DataMessage::Error { timestamp, .. } => *timestamp,
            DataMessage::ValueChange { new_value, .. } => new_value.timestamp,
            DataMessage::QualityChange { timestamp, .. } => *timestamp,
            DataMessage::System(event) => event.timestamp(),
        }
    }

    /// Returns the device ID if this message is device-specific.
    pub fn device_id(&self) -> Option<&DeviceId> {
        match self {
            DataMessage::Data(p) => Some(&p.device_id),
            DataMessage::DataBatch(batch) => batch.first().map(|p| &p.device_id),
            DataMessage::DeviceStatus { device_id, .. } => Some(device_id),
            DataMessage::HealthCheck { device_id, .. } => Some(device_id),
            DataMessage::Error { device_id, .. } => device_id.as_ref(),
            DataMessage::ValueChange { device_id, .. } => Some(device_id),
            DataMessage::QualityChange { device_id, .. } => Some(device_id),
            DataMessage::System(_) => None,
        }
    }

    /// Returns `true` if this is a data message (Data or DataBatch).
    pub fn is_data(&self) -> bool {
        matches!(self, DataMessage::Data(_) | DataMessage::DataBatch(_))
    }

    /// Returns `true` if this is an error message.
    pub fn is_error(&self) -> bool {
        matches!(self, DataMessage::Error { .. })
    }

    /// Returns `true` if this is a system event.
    pub fn is_system(&self) -> bool {
        matches!(self, DataMessage::System(_))
    }

    /// Returns the message type name for logging/metrics.
    pub fn message_type(&self) -> &'static str {
        match self {
            DataMessage::Data(_) => "data",
            DataMessage::DataBatch(_) => "data_batch",
            DataMessage::DeviceStatus { .. } => "device_status",
            DataMessage::HealthCheck { .. } => "health_check",
            DataMessage::Error { .. } => "error",
            DataMessage::ValueChange { .. } => "value_change",
            DataMessage::QualityChange { .. } => "quality_change",
            DataMessage::System(_) => "system",
        }
    }
}

// =============================================================================
// Connection Status
// =============================================================================

/// Extended connection status with more detail than ConnectionState.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    /// Device is connected and operational.
    Connected,
    /// Device is disconnected.
    Disconnected,
    /// Device is connecting.
    Connecting,
    /// Device is reconnecting after failure.
    Reconnecting,
    /// Connection failed.
    Failed,
    /// Circuit breaker is open (device isolated).
    CircuitOpen,
    /// Device is in maintenance mode.
    Maintenance,
}

impl ConnectionStatus {
    /// Returns `true` if the device is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, ConnectionStatus::Connected)
    }

    /// Returns `true` if the device is in a failed state.
    pub fn is_failed(&self) -> bool {
        matches!(
            self,
            ConnectionStatus::Failed | ConnectionStatus::CircuitOpen
        )
    }
}

impl From<ConnectionState> for ConnectionStatus {
    fn from(state: ConnectionState) -> Self {
        match state {
            ConnectionState::Connected => ConnectionStatus::Connected,
            ConnectionState::Disconnected => ConnectionStatus::Disconnected,
            ConnectionState::Connecting => ConnectionStatus::Connecting,
            ConnectionState::Reconnecting => ConnectionStatus::Reconnecting,
            ConnectionState::Failed => ConnectionStatus::Failed,
        }
    }
}

impl std::fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ConnectionStatus::Connected => "Connected",
            ConnectionStatus::Disconnected => "Disconnected",
            ConnectionStatus::Connecting => "Connecting",
            ConnectionStatus::Reconnecting => "Reconnecting",
            ConnectionStatus::Failed => "Failed",
            ConnectionStatus::CircuitOpen => "Circuit Open",
            ConnectionStatus::Maintenance => "Maintenance",
        };
        write!(f, "{}", s)
    }
}

// =============================================================================
// Error Type
// =============================================================================

/// Categorized error types for message bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    /// Connection error.
    Connection,
    /// Timeout error.
    Timeout,
    /// Protocol error.
    Protocol,
    /// Configuration error.
    Configuration,
    /// Read operation error.
    Read,
    /// Write operation error.
    Write,
    /// Authentication error.
    Authentication,
    /// Authorization error.
    Authorization,
    /// Rate limiting error.
    RateLimit,
    /// Buffer error.
    Buffer,
    /// Internal error.
    Internal,
    /// Unknown error.
    Unknown,
}

impl ErrorType {
    /// Returns `true` if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ErrorType::Connection | ErrorType::Timeout | ErrorType::RateLimit
        )
    }
}

impl std::fmt::Display for ErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ErrorType::Connection => "Connection",
            ErrorType::Timeout => "Timeout",
            ErrorType::Protocol => "Protocol",
            ErrorType::Configuration => "Configuration",
            ErrorType::Read => "Read",
            ErrorType::Write => "Write",
            ErrorType::Authentication => "Authentication",
            ErrorType::Authorization => "Authorization",
            ErrorType::RateLimit => "Rate Limit",
            ErrorType::Buffer => "Buffer",
            ErrorType::Internal => "Internal",
            ErrorType::Unknown => "Unknown",
        };
        write!(f, "{}", s)
    }
}

// =============================================================================
// System Events
// =============================================================================

/// System-level events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemEvent {
    /// System started.
    Started {
        /// When the system started.
        timestamp: DateTime<Utc>,
        /// System version.
        version: String,
    },

    /// Shutdown requested.
    ShutdownRequested {
        /// When the shutdown was requested.
        timestamp: DateTime<Utc>,
        /// Reason for shutdown (if provided).
        reason: Option<String>,
    },

    /// Shutdown complete.
    ShutdownComplete {
        /// When the shutdown completed.
        timestamp: DateTime<Utc>,
    },

    /// Configuration reloaded.
    ConfigReloaded {
        /// When the config was reloaded.
        timestamp: DateTime<Utc>,
        /// Devices affected.
        devices_affected: Vec<DeviceId>,
    },

    /// Buffer flush completed.
    BufferFlushed {
        /// When the flush completed.
        timestamp: DateTime<Utc>,
        /// Number of items flushed.
        items_flushed: u64,
        /// Whether the flush was successful.
        success: bool,
    },

    /// Circuit breaker state changed.
    CircuitBreakerStateChange {
        /// The device.
        device_id: DeviceId,
        /// Previous state.
        from_state: CircuitState,
        /// New state.
        to_state: CircuitState,
        /// When the change occurred.
        timestamp: DateTime<Utc>,
    },

    /// Reconnection attempt.
    ReconnectionAttempt {
        /// The device.
        device_id: DeviceId,
        /// Attempt number.
        attempt: u32,
        /// When the attempt was made.
        timestamp: DateTime<Utc>,
    },

    /// Heartbeat (periodic health signal).
    Heartbeat {
        /// When the heartbeat was sent.
        timestamp: DateTime<Utc>,
        /// Number of connected devices.
        connected_devices: u32,
        /// Total devices.
        total_devices: u32,
    },

    /// Custom event for extensions.
    Custom {
        /// Event name.
        name: String,
        /// Event data.
        data: serde_json::Value,
        /// When the event occurred.
        timestamp: DateTime<Utc>,
    },
}

impl SystemEvent {
    /// Creates a started event.
    pub fn started(version: impl Into<String>) -> Self {
        Self::Started {
            timestamp: Utc::now(),
            version: version.into(),
        }
    }

    /// Creates a shutdown requested event.
    pub fn shutdown_requested(reason: Option<String>) -> Self {
        Self::ShutdownRequested {
            timestamp: Utc::now(),
            reason,
        }
    }

    /// Creates a shutdown complete event.
    pub fn shutdown_complete() -> Self {
        Self::ShutdownComplete { timestamp: Utc::now() }
    }

    /// Creates a config reloaded event.
    pub fn config_reloaded(devices_affected: Vec<DeviceId>) -> Self {
        Self::ConfigReloaded {
            timestamp: Utc::now(),
            devices_affected,
        }
    }

    /// Creates a heartbeat event.
    pub fn heartbeat(connected_devices: u32, total_devices: u32) -> Self {
        Self::Heartbeat {
            timestamp: Utc::now(),
            connected_devices,
            total_devices,
        }
    }

    /// Creates a custom event.
    pub fn custom(name: impl Into<String>, data: serde_json::Value) -> Self {
        Self::Custom {
            name: name.into(),
            data,
            timestamp: Utc::now(),
        }
    }

    /// Returns the timestamp of this event.
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            SystemEvent::Started { timestamp, .. } => *timestamp,
            SystemEvent::ShutdownRequested { timestamp, .. } => *timestamp,
            SystemEvent::ShutdownComplete { timestamp } => *timestamp,
            SystemEvent::ConfigReloaded { timestamp, .. } => *timestamp,
            SystemEvent::BufferFlushed { timestamp, .. } => *timestamp,
            SystemEvent::CircuitBreakerStateChange { timestamp, .. } => *timestamp,
            SystemEvent::ReconnectionAttempt { timestamp, .. } => *timestamp,
            SystemEvent::Heartbeat { timestamp, .. } => *timestamp,
            SystemEvent::Custom { timestamp, .. } => *timestamp,
        }
    }

    /// Returns the event type name.
    pub fn event_type(&self) -> &'static str {
        match self {
            SystemEvent::Started { .. } => "started",
            SystemEvent::ShutdownRequested { .. } => "shutdown_requested",
            SystemEvent::ShutdownComplete { .. } => "shutdown_complete",
            SystemEvent::ConfigReloaded { .. } => "config_reloaded",
            SystemEvent::BufferFlushed { .. } => "buffer_flushed",
            SystemEvent::CircuitBreakerStateChange { .. } => "circuit_breaker_state_change",
            SystemEvent::ReconnectionAttempt { .. } => "reconnection_attempt",
            SystemEvent::Heartbeat { .. } => "heartbeat",
            SystemEvent::Custom { .. } => "custom",
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Value;

    #[test]
    fn test_data_message_creation() {
        let point = DataPoint::new(
            DeviceId::new("device1"),
            TagId::new("tag1"),
            Value::Float64(42.0),
            DataQuality::Good,
        );

        let msg = DataMessage::data(point.clone());
        assert!(msg.is_data());
        assert!(!msg.is_error());
        assert_eq!(msg.device_id(), Some(&DeviceId::new("device1")));
    }

    #[test]
    fn test_data_message_batch() {
        let points = vec![
            DataPoint::new(
                DeviceId::new("device1"),
                TagId::new("tag1"),
                Value::Float64(1.0),
                DataQuality::Good,
            ),
            DataPoint::new(
                DeviceId::new("device1"),
                TagId::new("tag2"),
                Value::Float64(2.0),
                DataQuality::Good,
            ),
        ];

        let msg = DataMessage::batch(points);
        assert!(msg.is_data());
        assert_eq!(msg.message_type(), "data_batch");
    }

    #[test]
    fn test_connection_status() {
        assert!(ConnectionStatus::Connected.is_operational());
        assert!(!ConnectionStatus::Disconnected.is_operational());
        assert!(ConnectionStatus::Failed.is_failed());
        assert!(ConnectionStatus::CircuitOpen.is_failed());
    }

    #[test]
    fn test_error_type_retryable() {
        assert!(ErrorType::Connection.is_retryable());
        assert!(ErrorType::Timeout.is_retryable());
        assert!(!ErrorType::Configuration.is_retryable());
        assert!(!ErrorType::Authentication.is_retryable());
    }

    #[test]
    fn test_system_event() {
        let event = SystemEvent::started("1.0.0");
        assert_eq!(event.event_type(), "started");

        let event = SystemEvent::heartbeat(5, 10);
        match event {
            SystemEvent::Heartbeat {
                connected_devices,
                total_devices,
                ..
            } => {
                assert_eq!(connected_devices, 5);
                assert_eq!(total_devices, 10);
            }
            _ => panic!("Expected Heartbeat"),
        }
    }

    #[test]
    fn test_message_serialization() {
        let msg = DataMessage::error(
            Some(DeviceId::new("device1")),
            "Connection timeout",
            ErrorType::Timeout,
        );

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("Connection timeout"));
        assert!(json.contains("timeout"));
    }
}
