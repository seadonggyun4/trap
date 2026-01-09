// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Driver hooks and event system.
//!
//! This module provides an extensible hook system for driver lifecycle events,
//! enabling observability, logging, metrics collection, and custom behavior
//! without modifying driver implementations.
//!
//! # Design Principles
//!
//! - **Non-blocking**: Hooks should not block driver operations
//! - **Composable**: Multiple hooks can be registered and chained
//! - **Type-safe**: Strongly typed events and handlers
//! - **Async-friendly**: Full async support for handlers
//!
//! # Event Types
//!
//! - Connection events: `OnConnect`, `OnDisconnect`, `OnReconnect`
//! - Operation events: `OnRead`, `OnWrite`, `OnBatchRead`, `OnBatchWrite`
//! - Error events: `OnError`, `OnCircuitStateChange`
//! - Health events: `OnHealthCheck`, `OnHealthChange`
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_core::hooks::{DriverHooks, HookContext, DriverEvent};
//!
//! let mut hooks = DriverHooks::new();
//!
//! // Add a logging hook
//! hooks.on_connect(|ctx, result| async move {
//!     tracing::info!(device_id = %ctx.device_id, "Device connected");
//! });
//!
//! // Add a metrics hook
//! hooks.on_read(|ctx, result| async move {
//!     if let Ok(value) = result {
//!         metrics::counter!("driver_reads_total").increment(1);
//!     }
//! });
//! ```

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::driver::CircuitState;
use crate::error::DriverError;
use crate::types::{DeviceId, Protocol, Value};

// =============================================================================
// Event Types
// =============================================================================

/// Context information passed to hook handlers.
#[derive(Debug, Clone)]
pub struct HookContext {
    /// The device ID.
    pub device_id: DeviceId,
    /// The protocol type.
    pub protocol: Protocol,
    /// Timestamp when the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Operation duration (if applicable).
    pub duration: Option<Duration>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

impl HookContext {
    /// Creates a new hook context.
    pub fn new(device_id: DeviceId, protocol: Protocol) -> Self {
        Self {
            device_id,
            protocol,
            timestamp: Utc::now(),
            duration: None,
            metadata: None,
        }
    }

    /// Sets the operation duration.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Sets additional metadata.
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Events emitted by driver operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum DriverEvent {
    /// Driver connected to device.
    Connected {
        /// Device identifier.
        device_id: String,
        /// Protocol type.
        protocol: Protocol,
    },

    /// Driver disconnected from device.
    Disconnected {
        /// Device identifier.
        device_id: String,
        /// Protocol type.
        protocol: Protocol,
        /// Disconnect reason.
        reason: Option<String>,
    },

    /// Reconnection attempt.
    Reconnecting {
        /// Device identifier.
        device_id: String,
        /// Current attempt number.
        attempt: u32,
        /// Maximum attempts.
        max_attempts: u32,
    },

    /// Reconnection succeeded.
    Reconnected {
        /// Device identifier.
        device_id: String,
        /// Total attempts taken.
        attempts: u32,
    },

    /// Read operation completed.
    ReadCompleted {
        /// Device identifier.
        device_id: String,
        /// Address read from.
        address: String,
        /// Whether read succeeded.
        success: bool,
        /// Duration in microseconds.
        duration_us: u64,
    },

    /// Write operation completed.
    WriteCompleted {
        /// Device identifier.
        device_id: String,
        /// Address written to.
        address: String,
        /// Whether write succeeded.
        success: bool,
        /// Duration in microseconds.
        duration_us: u64,
    },

    /// Batch read completed.
    BatchReadCompleted {
        /// Device identifier.
        device_id: String,
        /// Total addresses read.
        count: usize,
        /// Successful reads.
        success_count: usize,
        /// Duration in microseconds.
        duration_us: u64,
    },

    /// Batch write completed.
    BatchWriteCompleted {
        /// Device identifier.
        device_id: String,
        /// Total addresses written.
        count: usize,
        /// Successful writes.
        success_count: usize,
        /// Duration in microseconds.
        duration_us: u64,
    },

    /// Error occurred.
    Error {
        /// Device identifier.
        device_id: String,
        /// Type of error.
        error_type: String,
        /// Error message.
        message: String,
        /// Whether error is recoverable.
        recoverable: bool,
    },

    /// Circuit breaker state changed.
    CircuitStateChanged {
        /// Device identifier.
        device_id: String,
        /// Previous state.
        from_state: CircuitState,
        /// New state.
        to_state: CircuitState,
    },

    /// Health check performed.
    HealthChecked {
        /// Device identifier.
        device_id: String,
        /// Whether device is healthy.
        healthy: bool,
        /// Latency in microseconds.
        latency_us: Option<u64>,
    },

    /// Health status changed.
    HealthChanged {
        /// Device identifier.
        device_id: String,
        /// Previous health status.
        from_healthy: bool,
        /// New health status.
        to_healthy: bool,
    },

    /// Retry attempted.
    RetryAttempted {
        /// Device identifier.
        device_id: String,
        /// Operation being retried.
        operation: String,
        /// Current attempt.
        attempt: u32,
        /// Delay before retry in milliseconds.
        delay_ms: u64,
    },

    /// Custom event for extensions.
    Custom {
        /// Event name.
        name: String,
        /// Event payload.
        payload: serde_json::Value,
    },
}

impl DriverEvent {
    /// Returns the event type name.
    pub fn event_type(&self) -> &'static str {
        match self {
            DriverEvent::Connected { .. } => "connected",
            DriverEvent::Disconnected { .. } => "disconnected",
            DriverEvent::Reconnecting { .. } => "reconnecting",
            DriverEvent::Reconnected { .. } => "reconnected",
            DriverEvent::ReadCompleted { .. } => "read_completed",
            DriverEvent::WriteCompleted { .. } => "write_completed",
            DriverEvent::BatchReadCompleted { .. } => "batch_read_completed",
            DriverEvent::BatchWriteCompleted { .. } => "batch_write_completed",
            DriverEvent::Error { .. } => "error",
            DriverEvent::CircuitStateChanged { .. } => "circuit_state_changed",
            DriverEvent::HealthChecked { .. } => "health_checked",
            DriverEvent::HealthChanged { .. } => "health_changed",
            DriverEvent::RetryAttempted { .. } => "retry_attempted",
            DriverEvent::Custom { .. } => "custom",
        }
    }

    /// Returns the device ID from the event.
    pub fn device_id(&self) -> &str {
        match self {
            DriverEvent::Connected { device_id, .. } => device_id,
            DriverEvent::Disconnected { device_id, .. } => device_id,
            DriverEvent::Reconnecting { device_id, .. } => device_id,
            DriverEvent::Reconnected { device_id, .. } => device_id,
            DriverEvent::ReadCompleted { device_id, .. } => device_id,
            DriverEvent::WriteCompleted { device_id, .. } => device_id,
            DriverEvent::BatchReadCompleted { device_id, .. } => device_id,
            DriverEvent::BatchWriteCompleted { device_id, .. } => device_id,
            DriverEvent::Error { device_id, .. } => device_id,
            DriverEvent::CircuitStateChanged { device_id, .. } => device_id,
            DriverEvent::HealthChecked { device_id, .. } => device_id,
            DriverEvent::HealthChanged { device_id, .. } => device_id,
            DriverEvent::RetryAttempted { device_id, .. } => device_id,
            DriverEvent::Custom { .. } => "",
        }
    }
}

// =============================================================================
// Hook Handler Trait
// =============================================================================

/// A boxed future for hook handlers.
pub type HookFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// A handler for driver events.
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Returns the handler name for logging.
    fn name(&self) -> &str {
        "anonymous"
    }

    /// Handles a driver event.
    ///
    /// This method should be non-blocking. If expensive processing is needed,
    /// it should be spawned as a separate task.
    async fn handle(&self, event: &DriverEvent);

    /// Called when the handler is registered.
    fn on_register(&self) {}

    /// Called when the handler is unregistered.
    fn on_unregister(&self) {}
}

// =============================================================================
// Built-in Handlers
// =============================================================================

/// A handler that logs events using tracing.
#[derive(Debug, Default)]
pub struct TracingHandler {
    /// Log level for normal events.
    pub level: TracingLevel,
    /// Log level for error events.
    pub error_level: TracingLevel,
}

/// Tracing log levels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TracingLevel {
    /// Trace level (most verbose).
    Trace,
    /// Debug level.
    #[default]
    Debug,
    /// Info level.
    Info,
    /// Warning level.
    Warn,
    /// Error level (least verbose).
    Error,
}

impl TracingHandler {
    /// Creates a new tracing handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the log level for normal events.
    pub fn with_level(mut self, level: TracingLevel) -> Self {
        self.level = level;
        self
    }

    /// Sets the log level for error events.
    pub fn with_error_level(mut self, level: TracingLevel) -> Self {
        self.error_level = level;
        self
    }
}

#[async_trait]
impl EventHandler for TracingHandler {
    fn name(&self) -> &str {
        "tracing_handler"
    }

    async fn handle(&self, event: &DriverEvent) {
        let event_type = event.event_type();
        let device_id = event.device_id();

        match event {
            DriverEvent::Error { message, error_type, .. } => {
                match self.error_level {
                    TracingLevel::Trace => tracing::trace!(event = event_type, device_id, error_type, message),
                    TracingLevel::Debug => tracing::debug!(event = event_type, device_id, error_type, message),
                    TracingLevel::Info => tracing::info!(event = event_type, device_id, error_type, message),
                    TracingLevel::Warn => tracing::warn!(event = event_type, device_id, error_type, message),
                    TracingLevel::Error => tracing::error!(event = event_type, device_id, error_type, message),
                }
            }
            DriverEvent::Connected { protocol, .. } => {
                match self.level {
                    TracingLevel::Trace => tracing::trace!(event = event_type, device_id, ?protocol, "Driver connected"),
                    TracingLevel::Debug => tracing::debug!(event = event_type, device_id, ?protocol, "Driver connected"),
                    TracingLevel::Info => tracing::info!(event = event_type, device_id, ?protocol, "Driver connected"),
                    TracingLevel::Warn => tracing::warn!(event = event_type, device_id, ?protocol, "Driver connected"),
                    TracingLevel::Error => tracing::error!(event = event_type, device_id, ?protocol, "Driver connected"),
                }
            }
            DriverEvent::Disconnected { reason, .. } => {
                match self.level {
                    TracingLevel::Trace => tracing::trace!(event = event_type, device_id, ?reason, "Driver disconnected"),
                    TracingLevel::Debug => tracing::debug!(event = event_type, device_id, ?reason, "Driver disconnected"),
                    TracingLevel::Info => tracing::info!(event = event_type, device_id, ?reason, "Driver disconnected"),
                    TracingLevel::Warn => tracing::warn!(event = event_type, device_id, ?reason, "Driver disconnected"),
                    TracingLevel::Error => tracing::error!(event = event_type, device_id, ?reason, "Driver disconnected"),
                }
            }
            DriverEvent::CircuitStateChanged { from_state, to_state, .. } => {
                tracing::warn!(
                    event = event_type,
                    device_id,
                    ?from_state,
                    ?to_state,
                    "Circuit breaker state changed"
                );
            }
            _ => {
                match self.level {
                    TracingLevel::Trace => tracing::trace!(event = event_type, device_id),
                    TracingLevel::Debug => tracing::debug!(event = event_type, device_id),
                    TracingLevel::Info => tracing::info!(event = event_type, device_id),
                    TracingLevel::Warn => tracing::warn!(event = event_type, device_id),
                    TracingLevel::Error => tracing::error!(event = event_type, device_id),
                }
            }
        }
    }
}

/// A handler that collects events in memory (useful for testing).
#[derive(Debug, Default)]
pub struct CollectorHandler {
    events: RwLock<Vec<DriverEvent>>,
    max_events: usize,
}

impl CollectorHandler {
    /// Creates a new collector handler.
    pub fn new(max_events: usize) -> Self {
        Self {
            events: RwLock::new(Vec::with_capacity(max_events.min(1000))),
            max_events,
        }
    }

    /// Returns collected events.
    pub fn events(&self) -> Vec<DriverEvent> {
        self.events.read().clone()
    }

    /// Clears collected events.
    pub fn clear(&self) {
        self.events.write().clear();
    }

    /// Returns the number of collected events.
    pub fn len(&self) -> usize {
        self.events.read().len()
    }

    /// Returns true if no events collected.
    pub fn is_empty(&self) -> bool {
        self.events.read().is_empty()
    }
}

#[async_trait]
impl EventHandler for CollectorHandler {
    fn name(&self) -> &str {
        "collector_handler"
    }

    async fn handle(&self, event: &DriverEvent) {
        let mut events = self.events.write();

        // Remove oldest if at capacity
        if events.len() >= self.max_events {
            events.remove(0);
        }

        events.push(event.clone());
    }
}

/// A handler that filters events before passing to another handler.
pub struct FilterHandler<H: EventHandler> {
    inner: H,
    filter: Box<dyn Fn(&DriverEvent) -> bool + Send + Sync>,
}

impl<H: EventHandler> FilterHandler<H> {
    /// Creates a new filter handler.
    pub fn new<F>(inner: H, filter: F) -> Self
    where
        F: Fn(&DriverEvent) -> bool + Send + Sync + 'static,
    {
        Self {
            inner,
            filter: Box::new(filter),
        }
    }

    /// Creates a filter that only passes error events.
    pub fn errors_only(inner: H) -> Self {
        Self::new(inner, |event| matches!(event, DriverEvent::Error { .. }))
    }

    /// Creates a filter for a specific device.
    pub fn for_device(inner: H, device_id: String) -> Self {
        Self::new(inner, move |event| event.device_id() == device_id)
    }
}

#[async_trait]
impl<H: EventHandler> EventHandler for FilterHandler<H> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn handle(&self, event: &DriverEvent) {
        if (self.filter)(event) {
            self.inner.handle(event).await;
        }
    }

    fn on_register(&self) {
        self.inner.on_register();
    }

    fn on_unregister(&self) {
        self.inner.on_unregister();
    }
}

impl<H: EventHandler + fmt::Debug> fmt::Debug for FilterHandler<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilterHandler")
            .field("inner", &self.inner)
            .finish()
    }
}

// =============================================================================
// Event Dispatcher
// =============================================================================

/// Dispatches events to registered handlers.
pub struct EventDispatcher {
    handlers: RwLock<Vec<Arc<dyn EventHandler>>>,
}

impl EventDispatcher {
    /// Creates a new event dispatcher.
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(Vec::new()),
        }
    }

    /// Registers an event handler.
    pub fn register(&self, handler: Arc<dyn EventHandler>) {
        handler.on_register();
        self.handlers.write().push(handler);
    }

    /// Removes all handlers with a specific name.
    pub fn unregister(&self, name: &str) {
        let mut handlers = self.handlers.write();
        handlers.retain(|h| {
            if h.name() == name {
                h.on_unregister();
                false
            } else {
                true
            }
        });
    }

    /// Dispatches an event to all handlers.
    pub async fn dispatch(&self, event: &DriverEvent) {
        let handlers = self.handlers.read().clone();

        for handler in handlers {
            handler.handle(event).await;
        }
    }

    /// Dispatches an event without waiting (spawns tasks).
    pub fn dispatch_async(&self, event: DriverEvent) {
        let handlers = self.handlers.read().clone();

        for handler in handlers {
            let event = event.clone();
            tokio::spawn(async move {
                handler.handle(&event).await;
            });
        }
    }

    /// Returns the number of registered handlers.
    pub fn handler_count(&self) -> usize {
        self.handlers.read().len()
    }
}

impl Default for EventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EventDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let handlers = self.handlers.read();
        let names: Vec<_> = handlers.iter().map(|h| h.name()).collect();
        f.debug_struct("EventDispatcher")
            .field("handlers", &names)
            .finish()
    }
}

// =============================================================================
// Hook Registry (Type-safe Hooks)
// =============================================================================

/// Type alias for hook callback.
pub type HookCallback<T> = Box<dyn Fn(&HookContext, &T) + Send + Sync>;

/// Registry for type-safe operation hooks.
pub struct HookRegistry {
    /// Called before connect.
    pub pre_connect: RwLock<Vec<HookCallback<()>>>,
    /// Called after connect.
    pub post_connect: RwLock<Vec<HookCallback<Result<(), DriverError>>>>,
    /// Called before disconnect.
    pub pre_disconnect: RwLock<Vec<HookCallback<()>>>,
    /// Called after disconnect.
    pub post_disconnect: RwLock<Vec<HookCallback<Result<(), DriverError>>>>,
    /// Called before read.
    pub pre_read: RwLock<Vec<HookCallback<Address>>>,
    /// Called after read.
    pub post_read: RwLock<Vec<HookCallback<Result<Value, DriverError>>>>,
    /// Called before write.
    pub pre_write: RwLock<Vec<HookCallback<(Address, Value)>>>,
    /// Called after write.
    pub post_write: RwLock<Vec<HookCallback<Result<(), DriverError>>>>,
}

impl HookRegistry {
    /// Creates a new hook registry.
    pub fn new() -> Self {
        Self {
            pre_connect: RwLock::new(Vec::new()),
            post_connect: RwLock::new(Vec::new()),
            pre_disconnect: RwLock::new(Vec::new()),
            post_disconnect: RwLock::new(Vec::new()),
            pre_read: RwLock::new(Vec::new()),
            post_read: RwLock::new(Vec::new()),
            pre_write: RwLock::new(Vec::new()),
            post_write: RwLock::new(Vec::new()),
        }
    }

    /// Registers a pre-connect hook.
    pub fn on_pre_connect<F>(&self, callback: F)
    where
        F: Fn(&HookContext, &()) + Send + Sync + 'static,
    {
        self.pre_connect.write().push(Box::new(callback));
    }

    /// Registers a post-connect hook.
    pub fn on_post_connect<F>(&self, callback: F)
    where
        F: Fn(&HookContext, &Result<(), DriverError>) + Send + Sync + 'static,
    {
        self.post_connect.write().push(Box::new(callback));
    }

    /// Registers a pre-read hook.
    pub fn on_pre_read<F>(&self, callback: F)
    where
        F: Fn(&HookContext, &Address) + Send + Sync + 'static,
    {
        self.pre_read.write().push(Box::new(callback));
    }

    /// Registers a post-read hook.
    pub fn on_post_read<F>(&self, callback: F)
    where
        F: Fn(&HookContext, &Result<Value, DriverError>) + Send + Sync + 'static,
    {
        self.post_read.write().push(Box::new(callback));
    }

    /// Registers a pre-write hook.
    pub fn on_pre_write<F>(&self, callback: F)
    where
        F: Fn(&HookContext, &(Address, Value)) + Send + Sync + 'static,
    {
        self.pre_write.write().push(Box::new(callback));
    }

    /// Registers a post-write hook.
    pub fn on_post_write<F>(&self, callback: F)
    where
        F: Fn(&HookContext, &Result<(), DriverError>) + Send + Sync + 'static,
    {
        self.post_write.write().push(Box::new(callback));
    }

    /// Invokes pre-connect hooks.
    pub fn invoke_pre_connect(&self, ctx: &HookContext) {
        for hook in self.pre_connect.read().iter() {
            hook(ctx, &());
        }
    }

    /// Invokes post-connect hooks.
    pub fn invoke_post_connect(&self, ctx: &HookContext, result: &Result<(), DriverError>) {
        for hook in self.post_connect.read().iter() {
            hook(ctx, result);
        }
    }

    /// Invokes pre-read hooks.
    pub fn invoke_pre_read(&self, ctx: &HookContext, address: &Address) {
        for hook in self.pre_read.read().iter() {
            hook(ctx, address);
        }
    }

    /// Invokes post-read hooks.
    pub fn invoke_post_read(&self, ctx: &HookContext, result: &Result<Value, DriverError>) {
        for hook in self.post_read.read().iter() {
            hook(ctx, result);
        }
    }

    /// Invokes pre-write hooks.
    pub fn invoke_pre_write(&self, ctx: &HookContext, write: &(Address, Value)) {
        for hook in self.pre_write.read().iter() {
            hook(ctx, write);
        }
    }

    /// Invokes post-write hooks.
    pub fn invoke_post_write(&self, ctx: &HookContext, result: &Result<(), DriverError>) {
        for hook in self.post_write.read().iter() {
            hook(ctx, result);
        }
    }

    /// Clears all registered hooks.
    pub fn clear(&self) {
        self.pre_connect.write().clear();
        self.post_connect.write().clear();
        self.pre_disconnect.write().clear();
        self.post_disconnect.write().clear();
        self.pre_read.write().clear();
        self.post_read.write().clear();
        self.pre_write.write().clear();
        self.post_write.write().clear();
    }
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HookRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HookRegistry")
            .field("pre_connect_count", &self.pre_connect.read().len())
            .field("post_connect_count", &self.post_connect.read().len())
            .field("pre_read_count", &self.pre_read.read().len())
            .field("post_read_count", &self.post_read.read().len())
            .field("pre_write_count", &self.pre_write.read().len())
            .field("post_write_count", &self.post_write.read().len())
            .finish()
    }
}

// =============================================================================
// Observable Driver Wrapper
// =============================================================================

/// A wrapper that adds hook/event support to any driver operation.
pub struct ObservableOperations {
    device_id: DeviceId,
    protocol: Protocol,
    hooks: Arc<HookRegistry>,
    dispatcher: Arc<EventDispatcher>,
}

impl ObservableOperations {
    /// Creates a new observable operations wrapper.
    pub fn new(
        device_id: DeviceId,
        protocol: Protocol,
        hooks: Arc<HookRegistry>,
        dispatcher: Arc<EventDispatcher>,
    ) -> Self {
        Self {
            device_id,
            protocol,
            hooks,
            dispatcher,
        }
    }

    /// Creates a hook context.
    fn create_context(&self) -> HookContext {
        HookContext::new(self.device_id.clone(), self.protocol)
    }

    /// Wraps a connect operation.
    pub async fn wrap_connect<F, Fut>(&self, operation: F) -> Result<(), DriverError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), DriverError>>,
    {
        let ctx = self.create_context();
        self.hooks.invoke_pre_connect(&ctx);

        let start = Instant::now();
        let result = operation().await;
        let duration = start.elapsed();

        let ctx = ctx.with_duration(duration);
        self.hooks.invoke_post_connect(&ctx, &result);

        // Dispatch event
        let event = if result.is_ok() {
            DriverEvent::Connected {
                device_id: self.device_id.as_str().to_string(),
                protocol: self.protocol,
            }
        } else {
            DriverEvent::Error {
                device_id: self.device_id.as_str().to_string(),
                error_type: "connection_failed".to_string(),
                message: result.as_ref().err().map(|e| e.to_string()).unwrap_or_default(),
                recoverable: true,
            }
        };

        self.dispatcher.dispatch(&event).await;

        result
    }

    /// Wraps a disconnect operation.
    pub async fn wrap_disconnect<F, Fut>(&self, operation: F, reason: Option<String>) -> Result<(), DriverError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), DriverError>>,
    {
        let result = operation().await;

        self.dispatcher
            .dispatch(&DriverEvent::Disconnected {
                device_id: self.device_id.as_str().to_string(),
                protocol: self.protocol,
                reason,
            })
            .await;

        result
    }

    /// Wraps a read operation.
    pub async fn wrap_read<F, Fut>(&self, address: &Address, operation: F) -> Result<Value, DriverError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Value, DriverError>>,
    {
        let ctx = self.create_context();
        self.hooks.invoke_pre_read(&ctx, address);

        let start = Instant::now();
        let result = operation().await;
        let duration = start.elapsed();

        let ctx = ctx.with_duration(duration);
        self.hooks.invoke_post_read(&ctx, &result);

        // Dispatch event
        self.dispatcher
            .dispatch(&DriverEvent::ReadCompleted {
                device_id: self.device_id.as_str().to_string(),
                address: format!("{:?}", address),
                success: result.is_ok(),
                duration_us: duration.as_micros() as u64,
            })
            .await;

        result
    }

    /// Wraps a write operation.
    pub async fn wrap_write<F, Fut>(
        &self,
        address: &Address,
        value: &Value,
        operation: F,
    ) -> Result<(), DriverError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), DriverError>>,
    {
        let ctx = self.create_context();
        let write_data = (address.clone(), value.clone());
        self.hooks.invoke_pre_write(&ctx, &write_data);

        let start = Instant::now();
        let result = operation().await;
        let duration = start.elapsed();

        let ctx = ctx.with_duration(duration);
        self.hooks.invoke_post_write(&ctx, &result);

        // Dispatch event
        self.dispatcher
            .dispatch(&DriverEvent::WriteCompleted {
                device_id: self.device_id.as_str().to_string(),
                address: format!("{:?}", address),
                success: result.is_ok(),
                duration_us: duration.as_micros() as u64,
            })
            .await;

        result
    }

    /// Dispatches a circuit state change event.
    pub async fn notify_circuit_change(&self, from: CircuitState, to: CircuitState) {
        self.dispatcher
            .dispatch(&DriverEvent::CircuitStateChanged {
                device_id: self.device_id.as_str().to_string(),
                from_state: from,
                to_state: to,
            })
            .await;
    }

    /// Dispatches a custom event.
    pub async fn notify_custom(&self, name: &str, payload: serde_json::Value) {
        self.dispatcher
            .dispatch(&DriverEvent::Custom {
                name: name.to_string(),
                payload,
            })
            .await;
    }
}

impl fmt::Debug for ObservableOperations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservableOperations")
            .field("device_id", &self.device_id)
            .field("protocol", &self.protocol)
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_hook_context() {
        let ctx = HookContext::new(DeviceId::new("test"), Protocol::ModbusTcp)
            .with_duration(Duration::from_millis(100));

        assert_eq!(ctx.device_id.as_str(), "test");
        assert_eq!(ctx.protocol, Protocol::ModbusTcp);
        assert_eq!(ctx.duration, Some(Duration::from_millis(100)));
    }

    #[test]
    fn test_driver_event_type() {
        let event = DriverEvent::Connected {
            device_id: "test".to_string(),
            protocol: Protocol::ModbusTcp,
        };

        assert_eq!(event.event_type(), "connected");
        assert_eq!(event.device_id(), "test");
    }

    #[test]
    fn test_driver_event_serialization() {
        let event = DriverEvent::ReadCompleted {
            device_id: "test".to_string(),
            address: "40001".to_string(),
            success: true,
            duration_us: 1500,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("read_completed"));
        assert!(json.contains("device_id"));
    }

    #[tokio::test]
    async fn test_collector_handler() {
        let collector = Arc::new(CollectorHandler::new(100));
        let dispatcher = EventDispatcher::new();
        dispatcher.register(collector.clone());

        dispatcher
            .dispatch(&DriverEvent::Connected {
                device_id: "test".to_string(),
                protocol: Protocol::ModbusTcp,
            })
            .await;

        assert_eq!(collector.len(), 1);
        assert!(!collector.is_empty());

        let events = collector.events();
        assert!(matches!(events[0], DriverEvent::Connected { .. }));

        collector.clear();
        assert!(collector.is_empty());
    }

    #[tokio::test]
    async fn test_event_dispatcher() {
        let dispatcher = EventDispatcher::new();
        let collector = Arc::new(CollectorHandler::new(100));

        dispatcher.register(collector.clone());
        assert_eq!(dispatcher.handler_count(), 1);

        dispatcher
            .dispatch(&DriverEvent::Connected {
                device_id: "test".to_string(),
                protocol: Protocol::ModbusTcp,
            })
            .await;

        assert_eq!(collector.len(), 1);
    }

    #[test]
    fn test_hook_registry() {
        let registry = HookRegistry::new();
        let counter = Arc::new(AtomicU32::new(0));

        let counter_clone = counter.clone();
        registry.on_pre_connect(move |_ctx, _| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let ctx = HookContext::new(DeviceId::new("test"), Protocol::ModbusTcp);
        registry.invoke_pre_connect(&ctx);

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_collector_max_events() {
        let collector = CollectorHandler::new(3);

        // Add 5 events
        for i in 0..5 {
            let event = DriverEvent::ReadCompleted {
                device_id: format!("device-{}", i),
                address: "addr".to_string(),
                success: true,
                duration_us: 100,
            };
            futures::executor::block_on(collector.handle(&event));
        }

        // Should only have 3 events (oldest removed)
        assert_eq!(collector.len(), 3);

        let events = collector.events();
        // First event should be device-2 (device-0 and device-1 were removed)
        match &events[0] {
            DriverEvent::ReadCompleted { device_id, .. } => {
                assert_eq!(device_id, "device-2");
            }
            _ => panic!("Unexpected event type"),
        }
    }

    #[tokio::test]
    async fn test_filter_handler() {
        // Create collector and wrap it in FilterHandler
        let collector = CollectorHandler::new(100);
        let _filtered = FilterHandler::errors_only(collector);

        // We need to access the inner collector through the filter
        // For this test, we'll use a shared Arc<CollectorHandler> approach
        let shared_collector = Arc::new(CollectorHandler::new(100));
        let collector_ref = shared_collector.clone();

        // Create a custom filter that delegates to our shared collector
        let filter_fn = move |event: &DriverEvent| matches!(event, DriverEvent::Error { .. });

        // Test the filter function directly
        let connected_event = DriverEvent::Connected {
            device_id: "test".to_string(),
            protocol: Protocol::ModbusTcp,
        };
        let error_event = DriverEvent::Error {
            device_id: "test".to_string(),
            error_type: "timeout".to_string(),
            message: "Connection timed out".to_string(),
            recoverable: true,
        };

        // Test filter logic
        assert!(!filter_fn(&connected_event));
        assert!(filter_fn(&error_event));

        // Test with dispatcher using simple collector
        let dispatcher = EventDispatcher::new();
        dispatcher.register(shared_collector);

        dispatcher.dispatch(&connected_event).await;
        assert_eq!(collector_ref.len(), 1); // Collector receives all events

        dispatcher.dispatch(&error_event).await;
        assert_eq!(collector_ref.len(), 2);
    }

    #[tokio::test]
    async fn test_filter_handler_integration() {
        // Test FilterHandler integration with inner handler call tracking
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingHandler {
            count: AtomicU32,
        }

        #[async_trait]
        impl EventHandler for CountingHandler {
            fn name(&self) -> &str {
                "counting"
            }

            async fn handle(&self, _event: &DriverEvent) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let counting = CountingHandler {
            count: AtomicU32::new(0),
        };
        let filtered = FilterHandler::errors_only(counting);

        // Non-error should be filtered
        filtered
            .handle(&DriverEvent::Connected {
                device_id: "test".to_string(),
                protocol: Protocol::ModbusTcp,
            })
            .await;
        // Error should pass through
        filtered
            .handle(&DriverEvent::Error {
                device_id: "test".to_string(),
                error_type: "timeout".to_string(),
                message: "test".to_string(),
                recoverable: true,
            })
            .await;

        // Only error event should have been handled
        assert_eq!(filtered.inner.count.load(Ordering::SeqCst), 1);
    }
}
