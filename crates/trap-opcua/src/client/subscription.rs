// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA Subscription Manager.
//!
//! This module provides a comprehensive subscription management system for OPC UA,
//! supporting data change notifications, event monitoring, and lifecycle management.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    SubscriptionManager                          │
//! │         (Manages multiple subscriptions and their lifecycle)    │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┼───────────────────┐
//!          ▼                   ▼                   ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │   Subscription  │ │   Subscription  │ │   Subscription  │
//! │   (ID: 1)       │ │   (ID: 2)       │ │   (ID: 3)       │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//!          │                   │                   │
//!          ▼                   ▼                   ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │ MonitoredItems  │ │ MonitoredItems  │ │ MonitoredItems  │
//! │ [Node1, Node2]  │ │ [Node3]         │ │ [Node4, Node5]  │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//! ```
//!
//! # Design Principles
//!
//! - **Extensibility**: Use traits for callback handling and item management
//! - **Maintainability**: Clear separation of concerns with modular components
//! - **Thread Safety**: All operations are `Send + Sync` safe
//! - **Async First**: Built on tokio for non-blocking operations
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_opcua::client::subscription::{SubscriptionManager, SubscriptionBuilder};
//!
//! let manager = SubscriptionManager::new();
//!
//! let subscription = SubscriptionBuilder::new()
//!     .publishing_interval(Duration::from_millis(500))
//!     .lifetime_count(60)
//!     .add_node(NodeId::numeric(2, 1001))
//!     .add_node(NodeId::string(2, "Temperature"))
//!     .on_data_change(|notification| {
//!         println!("Data changed: {:?}", notification);
//!     })
//!     .build()?;
//!
//! let handle = manager.create_subscription(subscription).await?;
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

use crate::error::{OpcUaError, OpcUaResult, SubscriptionError};
use crate::types::{DeadbandSettings, MonitoredItemSettings, MonitoringMode, NodeId, SubscriptionSettings};

use super::conversion::TypedValue;
use super::transport::OpcUaTransport;

// =============================================================================
// Subscription State
// =============================================================================

/// State of a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionState {
    /// Subscription is being created.
    #[default]
    Creating,

    /// Subscription is active and receiving updates.
    Active,

    /// Subscription is paused (publishing disabled).
    Paused,

    /// Subscription is being transferred.
    Transferring,

    /// Subscription has been deleted.
    Deleted,

    /// Subscription encountered an error.
    Error,
}

impl SubscriptionState {
    /// Returns `true` if the subscription can receive data.
    #[inline]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns `true` if the subscription is in a terminal state.
    #[inline]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Deleted | Self::Error)
    }

    /// Returns `true` if publishing is possible in this state.
    #[inline]
    pub const fn can_publish(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl fmt::Display for SubscriptionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Creating => write!(f, "Creating"),
            Self::Active => write!(f, "Active"),
            Self::Paused => write!(f, "Paused"),
            Self::Transferring => write!(f, "Transferring"),
            Self::Deleted => write!(f, "Deleted"),
            Self::Error => write!(f, "Error"),
        }
    }
}

// =============================================================================
// Data Change Notification
// =============================================================================

/// Notification for a data value change.
#[derive(Debug, Clone)]
pub struct DataChangeNotification {
    /// Subscription ID that generated this notification.
    pub subscription_id: SubscriptionId,

    /// Monitored item ID.
    pub monitored_item_id: MonitoredItemId,

    /// Client-provided handle.
    pub client_handle: u32,

    /// Node ID of the changed node.
    pub node_id: NodeId,

    /// New value.
    pub value: TypedValue,

    /// Server timestamp.
    pub server_timestamp: Option<DateTime<Utc>>,

    /// Source timestamp.
    pub source_timestamp: Option<DateTime<Utc>>,

    /// Sequence number within the subscription.
    pub sequence_number: u32,
}

impl DataChangeNotification {
    /// Creates a new data change notification.
    pub fn new(
        subscription_id: SubscriptionId,
        monitored_item_id: MonitoredItemId,
        client_handle: u32,
        node_id: NodeId,
        value: TypedValue,
    ) -> Self {
        Self {
            subscription_id,
            monitored_item_id,
            client_handle,
            node_id,
            value,
            server_timestamp: Some(Utc::now()),
            source_timestamp: None,
            sequence_number: 0,
        }
    }

    /// Sets timestamps.
    pub fn with_timestamps(
        mut self,
        server: Option<DateTime<Utc>>,
        source: Option<DateTime<Utc>>,
    ) -> Self {
        self.server_timestamp = server;
        self.source_timestamp = source;
        self
    }

    /// Sets the sequence number.
    pub fn with_sequence(mut self, sequence: u32) -> Self {
        self.sequence_number = sequence;
        self
    }
}

// =============================================================================
// IDs
// =============================================================================

/// Unique identifier for a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriptionId(pub u32);

impl SubscriptionId {
    /// Creates a new subscription ID.
    #[inline]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw ID value.
    #[inline]
    pub const fn value(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sub-{}", self.0)
    }
}

impl From<u32> for SubscriptionId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

/// Unique identifier for a monitored item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MonitoredItemId(pub u32);

impl MonitoredItemId {
    /// Creates a new monitored item ID.
    #[inline]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw ID value.
    #[inline]
    pub const fn value(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for MonitoredItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mi-{}", self.0)
    }
}

impl From<u32> for MonitoredItemId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

// =============================================================================
// Monitored Item
// =============================================================================

/// A monitored item within a subscription.
#[derive(Debug, Clone)]
pub struct MonitoredItem {
    /// Server-assigned monitored item ID.
    pub id: MonitoredItemId,

    /// Client-provided handle for correlation.
    pub client_handle: u32,

    /// Node being monitored.
    pub node_id: NodeId,

    /// Sampling interval.
    pub sampling_interval: Duration,

    /// Queue size for buffered values.
    pub queue_size: u32,

    /// Whether to discard oldest values when queue is full.
    pub discard_oldest: bool,

    /// Monitoring mode.
    pub monitoring_mode: MonitoringMode,

    /// Deadband filter settings.
    pub deadband: Option<DeadbandSettings>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last notification timestamp.
    pub last_notification: Option<DateTime<Utc>>,

    /// Notification count.
    pub notification_count: u64,
}

impl MonitoredItem {
    /// Creates a new monitored item.
    pub fn new(
        id: MonitoredItemId,
        client_handle: u32,
        node_id: NodeId,
        settings: &MonitoredItemSettings,
    ) -> Self {
        Self {
            id,
            client_handle,
            node_id,
            sampling_interval: settings.sampling_interval,
            queue_size: settings.queue_size,
            discard_oldest: settings.discard_oldest,
            monitoring_mode: settings.monitoring_mode,
            deadband: settings.deadband.clone(),
            created_at: Utc::now(),
            last_notification: None,
            notification_count: 0,
        }
    }

    /// Records a notification.
    pub fn record_notification(&mut self) {
        self.last_notification = Some(Utc::now());
        self.notification_count += 1;
    }

    /// Returns the age of this monitored item.
    pub fn age(&self) -> chrono::Duration {
        Utc::now() - self.created_at
    }

    /// Returns time since last notification.
    pub fn time_since_last_notification(&self) -> Option<chrono::Duration> {
        self.last_notification.map(|ts| Utc::now() - ts)
    }
}

// =============================================================================
// Subscription
// =============================================================================

/// An OPC UA subscription with its monitored items.
#[derive(Debug)]
pub struct Subscription {
    /// Server-assigned subscription ID.
    pub id: SubscriptionId,

    /// Human-readable name.
    pub name: Option<String>,

    /// Current state.
    state: RwLock<SubscriptionState>,

    /// Subscription settings.
    pub settings: SubscriptionSettings,

    /// Revised publishing interval (from server).
    pub revised_publishing_interval: Duration,

    /// Revised lifetime count (from server).
    pub revised_lifetime_count: u32,

    /// Revised max keep-alive count (from server).
    pub revised_keepalive_count: u32,

    /// Monitored items.
    monitored_items: RwLock<HashMap<MonitoredItemId, MonitoredItem>>,

    /// Node ID to monitored item ID mapping.
    node_to_item: RwLock<HashMap<NodeId, MonitoredItemId>>,

    /// Next client handle.
    next_client_handle: AtomicU32,

    /// Sequence number counter.
    sequence_number: AtomicU32,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last publish time.
    last_publish: RwLock<Option<DateTime<Utc>>>,

    /// Total notification count.
    notification_count: AtomicU64,

    /// Last error message.
    last_error: RwLock<Option<String>>,
}

impl Subscription {
    /// Creates a new subscription.
    pub fn new(id: SubscriptionId, settings: SubscriptionSettings) -> Self {
        Self {
            id,
            name: None,
            state: RwLock::new(SubscriptionState::Creating),
            settings: settings.clone(),
            revised_publishing_interval: settings.publishing_interval,
            revised_lifetime_count: settings.lifetime_count,
            revised_keepalive_count: settings.keepalive_count,
            monitored_items: RwLock::new(HashMap::new()),
            node_to_item: RwLock::new(HashMap::new()),
            next_client_handle: AtomicU32::new(1),
            sequence_number: AtomicU32::new(1),
            created_at: Utc::now(),
            last_publish: RwLock::new(None),
            notification_count: AtomicU64::new(0),
            last_error: RwLock::new(None),
        }
    }

    /// Creates a subscription with a name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Returns the current state.
    pub async fn state(&self) -> SubscriptionState {
        *self.state.read().await
    }

    /// Sets the subscription state.
    pub async fn set_state(&self, state: SubscriptionState) {
        *self.state.write().await = state;
    }

    /// Sets revised parameters from server.
    pub fn set_revised_parameters(
        &mut self,
        publishing_interval: Duration,
        lifetime_count: u32,
        keepalive_count: u32,
    ) {
        self.revised_publishing_interval = publishing_interval;
        self.revised_lifetime_count = lifetime_count;
        self.revised_keepalive_count = keepalive_count;
    }

    /// Generates the next client handle.
    pub fn next_client_handle(&self) -> u32 {
        self.next_client_handle.fetch_add(1, Ordering::SeqCst)
    }

    /// Generates the next sequence number.
    pub fn next_sequence_number(&self) -> u32 {
        self.sequence_number.fetch_add(1, Ordering::SeqCst)
    }

    /// Adds a monitored item.
    pub async fn add_monitored_item(&self, item: MonitoredItem) -> OpcUaResult<()> {
        let mut items = self.monitored_items.write().await;
        let mut node_map = self.node_to_item.write().await;

        // Check if node is already monitored
        if node_map.contains_key(&item.node_id) {
            return Err(OpcUaError::subscription(SubscriptionError::monitored_item_failed(
                item.node_id.to_string(),
                "Node is already monitored in this subscription",
            )));
        }

        node_map.insert(item.node_id.clone(), item.id);
        items.insert(item.id, item);

        Ok(())
    }

    /// Removes a monitored item by ID.
    pub async fn remove_monitored_item(&self, id: MonitoredItemId) -> Option<MonitoredItem> {
        let mut items = self.monitored_items.write().await;
        let mut node_map = self.node_to_item.write().await;

        if let Some(item) = items.remove(&id) {
            node_map.remove(&item.node_id);
            Some(item)
        } else {
            None
        }
    }

    /// Gets a monitored item by ID.
    pub async fn get_monitored_item(&self, id: MonitoredItemId) -> Option<MonitoredItem> {
        let items = self.monitored_items.read().await;
        items.get(&id).cloned()
    }

    /// Gets a monitored item by node ID.
    pub async fn get_monitored_item_by_node(&self, node_id: &NodeId) -> Option<MonitoredItem> {
        let node_map = self.node_to_item.read().await;
        if let Some(item_id) = node_map.get(node_id) {
            let items = self.monitored_items.read().await;
            items.get(item_id).cloned()
        } else {
            None
        }
    }

    /// Returns all monitored items.
    pub async fn monitored_items(&self) -> Vec<MonitoredItem> {
        let items = self.monitored_items.read().await;
        items.values().cloned().collect()
    }

    /// Returns the count of monitored items.
    pub async fn monitored_item_count(&self) -> usize {
        let items = self.monitored_items.read().await;
        items.len()
    }

    /// Returns all monitored node IDs.
    pub async fn monitored_node_ids(&self) -> Vec<NodeId> {
        let node_map = self.node_to_item.read().await;
        node_map.keys().cloned().collect()
    }

    /// Records a publish event.
    pub async fn record_publish(&self) {
        *self.last_publish.write().await = Some(Utc::now());
    }

    /// Records a notification.
    pub fn record_notification(&self) {
        self.notification_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total notification count.
    pub fn notification_count(&self) -> u64 {
        self.notification_count.load(Ordering::Relaxed)
    }

    /// Returns the last publish time.
    pub async fn last_publish_time(&self) -> Option<DateTime<Utc>> {
        *self.last_publish.read().await
    }

    /// Sets an error message.
    pub async fn set_error(&self, error: impl Into<String>) {
        *self.last_error.write().await = Some(error.into());
        self.set_state(SubscriptionState::Error).await;
    }

    /// Returns the last error.
    pub async fn last_error(&self) -> Option<String> {
        self.last_error.read().await.clone()
    }

    /// Returns subscription statistics.
    pub async fn stats(&self) -> SubscriptionStats {
        SubscriptionStats {
            id: self.id,
            state: self.state().await,
            monitored_item_count: self.monitored_item_count().await,
            notification_count: self.notification_count(),
            created_at: self.created_at,
            last_publish: self.last_publish_time().await,
            publishing_interval: self.revised_publishing_interval,
        }
    }
}

/// Subscription statistics.
#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionStats {
    /// Subscription ID.
    pub id: SubscriptionId,
    /// Current state.
    pub state: SubscriptionState,
    /// Number of monitored items.
    pub monitored_item_count: usize,
    /// Total notifications received.
    pub notification_count: u64,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last publish time.
    pub last_publish: Option<DateTime<Utc>>,
    /// Publishing interval.
    pub publishing_interval: Duration,
}

// =============================================================================
// Subscription Builder
// =============================================================================

/// Builder for creating subscriptions with a fluent API.
///
/// # Example
///
/// ```rust,ignore
/// let config = SubscriptionBuilder::new()
///     .name("Temperature Monitoring")
///     .publishing_interval(Duration::from_millis(500))
///     .lifetime_count(60)
///     .keepalive_count(10)
///     .priority(100)
///     .add_node(NodeId::numeric(2, 1001))
///     .add_nodes(vec![
///         NodeId::string(2, "Temp1"),
///         NodeId::string(2, "Temp2"),
///     ])
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct SubscriptionBuilder {
    /// Subscription name.
    name: Option<String>,

    /// Publishing interval.
    publishing_interval: Duration,

    /// Lifetime count.
    lifetime_count: u32,

    /// Keep-alive count.
    keepalive_count: u32,

    /// Maximum notifications per publish.
    max_notifications: u32,

    /// Priority.
    priority: u8,

    /// Publishing enabled.
    publishing_enabled: bool,

    /// Nodes to monitor.
    nodes: Vec<NodeId>,

    /// Default monitored item settings.
    default_item_settings: MonitoredItemSettings,

    /// Per-node settings overrides.
    node_settings: HashMap<NodeId, MonitoredItemSettings>,
}

impl Default for SubscriptionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscriptionBuilder {
    /// Creates a new subscription builder with default settings.
    pub fn new() -> Self {
        Self {
            name: None,
            publishing_interval: Duration::from_millis(1000),
            lifetime_count: 60,
            keepalive_count: 10,
            max_notifications: 65535,
            priority: 0,
            publishing_enabled: true,
            nodes: Vec::new(),
            default_item_settings: MonitoredItemSettings::default(),
            node_settings: HashMap::new(),
        }
    }

    /// Creates a builder from existing settings.
    pub fn from_settings(settings: &SubscriptionSettings) -> Self {
        Self {
            name: None,
            publishing_interval: settings.publishing_interval,
            lifetime_count: settings.lifetime_count,
            keepalive_count: settings.keepalive_count,
            max_notifications: settings.max_notifications_per_publish,
            priority: settings.priority,
            publishing_enabled: settings.publishing_enabled,
            nodes: Vec::new(),
            default_item_settings: MonitoredItemSettings::default(),
            node_settings: HashMap::new(),
        }
    }

    /// Sets the subscription name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the publishing interval.
    pub fn publishing_interval(mut self, interval: Duration) -> Self {
        self.publishing_interval = interval;
        self
    }

    /// Sets the lifetime count.
    pub fn lifetime_count(mut self, count: u32) -> Self {
        self.lifetime_count = count;
        self
    }

    /// Sets the keep-alive count.
    pub fn keepalive_count(mut self, count: u32) -> Self {
        self.keepalive_count = count;
        self
    }

    /// Sets the maximum notifications per publish.
    pub fn max_notifications(mut self, max: u32) -> Self {
        self.max_notifications = max;
        self
    }

    /// Sets the priority (0-255).
    pub fn priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Sets publishing enabled/disabled.
    pub fn publishing_enabled(mut self, enabled: bool) -> Self {
        self.publishing_enabled = enabled;
        self
    }

    /// Adds a node to monitor.
    pub fn add_node(mut self, node_id: NodeId) -> Self {
        if !self.nodes.contains(&node_id) {
            self.nodes.push(node_id);
        }
        self
    }

    /// Adds multiple nodes to monitor.
    pub fn add_nodes(mut self, node_ids: impl IntoIterator<Item = NodeId>) -> Self {
        for node_id in node_ids {
            if !self.nodes.contains(&node_id) {
                self.nodes.push(node_id);
            }
        }
        self
    }

    /// Sets the default monitored item settings.
    pub fn default_item_settings(mut self, settings: MonitoredItemSettings) -> Self {
        self.default_item_settings = settings;
        self
    }

    /// Sets custom settings for a specific node.
    pub fn node_settings(mut self, node_id: NodeId, settings: MonitoredItemSettings) -> Self {
        self.node_settings.insert(node_id, settings);
        self
    }

    /// Sets the default sampling interval.
    pub fn sampling_interval(mut self, interval: Duration) -> Self {
        self.default_item_settings.sampling_interval = interval;
        self
    }

    /// Sets the default queue size.
    pub fn queue_size(mut self, size: u32) -> Self {
        self.default_item_settings.queue_size = size;
        self
    }

    /// Sets the default deadband.
    pub fn deadband(mut self, deadband: DeadbandSettings) -> Self {
        self.default_item_settings.deadband = Some(deadband);
        self
    }

    /// Returns the nodes to be monitored.
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }

    /// Returns the settings for a specific node.
    pub fn settings_for_node(&self, node_id: &NodeId) -> &MonitoredItemSettings {
        self.node_settings
            .get(node_id)
            .unwrap_or(&self.default_item_settings)
    }

    /// Builds the subscription settings.
    pub fn build_settings(&self) -> SubscriptionSettings {
        SubscriptionSettings {
            publishing_interval: self.publishing_interval,
            lifetime_count: self.lifetime_count,
            keepalive_count: self.keepalive_count,
            max_notifications_per_publish: self.max_notifications,
            priority: self.priority,
            publishing_enabled: self.publishing_enabled,
        }
    }

    /// Validates the builder configuration.
    pub fn validate(&self) -> OpcUaResult<()> {
        if self.publishing_interval.is_zero() {
            return Err(OpcUaError::subscription(SubscriptionError::creation_failed(
                "Publishing interval must be greater than 0",
            )));
        }

        if self.lifetime_count < 3 {
            return Err(OpcUaError::subscription(SubscriptionError::creation_failed(
                "Lifetime count must be at least 3",
            )));
        }

        if self.keepalive_count == 0 {
            return Err(OpcUaError::subscription(SubscriptionError::creation_failed(
                "Keep-alive count must be greater than 0",
            )));
        }

        if self.keepalive_count > self.lifetime_count / 3 {
            return Err(OpcUaError::subscription(SubscriptionError::creation_failed(
                "Keep-alive count should not exceed lifetime_count / 3",
            )));
        }

        Ok(())
    }
}

// =============================================================================
// Subscription Callback
// =============================================================================

/// Callback for subscription events.
///
/// Implement this trait to handle subscription notifications and lifecycle events.
#[async_trait]
pub trait SubscriptionCallback: Send + Sync {
    /// Called when a data change notification is received.
    async fn on_data_change(&self, notification: DataChangeNotification);

    /// Called when the subscription state changes.
    async fn on_state_change(&self, _subscription_id: SubscriptionId, _new_state: SubscriptionState) {
        // Default: no-op
    }

    /// Called when a keep-alive is received (no data changes).
    async fn on_keep_alive(&self, _subscription_id: SubscriptionId) {
        // Default: no-op
    }

    /// Called when an error occurs.
    async fn on_error(&self, _subscription_id: SubscriptionId, _error: OpcUaError) {
        // Default: no-op
    }
}

/// A channel-based callback implementation.
pub struct ChannelCallback {
    /// Sender for data change notifications.
    sender: mpsc::Sender<DataChangeNotification>,
}

impl ChannelCallback {
    /// Creates a new channel callback.
    pub fn new(sender: mpsc::Sender<DataChangeNotification>) -> Self {
        Self { sender }
    }

    /// Creates a new channel callback with a receiver.
    pub fn with_channel(capacity: usize) -> (Self, mpsc::Receiver<DataChangeNotification>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self::new(tx), rx)
    }
}

#[async_trait]
impl SubscriptionCallback for ChannelCallback {
    async fn on_data_change(&self, notification: DataChangeNotification) {
        // Best effort send, ignore errors
        let _ = self.sender.send(notification).await;
    }
}

/// A broadcast-based callback implementation for multiple receivers.
pub struct BroadcastCallback {
    /// Sender for data change notifications.
    sender: broadcast::Sender<DataChangeNotification>,
}

impl BroadcastCallback {
    /// Creates a new broadcast callback.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Subscribes to receive notifications.
    pub fn subscribe(&self) -> broadcast::Receiver<DataChangeNotification> {
        self.sender.subscribe()
    }
}

#[async_trait]
impl SubscriptionCallback for BroadcastCallback {
    async fn on_data_change(&self, notification: DataChangeNotification) {
        // Best effort send, ignore errors (no receivers is ok)
        let _ = self.sender.send(notification);
    }
}

// =============================================================================
// Subscription Manager
// =============================================================================

/// Manages OPC UA subscriptions and their lifecycle.
///
/// The SubscriptionManager provides:
/// - Creation and deletion of subscriptions
/// - Monitoring of multiple nodes per subscription
/// - Callback dispatch for data change notifications
/// - State tracking and statistics
///
/// # Thread Safety
///
/// The manager is fully thread-safe and can be shared across tasks.
///
/// # Example
///
/// ```rust,ignore
/// let manager = SubscriptionManager::new(transport);
///
/// // Create a subscription
/// let builder = SubscriptionBuilder::new()
///     .publishing_interval(Duration::from_millis(500))
///     .add_node(NodeId::numeric(2, 1001));
///
/// let (callback, receiver) = ChannelCallback::with_channel(100);
/// let handle = manager.create_subscription(builder, callback).await?;
///
/// // Receive notifications
/// while let Some(notification) = receiver.recv().await {
///     println!("Value changed: {:?}", notification);
/// }
/// ```
pub struct SubscriptionManager<T: OpcUaTransport> {
    /// Transport layer.
    transport: Arc<Mutex<T>>,

    /// Active subscriptions.
    subscriptions: RwLock<HashMap<SubscriptionId, Arc<Subscription>>>,

    /// Subscription callbacks.
    callbacks: RwLock<HashMap<SubscriptionId, Arc<dyn SubscriptionCallback>>>,

    /// Next subscription ID (local tracking).
    next_local_id: AtomicU32,

    /// Manager is running.
    running: AtomicBool,

    /// Default subscription settings.
    default_settings: SubscriptionSettings,

    /// Maximum subscriptions allowed.
    max_subscriptions: usize,

    /// Maximum monitored items per subscription.
    max_monitored_items_per_subscription: usize,

    /// Statistics.
    stats: SubscriptionManagerStats,
}

impl<T: OpcUaTransport + 'static> SubscriptionManager<T> {
    /// Creates a new subscription manager.
    pub fn new(transport: Arc<Mutex<T>>) -> Self {
        Self {
            transport,
            subscriptions: RwLock::new(HashMap::new()),
            callbacks: RwLock::new(HashMap::new()),
            next_local_id: AtomicU32::new(1),
            running: AtomicBool::new(true),
            default_settings: SubscriptionSettings::default(),
            max_subscriptions: 100,
            max_monitored_items_per_subscription: 10000,
            stats: SubscriptionManagerStats::new(),
        }
    }

    /// Creates a new subscription manager with custom settings.
    pub fn with_settings(transport: Arc<Mutex<T>>, settings: SubscriptionSettings) -> Self {
        Self {
            transport,
            subscriptions: RwLock::new(HashMap::new()),
            callbacks: RwLock::new(HashMap::new()),
            next_local_id: AtomicU32::new(1),
            running: AtomicBool::new(true),
            default_settings: settings,
            max_subscriptions: 100,
            max_monitored_items_per_subscription: 10000,
            stats: SubscriptionManagerStats::new(),
        }
    }

    /// Sets the maximum number of subscriptions.
    pub fn set_max_subscriptions(&mut self, max: usize) {
        self.max_subscriptions = max;
    }

    /// Sets the maximum monitored items per subscription.
    pub fn set_max_monitored_items(&mut self, max: usize) {
        self.max_monitored_items_per_subscription = max;
    }

    /// Creates a subscription from a builder.
    pub async fn create_subscription(
        &self,
        builder: SubscriptionBuilder,
        callback: impl SubscriptionCallback + 'static,
    ) -> OpcUaResult<SubscriptionHandle> {
        // Validate builder
        builder.validate()?;

        // Check subscription limit
        let current_count = self.subscriptions.read().await.len();
        if current_count >= self.max_subscriptions {
            return Err(OpcUaError::subscription(SubscriptionError::creation_failed(
                format!(
                    "Maximum subscriptions reached ({}/{})",
                    current_count, self.max_subscriptions
                ),
            )));
        }

        // Check monitored items limit
        if builder.nodes.len() > self.max_monitored_items_per_subscription {
            return Err(OpcUaError::subscription(
                SubscriptionError::too_many_monitored_items(
                    builder.nodes.len() as u32,
                    self.max_monitored_items_per_subscription as u32,
                ),
            ));
        }

        let settings = builder.build_settings();
        let publishing_interval = settings.publishing_interval;
        let start = Instant::now();

        // Create subscription on server
        let subscription_id = {
            let transport = self.transport.lock().await;
            transport
                .create_subscription(publishing_interval)
                .await?
        };

        let sub_id = SubscriptionId::new(subscription_id);
        let mut subscription = Subscription::new(sub_id, settings);
        if let Some(ref name) = builder.name {
            subscription = subscription.with_name(name.clone());
        }

        // Create monitored items
        let nodes_len = builder.nodes.len();
        if !builder.nodes.is_empty() {
            let monitored_item_ids = {
                let transport = self.transport.lock().await;
                transport
                    .create_monitored_items(
                        subscription_id,
                        &builder.nodes,
                        builder.default_item_settings.sampling_interval,
                    )
                    .await?
            };

            // Add monitored items to subscription
            for (i, node_id) in builder.nodes.iter().enumerate() {
                let item_id = monitored_item_ids
                    .get(i)
                    .copied()
                    .unwrap_or(i as u32);

                let item = MonitoredItem::new(
                    MonitoredItemId::new(item_id),
                    subscription.next_client_handle(),
                    node_id.clone(),
                    builder.settings_for_node(node_id),
                );
                subscription.add_monitored_item(item).await?;
            }
        }

        // Set subscription to active
        subscription.set_state(SubscriptionState::Active).await;

        let subscription = Arc::new(subscription);

        // Store subscription and callback
        {
            let mut subs = self.subscriptions.write().await;
            subs.insert(sub_id, Arc::clone(&subscription));
        }
        {
            let mut callbacks = self.callbacks.write().await;
            callbacks.insert(sub_id, Arc::new(callback));
        }

        // Update stats
        self.stats.record_subscription_created(start.elapsed());

        tracing::info!(
            subscription_id = sub_id.0,
            monitored_items = nodes_len,
            publishing_interval_ms = publishing_interval.as_millis(),
            "Subscription created"
        );

        Ok(SubscriptionHandle {
            id: sub_id,
            subscription,
        })
    }

    /// Deletes a subscription.
    pub async fn delete_subscription(&self, id: SubscriptionId) -> OpcUaResult<()> {
        // Remove from local storage
        let subscription = {
            let mut subs = self.subscriptions.write().await;
            subs.remove(&id)
        };

        // Remove callback
        {
            let mut callbacks = self.callbacks.write().await;
            callbacks.remove(&id);
        }

        if let Some(sub) = subscription {
            // Mark as deleted
            sub.set_state(SubscriptionState::Deleted).await;

            // Delete on server
            let transport = self.transport.lock().await;
            transport.delete_subscription(id.0).await?;

            self.stats.record_subscription_deleted();

            tracing::info!(subscription_id = id.0, "Subscription deleted");
        }

        Ok(())
    }

    /// Adds monitored items to an existing subscription.
    pub async fn add_monitored_items(
        &self,
        subscription_id: SubscriptionId,
        nodes: &[NodeId],
        settings: Option<MonitoredItemSettings>,
    ) -> OpcUaResult<Vec<MonitoredItemId>> {
        let subscription = self.get_subscription(subscription_id).await?;
        let settings = settings.unwrap_or_default();

        // Check limit
        let current_count = subscription.monitored_item_count().await;
        if current_count + nodes.len() > self.max_monitored_items_per_subscription {
            return Err(OpcUaError::subscription(
                SubscriptionError::too_many_monitored_items(
                    (current_count + nodes.len()) as u32,
                    self.max_monitored_items_per_subscription as u32,
                ),
            ));
        }

        // Create on server
        let item_ids = {
            let transport = self.transport.lock().await;
            transport
                .create_monitored_items(
                    subscription_id.0,
                    nodes,
                    settings.sampling_interval,
                )
                .await?
        };

        // Add to subscription
        let mut result = Vec::with_capacity(nodes.len());
        for (i, node_id) in nodes.iter().enumerate() {
            let item_id = item_ids.get(i).copied().unwrap_or(i as u32);
            let monitored_item_id = MonitoredItemId::new(item_id);

            let item = MonitoredItem::new(
                monitored_item_id,
                subscription.next_client_handle(),
                node_id.clone(),
                &settings,
            );
            subscription.add_monitored_item(item).await?;
            result.push(monitored_item_id);
        }

        Ok(result)
    }

    /// Removes monitored items from a subscription.
    pub async fn remove_monitored_items(
        &self,
        subscription_id: SubscriptionId,
        item_ids: &[MonitoredItemId],
    ) -> OpcUaResult<()> {
        let subscription = self.get_subscription(subscription_id).await?;

        // Delete on server
        let raw_ids: Vec<u32> = item_ids.iter().map(|id| id.0).collect();
        {
            let transport = self.transport.lock().await;
            transport
                .delete_monitored_items(subscription_id.0, &raw_ids)
                .await?;
        }

        // Remove from subscription
        for item_id in item_ids {
            subscription.remove_monitored_item(*item_id).await;
        }

        Ok(())
    }

    /// Gets a subscription by ID.
    pub async fn get_subscription(&self, id: SubscriptionId) -> OpcUaResult<Arc<Subscription>> {
        let subs = self.subscriptions.read().await;
        subs.get(&id)
            .cloned()
            .ok_or_else(|| OpcUaError::subscription(SubscriptionError::not_found(id.0)))
    }

    /// Returns all active subscriptions.
    pub async fn subscriptions(&self) -> Vec<Arc<Subscription>> {
        let subs = self.subscriptions.read().await;
        subs.values().cloned().collect()
    }

    /// Returns the number of active subscriptions.
    pub async fn subscription_count(&self) -> usize {
        let subs = self.subscriptions.read().await;
        subs.len()
    }

    /// Pauses a subscription.
    pub async fn pause_subscription(&self, id: SubscriptionId) -> OpcUaResult<()> {
        let subscription = self.get_subscription(id).await?;
        subscription.set_state(SubscriptionState::Paused).await;

        // Notify callback
        if let Some(callback) = self.callbacks.read().await.get(&id) {
            callback.on_state_change(id, SubscriptionState::Paused).await;
        }

        Ok(())
    }

    /// Resumes a paused subscription.
    pub async fn resume_subscription(&self, id: SubscriptionId) -> OpcUaResult<()> {
        let subscription = self.get_subscription(id).await?;
        subscription.set_state(SubscriptionState::Active).await;

        // Notify callback
        if let Some(callback) = self.callbacks.read().await.get(&id) {
            callback.on_state_change(id, SubscriptionState::Active).await;
        }

        Ok(())
    }

    /// Processes a data change notification (called by transport/session layer).
    pub async fn process_notification(&self, notification: DataChangeNotification) {
        let subscription_id = notification.subscription_id;

        // Update subscription stats
        if let Ok(subscription) = self.get_subscription(subscription_id).await {
            subscription.record_notification();
            subscription.record_publish().await;

            // Update monitored item
            if let Some(mut item) = subscription
                .get_monitored_item(notification.monitored_item_id)
                .await
            {
                item.record_notification();
            }
        }

        // Dispatch to callback
        if let Some(callback) = self.callbacks.read().await.get(&subscription_id) {
            callback.on_data_change(notification).await;
        }

        self.stats.record_notification();
    }

    /// Processes a keep-alive notification.
    pub async fn process_keep_alive(&self, subscription_id: SubscriptionId) {
        if let Ok(subscription) = self.get_subscription(subscription_id).await {
            subscription.record_publish().await;
        }

        if let Some(callback) = self.callbacks.read().await.get(&subscription_id) {
            callback.on_keep_alive(subscription_id).await;
        }
    }

    /// Processes a subscription error.
    pub async fn process_error(&self, subscription_id: SubscriptionId, error: OpcUaError) {
        if let Ok(subscription) = self.get_subscription(subscription_id).await {
            subscription.set_error(error.to_string()).await;
        }

        if let Some(callback) = self.callbacks.read().await.get(&subscription_id) {
            callback.on_error(subscription_id, error).await;
        }

        self.stats.record_error();
    }

    /// Cleans up deleted or error subscriptions.
    pub async fn cleanup(&self) -> usize {
        let mut to_remove = Vec::new();

        {
            let subs = self.subscriptions.read().await;
            for (id, sub) in subs.iter() {
                if sub.state().await.is_terminal() {
                    to_remove.push(*id);
                }
            }
        }

        for id in &to_remove {
            let _ = self.delete_subscription(*id).await;
        }

        to_remove.len()
    }

    /// Stops the subscription manager.
    pub async fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);

        // Delete all subscriptions
        let ids: Vec<SubscriptionId> = {
            let subs = self.subscriptions.read().await;
            subs.keys().copied().collect()
        };

        for id in ids {
            let _ = self.delete_subscription(id).await;
        }

        tracing::info!("Subscription manager stopped");
    }

    /// Returns `true` if the manager is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Returns manager statistics.
    pub fn stats(&self) -> &SubscriptionManagerStats {
        &self.stats
    }
}

impl<T: OpcUaTransport> fmt::Debug for SubscriptionManager<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionManager")
            .field("running", &self.running.load(Ordering::SeqCst))
            .field("max_subscriptions", &self.max_subscriptions)
            .finish()
    }
}

// =============================================================================
// Subscription Handle
// =============================================================================

/// Handle to an active subscription.
///
/// This handle provides access to the subscription and its statistics.
pub struct SubscriptionHandle {
    /// Subscription ID.
    pub id: SubscriptionId,

    /// Reference to the subscription.
    subscription: Arc<Subscription>,
}

impl SubscriptionHandle {
    /// Returns subscription statistics.
    pub async fn stats(&self) -> SubscriptionStats {
        self.subscription.stats().await
    }

    /// Returns the subscription state.
    pub async fn state(&self) -> SubscriptionState {
        self.subscription.state().await
    }

    /// Returns monitored node IDs.
    pub async fn monitored_nodes(&self) -> Vec<NodeId> {
        self.subscription.monitored_node_ids().await
    }

    /// Returns the monitored item count.
    pub async fn monitored_item_count(&self) -> usize {
        self.subscription.monitored_item_count().await
    }
}

impl fmt::Debug for SubscriptionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionHandle")
            .field("id", &self.id)
            .finish()
    }
}

// =============================================================================
// Statistics
// =============================================================================

/// Statistics for the subscription manager.
#[derive(Debug)]
pub struct SubscriptionManagerStats {
    /// Total subscriptions created.
    subscriptions_created: AtomicU64,

    /// Total subscriptions deleted.
    subscriptions_deleted: AtomicU64,

    /// Total notifications processed.
    notifications_processed: AtomicU64,

    /// Total errors.
    errors: AtomicU64,

    /// Total time spent creating subscriptions (microseconds).
    total_creation_time_us: AtomicU64,
}

impl SubscriptionManagerStats {
    /// Creates new statistics.
    pub fn new() -> Self {
        Self {
            subscriptions_created: AtomicU64::new(0),
            subscriptions_deleted: AtomicU64::new(0),
            notifications_processed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            total_creation_time_us: AtomicU64::new(0),
        }
    }

    /// Records a subscription creation.
    pub fn record_subscription_created(&self, duration: Duration) {
        self.subscriptions_created.fetch_add(1, Ordering::Relaxed);
        self.total_creation_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Records a subscription deletion.
    pub fn record_subscription_deleted(&self) {
        self.subscriptions_deleted.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a notification.
    pub fn record_notification(&self) {
        self.notifications_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an error.
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns total subscriptions created.
    pub fn subscriptions_created(&self) -> u64 {
        self.subscriptions_created.load(Ordering::Relaxed)
    }

    /// Returns total notifications processed.
    pub fn notifications_processed(&self) -> u64 {
        self.notifications_processed.load(Ordering::Relaxed)
    }

    /// Returns total errors.
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Returns average subscription creation time.
    pub fn average_creation_time(&self) -> Duration {
        let count = self.subscriptions_created();
        if count == 0 {
            return Duration::ZERO;
        }
        let total_us = self.total_creation_time_us.load(Ordering::Relaxed);
        Duration::from_micros(total_us / count)
    }

    /// Resets all statistics.
    pub fn reset(&self) {
        self.subscriptions_created.store(0, Ordering::Relaxed);
        self.subscriptions_deleted.store(0, Ordering::Relaxed);
        self.notifications_processed.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.total_creation_time_us.store(0, Ordering::Relaxed);
    }
}

impl Default for SubscriptionManagerStats {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_state() {
        assert!(SubscriptionState::Active.is_active());
        assert!(!SubscriptionState::Paused.is_active());
        assert!(SubscriptionState::Active.can_publish());
        assert!(!SubscriptionState::Paused.can_publish());
        assert!(SubscriptionState::Deleted.is_terminal());
        assert!(SubscriptionState::Error.is_terminal());
    }

    #[test]
    fn test_subscription_id() {
        let id = SubscriptionId::new(42);
        assert_eq!(id.value(), 42);
        assert_eq!(format!("{}", id), "sub-42");

        let id2: SubscriptionId = 100u32.into();
        assert_eq!(id2.value(), 100);
    }

    #[test]
    fn test_monitored_item_id() {
        let id = MonitoredItemId::new(123);
        assert_eq!(id.value(), 123);
        assert_eq!(format!("{}", id), "mi-123");
    }

    #[test]
    fn test_subscription_builder() {
        let builder = SubscriptionBuilder::new()
            .name("Test Subscription")
            .publishing_interval(Duration::from_millis(500))
            .lifetime_count(60)
            .keepalive_count(10)
            .add_node(NodeId::numeric(2, 1001))
            .add_node(NodeId::string(2, "Temperature"));

        assert_eq!(builder.nodes().len(), 2);
        assert_eq!(builder.publishing_interval, Duration::from_millis(500));

        let settings = builder.build_settings();
        assert_eq!(settings.publishing_interval, Duration::from_millis(500));
        assert_eq!(settings.lifetime_count, 60);
    }

    #[test]
    fn test_subscription_builder_validation() {
        // Zero publishing interval
        let builder = SubscriptionBuilder::new().publishing_interval(Duration::ZERO);
        assert!(builder.validate().is_err());

        // Lifetime count too small
        let builder = SubscriptionBuilder::new()
            .publishing_interval(Duration::from_millis(100))
            .lifetime_count(2);
        assert!(builder.validate().is_err());

        // Keepalive too large
        let builder = SubscriptionBuilder::new()
            .publishing_interval(Duration::from_millis(100))
            .lifetime_count(30)
            .keepalive_count(20);
        assert!(builder.validate().is_err());

        // Valid configuration
        let builder = SubscriptionBuilder::new()
            .publishing_interval(Duration::from_millis(100))
            .lifetime_count(60)
            .keepalive_count(10);
        assert!(builder.validate().is_ok());
    }

    #[tokio::test]
    async fn test_subscription() {
        let settings = SubscriptionSettings::default();
        let sub = Subscription::new(SubscriptionId::new(1), settings);

        assert_eq!(sub.state().await, SubscriptionState::Creating);

        sub.set_state(SubscriptionState::Active).await;
        assert_eq!(sub.state().await, SubscriptionState::Active);

        // Test client handle generation
        let h1 = sub.next_client_handle();
        let h2 = sub.next_client_handle();
        assert_eq!(h1, 1);
        assert_eq!(h2, 2);

        // Test sequence number generation
        let s1 = sub.next_sequence_number();
        let s2 = sub.next_sequence_number();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
    }

    #[tokio::test]
    async fn test_monitored_item() {
        let settings = MonitoredItemSettings::default();
        let mut item = MonitoredItem::new(
            MonitoredItemId::new(1),
            100,
            NodeId::numeric(2, 1001),
            &settings,
        );

        assert_eq!(item.id.value(), 1);
        assert_eq!(item.client_handle, 100);
        assert_eq!(item.notification_count, 0);
        assert!(item.last_notification.is_none());

        item.record_notification();
        assert_eq!(item.notification_count, 1);
        assert!(item.last_notification.is_some());
    }

    #[test]
    fn test_data_change_notification() {
        let notification = DataChangeNotification::new(
            SubscriptionId::new(1),
            MonitoredItemId::new(10),
            100,
            NodeId::numeric(2, 1001),
            TypedValue::new(super::super::transport::OpcUaValue::Double(25.5)),
        )
        .with_sequence(42);

        assert_eq!(notification.subscription_id.value(), 1);
        assert_eq!(notification.monitored_item_id.value(), 10);
        assert_eq!(notification.client_handle, 100);
        assert_eq!(notification.sequence_number, 42);
    }

    #[tokio::test]
    async fn test_channel_callback() {
        let (callback, mut rx) = ChannelCallback::with_channel(10);

        let notification = DataChangeNotification::new(
            SubscriptionId::new(1),
            MonitoredItemId::new(1),
            1,
            NodeId::numeric(2, 1001),
            TypedValue::new(super::super::transport::OpcUaValue::Double(42.0)),
        );

        callback.on_data_change(notification).await;

        let received = rx.recv().await;
        assert!(received.is_some());
        assert_eq!(received.unwrap().subscription_id.value(), 1);
    }

    #[test]
    fn test_subscription_manager_stats() {
        let stats = SubscriptionManagerStats::new();

        stats.record_subscription_created(Duration::from_millis(100));
        stats.record_subscription_created(Duration::from_millis(200));
        stats.record_notification();
        stats.record_error();

        assert_eq!(stats.subscriptions_created(), 2);
        assert_eq!(stats.notifications_processed(), 1);
        assert_eq!(stats.errors(), 1);

        // Average: (100 + 200) / 2 = 150ms
        assert_eq!(stats.average_creation_time(), Duration::from_millis(150));

        stats.reset();
        assert_eq!(stats.subscriptions_created(), 0);
    }
}
