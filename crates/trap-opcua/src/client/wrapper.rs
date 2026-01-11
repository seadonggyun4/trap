// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! High-level OPC UA client wrapper.
//!
//! This module provides a high-level client API that wraps the transport layer
//! with retry logic, session management, and subscription support.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::error::{ConnectionError, OpcUaError, OpcUaResult, OperationError};
use crate::types::{NodeId, OpcUaConfig, TagMapping, SubscriptionSettings};

use super::conversion::{DataConverter, Quality, TypedValue};
use super::session::{SessionManager, SessionState};
use super::transport::{OpcUaTransport, OpcUaValue, ReadResult, TransportState, WriteResult};

// =============================================================================
// RetryStrategy
// =============================================================================

/// Strategy for retry delays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RetryStrategy {
    /// Fixed delay between retries.
    Fixed,

    /// Linear backoff (delay * attempt).
    Linear,

    /// Exponential backoff (delay * 2^attempt).
    #[default]
    Exponential,
}

impl RetryStrategy {
    /// Calculates the delay for a given attempt.
    pub fn delay(&self, base_delay: Duration, attempt: u32) -> Duration {
        match self {
            Self::Fixed => base_delay,
            Self::Linear => base_delay * (attempt + 1),
            Self::Exponential => base_delay * 2u32.saturating_pow(attempt),
        }
    }
}

impl fmt::Display for RetryStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed => write!(f, "Fixed"),
            Self::Linear => write!(f, "Linear"),
            Self::Exponential => write!(f, "Exponential"),
        }
    }
}

// =============================================================================
// RetryConfig
// =============================================================================

/// Configuration for retry behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries.
    pub max_retries: u32,

    /// Base delay between retries.
    #[serde(with = "duration_millis")]
    pub base_delay: Duration,

    /// Maximum delay between retries.
    #[serde(with = "duration_millis")]
    pub max_delay: Duration,

    /// Retry strategy.
    pub strategy: RetryStrategy,

    /// Whether to retry on connection errors.
    pub retry_connection: bool,

    /// Whether to retry on operation errors.
    pub retry_operations: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            strategy: RetryStrategy::Exponential,
            retry_connection: true,
            retry_operations: true,
        }
    }
}

impl RetryConfig {
    /// Creates a new retry configuration.
    pub fn new(max_retries: u32) -> Self {
        Self {
            max_retries,
            ..Default::default()
        }
    }

    /// Sets the base delay.
    pub fn with_base_delay(mut self, delay: Duration) -> Self {
        self.base_delay = delay;
        self
    }

    /// Sets the maximum delay.
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Sets the retry strategy.
    pub fn with_strategy(mut self, strategy: RetryStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Disables retries.
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Calculates the delay for a given attempt.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay = self.strategy.delay(self.base_delay, attempt);
        delay.min(self.max_delay)
    }
}

// =============================================================================
// ClientStats
// =============================================================================

/// Statistics for OPC UA client operations.
#[derive(Debug)]
pub struct ClientStats {
    /// Total number of read operations.
    reads: AtomicU64,

    /// Total number of write operations.
    writes: AtomicU64,

    /// Total number of browse operations.
    browses: AtomicU64,

    /// Total number of subscription updates.
    subscription_updates: AtomicU64,

    /// Total number of errors.
    errors: AtomicU64,

    /// Total number of retries.
    retries: AtomicU64,

    /// Total response time in microseconds.
    total_response_time_us: AtomicU64,

    /// Number of connections established.
    connections: AtomicU64,
}

impl ClientStats {
    /// Creates new statistics.
    pub fn new() -> Self {
        Self {
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            browses: AtomicU64::new(0),
            subscription_updates: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            total_response_time_us: AtomicU64::new(0),
            connections: AtomicU64::new(0),
        }
    }

    /// Records a successful read operation.
    pub fn record_read(&self, duration: Duration) {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Records a successful write operation.
    pub fn record_write(&self, duration: Duration) {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Records a browse operation.
    pub fn record_browse(&self) {
        self.browses.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a subscription update.
    pub fn record_subscription_update(&self) {
        self.subscription_updates.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an error.
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a retry attempt.
    pub fn record_retry(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a connection.
    pub fn record_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total number of reads.
    pub fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    /// Returns the total number of writes.
    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    /// Returns the total number of errors.
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Returns the total number of retries.
    pub fn retries(&self) -> u64 {
        self.retries.load(Ordering::Relaxed)
    }

    /// Returns the success rate.
    pub fn success_rate(&self) -> f64 {
        let total = self.reads() + self.writes();
        if total == 0 {
            return 1.0;
        }
        let errors = self.errors();
        (total - errors.min(total)) as f64 / total as f64
    }

    /// Returns the average response time.
    pub fn average_response_time(&self) -> Duration {
        let total_ops = self.reads() + self.writes();
        if total_ops == 0 {
            return Duration::ZERO;
        }
        let total_us = self.total_response_time_us.load(Ordering::Relaxed);
        Duration::from_micros(total_us / total_ops)
    }

    /// Resets all statistics.
    pub fn reset(&self) {
        self.reads.store(0, Ordering::Relaxed);
        self.writes.store(0, Ordering::Relaxed);
        self.browses.store(0, Ordering::Relaxed);
        self.subscription_updates.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.retries.store(0, Ordering::Relaxed);
        self.total_response_time_us.store(0, Ordering::Relaxed);
        self.connections.store(0, Ordering::Relaxed);
    }
}

impl Default for ClientStats {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// SubscriptionHandle
// =============================================================================

/// Handle to an active subscription.
pub struct SubscriptionHandle {
    /// Subscription ID.
    pub id: u32,

    /// Monitored node IDs.
    pub nodes: Vec<NodeId>,

    /// Receiver for data change notifications.
    pub receiver: mpsc::Receiver<DataChangeNotification>,

    /// Subscription settings.
    pub settings: SubscriptionSettings,
}

impl SubscriptionHandle {
    /// Creates a new subscription handle.
    pub fn new(
        id: u32,
        nodes: Vec<NodeId>,
        receiver: mpsc::Receiver<DataChangeNotification>,
        settings: SubscriptionSettings,
    ) -> Self {
        Self {
            id,
            nodes,
            receiver,
            settings,
        }
    }
}

impl fmt::Debug for SubscriptionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionHandle")
            .field("id", &self.id)
            .field("nodes", &self.nodes.len())
            .finish()
    }
}

// =============================================================================
// DataChangeNotification
// =============================================================================

/// Notification of a data change from a subscription.
#[derive(Debug, Clone)]
pub struct DataChangeNotification {
    /// The node ID that changed.
    pub node_id: NodeId,

    /// The new value.
    pub value: TypedValue,

    /// Monitored item ID.
    pub monitored_item_id: u32,

    /// Client-provided handle.
    pub client_handle: u32,
}

// =============================================================================
// OpcUaClient
// =============================================================================

/// High-level OPC UA client with session management and retry support.
///
/// This client provides a convenient API for OPC UA operations including:
/// - Automatic session management and renewal
/// - Configurable retry logic with backoff
/// - Subscription management
/// - Data type conversion
///
/// # Examples
///
/// ```rust,ignore
/// use trap_opcua::client::OpcUaClient;
/// use trap_opcua::types::OpcUaConfig;
///
/// let config = OpcUaConfig::builder()
///     .endpoint("opc.tcp://localhost:4840")
///     .build()?;
///
/// let client = OpcUaClient::new(config);
/// client.connect().await?;
///
/// // Read a node value
/// let value = client.read("ns=2;s=Temperature").await?;
/// println!("Temperature: {}", value);
/// ```
pub struct OpcUaClient<T: OpcUaTransport> {
    /// Configuration.
    config: OpcUaConfig,

    /// Transport layer.
    transport: Arc<Mutex<T>>,

    /// Session manager.
    session: Arc<SessionManager>,

    /// Retry configuration.
    retry_config: RetryConfig,

    /// Data converter.
    converter: DataConverter,

    /// Client statistics.
    stats: ClientStats,

    /// Active subscriptions.
    subscriptions: RwLock<HashMap<u32, Vec<NodeId>>>,

    /// Next subscription ID (for future use).
    #[allow(dead_code)]
    next_subscription_id: AtomicU64,
}

impl<T: OpcUaTransport> OpcUaClient<T> {
    /// Creates a new OPC UA client.
    pub fn new(config: OpcUaConfig, transport: T) -> Self {
        let session = Arc::new(SessionManager::new(config.clone()));

        Self {
            config,
            transport: Arc::new(Mutex::new(transport)),
            session,
            retry_config: RetryConfig::default(),
            converter: DataConverter::new(),
            stats: ClientStats::new(),
            subscriptions: RwLock::new(HashMap::new()),
            next_subscription_id: AtomicU64::new(1),
        }
    }

    /// Creates a new client with custom retry configuration.
    pub fn with_retry(config: OpcUaConfig, transport: T, retry_config: RetryConfig) -> Self {
        let session = Arc::new(SessionManager::new(config.clone()));

        Self {
            config,
            transport: Arc::new(Mutex::new(transport)),
            session,
            retry_config,
            converter: DataConverter::new(),
            stats: ClientStats::new(),
            subscriptions: RwLock::new(HashMap::new()),
            next_subscription_id: AtomicU64::new(1),
        }
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &OpcUaConfig {
        &self.config
    }

    /// Returns the retry configuration.
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    /// Sets the retry configuration.
    pub fn set_retry_config(&mut self, config: RetryConfig) {
        self.retry_config = config;
    }

    /// Returns the client statistics.
    pub fn stats(&self) -> &ClientStats {
        &self.stats
    }

    /// Resets the client statistics.
    pub fn reset_stats(&self) {
        self.stats.reset();
    }

    // =========================================================================
    // Connection Management
    // =========================================================================

    /// Connects to the OPC UA server.
    pub async fn connect(&self) -> OpcUaResult<()> {
        // Connect transport
        {
            let mut transport = self.transport.lock().await;
            transport.connect().await?;
        }

        // Create and activate session
        self.session.create_and_activate().await?;

        self.stats.record_connection();

        tracing::info!(
            endpoint = %self.config.endpoint,
            "OPC UA client connected"
        );

        Ok(())
    }

    /// Disconnects from the OPC UA server.
    pub async fn disconnect(&self) -> OpcUaResult<()> {
        // Close session first
        self.session.close().await.ok();

        // Delete all subscriptions
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.clear();
        }

        // Disconnect transport
        {
            let mut transport = self.transport.lock().await;
            transport.disconnect().await?;
        }

        tracing::info!(
            endpoint = %self.config.endpoint,
            "OPC UA client disconnected"
        );

        Ok(())
    }

    /// Returns `true` if the client is connected.
    pub async fn is_connected(&self) -> bool {
        let transport = self.transport.lock().await;
        transport.is_connected() && self.session.state().await.is_active()
    }

    /// Returns the current connection state.
    pub async fn connection_state(&self) -> TransportState {
        let transport = self.transport.lock().await;
        transport.state()
    }

    /// Returns the current session state.
    pub async fn session_state(&self) -> SessionState {
        self.session.state().await
    }

    /// Ensures the client is connected and session is active.
    async fn ensure_connected(&self) -> OpcUaResult<()> {
        // Ensure session is active
        self.session.ensure_active().await?;

        // Check transport state
        let transport = self.transport.lock().await;
        if !transport.is_connected() {
            return Err(OpcUaError::connection(ConnectionError::NotConnected));
        }

        Ok(())
    }

    // =========================================================================
    // Read Operations
    // =========================================================================

    /// Reads a single node value.
    pub async fn read(&self, node_id: &str) -> OpcUaResult<TypedValue> {
        let node = NodeId::from_str(node_id)?;
        self.read_node(&node).await
    }

    /// Reads a single node value by NodeId.
    pub async fn read_node(&self, node_id: &NodeId) -> OpcUaResult<TypedValue> {
        self.ensure_connected().await?;

        let start = Instant::now();
        let result = self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.read_value(node_id).await
        }).await?;

        self.stats.record_read(start.elapsed());
        self.session.touch().await;

        self.read_result_to_typed_value(result)
    }

    /// Reads multiple node values.
    pub async fn read_nodes(&self, node_ids: &[NodeId]) -> OpcUaResult<Vec<(NodeId, OpcUaResult<TypedValue>)>> {
        self.ensure_connected().await?;

        let start = Instant::now();
        let results = self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.read_values(node_ids).await
        }).await?;

        self.stats.record_read(start.elapsed());
        self.session.touch().await;

        let converted: Vec<(NodeId, OpcUaResult<TypedValue>)> = results
            .into_iter()
            .map(|r| {
                let node_id = r.node_id.clone();
                let value = self.read_result_to_typed_value(r);
                (node_id, value)
            })
            .collect();

        Ok(converted)
    }

    /// Reads a node value with tag mapping (applies scaling).
    pub async fn read_mapped(&self, mapping: &TagMapping) -> OpcUaResult<TypedValue> {
        let value = self.read_node(&mapping.node_id).await?;
        Ok(self.converter.apply_tag_scaling(&value, mapping))
    }

    // =========================================================================
    // Write Operations
    // =========================================================================

    /// Writes a value to a node.
    pub async fn write(&self, node_id: &str, value: OpcUaValue) -> OpcUaResult<()> {
        let node = NodeId::from_str(node_id)?;
        self.write_node(&node, value).await
    }

    /// Writes a value to a node by NodeId.
    pub async fn write_node(&self, node_id: &NodeId, value: OpcUaValue) -> OpcUaResult<()> {
        self.ensure_connected().await?;

        let start = Instant::now();
        let result = self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.write_value(node_id, value.clone()).await
        }).await?;

        self.stats.record_write(start.elapsed());
        self.session.touch().await;

        if result.is_good() {
            Ok(())
        } else {
            Err(OpcUaError::operation(OperationError::write_failed(
                node_id.to_string(),
                format!("Status code: 0x{:08X}", result.status_code),
            )))
        }
    }

    /// Writes multiple values to nodes.
    pub async fn write_nodes(&self, writes: &[(NodeId, OpcUaValue)]) -> OpcUaResult<Vec<WriteResult>> {
        self.ensure_connected().await?;

        let start = Instant::now();
        let results = self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.write_values(writes).await
        }).await?;

        self.stats.record_write(start.elapsed());
        self.session.touch().await;

        Ok(results)
    }

    /// Writes a value with tag mapping (applies inverse scaling).
    pub async fn write_mapped(&self, mapping: &TagMapping, value: f64) -> OpcUaResult<()> {
        if !mapping.writable {
            return Err(OpcUaError::operation(OperationError::NotWritable {
                node_id: mapping.node_id.to_string(),
            }));
        }

        let scaled_value = self.converter.apply_inverse_scaling(value, mapping);
        let opc_value = OpcUaValue::Double(scaled_value);
        self.write_node(&mapping.node_id, opc_value).await
    }

    // =========================================================================
    // Browse Operations
    // =========================================================================

    /// Browses child nodes of a given node.
    pub async fn browse(&self, node_id: &str) -> OpcUaResult<Vec<super::transport::BrowseResult>> {
        let node = NodeId::from_str(node_id)?;
        self.browse_node(&node).await
    }

    /// Browses child nodes by NodeId.
    pub async fn browse_node(&self, node_id: &NodeId) -> OpcUaResult<Vec<super::transport::BrowseResult>> {
        self.ensure_connected().await?;

        let results = self.execute_with_retry(|| async {
            let transport = self.transport.lock().await;
            transport.browse(node_id).await
        }).await?;

        self.stats.record_browse();
        self.session.touch().await;

        Ok(results)
    }

    // =========================================================================
    // Subscription Operations
    // =========================================================================

    /// Creates a subscription for data change notifications.
    pub async fn subscribe(
        &self,
        node_ids: &[NodeId],
        settings: Option<SubscriptionSettings>,
    ) -> OpcUaResult<SubscriptionHandle> {
        self.ensure_connected().await?;

        let settings = settings.unwrap_or_else(|| self.config.subscription.clone());

        // Create subscription on server
        let subscription_id = {
            let transport = self.transport.lock().await;
            transport.create_subscription(settings.publishing_interval).await?
        };

        // Create monitored items
        {
            let transport = self.transport.lock().await;
            transport
                .create_monitored_items(
                    subscription_id,
                    node_ids,
                    Duration::from_millis(250), // Default sampling interval
                )
                .await?;
        }

        // Create channel for notifications
        let (_tx, rx) = mpsc::channel(100);

        // Store subscription
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(subscription_id, node_ids.to_vec());
        }

        let handle = SubscriptionHandle::new(subscription_id, node_ids.to_vec(), rx, settings);

        tracing::info!(
            subscription_id = subscription_id,
            nodes = node_ids.len(),
            "Subscription created"
        );

        Ok(handle)
    }

    /// Deletes a subscription.
    pub async fn unsubscribe(&self, subscription_id: u32) -> OpcUaResult<()> {
        // Remove from local tracking
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.remove(&subscription_id);
        }

        // Delete on server
        if self.is_connected().await {
            let transport = self.transport.lock().await;
            transport.delete_subscription(subscription_id).await?;
        }

        tracing::info!(subscription_id = subscription_id, "Subscription deleted");

        Ok(())
    }

    // =========================================================================
    // Private Methods
    // =========================================================================

    /// Executes an operation with retry logic.
    async fn execute_with_retry<F, Fut, R>(&self, operation: F) -> OpcUaResult<R>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = OpcUaResult<R>>,
    {
        let mut last_error = None;
        let mut attempt = 0;

        while attempt <= self.retry_config.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    // Check if error is retryable
                    let should_retry = error.is_retryable()
                        && attempt < self.retry_config.max_retries
                        && match &error {
                            OpcUaError::Connection(_) => self.retry_config.retry_connection,
                            OpcUaError::Operation(_) => self.retry_config.retry_operations,
                            _ => true,
                        };

                    if !should_retry {
                        self.stats.record_error();
                        return Err(error);
                    }

                    // Calculate delay
                    let delay = self.retry_config.delay_for_attempt(attempt);

                    tracing::debug!(
                        attempt = attempt + 1,
                        max_retries = self.retry_config.max_retries,
                        delay_ms = delay.as_millis(),
                        error = %error,
                        "Retrying OPC UA operation"
                    );

                    self.stats.record_retry();
                    tokio::time::sleep(delay).await;

                    last_error = Some(error);
                    attempt += 1;
                }
            }
        }

        self.stats.record_error();
        Err(last_error.unwrap_or_else(OpcUaError::not_connected))
    }

    /// Converts a ReadResult to TypedValue.
    fn read_result_to_typed_value(&self, result: ReadResult) -> OpcUaResult<TypedValue> {
        if result.is_bad() {
            return Err(OpcUaError::operation(OperationError::read_failed(
                result.node_id.to_string(),
                format!("Status code: 0x{:08X}", result.status_code),
            )));
        }

        let value = result.value.unwrap_or(OpcUaValue::Null);
        let quality = Quality::from_status_code(result.status_code);

        Ok(TypedValue::full(
            value,
            quality,
            result.server_timestamp,
            result.source_timestamp,
        ))
    }
}

impl<T: OpcUaTransport> fmt::Debug for OpcUaClient<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpcUaClient")
            .field("endpoint", &self.config.endpoint)
            .finish()
    }
}

// =============================================================================
// Duration Serialization Helper
// =============================================================================

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
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_strategy() {
        let base = Duration::from_millis(100);

        assert_eq!(RetryStrategy::Fixed.delay(base, 0), Duration::from_millis(100));
        assert_eq!(RetryStrategy::Fixed.delay(base, 5), Duration::from_millis(100));

        assert_eq!(RetryStrategy::Linear.delay(base, 0), Duration::from_millis(100));
        assert_eq!(RetryStrategy::Linear.delay(base, 2), Duration::from_millis(300));

        assert_eq!(RetryStrategy::Exponential.delay(base, 0), Duration::from_millis(100));
        assert_eq!(RetryStrategy::Exponential.delay(base, 2), Duration::from_millis(400));
    }

    #[test]
    fn test_retry_config() {
        let config = RetryConfig::new(5)
            .with_base_delay(Duration::from_millis(200))
            .with_max_delay(Duration::from_secs(5))
            .with_strategy(RetryStrategy::Exponential);

        assert_eq!(config.max_retries, 5);
        assert_eq!(config.base_delay, Duration::from_millis(200));

        // Check clamping to max_delay
        let delay = config.delay_for_attempt(10);
        assert!(delay <= Duration::from_secs(5));
    }

    #[test]
    fn test_client_stats() {
        let stats = ClientStats::new();

        stats.record_read(Duration::from_millis(10));
        stats.record_read(Duration::from_millis(20));
        stats.record_write(Duration::from_millis(15));
        stats.record_error();

        assert_eq!(stats.reads(), 2);
        assert_eq!(stats.writes(), 1);
        assert_eq!(stats.errors(), 1);

        // Success rate: 3 total ops, 1 error = 66.7%
        let rate = stats.success_rate();
        assert!(rate > 0.6 && rate < 0.7);

        // Average response time: (10 + 20 + 15) / 3 = 15ms
        assert_eq!(stats.average_response_time(), Duration::from_millis(15));
    }

    #[test]
    fn test_no_retry_config() {
        let config = RetryConfig::no_retry();
        assert_eq!(config.max_retries, 0);
    }
}
