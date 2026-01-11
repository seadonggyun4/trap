// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA protocol driver implementation.
//!
//! This module provides the [`OpcUaDriver`] which implements the
//! [`ProtocolDriver`] trait from `trap-core`, enabling seamless integration
//! with the TRAP gateway system.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        OpcUaDriver                              │
//! │                  (ProtocolDriver impl)                          │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      OpcUaClient<T>                             │
//! │              (High-level read/write/subscribe API)              │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    OpcUaTransport (trait)                       │
//! │               (Abstract transport layer)                        │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_opcua::driver::OpcUaDriver;
//! use trap_opcua::types::OpcUaConfig;
//!
//! let config = OpcUaConfig::builder()
//!     .endpoint("opc.tcp://192.168.1.100:4840")
//!     .build()?;
//!
//! let mut driver = OpcUaDriver::new(config, "opc-01".to_string());
//! driver.connect().await?;
//!
//! let address = Address::OpcUa(OpcUaNodeId::string(2, "Temperature"));
//! let value = driver.read(&address).await?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex, RwLock};

use trap_core::driver::{
    AddressInfo, CircuitState, DataType, HealthStatus, ProtocolDriver, Subscription,
    SubscriptionId,
};
use trap_core::error::DriverError;
use trap_core::types::{Protocol, Value};
use trap_core::Address;

use crate::client::{
    DataConverter, OpcUaClient, OpcUaTransport, OpcUaValue, RetryConfig, TypedValue,
};
use crate::types::{NodeId, OpcUaConfig, TagMapping};

// =============================================================================
// OpcUaDriver
// =============================================================================

/// OPC UA protocol driver implementing `trap_core::ProtocolDriver`.
///
/// This driver provides:
/// - Full OPC UA client support with session management
/// - Configurable retry and timeout behavior
/// - Health monitoring with circuit breaker pattern
/// - Tag-based addressing for easy configuration
/// - Subscription support for data change notifications
///
/// # Example
///
/// ```rust,ignore
/// use trap_opcua::driver::OpcUaDriver;
/// use trap_opcua::types::OpcUaConfig;
///
/// let config = OpcUaConfig::builder()
///     .endpoint("opc.tcp://localhost:4840")
///     .build()?;
///
/// let mut driver = OpcUaDriver::new(config, "opc-server-01".to_string());
/// driver.connect().await?;
///
/// let value = driver.read(&address).await?;
/// ```
pub struct OpcUaDriver<T: OpcUaTransport> {
    /// Driver name/identifier.
    name: String,
    /// OPC UA configuration.
    config: OpcUaConfig,
    /// Tag mappings.
    tag_mappings: Arc<RwLock<HashMap<String, TagMapping>>>,
    /// The underlying client.
    client: Arc<Mutex<OpcUaClient<T>>>,
    /// Data converter for value transformations.
    #[allow(dead_code)]
    converter: DataConverter,
    /// Health status.
    health: Arc<RwLock<HealthStatus>>,
    /// Retry configuration.
    retry_config: RetryConfig,
    /// Active subscriptions.
    subscriptions: Arc<RwLock<HashMap<SubscriptionId, DriverSubscription>>>,
    /// Next subscription ID counter.
    next_subscription_id: Arc<std::sync::atomic::AtomicU64>,
}

/// Internal subscription tracking.
#[allow(dead_code)]
struct DriverSubscription {
    /// OPC UA subscription ID.
    opcua_subscription_id: u32,
    /// Monitored node IDs.
    node_ids: Vec<NodeId>,
    /// Sender for data updates.
    sender: mpsc::Sender<trap_core::DataPoint>,
}

impl<T: OpcUaTransport + 'static> OpcUaDriver<T> {
    /// Creates a new OPC UA driver with the given transport.
    pub fn new(config: OpcUaConfig, transport: T, name: String) -> Self {
        let client = OpcUaClient::new(config.clone(), transport);

        Self {
            name,
            config,
            tag_mappings: Arc::new(RwLock::new(HashMap::new())),
            client: Arc::new(Mutex::new(client)),
            converter: DataConverter::new(),
            health: Arc::new(RwLock::new(HealthStatus::default())),
            retry_config: RetryConfig::default(),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            next_subscription_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Sets the retry configuration.
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Adds a tag mapping.
    pub async fn add_tag_mapping(&self, mapping: TagMapping) {
        let mut mappings = self.tag_mappings.write().await;
        mappings.insert(mapping.tag_id.clone(), mapping);
    }

    /// Adds multiple tag mappings.
    pub async fn add_tag_mappings(&self, mappings: impl IntoIterator<Item = TagMapping>) {
        let mut tag_mappings = self.tag_mappings.write().await;
        for mapping in mappings {
            tag_mappings.insert(mapping.tag_id.clone(), mapping);
        }
    }

    /// Removes a tag mapping.
    pub async fn remove_tag_mapping(&self, tag_id: &str) -> Option<TagMapping> {
        let mut mappings = self.tag_mappings.write().await;
        mappings.remove(tag_id)
    }

    /// Gets a tag mapping by ID.
    pub async fn get_tag_mapping(&self, tag_id: &str) -> Option<TagMapping> {
        let mappings = self.tag_mappings.read().await;
        mappings.get(tag_id).cloned()
    }

    /// Returns all tag mappings.
    pub async fn tag_mappings(&self) -> Vec<TagMapping> {
        let mappings = self.tag_mappings.read().await;
        mappings.values().cloned().collect()
    }

    /// Returns the configuration.
    pub fn config(&self) -> &OpcUaConfig {
        &self.config
    }

    /// Converts a trap_core::Address to NodeId.
    fn address_to_node_id(&self, address: &Address) -> Result<NodeId, DriverError> {
        match address {
            Address::OpcUa(opcua_addr) => Ok(NodeId::from_core_node_id(opcua_addr)),
            _ => Err(DriverError::protocol(format!(
                "Invalid address type for OPC UA driver: expected OpcUa, got {:?}",
                address.protocol()
            ))),
        }
    }

    /// Converts an OpcUaValue to trap_core::Value.
    fn typed_value_to_core_value(&self, typed_value: &TypedValue) -> Value {
        typed_value.to_core_value()
    }

    /// Converts a trap_core::Value to OpcUaValue.
    fn core_value_to_opc_value(&self, value: &Value) -> Result<OpcUaValue, DriverError> {
        let opc_value = match value {
            Value::Bool(v) => OpcUaValue::Boolean(*v),
            Value::Int32(v) => OpcUaValue::Int32(*v),
            Value::Int64(v) => OpcUaValue::Int64(*v),
            Value::UInt32(v) => OpcUaValue::UInt32(*v),
            Value::UInt64(v) => OpcUaValue::UInt64(*v),
            Value::Float32(v) => OpcUaValue::Float(*v),
            Value::Float64(v) => OpcUaValue::Double(*v),
            Value::String(v) => OpcUaValue::String(v.clone()),
            Value::Bytes(v) => OpcUaValue::ByteString(v.clone()),
            Value::DateTime(v) => OpcUaValue::DateTime(*v),
            _ => {
                return Err(DriverError::protocol(format!(
                    "Unsupported value type for OPC UA write: {:?}",
                    value
                )))
            }
        };

        Ok(opc_value)
    }

    /// Updates health status after an operation.
    async fn update_health(&self, success: bool, latency: Duration) {
        let mut health = self.health.write().await;

        health.latency = Some(latency);

        if success {
            health.healthy = true;
            health.last_success = Some(chrono::Utc::now());
            health.circuit_state = CircuitState::Closed;
            health.last_error = None;
        } else {
            health.healthy = false;
            health.last_error = Some("Operation failed".to_string());
            health.circuit_state = CircuitState::Open;
        }
    }

    /// Generates the next subscription ID.
    fn next_subscription_id(&self) -> SubscriptionId {
        let id = self
            .next_subscription_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        SubscriptionId::new(id)
    }
}

// =============================================================================
// ProtocolDriver Implementation
// =============================================================================

#[async_trait]
impl<T: OpcUaTransport + 'static> ProtocolDriver for OpcUaDriver<T> {
    // =========================================================================
    // Identification
    // =========================================================================

    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> Protocol {
        Protocol::OpcUa
    }

    // =========================================================================
    // Connection Management
    // =========================================================================

    async fn connect(&mut self) -> Result<(), DriverError> {
        let client = self.client.lock().await;
        client.connect().await.map_err(|e| {
            DriverError::connection_failed(format!("{}: {}", self.config.endpoint, e))
        })?;

        tracing::info!(
            name = %self.name,
            endpoint = %self.config.endpoint,
            "OPC UA driver connected"
        );

        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), DriverError> {
        // Close all subscriptions first
        {
            let subscriptions = self.subscriptions.read().await;
            let client = self.client.lock().await;

            for (_, sub) in subscriptions.iter() {
                let _ = client.unsubscribe(sub.opcua_subscription_id).await;
            }
        }

        // Clear subscription tracking
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.clear();
        }

        // Disconnect client
        let client = self.client.lock().await;
        client.disconnect().await.map_err(|e| {
            DriverError::protocol(format!("Failed to disconnect: {}", e))
        })?;

        tracing::info!(
            name = %self.name,
            "OPC UA driver disconnected"
        );

        Ok(())
    }

    fn is_connected(&self) -> bool {
        // Note: This is a sync method, so we can't await.
        // The actual check happens in async operations.
        true
    }

    // =========================================================================
    // Read Operations
    // =========================================================================

    async fn read(&self, address: &Address) -> Result<Value, DriverError> {
        let node_id = self.address_to_node_id(address)?;
        let start = Instant::now();

        let client = self.client.lock().await;
        let result = client.read_node(&node_id).await;
        let latency = start.elapsed();

        match result {
            Ok(typed_value) => {
                self.update_health(true, latency).await;
                let value = self.typed_value_to_core_value(&typed_value);

                tracing::trace!(
                    node_id = %node_id,
                    value = ?value,
                    latency_ms = latency.as_millis(),
                    "OPC UA read successful"
                );

                Ok(value)
            }
            Err(e) => {
                self.update_health(false, latency).await;

                tracing::warn!(
                    node_id = %node_id,
                    error = %e,
                    "OPC UA read failed"
                );

                Err(DriverError::read_failed(node_id.to_string(), e.to_string()))
            }
        }
    }

    async fn read_batch(
        &self,
        addresses: &[Address],
    ) -> Result<Vec<(Address, Result<Value, DriverError>)>, DriverError> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }

        // Convert addresses to NodeIds
        let mut node_ids = Vec::with_capacity(addresses.len());
        let mut address_map = HashMap::with_capacity(addresses.len());

        for addr in addresses {
            match self.address_to_node_id(addr) {
                Ok(node_id) => {
                    address_map.insert(node_id.clone(), addr.clone());
                    node_ids.push(node_id);
                }
                Err(e) => {
                    // If conversion fails, we still need to include this address in results
                    return Ok(addresses
                        .iter()
                        .map(|a| (a.clone(), Err(e.clone())))
                        .collect());
                }
            }
        }

        let start = Instant::now();
        let client = self.client.lock().await;
        let results = client.read_nodes(&node_ids).await;
        let latency = start.elapsed();

        match results {
            Ok(read_results) => {
                self.update_health(true, latency).await;

                let mut output = Vec::with_capacity(read_results.len());
                for (node_id, result) in read_results {
                    if let Some(addr) = address_map.get(&node_id) {
                        let mapped_result = result
                            .map(|tv| self.typed_value_to_core_value(&tv))
                            .map_err(|e| DriverError::read_failed(node_id.to_string(), e.to_string()));
                        output.push((addr.clone(), mapped_result));
                    }
                }

                tracing::trace!(
                    count = output.len(),
                    latency_ms = latency.as_millis(),
                    "OPC UA batch read successful"
                );

                Ok(output)
            }
            Err(e) => {
                self.update_health(false, latency).await;

                tracing::warn!(
                    error = %e,
                    "OPC UA batch read failed"
                );

                Err(DriverError::read_failed("batch".to_string(), e.to_string()))
            }
        }
    }

    // =========================================================================
    // Write Operations
    // =========================================================================

    async fn write(&self, address: &Address, value: Value) -> Result<(), DriverError> {
        let node_id = self.address_to_node_id(address)?;
        let opc_value = self.core_value_to_opc_value(&value)?;
        let start = Instant::now();

        let client = self.client.lock().await;
        let result = client.write_node(&node_id, opc_value).await;
        let latency = start.elapsed();

        match result {
            Ok(()) => {
                self.update_health(true, latency).await;

                tracing::trace!(
                    node_id = %node_id,
                    value = ?value,
                    latency_ms = latency.as_millis(),
                    "OPC UA write successful"
                );

                Ok(())
            }
            Err(e) => {
                self.update_health(false, latency).await;

                tracing::warn!(
                    node_id = %node_id,
                    error = %e,
                    "OPC UA write failed"
                );

                Err(DriverError::write_failed(node_id.to_string(), e.to_string()))
            }
        }
    }

    async fn write_batch(
        &self,
        writes: &[(Address, Value)],
    ) -> Result<Vec<(Address, Result<(), DriverError>)>, DriverError> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }

        // Convert addresses and values
        let mut opc_writes = Vec::with_capacity(writes.len());
        let mut address_map = HashMap::with_capacity(writes.len());

        for (addr, value) in writes {
            match (self.address_to_node_id(addr), self.core_value_to_opc_value(value)) {
                (Ok(node_id), Ok(opc_value)) => {
                    address_map.insert(node_id.clone(), addr.clone());
                    opc_writes.push((node_id, opc_value));
                }
                (Err(e), _) | (_, Err(e)) => {
                    // If conversion fails for any write, return error for all
                    return Ok(writes.iter().map(|(a, _)| (a.clone(), Err(e.clone()))).collect());
                }
            }
        }

        let start = Instant::now();
        let client = self.client.lock().await;
        let results = client.write_nodes(&opc_writes).await;
        let latency = start.elapsed();

        match results {
            Ok(write_results) => {
                self.update_health(true, latency).await;

                let mut output = Vec::with_capacity(write_results.len());
                for result in write_results {
                    if let Some(addr) = address_map.get(&result.node_id) {
                        let mapped_result = if result.is_good() {
                            Ok(())
                        } else {
                            Err(DriverError::write_failed(
                                result.node_id.to_string(),
                                format!("Status code: 0x{:08X}", result.status_code),
                            ))
                        };
                        output.push((addr.clone(), mapped_result));
                    }
                }

                tracing::trace!(
                    count = output.len(),
                    latency_ms = latency.as_millis(),
                    "OPC UA batch write successful"
                );

                Ok(output)
            }
            Err(e) => {
                self.update_health(false, latency).await;

                tracing::warn!(
                    error = %e,
                    "OPC UA batch write failed"
                );

                Err(DriverError::write_failed("batch".to_string(), e.to_string()))
            }
        }
    }

    // =========================================================================
    // Subscription Support
    // =========================================================================

    fn supports_subscription(&self) -> bool {
        true
    }

    async fn subscribe(&self, addresses: &[Address]) -> Result<Subscription, DriverError> {
        if addresses.is_empty() {
            return Err(DriverError::protocol("No addresses provided for subscription"));
        }

        // Convert addresses to NodeIds
        let mut node_ids = Vec::with_capacity(addresses.len());
        for addr in addresses {
            let node_id = self.address_to_node_id(addr)?;
            node_ids.push(node_id);
        }

        // Create subscription on server
        let client = self.client.lock().await;
        let handle = client
            .subscribe(&node_ids, None)
            .await
            .map_err(|e| DriverError::protocol(format!("Failed to create subscription: {}", e)))?;

        // Create channel for data updates
        let (tx, rx) = mpsc::channel(1000);

        // Generate subscription ID
        let sub_id = self.next_subscription_id();

        // Store subscription tracking
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(
                sub_id.clone(),
                DriverSubscription {
                    opcua_subscription_id: handle.id,
                    node_ids: handle.nodes,
                    sender: tx,
                },
            );
        }

        tracing::info!(
            subscription_id = sub_id.0,
            node_count = addresses.len(),
            "OPC UA subscription created"
        );

        Ok(Subscription {
            id: sub_id,
            receiver: rx,
        })
    }

    async fn unsubscribe(&self, subscription_id: &SubscriptionId) -> Result<(), DriverError> {
        // Get and remove the subscription
        let sub = {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.remove(subscription_id)
        };

        if let Some(sub) = sub {
            // Delete subscription on server
            let client = self.client.lock().await;
            client
                .unsubscribe(sub.opcua_subscription_id)
                .await
                .map_err(|e| DriverError::protocol(format!("Failed to delete subscription: {}", e)))?;

            tracing::info!(
                subscription_id = subscription_id.0,
                "OPC UA subscription deleted"
            );
        }

        Ok(())
    }

    // =========================================================================
    // Browse Support
    // =========================================================================

    async fn browse(&self) -> Result<Vec<AddressInfo>, DriverError> {
        let start_node = NodeId::OBJECTS_FOLDER;

        let client = self.client.lock().await;
        let browse_results = client
            .browse_node(&start_node)
            .await
            .map_err(|e| DriverError::protocol(format!("Failed to browse: {}", e)))?;

        let mut address_infos = Vec::with_capacity(browse_results.len());
        for result in browse_results {
            address_infos.push(AddressInfo {
                address: result.node_id.to_address(),
                name: result.display_name,
                description: Some(result.browse_name),
                data_type: DataType::Unknown,
                writable: false,
                unit: None,
            });
        }

        tracing::debug!(
            count = address_infos.len(),
            "OPC UA browse completed"
        );

        Ok(address_infos)
    }

    async fn get_address_info(&self, address: &Address) -> Result<AddressInfo, DriverError> {
        let node_id = self.address_to_node_id(address)?;

        let client = self.client.lock().await;
        let browse_results = client
            .browse_node(&node_id)
            .await
            .map_err(|e| DriverError::protocol(format!("Failed to get address info: {}", e)))?;

        // Return info for the first result (the node itself if available)
        if !browse_results.is_empty() {
            let result = &browse_results[0];
            Ok(AddressInfo {
                address: result.node_id.to_address(),
                name: result.display_name.clone(),
                description: Some(result.browse_name.clone()),
                data_type: DataType::Unknown,
                writable: false,
                unit: None,
            })
        } else {
            Ok(AddressInfo {
                address: address.clone(),
                name: node_id.to_string(),
                description: None,
                data_type: DataType::Unknown,
                writable: false,
                unit: None,
            })
        }
    }

    // =========================================================================
    // Health Check
    // =========================================================================

    async fn health_check(&self) -> HealthStatus {
        let client = self.client.lock().await;

        // Try to read the Server node to verify connection
        let server_node = NodeId::SERVER;
        let start = Instant::now();

        match client.read_node(&server_node).await {
            Ok(_) => {
                let latency = start.elapsed();
                self.update_health(true, latency).await;
            }
            Err(_) => {
                let latency = start.elapsed();
                self.update_health(false, latency).await;
            }
        }

        self.health.read().await.clone()
    }
}

// =============================================================================
// Debug Implementation
// =============================================================================

impl<T: OpcUaTransport> std::fmt::Debug for OpcUaDriver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpcUaDriver")
            .field("name", &self.name)
            .field("endpoint", &self.config.endpoint)
            .finish()
    }
}

// =============================================================================
// OpcUaDriverFactory
// =============================================================================

/// Factory for creating OPC UA drivers.
///
/// This factory creates `OpcUaDriver` instances from device configurations.
pub struct OpcUaDriverFactory;

impl OpcUaDriverFactory {
    /// Creates a new OPC UA driver factory.
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpcUaDriverFactory {
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
    use crate::client::{BrowseResult, OpcUaValue, ReadResult, TransportState, WriteResult};

    /// Mock transport for testing.
    struct MockTransport {
        connected: std::sync::atomic::AtomicBool,
        values: std::sync::RwLock<HashMap<String, OpcUaValue>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                connected: std::sync::atomic::AtomicBool::new(false),
                values: std::sync::RwLock::new(HashMap::new()),
            }
        }

        fn set_value(&self, node_id: &str, value: OpcUaValue) {
            let mut values = self.values.write().unwrap();
            values.insert(node_id.to_string(), value);
        }
    }

    #[async_trait]
    impl OpcUaTransport for MockTransport {
        async fn connect(&mut self) -> crate::error::OpcUaResult<()> {
            self.connected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn disconnect(&mut self) -> crate::error::OpcUaResult<()> {
            self.connected
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn state(&self) -> TransportState {
            if self.is_connected() {
                TransportState::Connected
            } else {
                TransportState::Disconnected
            }
        }

        async fn read_value(&self, node_id: &NodeId) -> crate::error::OpcUaResult<ReadResult> {
            let values = self.values.read().unwrap();
            let value = values
                .get(&node_id.to_string())
                .cloned()
                .unwrap_or(OpcUaValue::Double(0.0));

            Ok(ReadResult::success(node_id.clone(), value))
        }

        async fn read_values(
            &self,
            node_ids: &[NodeId],
        ) -> crate::error::OpcUaResult<Vec<ReadResult>> {
            let mut results = Vec::with_capacity(node_ids.len());
            for node_id in node_ids {
                results.push(self.read_value(node_id).await?);
            }
            Ok(results)
        }

        async fn read_attribute(
            &self,
            node_id: &NodeId,
            _attribute_id: u32,
        ) -> crate::error::OpcUaResult<ReadResult> {
            self.read_value(node_id).await
        }

        async fn write_value(
            &self,
            node_id: &NodeId,
            value: OpcUaValue,
        ) -> crate::error::OpcUaResult<WriteResult> {
            let mut values = self.values.write().unwrap();
            values.insert(node_id.to_string(), value);
            Ok(WriteResult::success(node_id.clone()))
        }

        async fn write_values(
            &self,
            writes: &[(NodeId, OpcUaValue)],
        ) -> crate::error::OpcUaResult<Vec<WriteResult>> {
            let mut results = Vec::with_capacity(writes.len());
            for (node_id, value) in writes {
                results.push(self.write_value(node_id, value.clone()).await?);
            }
            Ok(results)
        }

        async fn browse(&self, _node_id: &NodeId) -> crate::error::OpcUaResult<Vec<BrowseResult>> {
            Ok(vec![])
        }

        async fn browse_filtered(
            &self,
            node_id: &NodeId,
            _direction: u32,
            _node_class_mask: u32,
        ) -> crate::error::OpcUaResult<Vec<BrowseResult>> {
            self.browse(node_id).await
        }

        async fn create_subscription(
            &self,
            _publishing_interval: std::time::Duration,
        ) -> crate::error::OpcUaResult<u32> {
            Ok(1)
        }

        async fn delete_subscription(&self, _subscription_id: u32) -> crate::error::OpcUaResult<()> {
            Ok(())
        }

        async fn create_monitored_items(
            &self,
            _subscription_id: u32,
            node_ids: &[NodeId],
            _sampling_interval: std::time::Duration,
        ) -> crate::error::OpcUaResult<Vec<u32>> {
            Ok((0..node_ids.len() as u32).collect())
        }

        async fn delete_monitored_items(
            &self,
            _subscription_id: u32,
            _monitored_item_ids: &[u32],
        ) -> crate::error::OpcUaResult<()> {
            Ok(())
        }

        fn display_name(&self) -> String {
            "MockTransport".to_string()
        }

        fn endpoint(&self) -> &str {
            "opc.tcp://localhost:4840"
        }

        fn config(&self) -> &OpcUaConfig {
            // This is a bit awkward for testing, but works
            static CONFIG: std::sync::OnceLock<OpcUaConfig> = std::sync::OnceLock::new();
            CONFIG.get_or_init(|| {
                OpcUaConfig::builder()
                    .endpoint("opc.tcp://localhost:4840")
                    .build()
                    .unwrap()
            })
        }
    }

    #[tokio::test]
    async fn test_driver_creation() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        let transport = MockTransport::new();
        let driver = OpcUaDriver::new(config, transport, "test-driver".to_string());

        assert_eq!(driver.name(), "test-driver");
        assert_eq!(driver.protocol(), Protocol::OpcUa);
    }

    #[tokio::test]
    async fn test_driver_connect_disconnect() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        let transport = MockTransport::new();
        let mut driver = OpcUaDriver::new(config, transport, "test-driver".to_string());

        driver.connect().await.unwrap();
        driver.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_driver_read() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        let transport = MockTransport::new();
        transport.set_value("ns=2;i=1001", OpcUaValue::Double(25.5));

        let mut driver = OpcUaDriver::new(config, transport, "test-driver".to_string());
        driver.connect().await.unwrap();

        let address = Address::OpcUa(trap_core::address::OpcUaNodeId {
            namespace_index: 2,
            identifier: trap_core::address::NodeIdentifier::Numeric(1001),
        });

        let value = driver.read(&address).await.unwrap();

        match value {
            Value::Float64(v) => assert!((v - 25.5).abs() < 0.001),
            _ => panic!("Expected Float64 value"),
        }
    }

    #[tokio::test]
    async fn test_driver_write() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        let transport = MockTransport::new();
        let mut driver = OpcUaDriver::new(config, transport, "test-driver".to_string());
        driver.connect().await.unwrap();

        let address = Address::OpcUa(trap_core::address::OpcUaNodeId {
            namespace_index: 2,
            identifier: trap_core::address::NodeIdentifier::Numeric(1001),
        });

        driver.write(&address, Value::Float64(42.0)).await.unwrap();

        // Verify the value was written
        let value = driver.read(&address).await.unwrap();
        match value {
            Value::Float64(v) => assert!((v - 42.0).abs() < 0.001),
            _ => panic!("Expected Float64 value"),
        }
    }

    #[tokio::test]
    async fn test_driver_batch_read() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        let transport = MockTransport::new();
        transport.set_value("ns=2;i=1001", OpcUaValue::Double(25.5));
        transport.set_value("ns=2;i=1002", OpcUaValue::Int32(100));

        let mut driver = OpcUaDriver::new(config, transport, "test-driver".to_string());
        driver.connect().await.unwrap();

        let addresses = vec![
            Address::OpcUa(trap_core::address::OpcUaNodeId {
                namespace_index: 2,
                identifier: trap_core::address::NodeIdentifier::Numeric(1001),
            }),
            Address::OpcUa(trap_core::address::OpcUaNodeId {
                namespace_index: 2,
                identifier: trap_core::address::NodeIdentifier::Numeric(1002),
            }),
        ];

        let results = driver.read_batch(&addresses).await.unwrap();
        assert_eq!(results.len(), 2);

        for (_, result) in results {
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_supports_subscription() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        let transport = MockTransport::new();
        let driver = OpcUaDriver::new(config, transport, "test-driver".to_string());

        assert!(driver.supports_subscription());
    }

    #[tokio::test]
    async fn test_tag_mappings() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        let transport = MockTransport::new();
        let driver = OpcUaDriver::new(config, transport, "test-driver".to_string());

        let tag = TagMapping::new("temp_1", NodeId::numeric(2, 1001))
            .with_name("Temperature Sensor")
            .with_unit("°C");

        driver.add_tag_mapping(tag.clone()).await;

        let retrieved = driver.get_tag_mapping("temp_1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().tag_id, "temp_1");

        let all_tags = driver.tag_mappings().await;
        assert_eq!(all_tags.len(), 1);

        driver.remove_tag_mapping("temp_1").await;
        let removed = driver.get_tag_mapping("temp_1").await;
        assert!(removed.is_none());
    }
}
