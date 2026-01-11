// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Real OPC UA transport implementation using the `opcua` crate.
//!
//! This module provides a production-ready transport layer for OPC UA communication.
//! It wraps the `opcua` crate's client functionality and implements the `OpcUaTransport` trait.
//!
//! # Features
//!
//! - Connection management with automatic reconnection
//! - Security mode support (None, Sign, SignAndEncrypt)
//! - User authentication (Anonymous, Username/Password, Certificate)
//! - Subscription and monitored item management
//! - Node browsing and attribute reading
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_opcua::client::RealOpcUaTransport;
//! use trap_opcua::types::OpcUaConfig;
//!
//! let config = OpcUaConfig::builder()
//!     .endpoint("opc.tcp://localhost:4840")
//!     .build()?;
//!
//! let mut transport = RealOpcUaTransport::new(config);
//! transport.connect().await?;
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

use opcua::client::prelude::*;
use opcua::sync::RwLock as OpcUaRwLock;

use crate::client::transport::{
    BrowseResult, OpcUaTransport, OpcUaValue, ReadResult, TransportState, WriteResult,
};
use crate::error::{BrowseError, ConnectionError, OpcUaError, OpcUaResult, OperationError, SubscriptionError};
use crate::types::{NodeId, OpcUaConfig, SecurityMode, SecurityPolicy, UserTokenType};

// =============================================================================
// RealOpcUaTransport
// =============================================================================

/// Real OPC UA transport implementation using the `opcua` crate.
///
/// This transport provides actual OPC UA protocol communication with
/// industrial devices and servers.
pub struct RealOpcUaTransport {
    /// Configuration for the transport.
    config: OpcUaConfig,

    /// Current connection state.
    state: RwLock<TransportState>,

    /// The underlying OPC UA session (wrapped in Arc for thread safety).
    session: RwLock<Option<Arc<OpcUaRwLock<Session>>>>,

    /// Active subscriptions by subscription ID.
    subscriptions: RwLock<HashMap<u32, SubscriptionInfo>>,

    /// Subscription ID counter.
    next_subscription_id: AtomicU32,

    /// Monitored item ID counter.
    next_monitored_item_id: AtomicU32,
}

/// Information about an active subscription.
#[derive(Debug)]
struct SubscriptionInfo {
    /// Server-assigned subscription ID.
    server_subscription_id: u32,
    /// Publishing interval.
    publishing_interval: Duration,
    /// Monitored items in this subscription.
    monitored_items: HashMap<u32, MonitoredItemInfo>,
}

/// Information about a monitored item.
#[derive(Debug)]
struct MonitoredItemInfo {
    /// The node being monitored.
    node_id: NodeId,
    /// Server-assigned monitored item ID.
    server_monitored_item_id: u32,
}

impl RealOpcUaTransport {
    /// Creates a new real OPC UA transport with the given configuration.
    pub fn new(config: OpcUaConfig) -> Self {
        Self {
            config,
            state: RwLock::new(TransportState::Disconnected),
            session: RwLock::new(None),
            subscriptions: RwLock::new(HashMap::new()),
            next_subscription_id: AtomicU32::new(1),
            next_monitored_item_id: AtomicU32::new(1),
        }
    }

    /// Builds the OPC UA client from configuration.
    fn build_client(&self) -> OpcUaResult<Client> {
        let mut builder = ClientBuilder::new()
            .application_name(&self.config.application_name)
            .application_uri(&self.config.effective_application_uri())
            .session_retry_limit(self.config.max_retries as i32)
            .session_timeout(self.config.session_timeout.as_millis() as u32);

        // Configure PKI directory
        if let Some(ref pki_dir) = self.config.pki_dir {
            builder = builder.pki_dir(pki_dir);
        }

        // Configure trust settings
        if self.config.trust_all_certificates {
            builder = builder.trust_server_certs(true);
        }

        // Build client
        let client = builder.client().ok_or_else(|| {
            OpcUaError::connection(ConnectionError::invalid_endpoint(
                &self.config.endpoint,
                "Failed to build OPC UA client",
            ))
        })?;

        Ok(client)
    }

    /// Converts our SecurityMode to opcua SecurityPolicy.
    fn get_security_policy(&self) -> opcua::client::prelude::SecurityPolicy {
        match self.config.security_policy {
            SecurityPolicy::None => opcua::client::prelude::SecurityPolicy::None,
            SecurityPolicy::Basic128Rsa15 => opcua::client::prelude::SecurityPolicy::Basic128Rsa15,
            SecurityPolicy::Basic256 => opcua::client::prelude::SecurityPolicy::Basic256,
            SecurityPolicy::Basic256Sha256 => opcua::client::prelude::SecurityPolicy::Basic256Sha256,
            SecurityPolicy::Aes128Sha256RsaOaep => {
                opcua::client::prelude::SecurityPolicy::Aes128Sha256RsaOaep
            }
            SecurityPolicy::Aes256Sha256RsaPss => {
                opcua::client::prelude::SecurityPolicy::Aes256Sha256RsaPss
            }
        }
    }

    /// Converts our SecurityMode to opcua MessageSecurityMode.
    fn get_message_security_mode(&self) -> opcua::types::MessageSecurityMode {
        match self.config.security_mode {
            SecurityMode::None => opcua::types::MessageSecurityMode::None,
            SecurityMode::Sign => opcua::types::MessageSecurityMode::Sign,
            SecurityMode::SignAndEncrypt => opcua::types::MessageSecurityMode::SignAndEncrypt,
        }
    }

    /// Creates identity token from configuration.
    fn get_identity_token(&self) -> IdentityToken {
        match &self.config.user_token {
            UserTokenType::Anonymous => IdentityToken::Anonymous,
            UserTokenType::UserName { username, password } => {
                IdentityToken::UserName(username.clone(), password.clone())
            }
            UserTokenType::Certificate {
                certificate_path,
                private_key_path,
            } => {
                // Load certificate and key for authentication
                IdentityToken::X509(
                    std::path::PathBuf::from(certificate_path),
                    std::path::PathBuf::from(private_key_path),
                )
            }
            UserTokenType::IssuedToken { .. } => {
                // Issued tokens not directly supported, fall back to anonymous
                warn!("Issued token authentication not supported, using anonymous");
                IdentityToken::Anonymous
            }
        }
    }

    /// Converts our NodeId to opcua NodeId.
    fn to_opcua_node_id(node_id: &NodeId) -> opcua::types::NodeId {
        match &node_id.identifier {
            crate::types::NodeIdentifier::Numeric(v) => {
                opcua::types::NodeId::new(node_id.namespace_index, *v)
            }
            crate::types::NodeIdentifier::String(v) => {
                opcua::types::NodeId::new(node_id.namespace_index, v.clone())
            }
            crate::types::NodeIdentifier::Guid(v) => {
                opcua::types::NodeId::new(node_id.namespace_index, opcua::types::Guid::from(*v))
            }
            crate::types::NodeIdentifier::Opaque(v) => {
                opcua::types::NodeId::new(node_id.namespace_index, opcua::types::ByteString::from(v.as_slice()))
            }
        }
    }

    /// Converts opcua NodeId to our NodeId.
    fn from_opcua_node_id(node_id: &opcua::types::NodeId) -> NodeId {
        let namespace_index = node_id.namespace;
        match &node_id.identifier {
            opcua::types::Identifier::Numeric(v) => NodeId::numeric(namespace_index, *v),
            opcua::types::Identifier::String(v) => {
                NodeId::string(namespace_index, v.as_ref())
            }
            opcua::types::Identifier::Guid(v) => {
                NodeId::guid(namespace_index, uuid::Uuid::from_bytes(*v.as_bytes()))
            }
            opcua::types::Identifier::ByteString(v) => {
                NodeId::opaque(namespace_index, v.value.clone().unwrap_or_default())
            }
        }
    }

    /// Converts opcua Variant to our OpcUaValue.
    fn from_opcua_variant(variant: &opcua::types::Variant) -> OpcUaValue {
        use opcua::types::Variant;

        match variant {
            Variant::Empty => OpcUaValue::Null,
            Variant::Boolean(v) => OpcUaValue::Boolean(*v),
            Variant::SByte(v) => OpcUaValue::SByte(*v),
            Variant::Byte(v) => OpcUaValue::Byte(*v),
            Variant::Int16(v) => OpcUaValue::Int16(*v),
            Variant::UInt16(v) => OpcUaValue::UInt16(*v),
            Variant::Int32(v) => OpcUaValue::Int32(*v),
            Variant::UInt32(v) => OpcUaValue::UInt32(*v),
            Variant::Int64(v) => OpcUaValue::Int64(*v),
            Variant::UInt64(v) => OpcUaValue::UInt64(*v),
            Variant::Float(v) => OpcUaValue::Float(*v),
            Variant::Double(v) => OpcUaValue::Double(*v),
            Variant::String(v) => OpcUaValue::String(v.as_ref().to_string()),
            Variant::DateTime(v) => {
                // Convert OPC UA DateTime to chrono
                let dt = chrono::DateTime::from_timestamp(
                    v.as_chrono().timestamp(),
                    v.as_chrono().timestamp_subsec_nanos(),
                )
                .unwrap_or_else(chrono::Utc::now);
                OpcUaValue::DateTime(dt)
            }
            Variant::Guid(v) => {
                OpcUaValue::Guid(uuid::Uuid::from_bytes(*v.as_bytes()))
            }
            Variant::ByteString(v) => {
                OpcUaValue::ByteString(v.value.clone().unwrap_or_default())
            }
            Variant::Array(arr) => {
                let values: Vec<OpcUaValue> = arr
                    .values
                    .iter()
                    .map(Self::from_opcua_variant)
                    .collect();
                OpcUaValue::Array(values)
            }
            _ => {
                // For complex types, try to convert to string
                OpcUaValue::String(format!("{:?}", variant))
            }
        }
    }

    /// Converts our OpcUaValue to opcua Variant.
    fn to_opcua_variant(value: &OpcUaValue) -> opcua::types::Variant {
        use opcua::types::Variant;

        match value {
            OpcUaValue::Null => Variant::Empty,
            OpcUaValue::Boolean(v) => Variant::Boolean(*v),
            OpcUaValue::SByte(v) => Variant::SByte(*v),
            OpcUaValue::Byte(v) => Variant::Byte(*v),
            OpcUaValue::Int16(v) => Variant::Int16(*v),
            OpcUaValue::UInt16(v) => Variant::UInt16(*v),
            OpcUaValue::Int32(v) => Variant::Int32(*v),
            OpcUaValue::UInt32(v) => Variant::UInt32(*v),
            OpcUaValue::Int64(v) => Variant::Int64(*v),
            OpcUaValue::UInt64(v) => Variant::UInt64(*v),
            OpcUaValue::Float(v) => Variant::Float(*v),
            OpcUaValue::Double(v) => Variant::Double(*v),
            OpcUaValue::String(v) => Variant::String(opcua::types::UAString::from(v.as_str())),
            OpcUaValue::DateTime(v) => {
                let opcua_dt = opcua::types::DateTime::from(*v);
                Variant::DateTime(Box::new(opcua_dt))
            }
            OpcUaValue::Guid(v) => {
                Variant::Guid(Box::new(opcua::types::Guid::from(*v)))
            }
            OpcUaValue::ByteString(v) => {
                Variant::ByteString(opcua::types::ByteString::from(v.as_slice()))
            }
            OpcUaValue::Array(arr) => {
                let variants: Vec<opcua::types::Variant> =
                    arr.iter().map(Self::to_opcua_variant).collect();
                Variant::Array(Box::new(opcua::types::Array::new(
                    opcua::types::VariantTypeId::Variant,
                    variants,
                ).unwrap()))
            }
        }
    }

    /// Gets the session, returning an error if not connected.
    async fn get_session(&self) -> OpcUaResult<Arc<OpcUaRwLock<Session>>> {
        let session_guard = self.session.read().await;
        session_guard.clone().ok_or_else(|| {
            OpcUaError::connection(ConnectionError::NotConnected)
        })
    }

}

#[async_trait]
impl OpcUaTransport for RealOpcUaTransport {
    async fn connect(&mut self) -> OpcUaResult<()> {
        // Update state
        {
            let mut state = self.state.write().await;
            *state = TransportState::Connecting;
        }

        info!(endpoint = %self.config.endpoint, "Connecting to OPC UA server");

        // Build client
        let client = self.build_client()?;

        // Get endpoint
        let endpoints = client
            .get_server_endpoints_from_url(&self.config.endpoint)
            .map_err(|e| {
                OpcUaError::connection(ConnectionError::endpoint_not_found(format!(
                    "{}: {}",
                    &self.config.endpoint, e
                )))
            })?;

        // Find matching endpoint
        let security_policy = self.get_security_policy();
        let message_security_mode = self.get_message_security_mode();

        let endpoint = endpoints
            .iter()
            .find(|e| {
                e.security_policy_uri.as_ref() == security_policy.to_uri()
                    && e.security_mode == message_security_mode
            })
            .cloned()
            .ok_or_else(|| {
                OpcUaError::connection(ConnectionError::no_suitable_endpoint(format!(
                    "{:?}/{:?}",
                    security_policy, message_security_mode
                )))
            })?;

        debug!(
            security_policy = %endpoint.security_policy_uri,
            security_mode = ?endpoint.security_mode,
            "Found matching endpoint"
        );

        // Get identity token
        let identity_token = self.get_identity_token();

        // Create session
        let mut client = client;
        let session = client
            .connect_to_endpoint(endpoint, identity_token)
            .map_err(|_| {
                OpcUaError::connection(ConnectionError::refused(&self.config.endpoint))
            })?;

        // Store session
        {
            let mut session_guard = self.session.write().await;
            *session_guard = Some(session);
        }

        // Update state
        {
            let mut state = self.state.write().await;
            *state = TransportState::Connected;
        }

        info!(endpoint = %self.config.endpoint, "Connected to OPC UA server");
        Ok(())
    }

    async fn disconnect(&mut self) -> OpcUaResult<()> {
        info!("Disconnecting from OPC UA server");

        // Get session
        let session_opt = {
            let mut session_guard = self.session.write().await;
            session_guard.take()
        };

        if let Some(session) = session_opt {
            // Close session
            let session_locked = session.read();
            session_locked.disconnect();
        }

        // Clear subscriptions
        {
            let mut subs = self.subscriptions.write().await;
            subs.clear();
        }

        // Update state
        {
            let mut state = self.state.write().await;
            *state = TransportState::Disconnected;
        }

        info!("Disconnected from OPC UA server");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        // Check state synchronously (use try_read for non-async context)
        if let Ok(state) = self.state.try_read() {
            state.is_connected()
        } else {
            false
        }
    }

    fn state(&self) -> TransportState {
        if let Ok(state) = self.state.try_read() {
            *state
        } else {
            TransportState::Disconnected
        }
    }

    async fn read_value(&self, node_id: &NodeId) -> OpcUaResult<ReadResult> {
        let session = self.get_session().await?;
        let opcua_node_id = Self::to_opcua_node_id(node_id);

        trace!(node_id = %node_id, "Reading node value");

        let read_value_id = ReadValueId {
            node_id: opcua_node_id,
            attribute_id: AttributeId::Value as u32,
            index_range: opcua::types::UAString::null(),
            data_encoding: opcua::types::QualifiedName::null(),
        };

        let session_locked = session.read();
        let result = session_locked
            .read(&[read_value_id], TimestampsToReturn::Both, 0.0)
            .map_err(|e| {
                OpcUaError::operation(OperationError::read_failed(
                    node_id.to_string(),
                    format!("Read failed: {:?}", e),
                ))
            })?;

        if result.is_empty() {
            return Ok(ReadResult::failure(node_id.clone(), 0x80000000));
        }

        let data_value = &result[0];
        let status_code = data_value.status.as_ref().map(|s| s.bits()).unwrap_or(0);

        if let Some(ref variant) = data_value.value {
            let value = Self::from_opcua_variant(variant);
            let mut result = ReadResult::success(node_id.clone(), value);
            result.status_code = status_code;
            result.server_timestamp = data_value.server_timestamp.map(|t| {
                chrono::DateTime::from_timestamp(
                    t.as_chrono().timestamp(),
                    t.as_chrono().timestamp_subsec_nanos(),
                )
                .unwrap_or_else(chrono::Utc::now)
            });
            result.source_timestamp = data_value.source_timestamp.map(|t| {
                chrono::DateTime::from_timestamp(
                    t.as_chrono().timestamp(),
                    t.as_chrono().timestamp_subsec_nanos(),
                )
                .unwrap_or_else(chrono::Utc::now)
            });
            Ok(result)
        } else {
            Ok(ReadResult::failure(node_id.clone(), status_code))
        }
    }

    async fn read_values(&self, node_ids: &[NodeId]) -> OpcUaResult<Vec<ReadResult>> {
        if node_ids.is_empty() {
            return Ok(Vec::new());
        }

        let session = self.get_session().await?;
        let read_value_ids: Vec<ReadValueId> = node_ids
            .iter()
            .map(|n| ReadValueId {
                node_id: Self::to_opcua_node_id(n),
                attribute_id: AttributeId::Value as u32,
                index_range: opcua::types::UAString::null(),
                data_encoding: opcua::types::QualifiedName::null(),
            })
            .collect();

        trace!(count = node_ids.len(), "Reading multiple node values");

        let session_locked = session.read();
        let results = session_locked.read(&read_value_ids, TimestampsToReturn::Both, 0.0).map_err(|e| {
            OpcUaError::operation(OperationError::read_failed(
                "batch".to_string(),
                format!("Batch read failed: {:?}", e),
            ))
        })?;

        let mut read_results = Vec::with_capacity(node_ids.len());
        for (i, data_value) in results.iter().enumerate() {
            let node_id = &node_ids[i];
            let status_code = data_value.status.as_ref().map(|s| s.bits()).unwrap_or(0);

            if let Some(ref variant) = data_value.value {
                let value = Self::from_opcua_variant(variant);
                let mut result = ReadResult::success(node_id.clone(), value);
                result.status_code = status_code;
                result.server_timestamp = data_value.server_timestamp.map(|t| {
                    chrono::DateTime::from_timestamp(
                        t.as_chrono().timestamp(),
                        t.as_chrono().timestamp_subsec_nanos(),
                    )
                    .unwrap_or_else(chrono::Utc::now)
                });
                read_results.push(result);
            } else {
                read_results.push(ReadResult::failure(node_id.clone(), status_code));
            }
        }

        Ok(read_results)
    }

    async fn read_attribute(
        &self,
        node_id: &NodeId,
        attribute_id: u32,
    ) -> OpcUaResult<ReadResult> {
        let session = self.get_session().await?;
        let opcua_node_id = Self::to_opcua_node_id(node_id);

        let attr_id = AttributeId::from_u32(attribute_id).unwrap_or(AttributeId::Value);

        trace!(node_id = %node_id, attribute_id = attribute_id, "Reading node attribute");

        let read_value_id = ReadValueId {
            node_id: opcua_node_id,
            attribute_id: attr_id as u32,
            index_range: opcua::types::UAString::null(),
            data_encoding: opcua::types::QualifiedName::null(),
        };

        let session_locked = session.read();
        let result = session_locked
            .read(&[read_value_id], TimestampsToReturn::Both, 0.0)
            .map_err(|e| {
                OpcUaError::operation(OperationError::read_failed(
                    node_id.to_string(),
                    format!("Attribute read failed: {:?}", e),
                ))
            })?;

        if result.is_empty() {
            return Ok(ReadResult::failure(node_id.clone(), 0x80000000));
        }

        let data_value = &result[0];
        let status_code = data_value.status.as_ref().map(|s| s.bits()).unwrap_or(0);

        if let Some(ref variant) = data_value.value {
            let value = Self::from_opcua_variant(variant);
            Ok(ReadResult::success(node_id.clone(), value))
        } else {
            Ok(ReadResult::failure(node_id.clone(), status_code))
        }
    }

    async fn write_value(&self, node_id: &NodeId, value: OpcUaValue) -> OpcUaResult<WriteResult> {
        let session = self.get_session().await?;
        let opcua_node_id = Self::to_opcua_node_id(node_id);
        let variant = Self::to_opcua_variant(&value);

        trace!(node_id = %node_id, "Writing node value");

        let write_value = WriteValue {
            node_id: opcua_node_id,
            attribute_id: AttributeId::Value as u32,
            index_range: opcua::types::UAString::null(),
            value: opcua::types::DataValue::new_now(variant),
        };

        let session_locked = session.read();
        let results = session_locked.write(&[write_value]).map_err(|e| {
            OpcUaError::operation(OperationError::write_failed(
                node_id.to_string(),
                format!("Write failed: {}", e),
            ))
        })?;

        if results.is_empty() {
            return Ok(WriteResult::failure(node_id.clone(), 0x80000000));
        }

        let status_code = results[0].bits();
        if results[0].is_good() {
            Ok(WriteResult::success(node_id.clone()))
        } else {
            Ok(WriteResult::failure(node_id.clone(), status_code))
        }
    }

    async fn write_values(
        &self,
        writes: &[(NodeId, OpcUaValue)],
    ) -> OpcUaResult<Vec<WriteResult>> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }

        let session = self.get_session().await?;

        let write_values: Vec<WriteValue> = writes
            .iter()
            .map(|(node_id, value)| WriteValue {
                node_id: Self::to_opcua_node_id(node_id),
                attribute_id: AttributeId::Value as u32,
                index_range: opcua::types::UAString::null(),
                value: opcua::types::DataValue::new_now(Self::to_opcua_variant(value)),
            })
            .collect();

        trace!(count = writes.len(), "Writing multiple node values");

        let session_locked = session.read();
        let results = session_locked.write(&write_values).map_err(|e| {
            OpcUaError::operation(OperationError::write_failed(
                "batch".to_string(),
                format!("Batch write failed: {}", e),
            ))
        })?;

        let mut write_results = Vec::with_capacity(writes.len());
        for (i, status_code) in results.iter().enumerate() {
            let node_id = &writes[i].0;
            if status_code.is_good() {
                write_results.push(WriteResult::success(node_id.clone()));
            } else {
                write_results.push(WriteResult::failure(node_id.clone(), status_code.bits()));
            }
        }

        Ok(write_results)
    }

    async fn browse(&self, node_id: &NodeId) -> OpcUaResult<Vec<BrowseResult>> {
        self.browse_filtered(node_id, 0, 0).await
    }

    async fn browse_filtered(
        &self,
        node_id: &NodeId,
        direction: u32,
        node_class_mask: u32,
    ) -> OpcUaResult<Vec<BrowseResult>> {
        let session = self.get_session().await?;
        let opcua_node_id = Self::to_opcua_node_id(node_id);

        let browse_direction = match direction {
            0 => BrowseDirection::Forward,
            1 => BrowseDirection::Inverse,
            _ => BrowseDirection::Both,
        };

        trace!(node_id = %node_id, direction = ?browse_direction, "Browsing node");

        let browse_description = BrowseDescription {
            node_id: opcua_node_id,
            browse_direction,
            reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
            include_subtypes: true,
            node_class_mask,
            result_mask: BrowseDescriptionResultMask::all().bits(),
        };

        let session_locked = session.read();
        let browse_results = session_locked
            .browse(&[browse_description])
            .map_err(|e| {
                OpcUaError::browse(BrowseError::browse_failed(
                    node_id.to_string(),
                    format!("Browse failed: {}", e),
                ))
            })?;

        let browse_results = browse_results.ok_or_else(|| {
            OpcUaError::browse(BrowseError::browse_failed(
                node_id.to_string(),
                "No browse results returned",
            ))
        })?;

        if browse_results.is_empty() {
            return Ok(Vec::new());
        }

        let result = &browse_results[0];
        if let Some(ref refs) = result.references {
            let browse_results: Vec<BrowseResult> = refs
                .iter()
                .map(|r| BrowseResult {
                    node_id: Self::from_opcua_node_id(&r.node_id.node_id),
                    browse_name: r.browse_name.name.as_ref().to_string(),
                    display_name: r.display_name.text.as_ref().to_string(),
                    node_class: r.node_class as u32,
                    reference_type: Some(Self::from_opcua_node_id(&r.reference_type_id)),
                    type_definition: Some(Self::from_opcua_node_id(&r.type_definition.node_id)),
                })
                .collect();
            Ok(browse_results)
        } else {
            Ok(Vec::new())
        }
    }

    async fn create_subscription(&self, publishing_interval: Duration) -> OpcUaResult<u32> {
        let session = self.get_session().await?;

        trace!(interval = ?publishing_interval, "Creating subscription");

        let session_locked = session.read();
        let subscription_id = session_locked
            .create_subscription(
                publishing_interval.as_millis() as f64,
                self.config.subscription.lifetime_count,
                self.config.subscription.keepalive_count,
                self.config.subscription.max_notifications_per_publish,
                self.config.subscription.priority,
                self.config.subscription.publishing_enabled,
                DataChangeCallback::new(|_| {
                    // Data change notifications are handled elsewhere
                }),
            )
            .map_err(|e| {
                OpcUaError::subscription(SubscriptionError::creation_failed(format!(
                    "Failed to create subscription: {}",
                    e
                )))
            })?;

        // Store subscription info
        let local_id = self.next_subscription_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut subs = self.subscriptions.write().await;
            subs.insert(
                local_id,
                SubscriptionInfo {
                    server_subscription_id: subscription_id,
                    publishing_interval,
                    monitored_items: HashMap::new(),
                },
            );
        }

        info!(subscription_id = local_id, "Created subscription");
        Ok(local_id)
    }

    async fn delete_subscription(&self, subscription_id: u32) -> OpcUaResult<()> {
        let session = self.get_session().await?;

        // Get server subscription ID
        let server_subscription_id = {
            let subs = self.subscriptions.read().await;
            subs.get(&subscription_id)
                .map(|s| s.server_subscription_id)
                .ok_or_else(|| {
                    OpcUaError::subscription(SubscriptionError::not_found(subscription_id))
                })?
        };

        trace!(subscription_id = subscription_id, "Deleting subscription");

        let session_locked = session.read();
        session_locked
            .delete_subscription(server_subscription_id)
            .map_err(|e| {
                OpcUaError::subscription(SubscriptionError::creation_failed(format!(
                    "Failed to delete subscription: {}",
                    e
                )))
            })?;

        // Remove from local storage
        {
            let mut subs = self.subscriptions.write().await;
            subs.remove(&subscription_id);
        }

        info!(subscription_id = subscription_id, "Deleted subscription");
        Ok(())
    }

    async fn create_monitored_items(
        &self,
        subscription_id: u32,
        node_ids: &[NodeId],
        sampling_interval: Duration,
    ) -> OpcUaResult<Vec<u32>> {
        let session = self.get_session().await?;

        // Get server subscription ID
        let server_subscription_id = {
            let subs = self.subscriptions.read().await;
            subs.get(&subscription_id)
                .map(|s| s.server_subscription_id)
                .ok_or_else(|| {
                    OpcUaError::subscription(SubscriptionError::not_found(subscription_id))
                })?
        };

        let items_to_create: Vec<MonitoredItemCreateRequest> = node_ids
            .iter()
            .map(|node_id| {
                MonitoredItemCreateRequest {
                    item_to_monitor: ReadValueId {
                        node_id: Self::to_opcua_node_id(node_id),
                        attribute_id: AttributeId::Value as u32,
                        index_range: opcua::types::UAString::null(),
                        data_encoding: opcua::types::QualifiedName::null(),
                    },
                    monitoring_mode: MonitoringMode::Reporting,
                    requested_parameters: MonitoringParameters {
                        sampling_interval: sampling_interval.as_millis() as f64,
                        filter: ExtensionObject::null(),
                        queue_size: 10,
                        discard_oldest: true,
                        client_handle: 0,
                    },
                }
            })
            .collect();

        trace!(
            subscription_id = subscription_id,
            count = node_ids.len(),
            "Creating monitored items"
        );

        let session_locked = session.read();
        let results = session_locked
            .create_monitored_items(server_subscription_id, TimestampsToReturn::Both, &items_to_create)
            .map_err(|e| {
                OpcUaError::subscription(SubscriptionError::monitored_item_failed(
                    "batch",
                    format!("Failed to create monitored items: {}", e),
                ))
            })?;

        let mut local_ids = Vec::with_capacity(node_ids.len());
        {
            let mut subs = self.subscriptions.write().await;
            if let Some(sub_info) = subs.get_mut(&subscription_id) {
                for (i, result) in results.iter().enumerate() {
                    if result.status_code.is_good() {
                        let local_id = self.next_monitored_item_id.fetch_add(1, Ordering::SeqCst);
                        sub_info.monitored_items.insert(
                            local_id,
                            MonitoredItemInfo {
                                node_id: node_ids[i].clone(),
                                server_monitored_item_id: result.monitored_item_id,
                            },
                        );
                        local_ids.push(local_id);
                    } else {
                        error!(
                            node_id = %node_ids[i],
                            status = ?result.status_code,
                            "Failed to create monitored item"
                        );
                    }
                }
            }
        }

        info!(
            subscription_id = subscription_id,
            count = local_ids.len(),
            "Created monitored items"
        );
        Ok(local_ids)
    }

    async fn delete_monitored_items(
        &self,
        subscription_id: u32,
        monitored_item_ids: &[u32],
    ) -> OpcUaResult<()> {
        let session = self.get_session().await?;

        // Get server subscription ID and monitored item IDs
        let (server_subscription_id, server_item_ids): (u32, Vec<u32>) = {
            let subs = self.subscriptions.read().await;
            let sub_info = subs.get(&subscription_id).ok_or_else(|| {
                OpcUaError::subscription(SubscriptionError::not_found(subscription_id))
            })?;

            let server_ids: Vec<u32> = monitored_item_ids
                .iter()
                .filter_map(|id| sub_info.monitored_items.get(id))
                .map(|info| info.server_monitored_item_id)
                .collect();

            (sub_info.server_subscription_id, server_ids)
        };

        if server_item_ids.is_empty() {
            return Ok(());
        }

        trace!(
            subscription_id = subscription_id,
            count = server_item_ids.len(),
            "Deleting monitored items"
        );

        let session_locked = session.read();
        session_locked
            .delete_monitored_items(server_subscription_id, &server_item_ids)
            .map_err(|e| {
                OpcUaError::subscription(SubscriptionError::monitored_item_failed(
                    "batch",
                    format!("Failed to delete monitored items: {}", e),
                ))
            })?;

        // Remove from local storage
        {
            let mut subs = self.subscriptions.write().await;
            if let Some(sub_info) = subs.get_mut(&subscription_id) {
                for id in monitored_item_ids {
                    sub_info.monitored_items.remove(id);
                }
            }
        }

        info!(
            subscription_id = subscription_id,
            count = monitored_item_ids.len(),
            "Deleted monitored items"
        );
        Ok(())
    }

    fn display_name(&self) -> String {
        format!("RealOpcUaTransport({})", self.config.endpoint)
    }

    fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    fn config(&self) -> &OpcUaConfig {
        &self.config
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_conversion() {
        // Numeric
        let node = NodeId::numeric(2, 1001);
        let opcua_node = RealOpcUaTransport::to_opcua_node_id(&node);
        let back = RealOpcUaTransport::from_opcua_node_id(&opcua_node);
        assert_eq!(node, back);

        // String
        let node = NodeId::string(2, "Test.Node");
        let opcua_node = RealOpcUaTransport::to_opcua_node_id(&node);
        let back = RealOpcUaTransport::from_opcua_node_id(&opcua_node);
        assert_eq!(node, back);
    }

    #[test]
    fn test_value_conversion() {
        // Boolean
        let value = OpcUaValue::Boolean(true);
        let variant = RealOpcUaTransport::to_opcua_variant(&value);
        let back = RealOpcUaTransport::from_opcua_variant(&variant);
        assert_eq!(value, back);

        // Double
        let value = OpcUaValue::Double(3.14159);
        let variant = RealOpcUaTransport::to_opcua_variant(&value);
        let back = RealOpcUaTransport::from_opcua_variant(&variant);
        assert_eq!(value, back);

        // String
        let value = OpcUaValue::String("Hello".to_string());
        let variant = RealOpcUaTransport::to_opcua_variant(&value);
        let back = RealOpcUaTransport::from_opcua_variant(&variant);
        assert_eq!(value, back);
    }

    #[test]
    fn test_transport_creation() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        let transport = RealOpcUaTransport::new(config);
        assert_eq!(transport.state(), TransportState::Disconnected);
        assert!(!transport.is_connected());
    }
}
