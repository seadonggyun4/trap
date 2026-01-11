// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA client implementations.
//!
//! This module provides protocol-agnostic client implementations for OPC UA communication:
//!
//! - **Transport Layer**: Abstract transport trait for connection management
//! - **Session Management**: OPC UA session lifecycle handling
//! - **Client Wrapper**: High-level API with retry support and subscription management
//! - **Data Conversion**: Type-safe value conversion utilities
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
//! │                      OpcUaClient                                │
//! │              (High-level read/write/subscribe API)              │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    SessionManager                               │
//! │               (Session lifecycle management)                    │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    OpcUaTransport                               │
//! │               (Abstract transport layer)                        │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Examples
//!
//! ```rust,ignore
//! use trap_opcua::client::{OpcUaClient, SessionManager};
//! use trap_opcua::types::OpcUaConfig;
//!
//! // Create client configuration
//! let config = OpcUaConfig::builder()
//!     .endpoint("opc.tcp://localhost:4840")
//!     .build()?;
//!
//! // Create and connect client
//! let mut client = OpcUaClient::new(config);
//! client.connect().await?;
//!
//! // Read node value
//! let value = client.read_node("ns=2;s=Temperature").await?;
//! println!("Temperature: {:?}", value);
//!
//! // Subscribe to data changes
//! let subscription = client.subscribe(&["ns=2;s=Temperature"]).await?;
//! while let Some(update) = subscription.receiver.recv().await {
//!     println!("Update: {:?}", update);
//! }
//! ```

mod conversion;
mod session;
pub mod subscription;
mod transport;
mod wrapper;

#[cfg(feature = "real-transport")]
mod real_transport;

pub use conversion::{DataConverter, Quality, TypedValue};
pub use session::{SessionManager, SessionState};
pub use subscription::{
    BroadcastCallback, ChannelCallback, MonitoredItem, MonitoredItemId,
    Subscription, SubscriptionBuilder, SubscriptionCallback, SubscriptionId,
    SubscriptionManager, SubscriptionManagerStats, SubscriptionState, SubscriptionStats,
    SubscriptionHandle as ManagedSubscriptionHandle,
    DataChangeNotification as SubscriptionNotification,
};
pub use transport::{BrowseResult, OpcUaTransport, OpcUaValue, ReadResult, TransportState, WriteResult};
pub use wrapper::{ClientStats, DataChangeNotification, OpcUaClient, RetryConfig, RetryStrategy, SubscriptionHandle};

#[cfg(feature = "real-transport")]
pub use real_transport::RealOpcUaTransport;
