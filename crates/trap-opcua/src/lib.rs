// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA protocol driver for TRAP gateway.
//!
//! This crate provides OPC UA client functionality for the TRAP industrial
//! protocol gateway. It implements the `ProtocolDriver` trait from `trap-core`
//! to enable seamless integration with other protocol drivers.
//!
//! # Features
//!
//! - OPC UA client with session management
//! - Node browsing and discovery
//! - Read/Write operations on nodes
//! - Subscription-based data change notifications
//! - Security modes: None, Sign, SignAndEncrypt
//! - Certificate management
//!
//! # Error Handling
//!
//! This crate provides a comprehensive error hierarchy through the [`error`] module:
//!
//! ```text
//! OpcUaError
//! ├── Connection    - Session and endpoint issues
//! ├── Session       - Session lifecycle errors
//! ├── Security      - Authentication and encryption errors
//! ├── Browse        - Node browsing failures
//! ├── Operation     - Read/write operation failures
//! ├── Subscription  - Subscription and monitoring errors
//! ├── Conversion    - Data type conversion errors
//! └── Configuration - Invalid settings
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_opcua::{OpcUaDriver, OpcUaConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = OpcUaConfig::builder()
//!         .endpoint("opc.tcp://localhost:4840")
//!         .build()?;
//!
//!     let driver = OpcUaDriver::new(config);
//!     driver.connect().await?;
//!
//!     // Read a node value
//!     let value = driver.read("ns=2;s=MyNode").await?;
//!     println!("Value: {:?}", value);
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]

pub mod browse;
pub mod certificate;
pub mod client;
pub mod driver;
pub mod error;
pub mod types;

// Re-export commonly used types
pub use error::{
    BrowseError, ConfigurationError, ConnectionError, ConversionError, ErrorCode, ErrorSeverity,
    OpcUaError, OpcUaErrorContext, OpcUaResult, OperationError, SecurityError, SessionError,
    SubscriptionError, TimeoutError,
};

pub use types::{
    AttributeId, BrowseDirection, DeadbandSettings, MonitoredItemSettings, MonitoringMode,
    NodeClass, NodeId, NodeIdentifier, OpcUaConfig, OpcUaConfigBuilder, OpcUaDataType,
    SecurityMode, SecurityPolicy, SubscriptionSettings, TagMapping, UserTokenType,
};

// Re-export client types
pub use client::{
    DataConverter, OpcUaClient, OpcUaTransport, RetryConfig, RetryStrategy,
    SessionManager, SessionState, TransportState, TypedValue, ClientStats,
};

// Re-export real transport when feature is enabled
#[cfg(feature = "real-transport")]
pub use client::RealOpcUaTransport;

// Re-export subscription types
pub use client::{
    BroadcastCallback, ChannelCallback, ManagedSubscriptionHandle, MonitoredItem,
    MonitoredItemId, Subscription, SubscriptionBuilder, SubscriptionCallback,
    SubscriptionId, SubscriptionManager, SubscriptionManagerStats, SubscriptionNotification,
    SubscriptionState, SubscriptionStats,
};

// Re-export driver types
pub use driver::{OpcUaDriver, OpcUaDriverFactory};

// Re-export browse types
pub use browse::{
    BrowseCache, BrowseNode, BrowseOptions, BrowsePath, BrowsePathSegment,
    BrowseStatistics, BrowseTreeConfig, NodeBrowser, NodeBrowserImpl, QualifiedName,
};

// Re-export certificate types
pub use certificate::{
    CertificateConfig, CertificateConfigBuilder, CertificateError, CertificateFormat,
    CertificateGenerator, CertificateManager, CertificateManagerBuilder, CertificateResult,
    CertificateStore, CertificateValidator, FileSystemStore, GeneratedCertificate,
    KeyAlgorithm, KeyUsage, MemoryStore, SelfSignedGenerator, SignatureAlgorithm,
    StoredCertificate, SubjectAltName, SubjectName, TrustStatus, ValidationPolicy,
    ValidationResult, X509Validator,
};
