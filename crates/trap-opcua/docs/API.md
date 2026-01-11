# trap-opcua API Documentation

> OPC UA Protocol Driver for TRAP Gateway

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Core Components](#core-components)
  - [OpcUaDriver](#opcuadriver)
  - [OpcUaConfig](#opcuaconfig)
  - [NodeId](#nodeid)
- [Operations](#operations)
  - [Connection](#connection)
  - [Read Operations](#read-operations)
  - [Write Operations](#write-operations)
  - [Browse Operations](#browse-operations)
  - [Subscriptions](#subscriptions)
- [Type Conversion](#type-conversion)
- [Error Handling](#error-handling)
- [Tag Mapping](#tag-mapping)
- [Examples](#examples)

---

## Overview

`trap-opcua` provides a comprehensive OPC UA client implementation for the TRAP gateway. It implements the `ProtocolDriver` trait from `trap-core`, enabling seamless integration with other protocol drivers.

### Key Features

- Async/await support with Tokio
- Automatic session management
- Configurable retry logic with exponential backoff
- Subscription support for data change notifications
- Comprehensive type conversion system
- Tag mapping with scaling support
- Health monitoring

---

## Quick Start

```rust
use trap_opcua::{OpcUaConfig, OpcUaDriver, NodeId};
use trap_core::driver::ProtocolDriver;
use trap_core::Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create configuration
    let config = OpcUaConfig::builder()
        .endpoint("opc.tcp://localhost:4840")
        .build()?;

    // 2. Create driver (with mock transport for example)
    let transport = /* your transport implementation */;
    let mut driver = OpcUaDriver::new(config, transport, "my-driver".to_string());

    // 3. Connect
    driver.connect().await?;

    // 4. Read a value
    let address = Address::OpcUa(trap_core::address::OpcUaNodeId {
        namespace_index: 2,
        identifier: trap_core::address::NodeIdentifier::Numeric(1001),
    });

    let value = driver.read(&address).await?;
    println!("Value: {:?}", value);

    // 5. Cleanup
    driver.disconnect().await?;
    Ok(())
}
```

---

## Core Components

### OpcUaDriver

The main driver struct that implements `ProtocolDriver`.

```rust
pub struct OpcUaDriver<T: OpcUaTransport> {
    // ... internal fields
}

impl<T: OpcUaTransport + 'static> OpcUaDriver<T> {
    /// Creates a new OPC UA driver instance.
    pub fn new(config: OpcUaConfig, transport: T, name: String) -> Self;

    /// Returns the driver name.
    pub fn name(&self) -> &str;

    /// Returns the protocol type (always Protocol::OpcUa).
    pub fn protocol(&self) -> Protocol;

    /// Returns the configuration.
    pub fn config(&self) -> &OpcUaConfig;

    /// Returns whether the driver is connected.
    pub fn is_connected(&self) -> bool;

    /// Returns whether subscription is supported (always true).
    pub fn supports_subscription(&self) -> bool;
}
```

#### ProtocolDriver Implementation

```rust
#[async_trait]
impl<T: OpcUaTransport + 'static> ProtocolDriver for OpcUaDriver<T> {
    async fn connect(&mut self) -> DriverResult<()>;
    async fn disconnect(&mut self) -> DriverResult<()>;
    async fn read(&self, address: &Address) -> DriverResult<Value>;
    async fn write(&self, address: &Address, value: Value) -> DriverResult<()>;
    async fn read_batch(&self, addresses: &[Address]) -> DriverResult<Vec<(Address, DriverResult<Value>)>>;
    async fn write_batch(&self, writes: &[(Address, Value)]) -> DriverResult<Vec<(Address, DriverResult<()>)>>;
    async fn subscribe(&mut self, addresses: &[Address]) -> DriverResult<Subscription>;
    async fn unsubscribe(&mut self, subscription_id: &SubscriptionId) -> DriverResult<()>;
    async fn health_check(&self) -> HealthStatus;
    async fn browse(&self) -> DriverResult<Vec<NodeInfo>>;
}
```

### OpcUaConfig

Configuration for the OPC UA driver.

```rust
pub struct OpcUaConfig {
    /// Server endpoint URL (e.g., "opc.tcp://localhost:4840")
    pub endpoint: String,

    /// Application name
    pub application_name: String,

    /// Application URI
    pub application_uri: String,

    /// Security mode (None, Sign, SignAndEncrypt)
    pub security_mode: SecurityMode,

    /// Security policy (None, Basic128Rsa15, Basic256, Basic256Sha256, etc.)
    pub security_policy: SecurityPolicy,

    /// User identity (anonymous, username/password, certificate)
    pub user_identity: UserIdentity,

    /// Session timeout
    pub session_timeout: Duration,

    /// Request timeout
    pub request_timeout: Duration,

    /// Default subscription settings
    pub subscription: SubscriptionSettings,

    /// Certificate configuration
    pub certificate: Option<CertificateConfig>,
}
```

#### Builder Pattern

```rust
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://localhost:4840")
    .application_name("TRAP Gateway")
    .security_mode(SecurityMode::SignAndEncrypt)
    .security_policy(SecurityPolicy::Basic256Sha256)
    .username("admin", "password")
    .session_timeout(Duration::from_secs(3600))
    .request_timeout(Duration::from_secs(30))
    .subscription(SubscriptionSettings {
        publishing_interval: Duration::from_millis(500),
        lifetime_count: 60,
        keepalive_count: 10,
        max_notifications_per_publish: 1000,
        priority: 0,
        publishing_enabled: true,
    })
    .build()?;
```

### NodeId

OPC UA node identifier.

```rust
pub enum NodeId {
    /// Numeric identifier (namespace, id)
    Numeric(u16, u32),

    /// String identifier (namespace, id)
    String(u16, String),

    /// GUID identifier (namespace, guid)
    Guid(u16, uuid::Uuid),

    /// ByteString identifier (namespace, bytes)
    ByteString(u16, Vec<u8>),
}

impl NodeId {
    /// Creates a numeric node ID.
    pub fn numeric(namespace: u16, id: u32) -> Self;

    /// Creates a string node ID.
    pub fn string(namespace: u16, id: impl Into<String>) -> Self;

    /// Creates a GUID node ID.
    pub fn guid(namespace: u16, guid: uuid::Uuid) -> Self;

    /// Returns the namespace index.
    pub fn namespace(&self) -> u16;

    /// Parses a node ID from a string (e.g., "ns=2;i=1001" or "ns=2;s=Temperature").
    pub fn from_str(s: &str) -> Result<Self, OpcUaError>;
}
```

---

## Operations

### Connection

```rust
// Connect to server
driver.connect().await?;

// Check connection status
if driver.is_connected() {
    println!("Connected!");
}

// Disconnect
driver.disconnect().await?;
```

### Read Operations

#### Single Read

```rust
// Using Address enum
let address = Address::OpcUa(OpcUaNodeId {
    namespace_index: 2,
    identifier: NodeIdentifier::Numeric(1001),
});

let value = driver.read(&address).await?;

// Value is trap_core::types::Value
match value {
    Value::Float64(v) => println!("Temperature: {}", v),
    Value::Int32(v) => println!("Counter: {}", v),
    Value::Boolean(v) => println!("Status: {}", v),
    _ => println!("Other value: {:?}", value),
}
```

#### Batch Read

```rust
let addresses = vec![
    Address::OpcUa(OpcUaNodeId {
        namespace_index: 2,
        identifier: NodeIdentifier::Numeric(1001),
    }),
    Address::OpcUa(OpcUaNodeId {
        namespace_index: 2,
        identifier: NodeIdentifier::Numeric(1002),
    }),
];

let results = driver.read_batch(&addresses).await?;

for (address, result) in results {
    match result {
        Ok(value) => println!("{:?} = {:?}", address, value),
        Err(e) => println!("{:?} failed: {}", address, e),
    }
}
```

### Write Operations

#### Single Write

```rust
let address = Address::OpcUa(OpcUaNodeId {
    namespace_index: 2,
    identifier: NodeIdentifier::Numeric(1001),
});

driver.write(&address, Value::Float64(25.5)).await?;
```

#### Batch Write

```rust
let writes = vec![
    (
        Address::OpcUa(OpcUaNodeId {
            namespace_index: 2,
            identifier: NodeIdentifier::Numeric(1001),
        }),
        Value::Float64(25.5),
    ),
    (
        Address::OpcUa(OpcUaNodeId {
            namespace_index: 2,
            identifier: NodeIdentifier::Numeric(1002),
        }),
        Value::Int32(100),
    ),
];

let results = driver.write_batch(&writes).await?;
```

### Browse Operations

```rust
// Browse the server's address space
let nodes = driver.browse().await?;

for node in nodes {
    println!("Node: {} at {}", node.name, node.address);
}
```

### Subscriptions

Subscriptions enable data change notifications without polling.

```rust
// Create subscription
let addresses = vec![
    Address::OpcUa(OpcUaNodeId {
        namespace_index: 2,
        identifier: NodeIdentifier::Numeric(1001),
    }),
    Address::OpcUa(OpcUaNodeId {
        namespace_index: 2,
        identifier: NodeIdentifier::Numeric(1002),
    }),
];

let mut subscription = driver.subscribe(&addresses).await?;
println!("Subscription ID: {:?}", subscription.id);

// Receive data changes
while let Some(data_point) = subscription.receiver.recv().await {
    println!("Data change: {:?} = {:?}", data_point.tag_id, data_point.value);
}

// Unsubscribe when done
driver.unsubscribe(&subscription.id).await?;
```

#### Subscription Settings

```rust
let settings = SubscriptionSettings {
    /// Publishing interval - how often the server sends updates
    publishing_interval: Duration::from_millis(500),

    /// Lifetime count - number of publishing intervals before timeout
    lifetime_count: 60,

    /// Keep-alive count - intervals between keep-alive messages
    keepalive_count: 10,

    /// Max notifications per publish response
    max_notifications_per_publish: 1000,

    /// Priority (0 = lowest)
    priority: 0,

    /// Whether publishing is enabled
    publishing_enabled: true,
};
```

---

## Type Conversion

The driver automatically converts between OPC UA types and `trap-core` types.

### OPC UA to trap-core Mapping

| OPC UA Type | trap-core Value |
|------------|-----------------|
| Boolean | Value::Boolean |
| SByte | Value::Int8 |
| Byte | Value::UInt8 |
| Int16 | Value::Int16 |
| UInt16 | Value::UInt16 |
| Int32 | Value::Int32 |
| UInt32 | Value::UInt32 |
| Int64 | Value::Int64 |
| UInt64 | Value::UInt64 |
| Float | Value::Float32 |
| Double | Value::Float64 |
| String | Value::String |
| DateTime | Value::DateTime |
| ByteString | Value::Bytes |
| XmlElement | Value::String |
| NodeId | Value::String |
| LocalizedText | Value::String |
| Variant Array | Value::Array |

### Quality Information

Read operations include quality information:

```rust
pub struct TypedValue {
    /// The value
    pub value: OpcUaValue,

    /// Quality indicator
    pub quality: Quality,

    /// Server timestamp
    pub server_timestamp: Option<DateTime<Utc>>,

    /// Source timestamp
    pub source_timestamp: Option<DateTime<Utc>>,
}

pub enum Quality {
    Good,
    Uncertain(u32),
    Bad(u32),
}
```

---

## Error Handling

### Error Types

```rust
pub enum OpcUaError {
    /// Configuration errors
    Configuration(ConfigError),

    /// Connection errors (timeout, refused, lost)
    Connection(ConnectionError),

    /// Session errors (creation, activation, timeout)
    Session(SessionError),

    /// Subscription errors (creation, deletion, monitored items)
    Subscription(SubscriptionError),

    /// Operation errors (read, write, browse failures)
    Operation(OperationError),

    /// Type conversion errors
    TypeConversion(TypeConversionError),

    /// Security/certificate errors
    Security(SecurityError),
}
```

### Error Recovery

```rust
// Check if error is retryable
if error.is_retryable() {
    // Automatic retry with configured backoff
}

// Get recovery hints
let hints = error.recovery_hints();
for hint in hints {
    println!("Recovery hint: {}", hint);
}

// Check error severity
match error.severity() {
    ErrorSeverity::Transient => { /* Will likely resolve */ },
    ErrorSeverity::Recoverable => { /* Can be fixed by user action */ },
    ErrorSeverity::Fatal => { /* Requires configuration change */ },
}
```

---

## Tag Mapping

Tag mappings provide named access to nodes with optional scaling.

```rust
// Create a tag mapping
let tag = TagMapping::new("temp_sensor_1", NodeId::numeric(2, 1001))
    .with_name("Temperature Sensor 1")
    .with_description("Main temperature sensor")
    .with_unit("°C")
    .with_scaling(0.1, 0.0)  // scale factor, offset
    .with_range(-40.0, 85.0);

// Add to driver
driver.add_tag_mapping(tag).await;

// Read by tag ID
let mapping = driver.get_tag_mapping("temp_sensor_1").await;
if let Some(mapping) = mapping {
    // Read with scaling applied
    let value = driver.read_mapped(&mapping).await?;
}

// List all tags
let all_tags = driver.tag_mappings().await;

// Remove tag
driver.remove_tag_mapping("temp_sensor_1").await;
```

### TagMapping Structure

```rust
pub struct TagMapping {
    /// Unique tag identifier
    pub tag_id: String,

    /// Node ID in OPC UA server
    pub node_id: NodeId,

    /// Human-readable name
    pub name: Option<String>,

    /// Description
    pub description: Option<String>,

    /// Engineering unit
    pub unit: Option<String>,

    /// Scale factor (raw_value * scale + offset = engineering_value)
    pub scale: f64,

    /// Offset for scaling
    pub offset: f64,

    /// Minimum valid value
    pub min_value: Option<f64>,

    /// Maximum valid value
    pub max_value: Option<f64>,

    /// Whether the node is writable
    pub writable: bool,
}
```

---

## Examples

### Basic Read/Write

```rust
use trap_opcua::{OpcUaConfig, OpcUaDriver};

let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://192.168.1.100:4840")
    .build()?;

let transport = MockTransport::new();
let mut driver = OpcUaDriver::new(config, transport, "plc-driver".to_string());
driver.connect().await?;

// Read
let address = Address::from_str("ns=2;i=1001")?;
let value = driver.read(&address).await?;

// Write
driver.write(&address, Value::Float64(50.0)).await?;
```

### Subscription with Filtering

```rust
use trap_opcua::SubscriptionSettings;

// Custom subscription settings
let settings = SubscriptionSettings {
    publishing_interval: Duration::from_millis(100),  // Fast updates
    lifetime_count: 600,
    keepalive_count: 20,
    max_notifications_per_publish: 100,
    priority: 10,  // Higher priority
    publishing_enabled: true,
};

// Subscribe with custom settings
let mut subscription = driver.subscribe_with_settings(&addresses, settings).await?;

// Process updates
tokio::spawn(async move {
    while let Some(data) = subscription.receiver.recv().await {
        // Process data change
        process_data_change(data).await;
    }
});
```

### Secure Connection

```rust
use trap_opcua::{OpcUaConfig, SecurityMode, SecurityPolicy, CertificateConfig};

let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://192.168.1.100:4840")
    .security_mode(SecurityMode::SignAndEncrypt)
    .security_policy(SecurityPolicy::Basic256Sha256)
    .certificate(CertificateConfig {
        cert_path: "/path/to/client.der".into(),
        private_key_path: "/path/to/client.pem".into(),
        trust_server_certs: false,
        trusted_certs_dir: Some("/path/to/trusted".into()),
        rejected_certs_dir: Some("/path/to/rejected".into()),
    })
    .username("operator", "secret123")
    .build()?;
```

### Health Monitoring

```rust
// Periodic health check
let health = driver.health_check().await;

if health.healthy {
    println!("Driver healthy, latency: {:?}", health.latency);
} else {
    println!("Driver unhealthy: {}", health.message.unwrap_or_default());
}

// Access driver stats
let stats = driver.client_stats();
println!("Reads: {}, Writes: {}, Errors: {}",
    stats.reads(), stats.writes(), stats.errors());
println!("Success rate: {:.2}%", stats.success_rate() * 100.0);
```

---

## API Reference

For complete API documentation, run:

```bash
cargo doc -p trap-opcua --open
```

This will generate and open the Rustdoc documentation with detailed API reference.
