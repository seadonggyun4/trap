// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA-specific types with comprehensive configuration support.
//!
//! This module provides rich type definitions for OPC UA protocol operations:
//!
//! - **NodeId**: All four OPC UA node identifier types with parsing and validation
//! - **OpcUaDataType**: Data types for node value interpretation
//! - **SecurityMode/Policy**: Security configuration types
//! - **OpcUaConfig**: Client connection configuration with builder
//! - **SubscriptionSettings**: Subscription and monitoring configuration
//! - **TagMapping**: Tag-to-node mapping with data conversion
//!
//! # Examples
//!
//! ```
//! use trap_opcua::types::{NodeId, OpcUaConfig, SecurityMode};
//!
//! // Create a string node ID
//! let node_id = NodeId::string(2, "Temperature.Value");
//!
//! // Create client configuration
//! let config = OpcUaConfig::builder()
//!     .endpoint("opc.tcp://localhost:4840")
//!     .security_mode(SecurityMode::None)
//!     .build()
//!     .unwrap();
//! ```

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ConfigurationError, OpcUaError};

// =============================================================================
// NodeId
// =============================================================================

/// OPC UA Node Identifier.
///
/// A NodeId uniquely identifies a node within an OPC UA server.
/// It consists of a namespace index and an identifier which can be
/// numeric, string, GUID, or opaque (byte string).
///
/// # Examples
///
/// ```
/// use trap_opcua::types::NodeId;
///
/// // Numeric node ID (most common)
/// let numeric = NodeId::numeric(2, 1001);
///
/// // String node ID
/// let string = NodeId::string(2, "MyDevice.Temperature");
///
/// // Parse from string format
/// let parsed: NodeId = "ns=2;s=MyDevice.Temperature".parse().unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId {
    /// Namespace index (0 = OPC UA standard namespace).
    pub namespace_index: u16,

    /// The node identifier.
    pub identifier: NodeIdentifier,
}

impl NodeId {
    // =========================================================================
    // Constructors
    // =========================================================================

    /// Creates a numeric node ID.
    ///
    /// Numeric identifiers are the most efficient and commonly used.
    ///
    /// # Examples
    ///
    /// ```
    /// use trap_opcua::types::NodeId;
    ///
    /// let node = NodeId::numeric(2, 1001);
    /// assert_eq!(node.namespace_index, 2);
    /// ```
    #[inline]
    pub fn numeric(namespace_index: u16, value: u32) -> Self {
        Self {
            namespace_index,
            identifier: NodeIdentifier::Numeric(value),
        }
    }

    /// Creates a string node ID.
    ///
    /// String identifiers are human-readable but less efficient.
    ///
    /// # Examples
    ///
    /// ```
    /// use trap_opcua::types::NodeId;
    ///
    /// let node = NodeId::string(2, "Temperature.Value");
    /// assert!(node.is_string());
    /// ```
    #[inline]
    pub fn string(namespace_index: u16, value: impl Into<String>) -> Self {
        Self {
            namespace_index,
            identifier: NodeIdentifier::String(value.into()),
        }
    }

    /// Creates a GUID node ID.
    ///
    /// GUID identifiers are useful for globally unique identification.
    #[inline]
    pub fn guid(namespace_index: u16, value: Uuid) -> Self {
        Self {
            namespace_index,
            identifier: NodeIdentifier::Guid(value),
        }
    }

    /// Creates a GUID node ID from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid UUID format.
    pub fn guid_from_str(
        namespace_index: u16,
        value: &str,
    ) -> Result<Self, OpcUaError> {
        let uuid = Uuid::parse_str(value).map_err(|e| {
            OpcUaError::configuration(ConfigurationError::invalid_node_id(
                value,
                format!("Invalid GUID format: {}", e),
            ))
        })?;
        Ok(Self::guid(namespace_index, uuid))
    }

    /// Creates an opaque (byte string) node ID.
    ///
    /// Opaque identifiers are application-specific byte arrays.
    #[inline]
    pub fn opaque(namespace_index: u16, value: Vec<u8>) -> Self {
        Self {
            namespace_index,
            identifier: NodeIdentifier::Opaque(value),
        }
    }

    /// Creates an opaque node ID from a base64-encoded string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid base64.
    pub fn opaque_from_base64(
        namespace_index: u16,
        value: &str,
    ) -> Result<Self, OpcUaError> {
        let bytes = BASE64.decode(value).map_err(|e| {
            OpcUaError::configuration(ConfigurationError::invalid_node_id(
                value,
                format!("Invalid base64 format: {}", e),
            ))
        })?;
        Ok(Self::opaque(namespace_index, bytes))
    }

    // =========================================================================
    // Standard Node IDs
    // =========================================================================

    /// Root folder node (ns=0, i=84).
    pub const ROOT_FOLDER: NodeId = NodeId {
        namespace_index: 0,
        identifier: NodeIdentifier::Numeric(84),
    };

    /// Objects folder node (ns=0, i=85).
    pub const OBJECTS_FOLDER: NodeId = NodeId {
        namespace_index: 0,
        identifier: NodeIdentifier::Numeric(85),
    };

    /// Types folder node (ns=0, i=86).
    pub const TYPES_FOLDER: NodeId = NodeId {
        namespace_index: 0,
        identifier: NodeIdentifier::Numeric(86),
    };

    /// Views folder node (ns=0, i=87).
    pub const VIEWS_FOLDER: NodeId = NodeId {
        namespace_index: 0,
        identifier: NodeIdentifier::Numeric(87),
    };

    /// Server node (ns=0, i=2253).
    pub const SERVER: NodeId = NodeId {
        namespace_index: 0,
        identifier: NodeIdentifier::Numeric(2253),
    };

    // =========================================================================
    // Properties
    // =========================================================================

    /// Returns `true` if this is a numeric identifier.
    #[inline]
    pub const fn is_numeric(&self) -> bool {
        matches!(self.identifier, NodeIdentifier::Numeric(_))
    }

    /// Returns `true` if this is a string identifier.
    #[inline]
    pub const fn is_string(&self) -> bool {
        matches!(self.identifier, NodeIdentifier::String(_))
    }

    /// Returns `true` if this is a GUID identifier.
    #[inline]
    pub const fn is_guid(&self) -> bool {
        matches!(self.identifier, NodeIdentifier::Guid(_))
    }

    /// Returns `true` if this is an opaque identifier.
    #[inline]
    pub const fn is_opaque(&self) -> bool {
        matches!(self.identifier, NodeIdentifier::Opaque(_))
    }

    /// Returns `true` if this is in the standard namespace (ns=0).
    #[inline]
    pub const fn is_standard(&self) -> bool {
        self.namespace_index == 0
    }

    /// Returns `true` if this is a null node ID (ns=0, i=0).
    #[inline]
    pub fn is_null(&self) -> bool {
        self.namespace_index == 0 && matches!(self.identifier, NodeIdentifier::Numeric(0))
    }

    /// Returns the null node ID (ns=0, i=0).
    #[inline]
    pub const fn null() -> Self {
        Self {
            namespace_index: 0,
            identifier: NodeIdentifier::Numeric(0),
        }
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    /// Returns the numeric value if this is a numeric identifier.
    #[inline]
    pub fn as_numeric(&self) -> Option<u32> {
        match &self.identifier {
            NodeIdentifier::Numeric(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the string value if this is a string identifier.
    #[inline]
    pub fn as_string(&self) -> Option<&str> {
        match &self.identifier {
            NodeIdentifier::String(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the GUID value if this is a GUID identifier.
    #[inline]
    pub fn as_guid(&self) -> Option<&Uuid> {
        match &self.identifier {
            NodeIdentifier::Guid(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the opaque value if this is an opaque identifier.
    #[inline]
    pub fn as_opaque(&self) -> Option<&[u8]> {
        match &self.identifier {
            NodeIdentifier::Opaque(v) => Some(v),
            _ => None,
        }
    }

    // =========================================================================
    // Conversion
    // =========================================================================

    /// Converts to the OPC UA string format.
    ///
    /// Format: `ns=<namespace>;{i|s|g|b}=<identifier>`
    ///
    /// # Examples
    ///
    /// ```
    /// use trap_opcua::types::NodeId;
    ///
    /// let node = NodeId::numeric(2, 1001);
    /// assert_eq!(node.to_opc_string(), "ns=2;i=1001");
    ///
    /// let node = NodeId::string(2, "MyNode");
    /// assert_eq!(node.to_opc_string(), "ns=2;s=MyNode");
    /// ```
    pub fn to_opc_string(&self) -> String {
        let id_str = match &self.identifier {
            NodeIdentifier::Numeric(v) => format!("i={}", v),
            NodeIdentifier::String(v) => format!("s={}", v),
            NodeIdentifier::Guid(v) => format!("g={}", v),
            NodeIdentifier::Opaque(v) => format!("b={}", BASE64.encode(v)),
        };

        if self.namespace_index == 0 {
            id_str
        } else {
            format!("ns={};{}", self.namespace_index, id_str)
        }
    }

    /// Converts to trap_core::OpcUaNodeId.
    pub fn to_core_node_id(&self) -> trap_core::address::OpcUaNodeId {
        trap_core::address::OpcUaNodeId {
            namespace_index: self.namespace_index,
            identifier: match &self.identifier {
                NodeIdentifier::Numeric(v) => trap_core::address::NodeIdentifier::Numeric(*v),
                NodeIdentifier::String(v) => trap_core::address::NodeIdentifier::String(v.clone()),
                NodeIdentifier::Guid(v) => trap_core::address::NodeIdentifier::Guid(v.to_string()),
                NodeIdentifier::Opaque(v) => trap_core::address::NodeIdentifier::Opaque(v.clone()),
            },
        }
    }

    /// Converts to trap_core::Address.
    pub fn to_address(&self) -> trap_core::Address {
        trap_core::Address::OpcUa(self.to_core_node_id())
    }

    /// Creates from trap_core::OpcUaNodeId.
    pub fn from_core_node_id(node_id: &trap_core::address::OpcUaNodeId) -> Self {
        Self {
            namespace_index: node_id.namespace_index,
            identifier: match &node_id.identifier {
                trap_core::address::NodeIdentifier::Numeric(v) => NodeIdentifier::Numeric(*v),
                trap_core::address::NodeIdentifier::String(v) => NodeIdentifier::String(v.clone()),
                trap_core::address::NodeIdentifier::Guid(v) => {
                    NodeIdentifier::Guid(Uuid::parse_str(v).unwrap_or_default())
                }
                trap_core::address::NodeIdentifier::Opaque(v) => NodeIdentifier::Opaque(v.clone()),
            },
        }
    }

    /// Returns the identifier type as a string.
    pub const fn identifier_type(&self) -> &'static str {
        match &self.identifier {
            NodeIdentifier::Numeric(_) => "Numeric",
            NodeIdentifier::String(_) => "String",
            NodeIdentifier::Guid(_) => "Guid",
            NodeIdentifier::Opaque(_) => "Opaque",
        }
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::null()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_opc_string())
    }
}

impl FromStr for NodeId {
    type Err = OpcUaError;

    /// Parses a NodeId from OPC UA string format.
    ///
    /// Supported formats:
    /// - `ns=2;i=1001` (numeric)
    /// - `ns=2;s=MyNode` (string)
    /// - `ns=2;g=550e8400-e29b-41d4-a716-446655440000` (GUID)
    /// - `ns=2;b=SGVsbG8=` (opaque, base64 encoded)
    /// - `i=1001` (numeric, namespace 0)
    /// - `s=MyNode` (string, namespace 0)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // Parse namespace index
        let (namespace_index, identifier_part) = if s.starts_with("ns=") {
            let parts: Vec<&str> = s.splitn(2, ';').collect();
            if parts.len() != 2 {
                return Err(OpcUaError::configuration(
                    ConfigurationError::invalid_node_id(s, "Missing identifier after namespace"),
                ));
            }

            let ns_str = parts[0].strip_prefix("ns=").unwrap();
            let ns: u16 = ns_str.parse().map_err(|_| {
                OpcUaError::configuration(ConfigurationError::invalid_node_id(
                    s,
                    "Invalid namespace index",
                ))
            })?;

            (ns, parts[1])
        } else {
            (0, s)
        };

        // Parse identifier
        let identifier = if let Some(id) = identifier_part.strip_prefix("i=") {
            let value: u32 = id.parse().map_err(|_| {
                OpcUaError::configuration(ConfigurationError::invalid_node_id(
                    s,
                    "Invalid numeric identifier",
                ))
            })?;
            NodeIdentifier::Numeric(value)
        } else if let Some(id) = identifier_part.strip_prefix("s=") {
            NodeIdentifier::String(id.to_string())
        } else if let Some(id) = identifier_part.strip_prefix("g=") {
            let uuid = Uuid::parse_str(id).map_err(|e| {
                OpcUaError::configuration(ConfigurationError::invalid_node_id(
                    s,
                    format!("Invalid GUID: {}", e),
                ))
            })?;
            NodeIdentifier::Guid(uuid)
        } else if let Some(id) = identifier_part.strip_prefix("b=") {
            let bytes = BASE64.decode(id).map_err(|e| {
                OpcUaError::configuration(ConfigurationError::invalid_node_id(
                    s,
                    format!("Invalid base64: {}", e),
                ))
            })?;
            NodeIdentifier::Opaque(bytes)
        } else {
            return Err(OpcUaError::configuration(ConfigurationError::invalid_node_id(
                s,
                "Unknown identifier type. Expected i=, s=, g=, or b=",
            )));
        };

        Ok(Self {
            namespace_index,
            identifier,
        })
    }
}

// =============================================================================
// NodeIdentifier
// =============================================================================

/// OPC UA node identifier types.
///
/// This enum represents the four types of node identifiers defined
/// by the OPC UA specification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum NodeIdentifier {
    /// Numeric identifier (most efficient, commonly used for standard nodes).
    Numeric(u32),

    /// String identifier (human-readable, used for custom nodes).
    String(String),

    /// GUID identifier (globally unique).
    Guid(Uuid),

    /// Opaque identifier (application-specific byte array).
    Opaque(Vec<u8>),
}

impl NodeIdentifier {
    /// Returns the identifier type prefix for OPC UA string format.
    pub const fn type_prefix(&self) -> char {
        match self {
            Self::Numeric(_) => 'i',
            Self::String(_) => 's',
            Self::Guid(_) => 'g',
            Self::Opaque(_) => 'b',
        }
    }
}

impl fmt::Display for NodeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Numeric(v) => write!(f, "i={}", v),
            Self::String(v) => write!(f, "s={}", v),
            Self::Guid(v) => write!(f, "g={}", v),
            Self::Opaque(v) => write!(f, "b={}", BASE64.encode(v)),
        }
    }
}

// =============================================================================
// OpcUaDataType
// =============================================================================

/// OPC UA data types for value interpretation.
///
/// This enum maps to OPC UA built-in data types and provides
/// conversion to/from trap_core::Value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OpcUaDataType {
    /// Boolean value.
    Boolean,

    /// Signed 8-bit integer.
    SByte,

    /// Unsigned 8-bit integer.
    Byte,

    /// Signed 16-bit integer.
    Int16,

    /// Unsigned 16-bit integer.
    UInt16,

    /// Signed 32-bit integer.
    Int32,

    /// Unsigned 32-bit integer.
    #[default]
    UInt32,

    /// Signed 64-bit integer.
    Int64,

    /// Unsigned 64-bit integer.
    UInt64,

    /// 32-bit IEEE 754 float.
    Float,

    /// 64-bit IEEE 754 double.
    Double,

    /// UTF-8 string.
    String,

    /// Date and time.
    DateTime,

    /// GUID.
    Guid,

    /// Raw byte string.
    ByteString,

    /// XML element.
    XmlElement,

    /// Node ID.
    NodeId,

    /// Expanded node ID.
    ExpandedNodeId,

    /// Status code.
    StatusCode,

    /// Qualified name.
    QualifiedName,

    /// Localized text.
    LocalizedText,

    /// Variant (can contain any type).
    Variant,
}

impl OpcUaDataType {
    /// Returns the OPC UA type ID for built-in types.
    pub const fn type_id(&self) -> u32 {
        match self {
            Self::Boolean => 1,
            Self::SByte => 2,
            Self::Byte => 3,
            Self::Int16 => 4,
            Self::UInt16 => 5,
            Self::Int32 => 6,
            Self::UInt32 => 7,
            Self::Int64 => 8,
            Self::UInt64 => 9,
            Self::Float => 10,
            Self::Double => 11,
            Self::String => 12,
            Self::DateTime => 13,
            Self::Guid => 14,
            Self::ByteString => 15,
            Self::XmlElement => 16,
            Self::NodeId => 17,
            Self::ExpandedNodeId => 18,
            Self::StatusCode => 19,
            Self::QualifiedName => 20,
            Self::LocalizedText => 21,
            Self::Variant => 24,
        }
    }

    /// Returns `true` if this is a numeric type.
    #[inline]
    pub const fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::SByte
                | Self::Byte
                | Self::Int16
                | Self::UInt16
                | Self::Int32
                | Self::UInt32
                | Self::Int64
                | Self::UInt64
                | Self::Float
                | Self::Double
        )
    }

    /// Returns `true` if this is an integer type.
    #[inline]
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::SByte
                | Self::Byte
                | Self::Int16
                | Self::UInt16
                | Self::Int32
                | Self::UInt32
                | Self::Int64
                | Self::UInt64
        )
    }

    /// Returns `true` if this is a floating point type.
    #[inline]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float | Self::Double)
    }

    /// Returns `true` if this is a signed type.
    #[inline]
    pub const fn is_signed(&self) -> bool {
        matches!(
            self,
            Self::SByte | Self::Int16 | Self::Int32 | Self::Int64 | Self::Float | Self::Double
        )
    }

    /// Returns the byte size for fixed-size types, None for variable types.
    pub const fn byte_size(&self) -> Option<usize> {
        match self {
            Self::Boolean | Self::SByte | Self::Byte => Some(1),
            Self::Int16 | Self::UInt16 => Some(2),
            Self::Int32 | Self::UInt32 | Self::Float | Self::StatusCode => Some(4),
            Self::Int64 | Self::UInt64 | Self::Double | Self::DateTime => Some(8),
            Self::Guid => Some(16),
            _ => None, // Variable-length types
        }
    }

    /// Converts to trap_core::DataType.
    pub const fn to_core_data_type(&self) -> trap_core::DataType {
        match self {
            Self::Boolean => trap_core::DataType::Bool,
            Self::SByte => trap_core::DataType::Int8,
            Self::Byte => trap_core::DataType::UInt8,
            Self::Int16 => trap_core::DataType::Int16,
            Self::UInt16 => trap_core::DataType::UInt16,
            Self::Int32 => trap_core::DataType::Int32,
            Self::UInt32 => trap_core::DataType::UInt32,
            Self::Int64 => trap_core::DataType::Int64,
            Self::UInt64 => trap_core::DataType::UInt64,
            Self::Float => trap_core::DataType::Float32,
            Self::Double => trap_core::DataType::Float64,
            Self::String | Self::XmlElement | Self::LocalizedText => trap_core::DataType::String,
            Self::ByteString => trap_core::DataType::Bytes,
            Self::DateTime => trap_core::DataType::DateTime,
            _ => trap_core::DataType::Unknown,
        }
    }

    /// Creates from trap_core::DataType.
    pub fn from_core_data_type(dt: trap_core::DataType) -> Self {
        match dt {
            trap_core::DataType::Bool => Self::Boolean,
            trap_core::DataType::Int8 => Self::SByte,
            trap_core::DataType::UInt8 => Self::Byte,
            trap_core::DataType::Int16 => Self::Int16,
            trap_core::DataType::UInt16 => Self::UInt16,
            trap_core::DataType::Int32 => Self::Int32,
            trap_core::DataType::UInt32 => Self::UInt32,
            trap_core::DataType::Int64 => Self::Int64,
            trap_core::DataType::UInt64 => Self::UInt64,
            trap_core::DataType::Float32 => Self::Float,
            trap_core::DataType::Float64 => Self::Double,
            trap_core::DataType::String => Self::String,
            trap_core::DataType::Bytes => Self::ByteString,
            trap_core::DataType::DateTime => Self::DateTime,
            _ => Self::Variant,
        }
    }

    /// Returns the display name.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Boolean => "Boolean",
            Self::SByte => "SByte",
            Self::Byte => "Byte",
            Self::Int16 => "Int16",
            Self::UInt16 => "UInt16",
            Self::Int32 => "Int32",
            Self::UInt32 => "UInt32",
            Self::Int64 => "Int64",
            Self::UInt64 => "UInt64",
            Self::Float => "Float",
            Self::Double => "Double",
            Self::String => "String",
            Self::DateTime => "DateTime",
            Self::Guid => "Guid",
            Self::ByteString => "ByteString",
            Self::XmlElement => "XmlElement",
            Self::NodeId => "NodeId",
            Self::ExpandedNodeId => "ExpandedNodeId",
            Self::StatusCode => "StatusCode",
            Self::QualifiedName => "QualifiedName",
            Self::LocalizedText => "LocalizedText",
            Self::Variant => "Variant",
        }
    }
}

impl fmt::Display for OpcUaDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for OpcUaDataType {
    type Err = OpcUaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bool" | "boolean" => Ok(Self::Boolean),
            "sbyte" | "int8" | "i8" => Ok(Self::SByte),
            "byte" | "uint8" | "u8" => Ok(Self::Byte),
            "int16" | "i16" | "short" => Ok(Self::Int16),
            "uint16" | "u16" | "ushort" => Ok(Self::UInt16),
            "int32" | "i32" | "int" => Ok(Self::Int32),
            "uint32" | "u32" | "uint" => Ok(Self::UInt32),
            "int64" | "i64" | "long" => Ok(Self::Int64),
            "uint64" | "u64" | "ulong" => Ok(Self::UInt64),
            "float" | "f32" | "single" => Ok(Self::Float),
            "double" | "f64" => Ok(Self::Double),
            "string" | "str" => Ok(Self::String),
            "datetime" | "date" | "time" => Ok(Self::DateTime),
            "guid" | "uuid" => Ok(Self::Guid),
            "bytestring" | "bytes" | "binary" => Ok(Self::ByteString),
            "xml" | "xmlelement" => Ok(Self::XmlElement),
            "nodeid" => Ok(Self::NodeId),
            "expandednodeid" => Ok(Self::ExpandedNodeId),
            "statuscode" | "status" => Ok(Self::StatusCode),
            "qualifiedname" | "qname" => Ok(Self::QualifiedName),
            "localizedtext" | "text" => Ok(Self::LocalizedText),
            "variant" | "any" => Ok(Self::Variant),
            _ => Err(OpcUaError::configuration(ConfigurationError::invalid_data_type(s))),
        }
    }
}

// =============================================================================
// SecurityMode
// =============================================================================

/// OPC UA message security mode.
///
/// Defines the level of security applied to messages exchanged
/// between client and server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecurityMode {
    /// No security (messages are neither signed nor encrypted).
    #[default]
    None,

    /// Messages are signed but not encrypted.
    Sign,

    /// Messages are signed and encrypted (most secure).
    SignAndEncrypt,
}

impl SecurityMode {
    /// Returns the OPC UA security mode value.
    pub const fn value(&self) -> u32 {
        match self {
            Self::None => 1,
            Self::Sign => 2,
            Self::SignAndEncrypt => 3,
        }
    }

    /// Creates from OPC UA security mode value.
    pub fn from_value(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::None),
            2 => Some(Self::Sign),
            3 => Some(Self::SignAndEncrypt),
            _ => Option::None,
        }
    }

    /// Returns `true` if this mode provides message signing.
    #[inline]
    pub const fn is_signed(&self) -> bool {
        matches!(self, Self::Sign | Self::SignAndEncrypt)
    }

    /// Returns `true` if this mode provides message encryption.
    #[inline]
    pub const fn is_encrypted(&self) -> bool {
        matches!(self, Self::SignAndEncrypt)
    }

    /// Returns `true` if this mode provides no security.
    #[inline]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns the display name.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Sign => "Sign",
            Self::SignAndEncrypt => "SignAndEncrypt",
        }
    }
}

impl fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for SecurityMode {
    type Err = OpcUaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace(['-', '_'], "").as_str() {
            "none" | "nosecurity" => Ok(Self::None),
            "sign" | "signed" => Ok(Self::Sign),
            "signandencrypt" | "signencrypt" | "encrypted" => Ok(Self::SignAndEncrypt),
            _ => Err(OpcUaError::configuration(
                ConfigurationError::invalid_security_mode(s),
            )),
        }
    }
}

// =============================================================================
// SecurityPolicy
// =============================================================================

/// OPC UA security policy.
///
/// Defines the cryptographic algorithms used for securing messages.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecurityPolicy {
    /// No security policy (use with SecurityMode::None).
    #[default]
    None,

    /// Basic128Rsa15 (deprecated, for legacy systems).
    Basic128Rsa15,

    /// Basic256 (deprecated, for legacy systems).
    Basic256,

    /// Basic256Sha256 (recommended minimum).
    Basic256Sha256,

    /// Aes128Sha256RsaOaep.
    Aes128Sha256RsaOaep,

    /// Aes256Sha256RsaPss (most secure).
    Aes256Sha256RsaPss,
}

impl SecurityPolicy {
    /// Returns the OPC UA policy URI.
    pub const fn uri(&self) -> &'static str {
        match self {
            Self::None => "http://opcfoundation.org/UA/SecurityPolicy#None",
            Self::Basic128Rsa15 => "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
            Self::Basic256 => "http://opcfoundation.org/UA/SecurityPolicy#Basic256",
            Self::Basic256Sha256 => "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            Self::Aes128Sha256RsaOaep => {
                "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
            }
            Self::Aes256Sha256RsaPss => {
                "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
            }
        }
    }

    /// Returns the short name.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Basic128Rsa15 => "Basic128Rsa15",
            Self::Basic256 => "Basic256",
            Self::Basic256Sha256 => "Basic256Sha256",
            Self::Aes128Sha256RsaOaep => "Aes128Sha256RsaOaep",
            Self::Aes256Sha256RsaPss => "Aes256Sha256RsaPss",
        }
    }

    /// Returns `true` if this policy is deprecated.
    #[inline]
    pub const fn is_deprecated(&self) -> bool {
        matches!(self, Self::Basic128Rsa15 | Self::Basic256)
    }

    /// Returns `true` if certificates are required for this policy.
    #[inline]
    pub const fn requires_certificates(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Returns the recommended key length for this policy.
    pub const fn recommended_key_length(&self) -> Option<u32> {
        match self {
            Self::None => Option::None,
            Self::Basic128Rsa15 | Self::Basic256 => Some(1024),
            Self::Basic256Sha256 | Self::Aes128Sha256RsaOaep => Some(2048),
            Self::Aes256Sha256RsaPss => Some(4096),
        }
    }

    /// Creates from URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            s if s.ends_with("#None") => Some(Self::None),
            s if s.ends_with("#Basic128Rsa15") => Some(Self::Basic128Rsa15),
            s if s.ends_with("#Basic256") => Some(Self::Basic256),
            s if s.ends_with("#Basic256Sha256") => Some(Self::Basic256Sha256),
            s if s.contains("Aes128_Sha256_RsaOaep") => Some(Self::Aes128Sha256RsaOaep),
            s if s.contains("Aes256_Sha256_RsaPss") => Some(Self::Aes256Sha256RsaPss),
            _ => Option::None,
        }
    }
}

impl fmt::Display for SecurityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for SecurityPolicy {
    type Err = OpcUaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try URI first
        if let Some(policy) = Self::from_uri(s) {
            return Ok(policy);
        }

        // Try name matching
        match s.to_lowercase().replace(['-', '_'], "").as_str() {
            "none" => Ok(Self::None),
            "basic128rsa15" | "basic128" => Ok(Self::Basic128Rsa15),
            "basic256" => Ok(Self::Basic256),
            "basic256sha256" => Ok(Self::Basic256Sha256),
            "aes128sha256rsaoaep" | "aes128" => Ok(Self::Aes128Sha256RsaOaep),
            "aes256sha256rsapss" | "aes256" => Ok(Self::Aes256Sha256RsaPss),
            _ => Err(OpcUaError::configuration(
                ConfigurationError::invalid_security_policy(s),
            )),
        }
    }
}

// =============================================================================
// UserTokenType
// =============================================================================

/// OPC UA user token type.
///
/// Defines how the client authenticates to the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserTokenType {
    /// Anonymous authentication.
    #[default]
    Anonymous,

    /// Username and password authentication.
    UserName {
        /// The username.
        username: String,
        /// The password.
        password: String,
    },

    /// X.509 certificate authentication.
    Certificate {
        /// Path to the certificate file.
        certificate_path: String,
        /// Path to the private key file.
        private_key_path: String,
    },

    /// Issued token (e.g., Kerberos, OAuth).
    IssuedToken {
        /// Token type identifier.
        token_type: String,
        /// Token data.
        token_data: String,
    },
}

impl UserTokenType {
    /// Returns `true` if this is anonymous authentication.
    #[inline]
    pub fn is_anonymous(&self) -> bool {
        matches!(self, Self::Anonymous)
    }

    /// Returns `true` if this requires credentials.
    #[inline]
    pub fn requires_credentials(&self) -> bool {
        !matches!(self, Self::Anonymous)
    }

    /// Returns the type name.
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Anonymous => "Anonymous",
            Self::UserName { .. } => "UserName",
            Self::Certificate { .. } => "Certificate",
            Self::IssuedToken { .. } => "IssuedToken",
        }
    }
}

impl fmt::Display for UserTokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => write!(f, "Anonymous"),
            Self::UserName { username, .. } => write!(f, "UserName({})", username),
            Self::Certificate { certificate_path, .. } => {
                write!(f, "Certificate({})", certificate_path)
            }
            Self::IssuedToken { token_type, .. } => write!(f, "IssuedToken({})", token_type),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

// =============================================================================
// OpcUaConfig
// =============================================================================

/// OPC UA client configuration.
///
/// Provides comprehensive configuration for connecting to an OPC UA server
/// including security, session, and subscription settings.
///
/// # Examples
///
/// ```
/// use trap_opcua::types::{OpcUaConfig, SecurityMode, SecurityPolicy};
///
/// // Simple anonymous connection
/// let config = OpcUaConfig::builder()
///     .endpoint("opc.tcp://localhost:4840")
///     .build()
///     .unwrap();
///
/// // Secure connection with username/password (trust_all_certificates for testing)
/// let config = OpcUaConfig::builder()
///     .endpoint("opc.tcp://secure-server:4840")
///     .security_mode(SecurityMode::SignAndEncrypt)
///     .security_policy(SecurityPolicy::Basic256Sha256)
///     .username("admin", "password")
///     .trust_all_certificates(true)  // Only for testing!
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcUaConfig {
    /// Server endpoint URL (e.g., "opc.tcp://localhost:4840").
    pub endpoint: String,

    /// Security mode.
    #[serde(default)]
    pub security_mode: SecurityMode,

    /// Security policy.
    #[serde(default)]
    pub security_policy: SecurityPolicy,

    /// User authentication token.
    #[serde(default)]
    pub user_token: UserTokenType,

    /// Application name (used in certificate generation).
    #[serde(default = "default_application_name")]
    pub application_name: String,

    /// Application URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_uri: Option<String>,

    /// Product URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_uri: Option<String>,

    /// Session name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,

    /// Session timeout.
    #[serde(default = "default_session_timeout")]
    #[serde(with = "humantime_serde")]
    pub session_timeout: Duration,

    /// Request timeout for operations.
    #[serde(default = "default_request_timeout")]
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,

    /// Connection timeout.
    #[serde(default = "default_connect_timeout")]
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Maximum retries for connection.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Retry delay.
    #[serde(default = "default_retry_delay")]
    #[serde(with = "humantime_serde")]
    pub retry_delay: Duration,

    /// Session keepalive interval.
    #[serde(default = "default_keepalive_interval")]
    #[serde(with = "humantime_serde")]
    pub keepalive_interval: Duration,

    /// Path to client certificate file (for secure connections).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_path: Option<String>,

    /// Path to client private key file (for secure connections).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<String>,

    /// PKI directory for storing trusted certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pki_dir: Option<String>,

    /// Whether to trust all server certificates (insecure, for testing only).
    #[serde(default)]
    pub trust_all_certificates: bool,

    /// Default subscription settings.
    #[serde(default)]
    pub subscription: SubscriptionSettings,
}

fn default_application_name() -> String {
    "TRAP OPC UA Client".to_string()
}

fn default_session_timeout() -> Duration {
    Duration::from_secs(60)
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_delay() -> Duration {
    Duration::from_secs(1)
}

fn default_keepalive_interval() -> Duration {
    Duration::from_secs(10)
}

impl OpcUaConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> OpcUaConfigBuilder {
        OpcUaConfigBuilder::default()
    }

    /// Creates a simple configuration with just the endpoint.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Default::default()
        }
    }

    /// Validates this configuration.
    pub fn validate(&self) -> Result<(), OpcUaError> {
        // Validate endpoint
        if self.endpoint.is_empty() {
            return Err(OpcUaError::configuration(ConfigurationError::missing_field(
                "endpoint",
            )));
        }

        if !self.endpoint.starts_with("opc.tcp://") {
            return Err(OpcUaError::configuration(ConfigurationError::invalid_endpoint(
                &self.endpoint,
                "Endpoint must start with opc.tcp://",
            )));
        }

        // Validate security mode and policy combination
        if self.security_mode != SecurityMode::None && self.security_policy == SecurityPolicy::None
        {
            return Err(OpcUaError::configuration(ConfigurationError::invalid_security(
                "Security mode requires a security policy other than None",
            )));
        }

        if self.security_mode == SecurityMode::None && self.security_policy != SecurityPolicy::None
        {
            return Err(OpcUaError::configuration(ConfigurationError::invalid_security(
                "Security policy requires a security mode other than None",
            )));
        }

        // Validate certificate paths for secure connections
        if self.security_policy.requires_certificates() {
            if self.certificate_path.is_none() && !self.trust_all_certificates {
                return Err(OpcUaError::configuration(
                    ConfigurationError::missing_field("certificate_path"),
                ));
            }
            if self.private_key_path.is_none() && !self.trust_all_certificates {
                return Err(OpcUaError::configuration(
                    ConfigurationError::missing_field("private_key_path"),
                ));
            }
        }

        // Validate timeouts
        if self.session_timeout.is_zero() {
            return Err(OpcUaError::configuration(ConfigurationError::invalid_timeout(
                self.session_timeout,
                "Session timeout must be greater than 0",
            )));
        }

        Ok(())
    }

    /// Returns the effective application URI.
    pub fn effective_application_uri(&self) -> String {
        self.application_uri
            .clone()
            .unwrap_or_else(|| format!("urn:trap:opcua:{}", self.application_name.replace(' ', "")))
    }

    /// Returns `true` if this configuration uses security.
    #[inline]
    pub fn uses_security(&self) -> bool {
        self.security_mode != SecurityMode::None
    }
}

impl Default for OpcUaConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            security_mode: SecurityMode::default(),
            security_policy: SecurityPolicy::default(),
            user_token: UserTokenType::default(),
            application_name: default_application_name(),
            application_uri: None,
            product_uri: None,
            session_name: None,
            session_timeout: default_session_timeout(),
            request_timeout: default_request_timeout(),
            connect_timeout: default_connect_timeout(),
            max_retries: default_max_retries(),
            retry_delay: default_retry_delay(),
            keepalive_interval: default_keepalive_interval(),
            certificate_path: None,
            private_key_path: None,
            pki_dir: None,
            trust_all_certificates: false,
            subscription: SubscriptionSettings::default(),
        }
    }
}

// =============================================================================
// OpcUaConfigBuilder
// =============================================================================

/// Builder for `OpcUaConfig`.
#[derive(Debug, Default)]
pub struct OpcUaConfigBuilder {
    endpoint: Option<String>,
    security_mode: Option<SecurityMode>,
    security_policy: Option<SecurityPolicy>,
    user_token: Option<UserTokenType>,
    application_name: Option<String>,
    application_uri: Option<String>,
    product_uri: Option<String>,
    session_name: Option<String>,
    session_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    max_retries: Option<u32>,
    retry_delay: Option<Duration>,
    keepalive_interval: Option<Duration>,
    certificate_path: Option<String>,
    private_key_path: Option<String>,
    pki_dir: Option<String>,
    trust_all_certificates: Option<bool>,
    subscription: Option<SubscriptionSettings>,
}

impl OpcUaConfigBuilder {
    /// Sets the server endpoint URL.
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Sets the security mode.
    pub fn security_mode(mut self, mode: SecurityMode) -> Self {
        self.security_mode = Some(mode);
        self
    }

    /// Sets the security policy.
    pub fn security_policy(mut self, policy: SecurityPolicy) -> Self {
        self.security_policy = Some(policy);
        self
    }

    /// Sets username/password authentication.
    pub fn username(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.user_token = Some(UserTokenType::UserName {
            username: username.into(),
            password: password.into(),
        });
        self
    }

    /// Sets anonymous authentication.
    pub fn anonymous(mut self) -> Self {
        self.user_token = Some(UserTokenType::Anonymous);
        self
    }

    /// Sets certificate authentication.
    pub fn certificate_auth(
        mut self,
        certificate_path: impl Into<String>,
        private_key_path: impl Into<String>,
    ) -> Self {
        self.user_token = Some(UserTokenType::Certificate {
            certificate_path: certificate_path.into(),
            private_key_path: private_key_path.into(),
        });
        self
    }

    /// Sets the application name.
    pub fn application_name(mut self, name: impl Into<String>) -> Self {
        self.application_name = Some(name.into());
        self
    }

    /// Sets the application URI.
    pub fn application_uri(mut self, uri: impl Into<String>) -> Self {
        self.application_uri = Some(uri.into());
        self
    }

    /// Sets the session name.
    pub fn session_name(mut self, name: impl Into<String>) -> Self {
        self.session_name = Some(name.into());
        self
    }

    /// Sets the session timeout.
    pub fn session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = Some(timeout);
        self
    }

    /// Sets the request timeout.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Sets the connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Sets the maximum connection retries.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = Some(retries);
        self
    }

    /// Sets the retry delay.
    pub fn retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = Some(delay);
        self
    }

    /// Sets the keepalive interval.
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive_interval = Some(interval);
        self
    }

    /// Sets the client certificate path.
    pub fn certificate_path(mut self, path: impl Into<String>) -> Self {
        self.certificate_path = Some(path.into());
        self
    }

    /// Sets the client private key path.
    pub fn private_key_path(mut self, path: impl Into<String>) -> Self {
        self.private_key_path = Some(path.into());
        self
    }

    /// Sets the PKI directory.
    pub fn pki_dir(mut self, dir: impl Into<String>) -> Self {
        self.pki_dir = Some(dir.into());
        self
    }

    /// Sets whether to trust all server certificates (insecure).
    pub fn trust_all_certificates(mut self, trust: bool) -> Self {
        self.trust_all_certificates = Some(trust);
        self
    }

    /// Sets the subscription settings.
    pub fn subscription(mut self, settings: SubscriptionSettings) -> Self {
        self.subscription = Some(settings);
        self
    }

    /// Configures for no security (convenient shorthand).
    pub fn no_security(self) -> Self {
        self.security_mode(SecurityMode::None)
            .security_policy(SecurityPolicy::None)
    }

    /// Configures for basic security (Sign + Basic256Sha256).
    pub fn basic_security(self) -> Self {
        self.security_mode(SecurityMode::Sign)
            .security_policy(SecurityPolicy::Basic256Sha256)
    }

    /// Configures for full security (SignAndEncrypt + Aes256Sha256RsaPss).
    pub fn full_security(self) -> Self {
        self.security_mode(SecurityMode::SignAndEncrypt)
            .security_policy(SecurityPolicy::Aes256Sha256RsaPss)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<OpcUaConfig, OpcUaError> {
        let endpoint = self.endpoint.ok_or_else(|| {
            OpcUaError::configuration(ConfigurationError::missing_field("endpoint"))
        })?;

        let config = OpcUaConfig {
            endpoint,
            security_mode: self.security_mode.unwrap_or_default(),
            security_policy: self.security_policy.unwrap_or_default(),
            user_token: self.user_token.unwrap_or_default(),
            application_name: self.application_name.unwrap_or_else(default_application_name),
            application_uri: self.application_uri,
            product_uri: self.product_uri,
            session_name: self.session_name,
            session_timeout: self.session_timeout.unwrap_or_else(default_session_timeout),
            request_timeout: self.request_timeout.unwrap_or_else(default_request_timeout),
            connect_timeout: self.connect_timeout.unwrap_or_else(default_connect_timeout),
            max_retries: self.max_retries.unwrap_or_else(default_max_retries),
            retry_delay: self.retry_delay.unwrap_or_else(default_retry_delay),
            keepalive_interval: self.keepalive_interval.unwrap_or_else(default_keepalive_interval),
            certificate_path: self.certificate_path,
            private_key_path: self.private_key_path,
            pki_dir: self.pki_dir,
            trust_all_certificates: self.trust_all_certificates.unwrap_or(false),
            subscription: self.subscription.unwrap_or_default(),
        };

        config.validate()?;
        Ok(config)
    }
}

// =============================================================================
// SubscriptionSettings
// =============================================================================

/// OPC UA subscription configuration.
///
/// Controls how subscriptions are created and monitored items are sampled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionSettings {
    /// Publishing interval in milliseconds.
    #[serde(default = "default_publishing_interval")]
    #[serde(with = "humantime_serde")]
    pub publishing_interval: Duration,

    /// Lifetime count (number of publishing intervals before subscription expires).
    #[serde(default = "default_lifetime_count")]
    pub lifetime_count: u32,

    /// Max keep-alive count.
    #[serde(default = "default_keepalive_count")]
    pub keepalive_count: u32,

    /// Maximum notifications per publish.
    #[serde(default = "default_max_notifications")]
    pub max_notifications_per_publish: u32,

    /// Priority (0-255, higher is more important).
    #[serde(default)]
    pub priority: u8,

    /// Publishing enabled.
    #[serde(default = "default_true")]
    pub publishing_enabled: bool,
}

fn default_publishing_interval() -> Duration {
    Duration::from_millis(1000)
}

fn default_lifetime_count() -> u32 {
    60
}

fn default_keepalive_count() -> u32 {
    10
}

fn default_max_notifications() -> u32 {
    65535
}

fn default_true() -> bool {
    true
}

impl Default for SubscriptionSettings {
    fn default() -> Self {
        Self {
            publishing_interval: default_publishing_interval(),
            lifetime_count: default_lifetime_count(),
            keepalive_count: default_keepalive_count(),
            max_notifications_per_publish: default_max_notifications(),
            priority: 0,
            publishing_enabled: true,
        }
    }
}

impl SubscriptionSettings {
    /// Creates settings for fast sampling (100ms publishing interval).
    pub fn fast() -> Self {
        Self {
            publishing_interval: Duration::from_millis(100),
            keepalive_count: 5,
            ..Default::default()
        }
    }

    /// Creates settings for slow sampling (5s publishing interval).
    pub fn slow() -> Self {
        Self {
            publishing_interval: Duration::from_secs(5),
            keepalive_count: 20,
            ..Default::default()
        }
    }

    /// Creates settings with custom publishing interval.
    pub fn with_interval(interval: Duration) -> Self {
        Self {
            publishing_interval: interval,
            ..Default::default()
        }
    }
}

// =============================================================================
// MonitoredItemSettings
// =============================================================================

/// Settings for a monitored item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredItemSettings {
    /// Sampling interval.
    #[serde(default = "default_sampling_interval")]
    #[serde(with = "humantime_serde")]
    pub sampling_interval: Duration,

    /// Queue size for buffered values.
    #[serde(default = "default_queue_size")]
    pub queue_size: u32,

    /// Discard policy when queue is full.
    #[serde(default)]
    pub discard_oldest: bool,

    /// Monitoring mode.
    #[serde(default)]
    pub monitoring_mode: MonitoringMode,

    /// Deadband type for filtering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadband: Option<DeadbandSettings>,
}

fn default_sampling_interval() -> Duration {
    Duration::from_millis(250)
}

fn default_queue_size() -> u32 {
    10
}

impl Default for MonitoredItemSettings {
    fn default() -> Self {
        Self {
            sampling_interval: default_sampling_interval(),
            queue_size: default_queue_size(),
            discard_oldest: true,
            monitoring_mode: MonitoringMode::default(),
            deadband: None,
        }
    }
}

impl MonitoredItemSettings {
    /// Creates settings with custom sampling interval.
    pub fn with_sampling_interval(interval: Duration) -> Self {
        Self {
            sampling_interval: interval,
            ..Default::default()
        }
    }

    /// Sets the deadband filter.
    pub fn with_deadband(mut self, deadband: DeadbandSettings) -> Self {
        self.deadband = Some(deadband);
        self
    }
}

// =============================================================================
// MonitoringMode
// =============================================================================

/// OPC UA monitoring mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MonitoringMode {
    /// Monitoring disabled.
    Disabled,

    /// Sampling enabled, reporting disabled.
    Sampling,

    /// Sampling and reporting enabled.
    #[default]
    Reporting,
}

impl MonitoringMode {
    /// Returns the OPC UA value.
    pub const fn value(&self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Sampling => 1,
            Self::Reporting => 2,
        }
    }
}

// =============================================================================
// DeadbandSettings
// =============================================================================

/// Deadband filter settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeadbandSettings {
    /// No deadband filtering.
    #[default]
    None,

    /// Absolute deadband (report if change exceeds absolute value).
    Absolute {
        /// Absolute change threshold.
        value: f64,
    },

    /// Percent deadband (report if change exceeds percentage of EU range).
    Percent {
        /// Percentage of engineering unit range (0-100).
        percent: f64,
    },
}

impl DeadbandSettings {
    /// Creates an absolute deadband.
    pub fn absolute(value: f64) -> Self {
        Self::Absolute { value }
    }

    /// Creates a percent deadband.
    pub fn percent(percent: f64) -> Self {
        Self::Percent { percent }
    }

    /// Returns `true` if this is no deadband.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

// =============================================================================
// TagMapping
// =============================================================================

/// Maps a tag ID to an OPC UA node with conversion settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagMapping {
    /// Unique tag identifier.
    pub tag_id: String,

    /// Human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Tag description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// OPC UA node ID.
    pub node_id: NodeId,

    /// Expected data type (optional, for validation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<OpcUaDataType>,

    /// Engineering unit (e.g., "°C", "kWh").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,

    /// Scale factor for value conversion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scale: Option<f64>,

    /// Offset for value conversion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<f64>,

    /// Whether to subscribe to data changes.
    #[serde(default = "default_true")]
    pub subscribe: bool,

    /// Monitored item settings (for subscriptions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitored_item: Option<MonitoredItemSettings>,

    /// Whether this tag is writable.
    #[serde(default)]
    pub writable: bool,

    /// Custom metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl TagMapping {
    /// Creates a new tag mapping.
    pub fn new(tag_id: impl Into<String>, node_id: NodeId) -> Self {
        Self {
            tag_id: tag_id.into(),
            name: None,
            description: None,
            node_id,
            data_type: None,
            unit: None,
            scale: None,
            offset: None,
            subscribe: true,
            monitored_item: None,
            writable: false,
            metadata: None,
        }
    }

    /// Sets the name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the data type.
    pub fn with_data_type(mut self, data_type: OpcUaDataType) -> Self {
        self.data_type = Some(data_type);
        self
    }

    /// Sets the engineering unit.
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// Sets scaling parameters.
    pub fn with_scaling(mut self, scale: f64, offset: f64) -> Self {
        self.scale = Some(scale);
        self.offset = Some(offset);
        self
    }

    /// Sets the writable flag.
    pub fn with_writable(mut self, writable: bool) -> Self {
        self.writable = writable;
        self
    }

    /// Sets monitored item settings.
    pub fn with_monitored_item(mut self, settings: MonitoredItemSettings) -> Self {
        self.monitored_item = Some(settings);
        self
    }

    /// Disables subscription for this tag.
    pub fn without_subscription(mut self) -> Self {
        self.subscribe = false;
        self
    }

    /// Returns the effective name (tag_id if name is not set).
    pub fn effective_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.tag_id)
    }

    /// Returns the effective scale factor.
    pub fn effective_scale(&self) -> f64 {
        self.scale.unwrap_or(1.0)
    }

    /// Returns the effective offset.
    pub fn effective_offset(&self) -> f64 {
        self.offset.unwrap_or(0.0)
    }

    /// Returns `true` if scaling is applied.
    pub fn has_scaling(&self) -> bool {
        self.scale.is_some() || self.offset.is_some()
    }

    /// Applies scaling to a value.
    pub fn apply_scaling(&self, value: f64) -> f64 {
        value * self.effective_scale() + self.effective_offset()
    }

    /// Applies inverse scaling to a value (for writes).
    pub fn apply_inverse_scaling(&self, value: f64) -> f64 {
        (value - self.effective_offset()) / self.effective_scale()
    }
}

// =============================================================================
// BrowseDirection
// =============================================================================

/// OPC UA browse direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BrowseDirection {
    /// Browse forward references.
    #[default]
    Forward,

    /// Browse inverse references.
    Inverse,

    /// Browse both forward and inverse references.
    Both,
}

impl BrowseDirection {
    /// Returns the OPC UA value.
    pub const fn value(&self) -> u32 {
        match self {
            Self::Forward => 0,
            Self::Inverse => 1,
            Self::Both => 2,
        }
    }
}

// =============================================================================
// NodeClass
// =============================================================================

/// OPC UA node class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeClass {
    /// Object node.
    Object,
    /// Variable node.
    Variable,
    /// Method node.
    Method,
    /// Object type node.
    ObjectType,
    /// Variable type node.
    VariableType,
    /// Reference type node.
    ReferenceType,
    /// Data type node.
    DataType,
    /// View node.
    View,
}

impl NodeClass {
    /// Returns the OPC UA bit mask value.
    pub const fn value(&self) -> u32 {
        match self {
            Self::Object => 1,
            Self::Variable => 2,
            Self::Method => 4,
            Self::ObjectType => 8,
            Self::VariableType => 16,
            Self::ReferenceType => 32,
            Self::DataType => 64,
            Self::View => 128,
        }
    }

    /// Creates from OPC UA value.
    pub fn from_value(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Object),
            2 => Some(Self::Variable),
            4 => Some(Self::Method),
            8 => Some(Self::ObjectType),
            16 => Some(Self::VariableType),
            32 => Some(Self::ReferenceType),
            64 => Some(Self::DataType),
            128 => Some(Self::View),
            _ => None,
        }
    }

    /// Returns `true` if this node class can have a value.
    pub const fn has_value(&self) -> bool {
        matches!(self, Self::Variable)
    }
}

// =============================================================================
// AttributeId
// =============================================================================

/// OPC UA attribute IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AttributeId {
    /// Node ID attribute.
    NodeId,
    /// Node class attribute.
    NodeClass,
    /// Browse name attribute.
    BrowseName,
    /// Display name attribute.
    DisplayName,
    /// Description attribute.
    Description,
    /// Write mask attribute.
    WriteMask,
    /// User write mask attribute.
    UserWriteMask,
    /// Is abstract attribute.
    IsAbstract,
    /// Symmetric attribute.
    Symmetric,
    /// Inverse name attribute.
    InverseName,
    /// Contains no loops attribute.
    ContainsNoLoops,
    /// Event notifier attribute.
    EventNotifier,
    /// Value attribute.
    #[default]
    Value,
    /// Data type attribute.
    DataType,
    /// Value rank attribute.
    ValueRank,
    /// Array dimensions attribute.
    ArrayDimensions,
    /// Access level attribute.
    AccessLevel,
    /// User access level attribute.
    UserAccessLevel,
    /// Minimum sampling interval attribute.
    MinimumSamplingInterval,
    /// Historizing attribute.
    Historizing,
    /// Executable attribute.
    Executable,
    /// User executable attribute.
    UserExecutable,
}

impl AttributeId {
    /// Returns the OPC UA numeric value.
    pub const fn value(&self) -> u32 {
        match self {
            Self::NodeId => 1,
            Self::NodeClass => 2,
            Self::BrowseName => 3,
            Self::DisplayName => 4,
            Self::Description => 5,
            Self::WriteMask => 6,
            Self::UserWriteMask => 7,
            Self::IsAbstract => 8,
            Self::Symmetric => 9,
            Self::InverseName => 10,
            Self::ContainsNoLoops => 11,
            Self::EventNotifier => 12,
            Self::Value => 13,
            Self::DataType => 14,
            Self::ValueRank => 15,
            Self::ArrayDimensions => 16,
            Self::AccessLevel => 17,
            Self::UserAccessLevel => 18,
            Self::MinimumSamplingInterval => 19,
            Self::Historizing => 20,
            Self::Executable => 21,
            Self::UserExecutable => 22,
        }
    }
}

// =============================================================================
// humantime_serde helper
// =============================================================================

mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        humantime::format_duration(*duration)
            .to_string()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // NodeId Tests
    // =========================================================================

    #[test]
    fn test_node_id_numeric() {
        let node = NodeId::numeric(2, 1001);
        assert_eq!(node.namespace_index, 2);
        assert!(node.is_numeric());
        assert_eq!(node.as_numeric(), Some(1001));
        assert_eq!(node.to_opc_string(), "ns=2;i=1001");
    }

    #[test]
    fn test_node_id_string() {
        let node = NodeId::string(2, "Temperature.Value");
        assert!(node.is_string());
        assert_eq!(node.as_string(), Some("Temperature.Value"));
        assert_eq!(node.to_opc_string(), "ns=2;s=Temperature.Value");
    }

    #[test]
    fn test_node_id_guid() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let node = NodeId::guid(2, uuid);
        assert!(node.is_guid());
        assert_eq!(node.to_opc_string(), "ns=2;g=550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_node_id_opaque() {
        let data = vec![1, 2, 3, 4];
        let node = NodeId::opaque(2, data);
        assert!(node.is_opaque());
        // Base64 encoded [1,2,3,4] = "AQIDBA=="
        assert!(node.to_opc_string().starts_with("ns=2;b="));
    }

    #[test]
    fn test_node_id_parse() {
        // Numeric
        let node: NodeId = "ns=2;i=1001".parse().unwrap();
        assert_eq!(node.namespace_index, 2);
        assert_eq!(node.as_numeric(), Some(1001));

        // String
        let node: NodeId = "ns=2;s=MyNode".parse().unwrap();
        assert_eq!(node.as_string(), Some("MyNode"));

        // Namespace 0
        let node: NodeId = "i=85".parse().unwrap();
        assert_eq!(node.namespace_index, 0);
        assert_eq!(node.as_numeric(), Some(85));
    }

    #[test]
    fn test_node_id_standard_nodes() {
        assert_eq!(NodeId::ROOT_FOLDER.as_numeric(), Some(84));
        assert_eq!(NodeId::OBJECTS_FOLDER.as_numeric(), Some(85));
        assert!(NodeId::null().is_null());
    }

    // =========================================================================
    // OpcUaDataType Tests
    // =========================================================================

    #[test]
    fn test_data_type_properties() {
        assert!(OpcUaDataType::Int32.is_numeric());
        assert!(OpcUaDataType::Int32.is_integer());
        assert!(OpcUaDataType::Int32.is_signed());
        assert!(!OpcUaDataType::UInt32.is_signed());

        assert!(OpcUaDataType::Double.is_float());
        assert_eq!(OpcUaDataType::Int32.byte_size(), Some(4));
        assert_eq!(OpcUaDataType::String.byte_size(), None);
    }

    #[test]
    fn test_data_type_from_str() {
        assert_eq!("int32".parse::<OpcUaDataType>().unwrap(), OpcUaDataType::Int32);
        assert_eq!("double".parse::<OpcUaDataType>().unwrap(), OpcUaDataType::Double);
        assert_eq!("bool".parse::<OpcUaDataType>().unwrap(), OpcUaDataType::Boolean);
    }

    // =========================================================================
    // SecurityMode Tests
    // =========================================================================

    #[test]
    fn test_security_mode() {
        assert!(!SecurityMode::None.is_signed());
        assert!(SecurityMode::Sign.is_signed());
        assert!(SecurityMode::SignAndEncrypt.is_encrypted());

        assert_eq!(SecurityMode::None.value(), 1);
        assert_eq!(SecurityMode::from_value(3), Some(SecurityMode::SignAndEncrypt));
    }

    #[test]
    fn test_security_mode_from_str() {
        assert_eq!("none".parse::<SecurityMode>().unwrap(), SecurityMode::None);
        assert_eq!("sign".parse::<SecurityMode>().unwrap(), SecurityMode::Sign);
        assert_eq!(
            "SignAndEncrypt".parse::<SecurityMode>().unwrap(),
            SecurityMode::SignAndEncrypt
        );
    }

    // =========================================================================
    // SecurityPolicy Tests
    // =========================================================================

    #[test]
    fn test_security_policy() {
        assert!(SecurityPolicy::None.uri().ends_with("#None"));
        assert!(SecurityPolicy::Basic128Rsa15.is_deprecated());
        assert!(!SecurityPolicy::Basic256Sha256.is_deprecated());
        assert!(SecurityPolicy::Basic256Sha256.requires_certificates());
    }

    #[test]
    fn test_security_policy_from_str() {
        assert_eq!(
            "Basic256Sha256".parse::<SecurityPolicy>().unwrap(),
            SecurityPolicy::Basic256Sha256
        );

        let uri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
        assert_eq!(
            SecurityPolicy::from_uri(uri),
            Some(SecurityPolicy::Basic256Sha256)
        );
    }

    // =========================================================================
    // UserTokenType Tests
    // =========================================================================

    #[test]
    fn test_user_token_type() {
        assert!(UserTokenType::Anonymous.is_anonymous());
        assert!(!UserTokenType::Anonymous.requires_credentials());

        let username = UserTokenType::UserName {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };
        assert!(username.requires_credentials());
        assert_eq!(username.type_name(), "UserName");
    }

    // =========================================================================
    // OpcUaConfig Tests
    // =========================================================================

    #[test]
    fn test_config_builder_simple() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        assert_eq!(config.endpoint, "opc.tcp://localhost:4840");
        assert_eq!(config.security_mode, SecurityMode::None);
        assert!(config.user_token.is_anonymous());
    }

    #[test]
    fn test_config_builder_with_auth() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .username("admin", "password")
            .build()
            .unwrap();

        match &config.user_token {
            UserTokenType::UserName { username, password } => {
                assert_eq!(username, "admin");
                assert_eq!(password, "password");
            }
            _ => panic!("Expected UserName token"),
        }
    }

    #[test]
    fn test_config_missing_endpoint() {
        let result = OpcUaConfig::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_invalid_endpoint() {
        let result = OpcUaConfig::builder()
            .endpoint("http://localhost:4840")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_security_validation() {
        // Sign mode without policy should fail
        let result = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .security_mode(SecurityMode::Sign)
            .security_policy(SecurityPolicy::None)
            .build();
        assert!(result.is_err());
    }

    // =========================================================================
    // SubscriptionSettings Tests
    // =========================================================================

    #[test]
    fn test_subscription_settings_default() {
        let settings = SubscriptionSettings::default();
        assert_eq!(settings.publishing_interval, Duration::from_millis(1000));
        assert!(settings.publishing_enabled);
    }

    #[test]
    fn test_subscription_settings_fast() {
        let settings = SubscriptionSettings::fast();
        assert_eq!(settings.publishing_interval, Duration::from_millis(100));
    }

    // =========================================================================
    // TagMapping Tests
    // =========================================================================

    #[test]
    fn test_tag_mapping() {
        let tag = TagMapping::new("temp_1", NodeId::numeric(2, 1001))
            .with_name("Temperature Sensor 1")
            .with_unit("°C")
            .with_data_type(OpcUaDataType::Double);

        assert_eq!(tag.tag_id, "temp_1");
        assert_eq!(tag.effective_name(), "Temperature Sensor 1");
        assert_eq!(tag.unit, Some("°C".to_string()));
    }

    #[test]
    fn test_tag_mapping_scaling() {
        let tag = TagMapping::new("raw_value", NodeId::numeric(2, 1001))
            .with_scaling(0.1, 10.0);

        assert!(tag.has_scaling());
        assert_eq!(tag.apply_scaling(100.0), 20.0); // 100 * 0.1 + 10
        assert_eq!(tag.apply_inverse_scaling(20.0), 100.0);
    }

    // =========================================================================
    // DeadbandSettings Tests
    // =========================================================================

    #[test]
    fn test_deadband_settings() {
        let none = DeadbandSettings::default();
        assert!(none.is_none());

        let abs = DeadbandSettings::absolute(0.5);
        assert!(!abs.is_none());

        let pct = DeadbandSettings::percent(5.0);
        assert!(!pct.is_none());
    }

    // =========================================================================
    // AttributeId Tests
    // =========================================================================

    #[test]
    fn test_attribute_id() {
        assert_eq!(AttributeId::Value.value(), 13);
        assert_eq!(AttributeId::DataType.value(), 14);
        assert_eq!(AttributeId::default(), AttributeId::Value);
    }

    // =========================================================================
    // NodeClass Tests
    // =========================================================================

    #[test]
    fn test_node_class() {
        assert!(NodeClass::Variable.has_value());
        assert!(!NodeClass::Object.has_value());
        assert_eq!(NodeClass::Variable.value(), 2);
        assert_eq!(NodeClass::from_value(2), Some(NodeClass::Variable));
    }
}
