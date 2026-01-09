// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Protocol-agnostic address abstraction.
//!
//! This module provides unified address types that abstract over different
//! industrial protocol addressing schemes.
//!
//! # Supported Protocols
//!
//! - **Modbus**: Register type + address + count
//! - **OPC UA**: Namespace index + node identifier
//! - **BACnet**: Object type + instance
//! - **KNX**: Main/middle/sub group addresses
//!
//! # Examples
//!
//! ```
//! use trap_core::address::{Address, ModbusAddress, ModbusRegisterType};
//!
//! // Create a Modbus holding register address using the constructor
//! let addr = Address::Modbus(ModbusAddress::holding_register(100));
//!
//! assert!(addr.is_modbus());
//! ```

use crate::types::Protocol;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::Hash;

// =============================================================================
// Address Enum
// =============================================================================

/// A protocol-agnostic address.
///
/// This enum represents addresses across different industrial protocols,
/// allowing the upper layers to work with addresses without knowing
/// the specific protocol details.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "protocol", content = "address")]
pub enum Address {
    /// Modbus register address
    Modbus(ModbusAddress),

    /// OPC UA node ID
    OpcUa(OpcUaNodeId),

    /// BACnet object identifier
    BacNet(BacNetObjectId),

    /// KNX group address
    Knx(KnxGroupAddress),

    /// Generic string-based address (for extensions)
    Generic(GenericAddress),
}

impl Address {
    /// Returns the protocol type for this address.
    pub fn protocol(&self) -> Protocol {
        match self {
            Address::Modbus(addr) => {
                if addr.is_tcp {
                    Protocol::ModbusTcp
                } else {
                    Protocol::ModbusRtu
                }
            }
            Address::OpcUa(_) => Protocol::OpcUa,
            Address::BacNet(_) => Protocol::BacNetIp,
            Address::Knx(_) => Protocol::Knx,
            Address::Generic(_) => Protocol::Unknown,
        }
    }

    /// Returns `true` if this is a Modbus address.
    #[inline]
    pub fn is_modbus(&self) -> bool {
        matches!(self, Address::Modbus(_))
    }

    /// Returns `true` if this is an OPC UA address.
    #[inline]
    pub fn is_opcua(&self) -> bool {
        matches!(self, Address::OpcUa(_))
    }

    /// Returns `true` if this is a BACnet address.
    #[inline]
    pub fn is_bacnet(&self) -> bool {
        matches!(self, Address::BacNet(_))
    }

    /// Returns `true` if this is a KNX address.
    #[inline]
    pub fn is_knx(&self) -> bool {
        matches!(self, Address::Knx(_))
    }

    /// Attempts to get this as a Modbus address.
    #[inline]
    pub fn as_modbus(&self) -> Option<&ModbusAddress> {
        match self {
            Address::Modbus(addr) => Some(addr),
            _ => None,
        }
    }

    /// Attempts to get this as an OPC UA node ID.
    #[inline]
    pub fn as_opcua(&self) -> Option<&OpcUaNodeId> {
        match self {
            Address::OpcUa(addr) => Some(addr),
            _ => None,
        }
    }

    /// Attempts to get this as a BACnet object ID.
    #[inline]
    pub fn as_bacnet(&self) -> Option<&BacNetObjectId> {
        match self {
            Address::BacNet(addr) => Some(addr),
            _ => None,
        }
    }

    /// Attempts to get this as a KNX group address.
    #[inline]
    pub fn as_knx(&self) -> Option<&KnxGroupAddress> {
        match self {
            Address::Knx(addr) => Some(addr),
            _ => None,
        }
    }

    /// Returns a canonical string representation of this address.
    pub fn to_uri(&self) -> String {
        match self {
            Address::Modbus(addr) => addr.to_uri(),
            Address::OpcUa(addr) => addr.to_uri(),
            Address::BacNet(addr) => addr.to_uri(),
            Address::Knx(addr) => addr.to_uri(),
            Address::Generic(addr) => addr.to_uri(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

// =============================================================================
// Modbus Address
// =============================================================================

/// A Modbus register address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModbusAddress {
    /// The type of register.
    pub register_type: ModbusRegisterType,

    /// The starting register address (0-based).
    pub address: u16,

    /// The number of registers to read/write.
    #[serde(default = "default_count")]
    pub count: u16,

    /// Whether this is TCP (true) or RTU (false).
    #[serde(default = "default_is_tcp")]
    pub is_tcp: bool,

    /// The unit ID (slave address).
    #[serde(default = "default_unit_id")]
    pub unit_id: u8,
}

fn default_count() -> u16 {
    1
}
fn default_is_tcp() -> bool {
    true
}
fn default_unit_id() -> u8 {
    1
}

impl ModbusAddress {
    /// Creates a new Modbus holding register address.
    pub fn holding_register(address: u16) -> Self {
        Self {
            register_type: ModbusRegisterType::HoldingRegister,
            address,
            count: 1,
            is_tcp: true,
            unit_id: 1,
        }
    }

    /// Creates a new Modbus input register address.
    pub fn input_register(address: u16) -> Self {
        Self {
            register_type: ModbusRegisterType::InputRegister,
            address,
            count: 1,
            is_tcp: true,
            unit_id: 1,
        }
    }

    /// Creates a new Modbus coil address.
    pub fn coil(address: u16) -> Self {
        Self {
            register_type: ModbusRegisterType::Coil,
            address,
            count: 1,
            is_tcp: true,
            unit_id: 1,
        }
    }

    /// Creates a new Modbus discrete input address.
    pub fn discrete_input(address: u16) -> Self {
        Self {
            register_type: ModbusRegisterType::DiscreteInput,
            address,
            count: 1,
            is_tcp: true,
            unit_id: 1,
        }
    }

    /// Sets the count for this address.
    #[inline]
    pub fn with_count(mut self, count: u16) -> Self {
        self.count = count;
        self
    }

    /// Sets the unit ID for this address.
    #[inline]
    pub fn with_unit_id(mut self, unit_id: u8) -> Self {
        self.unit_id = unit_id;
        self
    }

    /// Sets whether this is RTU mode.
    #[inline]
    pub fn with_rtu(mut self) -> Self {
        self.is_tcp = false;
        self
    }

    /// Returns the end address (exclusive).
    #[inline]
    pub fn end_address(&self) -> u16 {
        self.address.saturating_add(self.count)
    }

    /// Returns `true` if this address overlaps with another.
    pub fn overlaps(&self, other: &ModbusAddress) -> bool {
        if self.register_type != other.register_type {
            return false;
        }
        let self_end = self.end_address();
        let other_end = other.end_address();
        self.address < other_end && other.address < self_end
    }

    /// Returns `true` if this address is contiguous with another.
    pub fn is_contiguous_with(&self, other: &ModbusAddress) -> bool {
        if self.register_type != other.register_type {
            return false;
        }
        self.end_address() == other.address || other.end_address() == self.address
    }

    /// Returns the URI representation.
    pub fn to_uri(&self) -> String {
        let protocol = if self.is_tcp { "modbus-tcp" } else { "modbus-rtu" };
        format!(
            "{}://{}:{}:{}/{}",
            protocol, self.unit_id, self.register_type, self.address, self.count
        )
    }
}

impl fmt::Display for ModbusAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

impl From<ModbusAddress> for Address {
    fn from(addr: ModbusAddress) -> Self {
        Address::Modbus(addr)
    }
}

/// Modbus register types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModbusRegisterType {
    /// Coil (read/write, 1 bit) - Function codes 1, 5, 15
    Coil,

    /// Discrete input (read-only, 1 bit) - Function code 2
    DiscreteInput,

    /// Input register (read-only, 16 bit) - Function code 4
    InputRegister,

    /// Holding register (read/write, 16 bit) - Function codes 3, 6, 16
    HoldingRegister,
}

impl ModbusRegisterType {
    /// Returns the function code for reading this register type.
    pub fn read_function_code(&self) -> u8 {
        match self {
            ModbusRegisterType::Coil => 1,
            ModbusRegisterType::DiscreteInput => 2,
            ModbusRegisterType::InputRegister => 4,
            ModbusRegisterType::HoldingRegister => 3,
        }
    }

    /// Returns the function code for writing a single value.
    pub fn write_single_function_code(&self) -> Option<u8> {
        match self {
            ModbusRegisterType::Coil => Some(5),
            ModbusRegisterType::HoldingRegister => Some(6),
            _ => None,
        }
    }

    /// Returns the function code for writing multiple values.
    pub fn write_multiple_function_code(&self) -> Option<u8> {
        match self {
            ModbusRegisterType::Coil => Some(15),
            ModbusRegisterType::HoldingRegister => Some(16),
            _ => None,
        }
    }

    /// Returns `true` if this register type is writable.
    #[inline]
    pub fn is_writable(&self) -> bool {
        matches!(self, ModbusRegisterType::Coil | ModbusRegisterType::HoldingRegister)
    }

    /// Returns `true` if this is a bit-type register.
    #[inline]
    pub fn is_bit(&self) -> bool {
        matches!(self, ModbusRegisterType::Coil | ModbusRegisterType::DiscreteInput)
    }
}

impl fmt::Display for ModbusRegisterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModbusRegisterType::Coil => write!(f, "coil"),
            ModbusRegisterType::DiscreteInput => write!(f, "di"),
            ModbusRegisterType::InputRegister => write!(f, "ir"),
            ModbusRegisterType::HoldingRegister => write!(f, "hr"),
        }
    }
}

// =============================================================================
// OPC UA Node ID
// =============================================================================

/// An OPC UA node identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpcUaNodeId {
    /// The namespace index.
    pub namespace_index: u16,

    /// The identifier.
    pub identifier: NodeIdentifier,
}

impl OpcUaNodeId {
    /// Creates a new numeric node ID.
    pub fn numeric(namespace_index: u16, value: u32) -> Self {
        Self {
            namespace_index,
            identifier: NodeIdentifier::Numeric(value),
        }
    }

    /// Creates a new string node ID.
    pub fn string(namespace_index: u16, value: impl Into<String>) -> Self {
        Self {
            namespace_index,
            identifier: NodeIdentifier::String(value.into()),
        }
    }

    /// Creates a new GUID node ID.
    pub fn guid(namespace_index: u16, value: impl Into<String>) -> Self {
        Self {
            namespace_index,
            identifier: NodeIdentifier::Guid(value.into()),
        }
    }

    /// Creates a new opaque (byte string) node ID.
    pub fn opaque(namespace_index: u16, value: Vec<u8>) -> Self {
        Self {
            namespace_index,
            identifier: NodeIdentifier::Opaque(value),
        }
    }

    /// Returns the URI representation.
    pub fn to_uri(&self) -> String {
        match &self.identifier {
            NodeIdentifier::Numeric(v) => format!("opcua://ns={};i={}", self.namespace_index, v),
            NodeIdentifier::String(v) => format!("opcua://ns={};s={}", self.namespace_index, v),
            NodeIdentifier::Guid(v) => format!("opcua://ns={};g={}", self.namespace_index, v),
            NodeIdentifier::Opaque(v) => {
                format!("opcua://ns={};b={}", self.namespace_index, base64_encode(v))
            }
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 4 / 3 + 4);
    for byte in data {
        write!(s, "{:02x}", byte).unwrap();
    }
    s
}

impl fmt::Display for OpcUaNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

impl From<OpcUaNodeId> for Address {
    fn from(addr: OpcUaNodeId) -> Self {
        Address::OpcUa(addr)
    }
}

/// OPC UA node identifier types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum NodeIdentifier {
    /// Numeric identifier
    Numeric(u32),

    /// String identifier
    String(String),

    /// GUID identifier
    Guid(String),

    /// Opaque (byte string) identifier
    Opaque(Vec<u8>),
}

// =============================================================================
// BACnet Object ID
// =============================================================================

/// A BACnet object identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BacNetObjectId {
    /// The object type.
    pub object_type: BacNetObjectType,

    /// The instance number.
    pub instance: u32,

    /// The property to read (default: present-value).
    #[serde(default = "default_property")]
    pub property: BacNetProperty,
}

fn default_property() -> BacNetProperty {
    BacNetProperty::PresentValue
}

impl BacNetObjectId {
    /// Creates a new BACnet object ID for analog input.
    pub fn analog_input(instance: u32) -> Self {
        Self {
            object_type: BacNetObjectType::AnalogInput,
            instance,
            property: BacNetProperty::PresentValue,
        }
    }

    /// Creates a new BACnet object ID for analog output.
    pub fn analog_output(instance: u32) -> Self {
        Self {
            object_type: BacNetObjectType::AnalogOutput,
            instance,
            property: BacNetProperty::PresentValue,
        }
    }

    /// Creates a new BACnet object ID for analog value.
    pub fn analog_value(instance: u32) -> Self {
        Self {
            object_type: BacNetObjectType::AnalogValue,
            instance,
            property: BacNetProperty::PresentValue,
        }
    }

    /// Creates a new BACnet object ID for binary input.
    pub fn binary_input(instance: u32) -> Self {
        Self {
            object_type: BacNetObjectType::BinaryInput,
            instance,
            property: BacNetProperty::PresentValue,
        }
    }

    /// Creates a new BACnet object ID for binary output.
    pub fn binary_output(instance: u32) -> Self {
        Self {
            object_type: BacNetObjectType::BinaryOutput,
            instance,
            property: BacNetProperty::PresentValue,
        }
    }

    /// Creates a new BACnet object ID for binary value.
    pub fn binary_value(instance: u32) -> Self {
        Self {
            object_type: BacNetObjectType::BinaryValue,
            instance,
            property: BacNetProperty::PresentValue,
        }
    }

    /// Sets the property to read.
    #[inline]
    pub fn with_property(mut self, property: BacNetProperty) -> Self {
        self.property = property;
        self
    }

    /// Returns the URI representation.
    pub fn to_uri(&self) -> String {
        format!(
            "bacnet://{},{}/{}",
            self.object_type.type_id(),
            self.instance,
            self.property.property_id()
        )
    }
}

impl fmt::Display for BacNetObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

impl From<BacNetObjectId> for Address {
    fn from(addr: BacNetObjectId) -> Self {
        Address::BacNet(addr)
    }
}

/// BACnet object types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BacNetObjectType {
    /// Analog input
    AnalogInput,
    /// Analog output
    AnalogOutput,
    /// Analog value
    AnalogValue,
    /// Binary input
    BinaryInput,
    /// Binary output
    BinaryOutput,
    /// Binary value
    BinaryValue,
    /// Multi-state input
    MultiStateInput,
    /// Multi-state output
    MultiStateOutput,
    /// Multi-state value
    MultiStateValue,
    /// Device object
    Device,
    /// Schedule object
    Schedule,
    /// Calendar object
    Calendar,
    /// Trend log object
    TrendLog,
}

impl BacNetObjectType {
    /// Returns the BACnet type ID.
    pub fn type_id(&self) -> u16 {
        match self {
            BacNetObjectType::AnalogInput => 0,
            BacNetObjectType::AnalogOutput => 1,
            BacNetObjectType::AnalogValue => 2,
            BacNetObjectType::BinaryInput => 3,
            BacNetObjectType::BinaryOutput => 4,
            BacNetObjectType::BinaryValue => 5,
            BacNetObjectType::MultiStateInput => 13,
            BacNetObjectType::MultiStateOutput => 14,
            BacNetObjectType::MultiStateValue => 19,
            BacNetObjectType::Device => 8,
            BacNetObjectType::Schedule => 17,
            BacNetObjectType::Calendar => 6,
            BacNetObjectType::TrendLog => 20,
        }
    }
}

/// BACnet properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BacNetProperty {
    /// Present value
    #[default]
    PresentValue,
    /// Object name
    ObjectName,
    /// Description
    Description,
    /// Status flags
    StatusFlags,
    /// Event state
    EventState,
    /// Reliability
    Reliability,
    /// Out of service
    OutOfService,
    /// Units
    Units,
}

impl BacNetProperty {
    /// Returns the BACnet property ID.
    pub fn property_id(&self) -> u32 {
        match self {
            BacNetProperty::PresentValue => 85,
            BacNetProperty::ObjectName => 77,
            BacNetProperty::Description => 28,
            BacNetProperty::StatusFlags => 111,
            BacNetProperty::EventState => 36,
            BacNetProperty::Reliability => 103,
            BacNetProperty::OutOfService => 81,
            BacNetProperty::Units => 117,
        }
    }
}

// =============================================================================
// KNX Group Address
// =============================================================================

/// A KNX group address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KnxGroupAddress {
    /// Main group (0-31 for 3-level, 0-31 for 2-level).
    pub main: u8,

    /// Middle group (0-7 for 3-level, ignored for 2-level).
    pub middle: u8,

    /// Sub group (0-255 for 3-level, 0-2047 for 2-level).
    pub sub: u16,

    /// Address format (2 or 3 level).
    #[serde(default = "default_level")]
    pub level: KnxAddressLevel,
}

fn default_level() -> KnxAddressLevel {
    KnxAddressLevel::ThreeLevel
}

impl KnxGroupAddress {
    /// Creates a new 3-level KNX group address.
    pub fn three_level(main: u8, middle: u8, sub: u16) -> Self {
        Self {
            main,
            middle,
            sub,
            level: KnxAddressLevel::ThreeLevel,
        }
    }

    /// Creates a new 2-level KNX group address.
    pub fn two_level(main: u8, sub: u16) -> Self {
        Self {
            main,
            middle: 0,
            sub,
            level: KnxAddressLevel::TwoLevel,
        }
    }

    /// Converts to raw 16-bit group address.
    pub fn to_raw(&self) -> u16 {
        match self.level {
            KnxAddressLevel::ThreeLevel => {
                ((self.main as u16) << 11) | ((self.middle as u16) << 8) | (self.sub & 0xFF)
            }
            KnxAddressLevel::TwoLevel => ((self.main as u16) << 11) | (self.sub & 0x7FF),
        }
    }

    /// Creates from raw 16-bit group address.
    pub fn from_raw(raw: u16, level: KnxAddressLevel) -> Self {
        match level {
            KnxAddressLevel::ThreeLevel => Self {
                main: ((raw >> 11) & 0x1F) as u8,
                middle: ((raw >> 8) & 0x07) as u8,
                sub: raw & 0xFF,
                level,
            },
            KnxAddressLevel::TwoLevel => Self {
                main: ((raw >> 11) & 0x1F) as u8,
                middle: 0,
                sub: raw & 0x7FF,
                level,
            },
        }
    }

    /// Returns the URI representation.
    pub fn to_uri(&self) -> String {
        match self.level {
            KnxAddressLevel::ThreeLevel => {
                format!("knx://{}/{}/{}", self.main, self.middle, self.sub)
            }
            KnxAddressLevel::TwoLevel => {
                format!("knx://{}/{}", self.main, self.sub)
            }
        }
    }
}

impl fmt::Display for KnxGroupAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

impl From<KnxGroupAddress> for Address {
    fn from(addr: KnxGroupAddress) -> Self {
        Address::Knx(addr)
    }
}

/// KNX address level format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KnxAddressLevel {
    /// 2-level addressing (main/sub).
    TwoLevel,

    /// 3-level addressing (main/middle/sub).
    #[default]
    ThreeLevel,
}

// =============================================================================
// Generic Address
// =============================================================================

/// A generic string-based address for extensibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GenericAddress {
    /// The protocol name.
    pub protocol: String,

    /// The address string.
    pub address: String,
}

impl GenericAddress {
    /// Creates a new generic address.
    pub fn new(protocol: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            address: address.into(),
        }
    }

    /// Returns the URI representation.
    pub fn to_uri(&self) -> String {
        format!("{}://{}", self.protocol, self.address)
    }
}

impl fmt::Display for GenericAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

impl From<GenericAddress> for Address {
    fn from(addr: GenericAddress) -> Self {
        Address::Generic(addr)
    }
}

// =============================================================================
// Address Metadata
// =============================================================================

/// Metadata about an address/tag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddressInfo {
    /// The address.
    pub address: Address,

    /// Human-readable name.
    pub name: String,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Data type hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,

    /// Whether the address is writable.
    #[serde(default)]
    pub writable: bool,

    /// Engineering units (e.g., "°C", "kWh").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,

    /// Minimum value (for numeric types).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_value: Option<f64>,

    /// Maximum value (for numeric types).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_value: Option<f64>,
}

impl AddressInfo {
    /// Creates a new address info with minimal information.
    pub fn new(address: Address, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            description: None,
            data_type: None,
            writable: false,
            unit: None,
            min_value: None,
            max_value: None,
        }
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the data type.
    pub fn with_data_type(mut self, data_type: impl Into<String>) -> Self {
        self.data_type = Some(data_type.into());
        self
    }

    /// Sets the writable flag.
    pub fn with_writable(mut self, writable: bool) -> Self {
        self.writable = writable;
        self
    }

    /// Sets the engineering unit.
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// Sets the value range.
    pub fn with_range(mut self, min: f64, max: f64) -> Self {
        self.min_value = Some(min);
        self.max_value = Some(max);
        self
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_address() {
        let addr = ModbusAddress::holding_register(100);
        assert_eq!(addr.register_type, ModbusRegisterType::HoldingRegister);
        assert_eq!(addr.address, 100);
        assert_eq!(addr.count, 1);
        assert!(addr.is_tcp);

        let addr = addr.with_count(10).with_unit_id(2);
        assert_eq!(addr.count, 10);
        assert_eq!(addr.unit_id, 2);
        assert_eq!(addr.end_address(), 110);
    }

    #[test]
    fn test_modbus_overlap() {
        let addr1 = ModbusAddress::holding_register(100).with_count(10);
        let addr2 = ModbusAddress::holding_register(105).with_count(10);
        let addr3 = ModbusAddress::holding_register(110).with_count(5);
        let addr4 = ModbusAddress::input_register(100).with_count(10);

        assert!(addr1.overlaps(&addr2));
        assert!(!addr1.overlaps(&addr3));
        assert!(!addr1.overlaps(&addr4)); // Different register type
        assert!(addr1.is_contiguous_with(&addr3));
    }

    #[test]
    fn test_opcua_node_id() {
        let node = OpcUaNodeId::numeric(2, 1234);
        assert_eq!(node.namespace_index, 2);
        assert!(matches!(node.identifier, NodeIdentifier::Numeric(1234)));

        let node = OpcUaNodeId::string(1, "Temperature");
        assert!(matches!(node.identifier, NodeIdentifier::String(_)));
    }

    #[test]
    fn test_bacnet_object_id() {
        let obj = BacNetObjectId::analog_input(1);
        assert_eq!(obj.object_type, BacNetObjectType::AnalogInput);
        assert_eq!(obj.instance, 1);
        assert_eq!(obj.property, BacNetProperty::PresentValue);
    }

    #[test]
    fn test_knx_group_address() {
        let addr = KnxGroupAddress::three_level(1, 2, 3);
        assert_eq!(addr.main, 1);
        assert_eq!(addr.middle, 2);
        assert_eq!(addr.sub, 3);

        let raw = addr.to_raw();
        let restored = KnxGroupAddress::from_raw(raw, KnxAddressLevel::ThreeLevel);
        assert_eq!(addr, restored);
    }

    #[test]
    fn test_address_protocol() {
        let modbus = Address::Modbus(ModbusAddress::holding_register(100));
        assert_eq!(modbus.protocol(), Protocol::ModbusTcp);
        assert!(modbus.is_modbus());

        let opcua = Address::OpcUa(OpcUaNodeId::numeric(1, 100));
        assert_eq!(opcua.protocol(), Protocol::OpcUa);
        assert!(opcua.is_opcua());
    }

    #[test]
    fn test_address_uri() {
        let modbus = Address::Modbus(ModbusAddress::holding_register(100).with_unit_id(2));
        assert!(modbus.to_uri().contains("modbus-tcp"));
        assert!(modbus.to_uri().contains("hr"));
        assert!(modbus.to_uri().contains("100"));

        let opcua = Address::OpcUa(OpcUaNodeId::numeric(2, 1234));
        assert!(opcua.to_uri().contains("opcua"));
        assert!(opcua.to_uri().contains("ns=2"));
    }

    #[test]
    fn test_register_type() {
        assert_eq!(ModbusRegisterType::Coil.read_function_code(), 1);
        assert_eq!(ModbusRegisterType::HoldingRegister.read_function_code(), 3);
        assert!(ModbusRegisterType::Coil.is_writable());
        assert!(!ModbusRegisterType::InputRegister.is_writable());
        assert!(ModbusRegisterType::Coil.is_bit());
        assert!(!ModbusRegisterType::HoldingRegister.is_bit());
    }
}
