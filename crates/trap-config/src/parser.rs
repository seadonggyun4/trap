// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Address parsing for TRAP configuration.
//!
//! This module provides parsers for converting string-based addresses
//! in configuration files to typed `Address` enum variants.
//!
//! # Supported Address Formats
//!
//! ## Modbus
//!
//! - `HR:100` - Holding Register at address 100
//! - `IR:100` - Input Register at address 100
//! - `C:100` - Coil at address 100
//! - `DI:100` - Discrete Input at address 100
//! - `HR:100:10` - Holding Register at address 100, count 10
//!
//! ## OPC UA
//!
//! - `ns=2;s=Device.Temperature` - String node ID
//! - `ns=2;i=2258` - Numeric node ID
//! - `i=2258` - Numeric node ID with namespace 0
//! - `s=Device.Temperature` - String node ID with namespace 0
//!
//! ## BACnet
//!
//! - `AI:0` - Analog Input, instance 0
//! - `AO:1` - Analog Output, instance 1
//! - `AV:2` - Analog Value, instance 2
//! - `BI:3` - Binary Input, instance 3
//! - `BO:4` - Binary Output, instance 4
//! - `BV:5` - Binary Value, instance 5
//! - `AI:0:85` - Analog Input, instance 0, property 85 (present-value)
//!
//! ## KNX
//!
//! - `1/2/3` - 3-level group address (main/middle/sub)
//! - `1/100` - 2-level group address (main/sub)

use crate::error::{ConfigError, ConfigResult};
use trap_core::address::{
    Address, BacNetObjectId, BacNetObjectType, BacNetProperty, GenericAddress, KnxAddressLevel,
    KnxGroupAddress, ModbusAddress, ModbusRegisterType, NodeIdentifier, OpcUaNodeId,
};

// =============================================================================
// Address Parser Trait
// =============================================================================

/// A trait for parsing protocol-specific addresses.
pub trait AddressParser {
    /// Parses a string address into a typed Address.
    ///
    /// # Arguments
    ///
    /// * `address` - The string address to parse
    ///
    /// # Returns
    ///
    /// * `Ok(Address)` - Successfully parsed address
    /// * `Err(ConfigError)` - If parsing fails
    fn parse(&self, address: &str) -> ConfigResult<Address>;

    /// Returns the protocol name for error messages.
    fn protocol_name(&self) -> &'static str;
}

// =============================================================================
// Unified Parser
// =============================================================================

/// A unified address parser that can parse any supported protocol.
///
/// The parser auto-detects the protocol based on address format or
/// can be explicitly configured for a specific protocol.
#[derive(Debug, Clone, Default)]
pub struct UnifiedAddressParser {
    /// Default protocol if auto-detection fails.
    default_protocol: Option<ProtocolHint>,
}

/// Protocol hint for the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolHint {
    /// Modbus TCP protocol.
    ModbusTcp,
    /// Modbus RTU protocol.
    ModbusRtu,
    /// OPC UA protocol.
    OpcUa,
    /// BACnet IP protocol.
    BacNet,
    /// KNX protocol.
    Knx,
}

impl UnifiedAddressParser {
    /// Creates a new unified parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a parser with a default protocol hint.
    pub fn with_default_protocol(protocol: ProtocolHint) -> Self {
        Self {
            default_protocol: Some(protocol),
        }
    }

    /// Parses an address string, auto-detecting the protocol.
    ///
    /// # Examples
    ///
    /// ```
    /// use trap_config::parser::UnifiedAddressParser;
    ///
    /// let parser = UnifiedAddressParser::new();
    ///
    /// // Modbus
    /// let addr = parser.parse("HR:100").unwrap();
    /// assert!(addr.is_modbus());
    ///
    /// // OPC UA
    /// let addr = parser.parse("ns=2;s=Temperature").unwrap();
    /// assert!(addr.is_opcua());
    ///
    /// // BACnet
    /// let addr = parser.parse("AI:0").unwrap();
    /// assert!(addr.is_bacnet());
    ///
    /// // KNX
    /// let addr = parser.parse("1/2/3").unwrap();
    /// assert!(addr.is_knx());
    /// ```
    pub fn parse(&self, address: &str) -> ConfigResult<Address> {
        let address = address.trim();

        if address.is_empty() {
            return Err(ConfigError::invalid_address(address, "address cannot be empty"));
        }

        // Try to detect protocol from format
        if let Some(protocol) = self.detect_protocol(address) {
            return self.parse_with_protocol(address, protocol);
        }

        // Use default protocol if set
        if let Some(protocol) = self.default_protocol {
            return self.parse_with_protocol(address, protocol);
        }

        Err(ConfigError::invalid_address(
            address,
            "unable to detect protocol; use explicit protocol prefix or set default protocol",
        ))
    }

    /// Parses an address with an explicit protocol.
    pub fn parse_with_protocol(
        &self,
        address: &str,
        protocol: ProtocolHint,
    ) -> ConfigResult<Address> {
        match protocol {
            ProtocolHint::ModbusTcp => {
                let mut addr = ModbusAddressParser::new().parse_modbus(address)?;
                addr.is_tcp = true;
                Ok(Address::Modbus(addr))
            }
            ProtocolHint::ModbusRtu => {
                let mut addr = ModbusAddressParser::new().parse_modbus(address)?;
                addr.is_tcp = false;
                Ok(Address::Modbus(addr))
            }
            ProtocolHint::OpcUa => OpcUaAddressParser::new().parse(address),
            ProtocolHint::BacNet => BacNetAddressParser::new().parse(address),
            ProtocolHint::Knx => KnxAddressParser::new().parse(address),
        }
    }

    /// Detects the protocol from the address format.
    fn detect_protocol(&self, address: &str) -> Option<ProtocolHint> {
        let upper = address.to_uppercase();

        // Check for Modbus prefixes
        if upper.starts_with("HR:")
            || upper.starts_with("IR:")
            || upper.starts_with("C:")
            || upper.starts_with("DI:")
        {
            return Some(ProtocolHint::ModbusTcp);
        }

        // Check for OPC UA format
        if address.starts_with("ns=")
            || address.starts_with("i=")
            || address.starts_with("s=")
            || address.starts_with("g=")
            || address.starts_with("b=")
        {
            return Some(ProtocolHint::OpcUa);
        }

        // Check for BACnet prefixes
        if upper.starts_with("AI:")
            || upper.starts_with("AO:")
            || upper.starts_with("AV:")
            || upper.starts_with("BI:")
            || upper.starts_with("BO:")
            || upper.starts_with("BV:")
            || upper.starts_with("MSI:")
            || upper.starts_with("MSO:")
            || upper.starts_with("MSV:")
            || upper.starts_with("DEV:")
            || upper.starts_with("SCH:")
            || upper.starts_with("CAL:")
            || upper.starts_with("TL:")
        {
            return Some(ProtocolHint::BacNet);
        }

        // Check for KNX format (x/y/z or x/y)
        if address.contains('/') && !address.contains("://") {
            let parts: Vec<&str> = address.split('/').collect();
            if (parts.len() == 2 || parts.len() == 3)
                && parts.iter().all(|p| p.parse::<u16>().is_ok())
            {
                return Some(ProtocolHint::Knx);
            }
        }

        None
    }
}

// =============================================================================
// Modbus Address Parser
// =============================================================================

/// Parser for Modbus addresses.
///
/// # Format
///
/// ```text
/// <type>:<address>[:<count>]
///
/// type: HR (Holding Register), IR (Input Register), C (Coil), DI (Discrete Input)
/// address: 0-65535
/// count: 1-65535 (optional, defaults to 1)
/// ```
///
/// # Examples
///
/// - `HR:100` - Holding Register at address 100
/// - `HR:100:10` - Holding Register at address 100, count 10
/// - `C:0` - Coil at address 0
#[derive(Debug, Clone, Default)]
pub struct ModbusAddressParser;

impl ModbusAddressParser {
    /// Creates a new Modbus address parser.
    pub fn new() -> Self {
        Self
    }

    /// Parses a Modbus address string.
    pub fn parse_modbus(&self, address: &str) -> ConfigResult<ModbusAddress> {
        let address = address.trim();

        // Split by ':'
        let parts: Vec<&str> = address.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(ConfigError::invalid_address(
                address,
                "expected format: <type>:<address>[:<count>]",
            ));
        }

        // Parse register type
        let register_type = match parts[0].to_uppercase().as_str() {
            "HR" | "HOLDING" | "HOLDINGREG" | "HOLDINGREGISTER" => {
                ModbusRegisterType::HoldingRegister
            }
            "IR" | "INPUT" | "INPUTREG" | "INPUTREGISTER" => ModbusRegisterType::InputRegister,
            "C" | "COIL" => ModbusRegisterType::Coil,
            "DI" | "DISCRETE" | "DISCRETEINPUT" => ModbusRegisterType::DiscreteInput,
            other => {
                return Err(ConfigError::invalid_address(
                    address,
                    format!(
                        "unknown register type '{}'; expected HR, IR, C, or DI",
                        other
                    ),
                ))
            }
        };

        // Parse address
        let addr: u16 = parts[1].trim().parse().map_err(|_| {
            ConfigError::invalid_address(
                address,
                format!("invalid address '{}'; expected 0-65535", parts[1]),
            )
        })?;

        // Parse count (optional)
        let count: u16 = if parts.len() == 3 {
            parts[2].trim().parse().map_err(|_| {
                ConfigError::invalid_address(
                    address,
                    format!("invalid count '{}'; expected 1-65535", parts[2]),
                )
            })?
        } else {
            1
        };

        if count == 0 {
            return Err(ConfigError::invalid_address(address, "count cannot be zero"));
        }

        // Check for overflow
        if (addr as u32) + (count as u32) > 65536 {
            return Err(ConfigError::invalid_address(
                address,
                format!(
                    "address range {}..{} exceeds maximum 65535",
                    addr,
                    addr as u32 + count as u32
                ),
            ));
        }

        Ok(ModbusAddress {
            register_type,
            address: addr,
            count,
            is_tcp: true,
            unit_id: 1,
        })
    }
}

impl AddressParser for ModbusAddressParser {
    fn parse(&self, address: &str) -> ConfigResult<Address> {
        Ok(Address::Modbus(self.parse_modbus(address)?))
    }

    fn protocol_name(&self) -> &'static str {
        "Modbus"
    }
}

// =============================================================================
// OPC UA Address Parser
// =============================================================================

/// Parser for OPC UA node IDs.
///
/// # Format
///
/// ```text
/// [ns=<namespace>;]<identifier_type>=<identifier>
///
/// namespace: 0-65535 (defaults to 0)
/// identifier_type: i (numeric), s (string), g (GUID), b (opaque/byte string)
/// identifier: value based on type
/// ```
///
/// # Examples
///
/// - `ns=2;s=Device.Temperature` - String node ID in namespace 2
/// - `ns=2;i=2258` - Numeric node ID in namespace 2
/// - `i=2258` - Numeric node ID in namespace 0
/// - `s=Temperature` - String node ID in namespace 0
#[derive(Debug, Clone, Default)]
pub struct OpcUaAddressParser;

impl OpcUaAddressParser {
    /// Creates a new OPC UA address parser.
    pub fn new() -> Self {
        Self
    }

    /// Parses an OPC UA node ID string.
    pub fn parse_opcua(&self, address: &str) -> ConfigResult<OpcUaNodeId> {
        let address = address.trim();

        let mut namespace_index: u16 = 0;
        let mut identifier_part = address;

        // Check for namespace prefix
        if address.starts_with("ns=") {
            // Split by ';'
            let parts: Vec<&str> = address.splitn(2, ';').collect();
            if parts.len() != 2 {
                return Err(ConfigError::invalid_address(
                    address,
                    "expected format: ns=<namespace>;<identifier_type>=<value>",
                ));
            }

            // Parse namespace
            let ns_str = &parts[0][3..]; // Skip "ns="
            namespace_index = ns_str.parse().map_err(|_| {
                ConfigError::invalid_address(
                    address,
                    format!("invalid namespace '{}'; expected 0-65535", ns_str),
                )
            })?;

            identifier_part = parts[1];
        }

        // Parse identifier
        let identifier = self.parse_identifier(address, identifier_part)?;

        Ok(OpcUaNodeId {
            namespace_index,
            identifier,
        })
    }

    fn parse_identifier(&self, full_address: &str, part: &str) -> ConfigResult<NodeIdentifier> {
        if part.starts_with("i=") {
            // Numeric identifier
            let value_str = &part[2..];
            let value: u32 = value_str.parse().map_err(|_| {
                ConfigError::invalid_address(
                    full_address,
                    format!("invalid numeric identifier '{}'; expected u32", value_str),
                )
            })?;
            Ok(NodeIdentifier::Numeric(value))
        } else if part.starts_with("s=") {
            // String identifier
            let value = &part[2..];
            if value.is_empty() {
                return Err(ConfigError::invalid_address(
                    full_address,
                    "string identifier cannot be empty",
                ));
            }
            Ok(NodeIdentifier::String(value.to_string()))
        } else if part.starts_with("g=") {
            // GUID identifier
            let value = &part[2..];
            // Basic GUID format validation
            if value.len() != 36
                || value.chars().filter(|&c| c == '-').count() != 4
            {
                return Err(ConfigError::invalid_address(
                    full_address,
                    format!("invalid GUID format '{}'; expected xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", value),
                ));
            }
            Ok(NodeIdentifier::Guid(value.to_string()))
        } else if part.starts_with("b=") {
            // Opaque (byte string) identifier - base64 encoded
            let value = &part[2..];
            let bytes = decode_base64(value).map_err(|e| {
                ConfigError::invalid_address(
                    full_address,
                    format!("invalid base64 encoded opaque identifier: {}", e),
                )
            })?;
            Ok(NodeIdentifier::Opaque(bytes))
        } else {
            Err(ConfigError::invalid_address(
                full_address,
                format!(
                    "unknown identifier type in '{}'; expected i=, s=, g=, or b=",
                    part
                ),
            ))
        }
    }
}

impl AddressParser for OpcUaAddressParser {
    fn parse(&self, address: &str) -> ConfigResult<Address> {
        Ok(Address::OpcUa(self.parse_opcua(address)?))
    }

    fn protocol_name(&self) -> &'static str {
        "OPC UA"
    }
}

// =============================================================================
// BACnet Address Parser
// =============================================================================

/// Parser for BACnet object identifiers.
///
/// # Format
///
/// ```text
/// <object_type>:<instance>[:<property>]
///
/// object_type: AI, AO, AV, BI, BO, BV, MSI, MSO, MSV, DEV, SCH, CAL, TL
/// instance: 0-4194303
/// property: optional property ID (defaults to present-value = 85)
/// ```
///
/// # Examples
///
/// - `AI:0` - Analog Input, instance 0
/// - `AI:0:85` - Analog Input, instance 0, present-value property
/// - `BV:100` - Binary Value, instance 100
#[derive(Debug, Clone, Default)]
pub struct BacNetAddressParser;

impl BacNetAddressParser {
    /// Creates a new BACnet address parser.
    pub fn new() -> Self {
        Self
    }

    /// Parses a BACnet object ID string.
    pub fn parse_bacnet(&self, address: &str) -> ConfigResult<BacNetObjectId> {
        let address = address.trim();

        // Split by ':'
        let parts: Vec<&str> = address.split(':').collect();
        if parts.is_empty() || parts.len() > 3 {
            return Err(ConfigError::invalid_address(
                address,
                "expected format: <object_type>:<instance>[:<property>]",
            ));
        }

        // Parse object type
        let object_type = match parts[0].to_uppercase().as_str() {
            "AI" => BacNetObjectType::AnalogInput,
            "AO" => BacNetObjectType::AnalogOutput,
            "AV" => BacNetObjectType::AnalogValue,
            "BI" => BacNetObjectType::BinaryInput,
            "BO" => BacNetObjectType::BinaryOutput,
            "BV" => BacNetObjectType::BinaryValue,
            "MSI" => BacNetObjectType::MultiStateInput,
            "MSO" => BacNetObjectType::MultiStateOutput,
            "MSV" => BacNetObjectType::MultiStateValue,
            "DEV" => BacNetObjectType::Device,
            "SCH" => BacNetObjectType::Schedule,
            "CAL" => BacNetObjectType::Calendar,
            "TL" => BacNetObjectType::TrendLog,
            other => {
                return Err(ConfigError::invalid_address(
                    address,
                    format!(
                        "unknown object type '{}'; expected AI, AO, AV, BI, BO, BV, etc.",
                        other
                    ),
                ))
            }
        };

        // Parse instance
        if parts.len() < 2 {
            return Err(ConfigError::invalid_address(
                address,
                "missing instance number",
            ));
        }

        let instance: u32 = parts[1].trim().parse().map_err(|_| {
            ConfigError::invalid_address(
                address,
                format!(
                    "invalid instance '{}'; expected 0-4194303",
                    parts[1]
                ),
            )
        })?;

        if instance > 4_194_303 {
            return Err(ConfigError::invalid_address(
                address,
                format!(
                    "instance {} exceeds maximum 4194303",
                    instance
                ),
            ));
        }

        // Parse property (optional)
        let property = if parts.len() == 3 {
            self.parse_property(address, parts[2])?
        } else {
            BacNetProperty::PresentValue
        };

        Ok(BacNetObjectId {
            object_type,
            instance,
            property,
        })
    }

    fn parse_property(&self, full_address: &str, part: &str) -> ConfigResult<BacNetProperty> {
        // First try to parse as number
        if let Ok(id) = part.trim().parse::<u32>() {
            return match id {
                85 => Ok(BacNetProperty::PresentValue),
                77 => Ok(BacNetProperty::ObjectName),
                28 => Ok(BacNetProperty::Description),
                111 => Ok(BacNetProperty::StatusFlags),
                36 => Ok(BacNetProperty::EventState),
                103 => Ok(BacNetProperty::Reliability),
                81 => Ok(BacNetProperty::OutOfService),
                117 => Ok(BacNetProperty::Units),
                _ => Err(ConfigError::invalid_address(
                    full_address,
                    format!("unsupported property ID {}; use standard properties", id),
                )),
            };
        }

        // Try to parse as name
        match part.to_lowercase().as_str() {
            "present-value" | "presentvalue" | "pv" => Ok(BacNetProperty::PresentValue),
            "object-name" | "objectname" | "name" => Ok(BacNetProperty::ObjectName),
            "description" | "desc" => Ok(BacNetProperty::Description),
            "status-flags" | "statusflags" | "status" => Ok(BacNetProperty::StatusFlags),
            "event-state" | "eventstate" => Ok(BacNetProperty::EventState),
            "reliability" => Ok(BacNetProperty::Reliability),
            "out-of-service" | "outofservice" | "oos" => Ok(BacNetProperty::OutOfService),
            "units" => Ok(BacNetProperty::Units),
            _ => Err(ConfigError::invalid_address(
                full_address,
                format!("unknown property '{}'; use present-value, object-name, etc.", part),
            )),
        }
    }
}

impl AddressParser for BacNetAddressParser {
    fn parse(&self, address: &str) -> ConfigResult<Address> {
        Ok(Address::BacNet(self.parse_bacnet(address)?))
    }

    fn protocol_name(&self) -> &'static str {
        "BACnet"
    }
}

// =============================================================================
// KNX Address Parser
// =============================================================================

/// Parser for KNX group addresses.
///
/// # Format
///
/// ```text
/// 3-level: <main>/<middle>/<sub>
/// 2-level: <main>/<sub>
///
/// 3-level: main (0-31), middle (0-7), sub (0-255)
/// 2-level: main (0-31), sub (0-2047)
/// ```
///
/// # Examples
///
/// - `1/2/3` - 3-level group address
/// - `1/100` - 2-level group address
#[derive(Debug, Clone, Default)]
pub struct KnxAddressParser;

impl KnxAddressParser {
    /// Creates a new KNX address parser.
    pub fn new() -> Self {
        Self
    }

    /// Parses a KNX group address string.
    pub fn parse_knx(&self, address: &str) -> ConfigResult<KnxGroupAddress> {
        let address = address.trim();

        let parts: Vec<&str> = address.split('/').collect();

        match parts.len() {
            3 => self.parse_three_level(address, &parts),
            2 => self.parse_two_level(address, &parts),
            _ => Err(ConfigError::invalid_address(
                address,
                "expected format: <main>/<middle>/<sub> or <main>/<sub>",
            )),
        }
    }

    fn parse_three_level(&self, full_address: &str, parts: &[&str]) -> ConfigResult<KnxGroupAddress> {
        let main: u8 = parts[0].trim().parse().map_err(|_| {
            ConfigError::invalid_address(
                full_address,
                format!("invalid main group '{}'; expected 0-31", parts[0]),
            )
        })?;

        if main > 31 {
            return Err(ConfigError::invalid_address(
                full_address,
                format!("main group {} exceeds maximum 31", main),
            ));
        }

        let middle: u8 = parts[1].trim().parse().map_err(|_| {
            ConfigError::invalid_address(
                full_address,
                format!("invalid middle group '{}'; expected 0-7", parts[1]),
            )
        })?;

        if middle > 7 {
            return Err(ConfigError::invalid_address(
                full_address,
                format!("middle group {} exceeds maximum 7", middle),
            ));
        }

        let sub: u16 = parts[2].trim().parse().map_err(|_| {
            ConfigError::invalid_address(
                full_address,
                format!("invalid sub group '{}'; expected 0-255", parts[2]),
            )
        })?;

        if sub > 255 {
            return Err(ConfigError::invalid_address(
                full_address,
                format!("sub group {} exceeds maximum 255 for 3-level addressing", sub),
            ));
        }

        Ok(KnxGroupAddress {
            main,
            middle,
            sub,
            level: KnxAddressLevel::ThreeLevel,
        })
    }

    fn parse_two_level(&self, full_address: &str, parts: &[&str]) -> ConfigResult<KnxGroupAddress> {
        let main: u8 = parts[0].trim().parse().map_err(|_| {
            ConfigError::invalid_address(
                full_address,
                format!("invalid main group '{}'; expected 0-31", parts[0]),
            )
        })?;

        if main > 31 {
            return Err(ConfigError::invalid_address(
                full_address,
                format!("main group {} exceeds maximum 31", main),
            ));
        }

        let sub: u16 = parts[1].trim().parse().map_err(|_| {
            ConfigError::invalid_address(
                full_address,
                format!("invalid sub group '{}'; expected 0-2047", parts[1]),
            )
        })?;

        if sub > 2047 {
            return Err(ConfigError::invalid_address(
                full_address,
                format!("sub group {} exceeds maximum 2047 for 2-level addressing", sub),
            ));
        }

        Ok(KnxGroupAddress {
            main,
            middle: 0,
            sub,
            level: KnxAddressLevel::TwoLevel,
        })
    }
}

impl AddressParser for KnxAddressParser {
    fn parse(&self, address: &str) -> ConfigResult<Address> {
        Ok(Address::Knx(self.parse_knx(address)?))
    }

    fn protocol_name(&self) -> &'static str {
        "KNX"
    }
}

// =============================================================================
// Generic Address Parser
// =============================================================================

/// Parser for generic/custom protocol addresses.
#[derive(Debug, Clone, Default)]
pub struct GenericAddressParser;

impl GenericAddressParser {
    /// Creates a new generic address parser.
    pub fn new() -> Self {
        Self
    }

    /// Parses a generic address.
    pub fn parse_generic(&self, address: &str) -> ConfigResult<GenericAddress> {
        let address = address.trim();

        if address.is_empty() {
            return Err(ConfigError::invalid_address(address, "address cannot be empty"));
        }

        // Try to detect protocol://address format
        if let Some(idx) = address.find("://") {
            let protocol = &address[..idx];
            let addr = &address[idx + 3..];
            Ok(GenericAddress::new(protocol, addr))
        } else {
            Ok(GenericAddress::new("generic", address))
        }
    }
}

impl AddressParser for GenericAddressParser {
    fn parse(&self, address: &str) -> ConfigResult<Address> {
        Ok(Address::Generic(self.parse_generic(address)?))
    }

    fn protocol_name(&self) -> &'static str {
        "Generic"
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Decodes a base64 string.
fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    // Simple base64 decoding
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buffer = 0u32;
    let mut bits = 0;

    for c in input.bytes() {
        let value = ALPHABET
            .iter()
            .position(|&b| b == c)
            .ok_or_else(|| format!("invalid base64 character: {}", c as char))?;

        buffer = (buffer << 6) | (value as u32);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    mod modbus {
        use super::*;

        #[test]
        fn test_parse_holding_register() {
            let parser = ModbusAddressParser::new();
            let addr = parser.parse_modbus("HR:100").unwrap();
            assert_eq!(addr.register_type, ModbusRegisterType::HoldingRegister);
            assert_eq!(addr.address, 100);
            assert_eq!(addr.count, 1);
        }

        #[test]
        fn test_parse_with_count() {
            let parser = ModbusAddressParser::new();
            let addr = parser.parse_modbus("HR:100:10").unwrap();
            assert_eq!(addr.count, 10);
        }

        #[test]
        fn test_parse_input_register() {
            let parser = ModbusAddressParser::new();
            let addr = parser.parse_modbus("IR:200").unwrap();
            assert_eq!(addr.register_type, ModbusRegisterType::InputRegister);
        }

        #[test]
        fn test_parse_coil() {
            let parser = ModbusAddressParser::new();
            let addr = parser.parse_modbus("C:0").unwrap();
            assert_eq!(addr.register_type, ModbusRegisterType::Coil);
        }

        #[test]
        fn test_parse_discrete_input() {
            let parser = ModbusAddressParser::new();
            let addr = parser.parse_modbus("DI:50").unwrap();
            assert_eq!(addr.register_type, ModbusRegisterType::DiscreteInput);
        }

        #[test]
        fn test_case_insensitive() {
            let parser = ModbusAddressParser::new();
            assert!(parser.parse_modbus("hr:100").is_ok());
            assert!(parser.parse_modbus("Hr:100").is_ok());
            assert!(parser.parse_modbus("HR:100").is_ok());
        }

        #[test]
        fn test_invalid_type() {
            let parser = ModbusAddressParser::new();
            assert!(parser.parse_modbus("XX:100").is_err());
        }

        #[test]
        fn test_invalid_address() {
            let parser = ModbusAddressParser::new();
            assert!(parser.parse_modbus("HR:abc").is_err());
            assert!(parser.parse_modbus("HR:").is_err());
        }

        #[test]
        fn test_address_overflow() {
            let parser = ModbusAddressParser::new();
            assert!(parser.parse_modbus("HR:65535:2").is_err());
        }

        #[test]
        fn test_zero_count() {
            let parser = ModbusAddressParser::new();
            assert!(parser.parse_modbus("HR:100:0").is_err());
        }
    }

    mod opcua {
        use super::*;

        #[test]
        fn test_parse_numeric() {
            let parser = OpcUaAddressParser::new();
            let addr = parser.parse_opcua("ns=2;i=2258").unwrap();
            assert_eq!(addr.namespace_index, 2);
            assert!(matches!(addr.identifier, NodeIdentifier::Numeric(2258)));
        }

        #[test]
        fn test_parse_string() {
            let parser = OpcUaAddressParser::new();
            let addr = parser.parse_opcua("ns=2;s=Device.Temperature").unwrap();
            assert_eq!(addr.namespace_index, 2);
            if let NodeIdentifier::String(s) = &addr.identifier {
                assert_eq!(s, "Device.Temperature");
            } else {
                panic!("Expected String identifier");
            }
        }

        #[test]
        fn test_parse_without_namespace() {
            let parser = OpcUaAddressParser::new();
            let addr = parser.parse_opcua("i=100").unwrap();
            assert_eq!(addr.namespace_index, 0);
            assert!(matches!(addr.identifier, NodeIdentifier::Numeric(100)));
        }

        #[test]
        fn test_parse_guid() {
            let parser = OpcUaAddressParser::new();
            let addr = parser
                .parse_opcua("ns=1;g=12345678-1234-1234-1234-123456789012")
                .unwrap();
            assert!(matches!(addr.identifier, NodeIdentifier::Guid(_)));
        }

        #[test]
        fn test_invalid_guid_format() {
            let parser = OpcUaAddressParser::new();
            assert!(parser.parse_opcua("ns=1;g=invalid-guid").is_err());
        }

        #[test]
        fn test_empty_string_identifier() {
            let parser = OpcUaAddressParser::new();
            assert!(parser.parse_opcua("ns=1;s=").is_err());
        }
    }

    mod bacnet {
        use super::*;

        #[test]
        fn test_parse_analog_input() {
            let parser = BacNetAddressParser::new();
            let addr = parser.parse_bacnet("AI:0").unwrap();
            assert_eq!(addr.object_type, BacNetObjectType::AnalogInput);
            assert_eq!(addr.instance, 0);
            assert_eq!(addr.property, BacNetProperty::PresentValue);
        }

        #[test]
        fn test_parse_with_property() {
            let parser = BacNetAddressParser::new();
            let addr = parser.parse_bacnet("AI:0:77").unwrap();
            assert_eq!(addr.property, BacNetProperty::ObjectName);
        }

        #[test]
        fn test_parse_property_by_name() {
            let parser = BacNetAddressParser::new();
            let addr = parser.parse_bacnet("AI:0:present-value").unwrap();
            assert_eq!(addr.property, BacNetProperty::PresentValue);
        }

        #[test]
        fn test_parse_binary_value() {
            let parser = BacNetAddressParser::new();
            let addr = parser.parse_bacnet("BV:100").unwrap();
            assert_eq!(addr.object_type, BacNetObjectType::BinaryValue);
            assert_eq!(addr.instance, 100);
        }

        #[test]
        fn test_case_insensitive() {
            let parser = BacNetAddressParser::new();
            assert!(parser.parse_bacnet("ai:0").is_ok());
            assert!(parser.parse_bacnet("Ai:0").is_ok());
        }

        #[test]
        fn test_invalid_type() {
            let parser = BacNetAddressParser::new();
            assert!(parser.parse_bacnet("XX:0").is_err());
        }

        #[test]
        fn test_instance_overflow() {
            let parser = BacNetAddressParser::new();
            assert!(parser.parse_bacnet("AI:5000000").is_err());
        }
    }

    mod knx {
        use super::*;

        #[test]
        fn test_parse_three_level() {
            let parser = KnxAddressParser::new();
            let addr = parser.parse_knx("1/2/3").unwrap();
            assert_eq!(addr.main, 1);
            assert_eq!(addr.middle, 2);
            assert_eq!(addr.sub, 3);
            assert_eq!(addr.level, KnxAddressLevel::ThreeLevel);
        }

        #[test]
        fn test_parse_two_level() {
            let parser = KnxAddressParser::new();
            let addr = parser.parse_knx("1/100").unwrap();
            assert_eq!(addr.main, 1);
            assert_eq!(addr.middle, 0);
            assert_eq!(addr.sub, 100);
            assert_eq!(addr.level, KnxAddressLevel::TwoLevel);
        }

        #[test]
        fn test_three_level_max_values() {
            let parser = KnxAddressParser::new();
            let addr = parser.parse_knx("31/7/255").unwrap();
            assert_eq!(addr.main, 31);
            assert_eq!(addr.middle, 7);
            assert_eq!(addr.sub, 255);
        }

        #[test]
        fn test_two_level_max_values() {
            let parser = KnxAddressParser::new();
            let addr = parser.parse_knx("31/2047").unwrap();
            assert_eq!(addr.main, 31);
            assert_eq!(addr.sub, 2047);
        }

        #[test]
        fn test_main_overflow() {
            let parser = KnxAddressParser::new();
            assert!(parser.parse_knx("32/0/0").is_err());
        }

        #[test]
        fn test_middle_overflow() {
            let parser = KnxAddressParser::new();
            assert!(parser.parse_knx("0/8/0").is_err());
        }

        #[test]
        fn test_sub_overflow_three_level() {
            let parser = KnxAddressParser::new();
            assert!(parser.parse_knx("0/0/256").is_err());
        }

        #[test]
        fn test_sub_overflow_two_level() {
            let parser = KnxAddressParser::new();
            assert!(parser.parse_knx("0/2048").is_err());
        }
    }

    mod unified {
        use super::*;

        #[test]
        fn test_auto_detect_modbus() {
            let parser = UnifiedAddressParser::new();
            let addr = parser.parse("HR:100").unwrap();
            assert!(addr.is_modbus());
        }

        #[test]
        fn test_auto_detect_opcua() {
            let parser = UnifiedAddressParser::new();
            let addr = parser.parse("ns=2;i=100").unwrap();
            assert!(addr.is_opcua());
        }

        #[test]
        fn test_auto_detect_bacnet() {
            let parser = UnifiedAddressParser::new();
            let addr = parser.parse("AI:0").unwrap();
            assert!(addr.is_bacnet());
        }

        #[test]
        fn test_auto_detect_knx() {
            let parser = UnifiedAddressParser::new();
            let addr = parser.parse("1/2/3").unwrap();
            assert!(addr.is_knx());
        }

        #[test]
        fn test_with_default_protocol() {
            let parser = UnifiedAddressParser::with_default_protocol(ProtocolHint::ModbusTcp);
            // Without prefix, should use default protocol
            let addr = parser.parse_with_protocol("100", ProtocolHint::BacNet);
            assert!(addr.is_err()); // "100" is not valid BACnet format
        }

        #[test]
        fn test_unknown_format() {
            let parser = UnifiedAddressParser::new();
            assert!(parser.parse("unknown-format").is_err());
        }

        #[test]
        fn test_empty_address() {
            let parser = UnifiedAddressParser::new();
            assert!(parser.parse("").is_err());
            assert!(parser.parse("   ").is_err());
        }
    }
}
