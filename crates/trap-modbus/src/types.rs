// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Modbus-specific types with comprehensive configuration support.
//!
//! This module provides rich type definitions for Modbus protocol operations:
//!
//! - **RegisterType**: All four Modbus register types with metadata
//! - **ModbusAddress**: Extended address with parsing and validation
//! - **ModbusTcpConfig**: TCP connection configuration with builder
//! - **ModbusRtuConfig**: RTU serial configuration with builder
//! - **TagMapping**: Tag-to-register mapping with data conversion
//!
//! # Examples
//!
//! ```
//! use trap_modbus::types::{RegisterType, ModbusDataAddress, ModbusTcpConfig, ModbusDataType};
//!
//! // Create a holding register address
//! let addr = ModbusDataAddress::holding_register(40001)
//!     .with_count(2)
//!     .with_data_type(ModbusDataType::Float32);
//!
//! // Create TCP configuration
//! let config = ModbusTcpConfig::builder()
//!     .host("192.168.1.100")
//!     .port(502)
//!     .unit_id(1)
//!     .build()
//!     .unwrap();
//! ```

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{ConfigurationError, ModbusError};

// =============================================================================
// RegisterType
// =============================================================================

/// Modbus register type with comprehensive metadata.
///
/// Modbus defines four types of registers, each with different characteristics
/// for read/write access and data size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterType {
    /// Coil (read/write, 1 bit)
    ///
    /// - Function code 1: Read Coils
    /// - Function code 5: Write Single Coil
    /// - Function code 15: Write Multiple Coils
    /// - Address range: 0x0000 - 0xFFFF (00001-09999 in Modbus notation)
    Coil,

    /// Discrete Input (read-only, 1 bit)
    ///
    /// - Function code 2: Read Discrete Inputs
    /// - Address range: 0x0000 - 0xFFFF (10001-19999 in Modbus notation)
    DiscreteInput,

    /// Holding Register (read/write, 16 bits)
    ///
    /// - Function code 3: Read Holding Registers
    /// - Function code 6: Write Single Register
    /// - Function code 16: Write Multiple Registers
    /// - Function code 23: Read/Write Multiple Registers
    /// - Address range: 0x0000 - 0xFFFF (40001-49999 in Modbus notation)
    #[default]
    HoldingRegister,

    /// Input Register (read-only, 16 bits)
    ///
    /// - Function code 4: Read Input Registers
    /// - Address range: 0x0000 - 0xFFFF (30001-39999 in Modbus notation)
    InputRegister,
}

impl RegisterType {
    // =========================================================================
    // Properties
    // =========================================================================

    /// Returns `true` if this register type is writable.
    #[inline]
    pub const fn is_writable(&self) -> bool {
        matches!(self, Self::Coil | Self::HoldingRegister)
    }

    /// Returns `true` if this is a bit-type register (1-bit).
    #[inline]
    pub const fn is_bit(&self) -> bool {
        matches!(self, Self::Coil | Self::DiscreteInput)
    }

    /// Returns `true` if this is a word-type register (16-bit).
    #[inline]
    pub const fn is_word(&self) -> bool {
        matches!(self, Self::HoldingRegister | Self::InputRegister)
    }

    /// Returns `true` if this is a read-only register type.
    #[inline]
    pub const fn is_read_only(&self) -> bool {
        matches!(self, Self::DiscreteInput | Self::InputRegister)
    }

    /// Returns the bit size of values in this register type.
    #[inline]
    pub const fn bit_size(&self) -> u8 {
        match self {
            Self::Coil | Self::DiscreteInput => 1,
            Self::HoldingRegister | Self::InputRegister => 16,
        }
    }

    // =========================================================================
    // Function Codes
    // =========================================================================

    /// Returns the function code for reading this register type.
    #[inline]
    pub const fn read_function_code(&self) -> u8 {
        match self {
            Self::Coil => 0x01,
            Self::DiscreteInput => 0x02,
            Self::HoldingRegister => 0x03,
            Self::InputRegister => 0x04,
        }
    }

    /// Returns the function code for writing a single value.
    ///
    /// Returns `None` for read-only register types.
    #[inline]
    pub const fn write_single_function_code(&self) -> Option<u8> {
        match self {
            Self::Coil => Some(0x05),
            Self::HoldingRegister => Some(0x06),
            Self::DiscreteInput | Self::InputRegister => None,
        }
    }

    /// Returns the function code for writing multiple values.
    ///
    /// Returns `None` for read-only register types.
    #[inline]
    pub const fn write_multiple_function_code(&self) -> Option<u8> {
        match self {
            Self::Coil => Some(0x0F),
            Self::HoldingRegister => Some(0x10),
            Self::DiscreteInput | Self::InputRegister => None,
        }
    }

    // =========================================================================
    // Limits
    // =========================================================================

    /// Returns the maximum number of items that can be read in a single request.
    #[inline]
    pub const fn max_read_count(&self) -> u16 {
        match self {
            Self::Coil | Self::DiscreteInput => 2000,      // 2000 bits
            Self::HoldingRegister | Self::InputRegister => 125, // 125 registers
        }
    }

    /// Returns the maximum number of items that can be written in a single request.
    #[inline]
    pub const fn max_write_count(&self) -> Option<u16> {
        match self {
            Self::Coil => Some(1968),          // 1968 coils
            Self::HoldingRegister => Some(123), // 123 registers
            Self::DiscreteInput | Self::InputRegister => None,
        }
    }

    // =========================================================================
    // Address Notation
    // =========================================================================

    /// Returns the Modbus notation prefix (e.g., "4xxxx" for Holding Register).
    pub const fn notation_prefix(&self) -> char {
        match self {
            Self::Coil => '0',
            Self::DiscreteInput => '1',
            Self::InputRegister => '3',
            Self::HoldingRegister => '4',
        }
    }

    /// Returns the short name for this register type.
    pub const fn short_name(&self) -> &'static str {
        match self {
            Self::Coil => "C",
            Self::DiscreteInput => "DI",
            Self::InputRegister => "IR",
            Self::HoldingRegister => "HR",
        }
    }

    /// Returns the full name for this register type.
    pub const fn full_name(&self) -> &'static str {
        match self {
            Self::Coil => "Coil",
            Self::DiscreteInput => "Discrete Input",
            Self::InputRegister => "Input Register",
            Self::HoldingRegister => "Holding Register",
        }
    }

    /// Returns a description of this register type.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Coil => "Read/write single bit (digital output)",
            Self::DiscreteInput => "Read-only single bit (digital input)",
            Self::InputRegister => "Read-only 16-bit word (analog input)",
            Self::HoldingRegister => "Read/write 16-bit word (analog output/storage)",
        }
    }

    /// Creates from Modbus notation address (e.g., 40001 -> HoldingRegister).
    pub fn from_notation_address(address: u32) -> Option<(Self, u16)> {
        match address {
            1..=9999 => Some((Self::Coil, (address - 1) as u16)),
            10001..=19999 => Some((Self::DiscreteInput, (address - 10001) as u16)),
            30001..=39999 => Some((Self::InputRegister, (address - 30001) as u16)),
            40001..=49999 => Some((Self::HoldingRegister, (address - 40001) as u16)),
            // Extended addressing for 6-digit notation
            100001..=165535 => Some((Self::Coil, (address - 100001) as u16)),
            200001..=265535 => Some((Self::DiscreteInput, (address - 200001) as u16)),
            300001..=365535 => Some((Self::InputRegister, (address - 300001) as u16)),
            400001..=465535 => Some((Self::HoldingRegister, (address - 400001) as u16)),
            _ => None,
        }
    }

    /// Converts to Modbus notation address.
    pub const fn to_notation_address(&self, address: u16) -> u32 {
        match self {
            Self::Coil => address as u32 + 1,
            Self::DiscreteInput => address as u32 + 10001,
            Self::InputRegister => address as u32 + 30001,
            Self::HoldingRegister => address as u32 + 40001,
        }
    }

    /// All register types as an array.
    pub const ALL: [RegisterType; 4] = [
        Self::Coil,
        Self::DiscreteInput,
        Self::InputRegister,
        Self::HoldingRegister,
    ];
}

impl fmt::Display for RegisterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_name())
    }
}

impl FromStr for RegisterType {
    type Err = ModbusError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "C" | "COIL" | "CO" | "0" | "0X" => Ok(Self::Coil),
            "DI" | "DISCRETE" | "DISCRETE_INPUT" | "1" | "1X" => Ok(Self::DiscreteInput),
            "IR" | "INPUT" | "INPUT_REGISTER" | "3" | "3X" => Ok(Self::InputRegister),
            "HR" | "HOLDING" | "HOLDING_REGISTER" | "4" | "4X" => Ok(Self::HoldingRegister),
            _ => Err(ModbusError::configuration(
                ConfigurationError::invalid_address_format(
                    s,
                    "Expected: C/DI/IR/HR or Coil/DiscreteInput/InputRegister/HoldingRegister",
                ),
            )),
        }
    }
}

// =============================================================================
// ModbusDataType
// =============================================================================

/// Data types for Modbus register interpretation.
///
/// Modbus registers are 16-bit, but values often span multiple registers
/// or require specific interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ModbusDataType {
    /// Boolean (single bit for Coils/Discrete Inputs).
    Bool,

    /// 8-bit signed integer (low byte of register).
    Int8,

    /// 8-bit unsigned integer (low byte of register).
    UInt8,

    /// 16-bit signed integer (1 register).
    Int16,

    /// 16-bit unsigned integer (1 register).
    #[default]
    UInt16,

    /// 32-bit signed integer (2 registers).
    Int32,

    /// 32-bit unsigned integer (2 registers).
    UInt32,

    /// 64-bit signed integer (4 registers).
    Int64,

    /// 64-bit unsigned integer (4 registers).
    UInt64,

    /// 32-bit IEEE 754 float (2 registers).
    Float32,

    /// 64-bit IEEE 754 float (4 registers).
    Float64,

    /// ASCII string (variable length, 2 chars per register).
    String,

    /// Raw bytes (variable length).
    Bytes,
}

impl ModbusDataType {
    /// Returns the number of registers required for this data type.
    #[inline]
    pub const fn register_count(&self) -> u16 {
        match self {
            Self::Bool | Self::Int8 | Self::UInt8 | Self::Int16 | Self::UInt16 => 1,
            Self::Int32 | Self::UInt32 | Self::Float32 => 2,
            Self::Int64 | Self::UInt64 | Self::Float64 => 4,
            Self::String | Self::Bytes => 1, // Variable, minimum 1
        }
    }

    /// Returns the byte size of this data type.
    #[inline]
    pub const fn byte_size(&self) -> usize {
        match self {
            Self::Bool => 1,
            Self::Int8 | Self::UInt8 => 1,
            Self::Int16 | Self::UInt16 => 2,
            Self::Int32 | Self::UInt32 | Self::Float32 => 4,
            Self::Int64 | Self::UInt64 | Self::Float64 => 8,
            Self::String | Self::Bytes => 0, // Variable
        }
    }

    /// Returns `true` if this is a variable-length type.
    #[inline]
    pub const fn is_variable_length(&self) -> bool {
        matches!(self, Self::String | Self::Bytes)
    }

    /// Returns `true` if this is a signed integer type.
    #[inline]
    pub const fn is_signed(&self) -> bool {
        matches!(self, Self::Int8 | Self::Int16 | Self::Int32 | Self::Int64)
    }

    /// Returns `true` if this is a floating-point type.
    #[inline]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float32 | Self::Float64)
    }

    /// Returns `true` if this type is suitable for bit registers (Coil/DI).
    #[inline]
    pub const fn is_bit_compatible(&self) -> bool {
        matches!(self, Self::Bool)
    }

    /// Converts from trap_core::DataType.
    pub fn from_core_data_type(dt: trap_core::DataType) -> Self {
        match dt {
            trap_core::DataType::Bool => Self::Bool,
            trap_core::DataType::Int8 => Self::Int8,
            trap_core::DataType::Int16 => Self::Int16,
            trap_core::DataType::Int32 => Self::Int32,
            trap_core::DataType::Int64 => Self::Int64,
            trap_core::DataType::UInt8 => Self::UInt8,
            trap_core::DataType::UInt16 => Self::UInt16,
            trap_core::DataType::UInt32 => Self::UInt32,
            trap_core::DataType::UInt64 => Self::UInt64,
            trap_core::DataType::Float32 => Self::Float32,
            trap_core::DataType::Float64 => Self::Float64,
            trap_core::DataType::String => Self::String,
            trap_core::DataType::Bytes => Self::Bytes,
            _ => Self::UInt16,
        }
    }

    /// Converts to trap_core::DataType.
    pub const fn to_core_data_type(&self) -> trap_core::DataType {
        match self {
            Self::Bool => trap_core::DataType::Bool,
            Self::Int8 => trap_core::DataType::Int8,
            Self::Int16 => trap_core::DataType::Int16,
            Self::Int32 => trap_core::DataType::Int32,
            Self::Int64 => trap_core::DataType::Int64,
            Self::UInt8 => trap_core::DataType::UInt8,
            Self::UInt16 => trap_core::DataType::UInt16,
            Self::UInt32 => trap_core::DataType::UInt32,
            Self::UInt64 => trap_core::DataType::UInt64,
            Self::Float32 => trap_core::DataType::Float32,
            Self::Float64 => trap_core::DataType::Float64,
            Self::String => trap_core::DataType::String,
            Self::Bytes => trap_core::DataType::Bytes,
        }
    }
}

impl fmt::Display for ModbusDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Bool => "bool",
            Self::Int8 => "int8",
            Self::UInt8 => "uint8",
            Self::Int16 => "int16",
            Self::UInt16 => "uint16",
            Self::Int32 => "int32",
            Self::UInt32 => "uint32",
            Self::Int64 => "int64",
            Self::UInt64 => "uint64",
            Self::Float32 => "float32",
            Self::Float64 => "float64",
            Self::String => "string",
            Self::Bytes => "bytes",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for ModbusDataType {
    type Err = ModbusError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bool" | "boolean" | "bit" => Ok(Self::Bool),
            "int8" | "i8" | "sbyte" => Ok(Self::Int8),
            "uint8" | "u8" | "byte" => Ok(Self::UInt8),
            "int16" | "i16" | "short" | "word" => Ok(Self::Int16),
            "uint16" | "u16" | "ushort" | "uword" => Ok(Self::UInt16),
            "int32" | "i32" | "int" | "dword" => Ok(Self::Int32),
            "uint32" | "u32" | "uint" | "udword" => Ok(Self::UInt32),
            "int64" | "i64" | "long" | "qword" => Ok(Self::Int64),
            "uint64" | "u64" | "ulong" | "uqword" => Ok(Self::UInt64),
            "float32" | "f32" | "float" | "real" | "single" => Ok(Self::Float32),
            "float64" | "f64" | "double" | "lreal" => Ok(Self::Float64),
            "string" | "str" | "text" => Ok(Self::String),
            "bytes" | "raw" | "binary" => Ok(Self::Bytes),
            _ => Err(ModbusError::configuration(
                ConfigurationError::invalid_data_type(s),
            )),
        }
    }
}

// =============================================================================
// ByteOrder
// =============================================================================

/// Byte order for multi-register values.
///
/// Different Modbus devices use different byte orderings, which is
/// critical for correctly interpreting 32-bit and 64-bit values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    /// Big-endian (most significant byte first).
    /// Register order: [MSW, LSW]
    /// Byte order within word: [MSB, LSB]
    #[default]
    BigEndian,

    /// Little-endian (least significant byte first).
    /// Register order: [LSW, MSW]
    /// Byte order within word: [LSB, MSB]
    LittleEndian,

    /// Big-endian word order, little-endian byte order within words.
    /// Register order: [MSW, LSW]
    /// Byte order within word: [LSB, MSB]
    /// Also known as "Mid-Big Endian" or "CDAB" format.
    MidBigEndian,

    /// Little-endian word order, big-endian byte order within words.
    /// Register order: [LSW, MSW]
    /// Byte order within word: [MSB, LSB]
    /// Also known as "Mid-Little Endian" or "BADC" format.
    MidLittleEndian,
}

impl ByteOrder {
    /// Returns common vendor-specific aliases for this byte order.
    pub const fn aliases(&self) -> &'static [&'static str] {
        match self {
            Self::BigEndian => &["ABCD", "big", "be", "network", "msb_first"],
            Self::LittleEndian => &["DCBA", "little", "le", "intel", "lsb_first"],
            Self::MidBigEndian => &["CDAB", "mid_big", "word_swap", "modicon"],
            Self::MidLittleEndian => &["BADC", "mid_little", "byte_swap"],
        }
    }

    /// Returns a description of this byte order.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::BigEndian => "Big-endian (ABCD) - Most common for Modbus",
            Self::LittleEndian => "Little-endian (DCBA) - Intel byte order",
            Self::MidBigEndian => "Mid-big-endian (CDAB) - Word swapped",
            Self::MidLittleEndian => "Mid-little-endian (BADC) - Byte swapped",
        }
    }
}

impl fmt::Display for ByteOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BigEndian => "big_endian",
            Self::LittleEndian => "little_endian",
            Self::MidBigEndian => "mid_big_endian",
            Self::MidLittleEndian => "mid_little_endian",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for ByteOrder {
    type Err = ModbusError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace(['-', '_'], "").as_str() {
            "bigendian" | "big" | "be" | "abcd" | "msbfirst" | "network" => Ok(Self::BigEndian),
            "littleendian" | "little" | "le" | "dcba" | "lsbfirst" | "intel" => {
                Ok(Self::LittleEndian)
            }
            "midbigendian" | "midbig" | "cdab" | "wordswap" | "modicon" => Ok(Self::MidBigEndian),
            "midlittleendian" | "midlittle" | "badc" | "byteswap" => Ok(Self::MidLittleEndian),
            _ => Err(ModbusError::configuration(
                ConfigurationError::InvalidAddressFormat {
                    address: s.to_string(),
                    reason: "Expected: big_endian, little_endian, mid_big_endian, mid_little_endian"
                        .to_string(),
                },
            )),
        }
    }
}

// =============================================================================
// ModbusDataAddress
// =============================================================================

/// Extended Modbus address with data type and conversion information.
///
/// This provides more functionality than `trap_core::ModbusAddress`,
/// including data type specification, byte ordering, and value scaling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModbusDataAddress {
    /// The register type.
    pub register_type: RegisterType,

    /// The starting register address (0-based).
    pub address: u16,

    /// The number of registers to read/write.
    #[serde(default = "default_count")]
    pub count: u16,

    /// The data type for value interpretation.
    #[serde(default)]
    pub data_type: ModbusDataType,

    /// Byte order for multi-register values.
    #[serde(default)]
    pub byte_order: ByteOrder,

    /// Bit position within register (for bit extraction from word registers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_position: Option<u8>,

    /// Scale factor for value conversion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scale: Option<f64>,

    /// Offset for value conversion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<f64>,
}

fn default_count() -> u16 {
    1
}

impl ModbusDataAddress {
    // =========================================================================
    // Constructors
    // =========================================================================

    /// Creates a new coil address.
    pub fn coil(address: u16) -> Self {
        Self {
            register_type: RegisterType::Coil,
            address,
            count: 1,
            data_type: ModbusDataType::Bool,
            byte_order: ByteOrder::default(),
            bit_position: None,
            scale: None,
            offset: None,
        }
    }

    /// Creates a new discrete input address.
    pub fn discrete_input(address: u16) -> Self {
        Self {
            register_type: RegisterType::DiscreteInput,
            address,
            count: 1,
            data_type: ModbusDataType::Bool,
            byte_order: ByteOrder::default(),
            bit_position: None,
            scale: None,
            offset: None,
        }
    }

    /// Creates a new holding register address.
    pub fn holding_register(address: u16) -> Self {
        Self {
            register_type: RegisterType::HoldingRegister,
            address,
            count: 1,
            data_type: ModbusDataType::UInt16,
            byte_order: ByteOrder::default(),
            bit_position: None,
            scale: None,
            offset: None,
        }
    }

    /// Creates a new input register address.
    pub fn input_register(address: u16) -> Self {
        Self {
            register_type: RegisterType::InputRegister,
            address,
            count: 1,
            data_type: ModbusDataType::UInt16,
            byte_order: ByteOrder::default(),
            bit_position: None,
            scale: None,
            offset: None,
        }
    }

    /// Creates from Modbus notation address (e.g., 40001).
    pub fn from_notation(notation_address: u32) -> Result<Self, ModbusError> {
        let (register_type, address) =
            RegisterType::from_notation_address(notation_address).ok_or_else(|| {
                ModbusError::configuration(ConfigurationError::invalid_address_format(
                    notation_address.to_string(),
                    "Invalid Modbus notation address",
                ))
            })?;

        Ok(Self {
            register_type,
            address,
            count: 1,
            data_type: if register_type.is_bit() {
                ModbusDataType::Bool
            } else {
                ModbusDataType::UInt16
            },
            byte_order: ByteOrder::default(),
            bit_position: None,
            scale: None,
            offset: None,
        })
    }

    // =========================================================================
    // Builder Methods
    // =========================================================================

    /// Sets the register count.
    #[inline]
    pub fn with_count(mut self, count: u16) -> Self {
        self.count = count;
        self
    }

    /// Sets the data type.
    #[inline]
    pub fn with_data_type(mut self, data_type: ModbusDataType) -> Self {
        self.data_type = data_type;
        // Auto-adjust count based on data type
        if !data_type.is_variable_length() && self.count < data_type.register_count() {
            self.count = data_type.register_count();
        }
        self
    }

    /// Sets the byte order.
    #[inline]
    pub fn with_byte_order(mut self, byte_order: ByteOrder) -> Self {
        self.byte_order = byte_order;
        self
    }

    /// Sets the bit position for bit extraction.
    #[inline]
    pub fn with_bit_position(mut self, bit: u8) -> Self {
        self.bit_position = Some(bit);
        self
    }

    /// Sets the scale factor.
    #[inline]
    pub fn with_scale(mut self, scale: f64) -> Self {
        self.scale = Some(scale);
        self
    }

    /// Sets the offset.
    #[inline]
    pub fn with_offset(mut self, offset: f64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Sets both scale and offset.
    #[inline]
    pub fn with_scaling(mut self, scale: f64, offset: f64) -> Self {
        self.scale = Some(scale);
        self.offset = Some(offset);
        self
    }

    // =========================================================================
    // Properties
    // =========================================================================

    /// Returns the end address (exclusive).
    #[inline]
    pub fn end_address(&self) -> u16 {
        self.address.saturating_add(self.count)
    }

    /// Returns `true` if this address is writable.
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.register_type.is_writable()
    }

    /// Returns `true` if this address has scaling applied.
    #[inline]
    pub fn has_scaling(&self) -> bool {
        self.scale.is_some() || self.offset.is_some()
    }

    /// Returns the effective scale factor.
    #[inline]
    pub fn effective_scale(&self) -> f64 {
        self.scale.unwrap_or(1.0)
    }

    /// Returns the effective offset.
    #[inline]
    pub fn effective_offset(&self) -> f64 {
        self.offset.unwrap_or(0.0)
    }

    /// Returns the Modbus notation address.
    pub fn notation_address(&self) -> u32 {
        self.register_type.to_notation_address(self.address)
    }

    // =========================================================================
    // Validation
    // =========================================================================

    /// Validates this address configuration.
    pub fn validate(&self) -> Result<(), ModbusError> {
        // Check bit-type compatibility
        if self.register_type.is_bit() && !self.data_type.is_bit_compatible() {
            return Err(ModbusError::configuration(
                ConfigurationError::invalid_address_format(
                    self.to_string(),
                    format!(
                        "Data type {} is not compatible with bit register type {}",
                        self.data_type, self.register_type
                    ),
                ),
            ));
        }

        // Check count is sufficient for data type
        if !self.data_type.is_variable_length() && self.count < self.data_type.register_count() {
            return Err(ModbusError::configuration(
                ConfigurationError::invalid_address_format(
                    self.to_string(),
                    format!(
                        "Count {} is insufficient for data type {} (requires {} registers)",
                        self.count,
                        self.data_type,
                        self.data_type.register_count()
                    ),
                ),
            ));
        }

        // Check max read count
        if self.count > self.register_type.max_read_count() {
            return Err(ModbusError::configuration(
                ConfigurationError::invalid_address_format(
                    self.to_string(),
                    format!(
                        "Count {} exceeds maximum {} for {}",
                        self.count,
                        self.register_type.max_read_count(),
                        self.register_type.full_name()
                    ),
                ),
            ));
        }

        // Check bit position
        if let Some(bit) = self.bit_position {
            if bit >= 16 {
                return Err(ModbusError::configuration(
                    ConfigurationError::invalid_address_format(
                        self.to_string(),
                        format!("Bit position {} must be 0-15", bit),
                    ),
                ));
            }
        }

        // Check for address overflow
        if self.address.checked_add(self.count).is_none() {
            return Err(ModbusError::configuration(
                ConfigurationError::invalid_address_format(
                    self.to_string(),
                    "Address range would overflow",
                ),
            ));
        }

        Ok(())
    }

    // =========================================================================
    // Overlap Detection
    // =========================================================================

    /// Returns `true` if this address overlaps with another.
    pub fn overlaps(&self, other: &ModbusDataAddress) -> bool {
        if self.register_type != other.register_type {
            return false;
        }
        let self_end = self.end_address();
        let other_end = other.end_address();
        self.address < other_end && other.address < self_end
    }

    /// Returns `true` if this address is contiguous with another.
    pub fn is_contiguous_with(&self, other: &ModbusDataAddress) -> bool {
        if self.register_type != other.register_type {
            return false;
        }
        self.end_address() == other.address || other.end_address() == self.address
    }

    /// Merges two contiguous addresses into one (for batch optimization).
    pub fn merge(&self, other: &ModbusDataAddress) -> Option<ModbusDataAddress> {
        if !self.is_contiguous_with(other) {
            return None;
        }

        let start = self.address.min(other.address);
        let end = self.end_address().max(other.end_address());

        Some(ModbusDataAddress {
            register_type: self.register_type,
            address: start,
            count: end - start,
            data_type: ModbusDataType::Bytes, // Generic for merged reads
            byte_order: self.byte_order,
            bit_position: None,
            scale: None,
            offset: None,
        })
    }

    // =========================================================================
    // Conversion
    // =========================================================================

    /// Converts to trap_core::ModbusAddress.
    pub fn to_core_address(&self) -> trap_core::address::ModbusAddress {
        trap_core::address::ModbusAddress {
            register_type: match self.register_type {
                RegisterType::Coil => trap_core::address::ModbusRegisterType::Coil,
                RegisterType::DiscreteInput => trap_core::address::ModbusRegisterType::DiscreteInput,
                RegisterType::HoldingRegister => {
                    trap_core::address::ModbusRegisterType::HoldingRegister
                }
                RegisterType::InputRegister => trap_core::address::ModbusRegisterType::InputRegister,
            },
            address: self.address,
            count: self.count,
            is_tcp: true,
            unit_id: 1,
        }
    }

    /// Converts to trap_core::Address.
    pub fn to_address(&self) -> trap_core::Address {
        trap_core::Address::Modbus(self.to_core_address())
    }
}

impl Default for ModbusDataAddress {
    fn default() -> Self {
        Self::holding_register(0)
    }
}

impl fmt::Display for ModbusDataAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.register_type.short_name(),
            self.address,
            self.count
        )?;
        if self.data_type != ModbusDataType::default() {
            write!(f, ":{}", self.data_type)?;
        }
        Ok(())
    }
}

impl FromStr for ModbusDataAddress {
    type Err = ModbusError;

    /// Parses an address from string format.
    ///
    /// Supported formats:
    /// - "HR:100" - Holding register 100
    /// - "HR:100:2" - Holding register 100, count 2
    /// - "HR:100:2:float32" - With data type
    /// - "40001" - Modbus notation
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // Try Modbus notation first (e.g., "40001")
        if let Ok(notation) = s.parse::<u32>() {
            return Self::from_notation(notation);
        }

        // Parse structured format (e.g., "HR:100:2:float32")
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() < 2 {
            return Err(ModbusError::configuration(
                ConfigurationError::invalid_address_format(
                    s,
                    "Expected format: TYPE:ADDRESS[:COUNT[:DATATYPE]]",
                ),
            ));
        }

        let register_type: RegisterType = parts[0].parse()?;

        let address: u16 = parts[1].parse().map_err(|_| {
            ModbusError::configuration(ConfigurationError::invalid_address_format(
                s,
                "Invalid address number",
            ))
        })?;

        let count: u16 = if parts.len() > 2 {
            parts[2].parse().map_err(|_| {
                ModbusError::configuration(ConfigurationError::invalid_address_format(
                    s,
                    "Invalid count number",
                ))
            })?
        } else {
            1
        };

        let data_type: ModbusDataType = if parts.len() > 3 {
            parts[3].parse()?
        } else if register_type.is_bit() {
            ModbusDataType::Bool
        } else {
            ModbusDataType::UInt16
        };

        let addr = Self {
            register_type,
            address,
            count,
            data_type,
            byte_order: ByteOrder::default(),
            bit_position: None,
            scale: None,
            offset: None,
        };

        addr.validate()?;
        Ok(addr)
    }
}

// =============================================================================
// ModbusTcpConfig
// =============================================================================

/// Configuration for Modbus TCP connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusTcpConfig {
    /// Target host address.
    pub host: String,

    /// Target port (default: 502).
    #[serde(default = "default_port")]
    pub port: u16,

    /// Unit ID / Slave address (default: 1).
    #[serde(default = "default_unit_id")]
    pub unit_id: u8,

    /// Connection timeout.
    #[serde(default = "default_connect_timeout")]
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Read/write operation timeout.
    #[serde(default = "default_operation_timeout")]
    #[serde(with = "humantime_serde")]
    pub operation_timeout: Duration,

    /// Maximum number of retries.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Delay between retries.
    #[serde(default = "default_retry_delay")]
    #[serde(with = "humantime_serde")]
    pub retry_delay: Duration,

    /// Keep-alive interval (None = disabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "option_duration")]
    pub keep_alive: Option<Duration>,

    /// Enable TCP_NODELAY.
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,

    /// Default byte order for multi-register values.
    #[serde(default)]
    pub byte_order: ByteOrder,
}

fn default_port() -> u16 {
    502
}

fn default_unit_id() -> u8 {
    1
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_operation_timeout() -> Duration {
    Duration::from_secs(3)
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_delay() -> Duration {
    Duration::from_millis(500)
}

fn default_true() -> bool {
    true
}

mod option_duration {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(d) => {
                let s = humantime::format_duration(*d).to_string();
                s.serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let d = humantime::parse_duration(&s).map_err(serde::de::Error::custom)?;
                Ok(Some(d))
            }
            None => Ok(None),
        }
    }
}

impl ModbusTcpConfig {
    /// Creates a new builder for ModbusTcpConfig.
    pub fn builder() -> ModbusTcpConfigBuilder {
        ModbusTcpConfigBuilder::default()
    }

    /// Creates a simple configuration with just host.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            ..Default::default()
        }
    }

    /// Creates configuration with host and port.
    pub fn with_port(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            ..Default::default()
        }
    }

    /// Returns the socket address string.
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Validates this configuration.
    pub fn validate(&self) -> Result<(), ModbusError> {
        if self.host.is_empty() {
            return Err(ModbusError::configuration(ConfigurationError::missing_field(
                "host",
            )));
        }

        if self.unit_id == 0 {
            return Err(ModbusError::configuration(
                ConfigurationError::invalid_unit_id(0),
            ));
        }

        if self.connect_timeout.is_zero() {
            return Err(ModbusError::configuration(ConfigurationError::InvalidTimeout {
                duration: self.connect_timeout,
                reason: "Connect timeout must be greater than 0".to_string(),
            }));
        }

        Ok(())
    }
}

impl Default for ModbusTcpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: default_port(),
            unit_id: default_unit_id(),
            connect_timeout: default_connect_timeout(),
            operation_timeout: default_operation_timeout(),
            max_retries: default_max_retries(),
            retry_delay: default_retry_delay(),
            keep_alive: None,
            tcp_nodelay: true,
            byte_order: ByteOrder::default(),
        }
    }
}

// =============================================================================
// ModbusTcpConfigBuilder
// =============================================================================

/// Builder for ModbusTcpConfig.
#[derive(Debug, Default)]
pub struct ModbusTcpConfigBuilder {
    host: Option<String>,
    port: Option<u16>,
    unit_id: Option<u8>,
    connect_timeout: Option<Duration>,
    operation_timeout: Option<Duration>,
    max_retries: Option<u32>,
    retry_delay: Option<Duration>,
    keep_alive: Option<Duration>,
    tcp_nodelay: Option<bool>,
    byte_order: Option<ByteOrder>,
}

impl ModbusTcpConfigBuilder {
    /// Sets the host address.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Sets the port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Sets the unit ID.
    pub fn unit_id(mut self, unit_id: u8) -> Self {
        self.unit_id = Some(unit_id);
        self
    }

    /// Sets the connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Sets the operation timeout.
    pub fn operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = Some(timeout);
        self
    }

    /// Sets the maximum retries.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = Some(retries);
        self
    }

    /// Sets the retry delay.
    pub fn retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = Some(delay);
        self
    }

    /// Sets the keep-alive interval.
    pub fn keep_alive(mut self, interval: Duration) -> Self {
        self.keep_alive = Some(interval);
        self
    }

    /// Sets TCP_NODELAY.
    pub fn tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.tcp_nodelay = Some(nodelay);
        self
    }

    /// Sets the default byte order.
    pub fn byte_order(mut self, order: ByteOrder) -> Self {
        self.byte_order = Some(order);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ModbusTcpConfig, ModbusError> {
        let host = self.host.ok_or_else(|| {
            ModbusError::configuration(ConfigurationError::missing_field("host"))
        })?;

        let config = ModbusTcpConfig {
            host,
            port: self.port.unwrap_or_else(default_port),
            unit_id: self.unit_id.unwrap_or_else(default_unit_id),
            connect_timeout: self.connect_timeout.unwrap_or_else(default_connect_timeout),
            operation_timeout: self.operation_timeout.unwrap_or_else(default_operation_timeout),
            max_retries: self.max_retries.unwrap_or_else(default_max_retries),
            retry_delay: self.retry_delay.unwrap_or_else(default_retry_delay),
            keep_alive: self.keep_alive,
            tcp_nodelay: self.tcp_nodelay.unwrap_or(true),
            byte_order: self.byte_order.unwrap_or_default(),
        };

        config.validate()?;
        Ok(config)
    }
}

// =============================================================================
// ModbusRtuConfig
// =============================================================================

/// Configuration for Modbus RTU connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusRtuConfig {
    /// Serial port path (e.g., "/dev/ttyUSB0" or "COM1").
    pub port: String,

    /// Baud rate.
    #[serde(default = "default_baud_rate")]
    pub baud_rate: u32,

    /// Data bits.
    #[serde(default)]
    pub data_bits: DataBits,

    /// Parity.
    #[serde(default)]
    pub parity: Parity,

    /// Stop bits.
    #[serde(default)]
    pub stop_bits: StopBits,

    /// Unit ID / Slave address.
    #[serde(default = "default_unit_id")]
    pub unit_id: u8,

    /// Read/write operation timeout.
    #[serde(default = "default_operation_timeout")]
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,

    /// Inter-frame delay (3.5 character times).
    /// If not set, calculated from baud rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "option_duration")]
    pub inter_frame_delay: Option<Duration>,

    /// Maximum number of retries.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Default byte order for multi-register values.
    #[serde(default)]
    pub byte_order: ByteOrder,
}

fn default_baud_rate() -> u32 {
    9600
}

impl ModbusRtuConfig {
    /// Creates a new builder for ModbusRtuConfig.
    pub fn builder() -> ModbusRtuConfigBuilder {
        ModbusRtuConfigBuilder::default()
    }

    /// Creates a simple configuration with just port.
    pub fn new(port: impl Into<String>) -> Self {
        Self {
            port: port.into(),
            ..Default::default()
        }
    }

    /// Calculates the inter-frame delay based on baud rate.
    ///
    /// Per Modbus specification, the delay should be 3.5 character times.
    /// At 9600 baud with 11 bits per character (1 start + 8 data + 1 parity + 1 stop):
    /// 3.5 * 11 / 9600 ≈ 4ms
    pub fn calculated_inter_frame_delay(&self) -> Duration {
        if let Some(delay) = self.inter_frame_delay {
            return delay;
        }

        // Calculate character time: bits per character / baud rate
        let bits_per_char = 1 + // Start bit
            self.data_bits.bits() +
            self.parity.bits() +
            self.stop_bits.bits();

        // 3.5 character times in microseconds
        let delay_us = (3.5 * bits_per_char as f64 / self.baud_rate as f64 * 1_000_000.0) as u64;

        // Minimum 1ms to account for OS scheduling
        Duration::from_micros(delay_us.max(1000))
    }

    /// Validates this configuration.
    pub fn validate(&self) -> Result<(), ModbusError> {
        if self.port.is_empty() {
            return Err(ModbusError::configuration(ConfigurationError::missing_field(
                "port",
            )));
        }

        const VALID_BAUD_RATES: &[u32] = &[
            300, 600, 1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 115200, 230400, 460800,
            921600,
        ];

        if !VALID_BAUD_RATES.contains(&self.baud_rate) {
            return Err(ModbusError::configuration(
                ConfigurationError::InvalidBaudRate {
                    baud_rate: self.baud_rate,
                },
            ));
        }

        if self.unit_id == 0 {
            return Err(ModbusError::configuration(
                ConfigurationError::invalid_unit_id(0),
            ));
        }

        Ok(())
    }
}

impl Default for ModbusRtuConfig {
    fn default() -> Self {
        Self {
            port: String::new(),
            baud_rate: default_baud_rate(),
            data_bits: DataBits::default(),
            parity: Parity::default(),
            stop_bits: StopBits::default(),
            unit_id: default_unit_id(),
            timeout: default_operation_timeout(),
            inter_frame_delay: None,
            max_retries: default_max_retries(),
            byte_order: ByteOrder::default(),
        }
    }
}

// =============================================================================
// ModbusRtuConfigBuilder
// =============================================================================

/// Builder for ModbusRtuConfig.
#[derive(Debug, Default)]
pub struct ModbusRtuConfigBuilder {
    port: Option<String>,
    baud_rate: Option<u32>,
    data_bits: Option<DataBits>,
    parity: Option<Parity>,
    stop_bits: Option<StopBits>,
    unit_id: Option<u8>,
    timeout: Option<Duration>,
    inter_frame_delay: Option<Duration>,
    max_retries: Option<u32>,
    byte_order: Option<ByteOrder>,
}

impl ModbusRtuConfigBuilder {
    /// Sets the serial port.
    pub fn port(mut self, port: impl Into<String>) -> Self {
        self.port = Some(port.into());
        self
    }

    /// Sets the baud rate.
    pub fn baud_rate(mut self, rate: u32) -> Self {
        self.baud_rate = Some(rate);
        self
    }

    /// Sets the data bits.
    pub fn data_bits(mut self, bits: DataBits) -> Self {
        self.data_bits = Some(bits);
        self
    }

    /// Sets the parity.
    pub fn parity(mut self, parity: Parity) -> Self {
        self.parity = Some(parity);
        self
    }

    /// Sets the stop bits.
    pub fn stop_bits(mut self, bits: StopBits) -> Self {
        self.stop_bits = Some(bits);
        self
    }

    /// Sets the unit ID.
    pub fn unit_id(mut self, id: u8) -> Self {
        self.unit_id = Some(id);
        self
    }

    /// Sets the operation timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the inter-frame delay.
    pub fn inter_frame_delay(mut self, delay: Duration) -> Self {
        self.inter_frame_delay = Some(delay);
        self
    }

    /// Sets the maximum retries.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = Some(retries);
        self
    }

    /// Sets the default byte order.
    pub fn byte_order(mut self, order: ByteOrder) -> Self {
        self.byte_order = Some(order);
        self
    }

    /// Sets common RTU parameters: 9600/8/N/1.
    pub fn default_9600_8n1(self) -> Self {
        self.baud_rate(9600)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .stop_bits(StopBits::One)
    }

    /// Sets common RTU parameters: 19200/8/E/1.
    pub fn default_19200_8e1(self) -> Self {
        self.baud_rate(19200)
            .data_bits(DataBits::Eight)
            .parity(Parity::Even)
            .stop_bits(StopBits::One)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ModbusRtuConfig, ModbusError> {
        let port = self.port.ok_or_else(|| {
            ModbusError::configuration(ConfigurationError::missing_field("port"))
        })?;

        let config = ModbusRtuConfig {
            port,
            baud_rate: self.baud_rate.unwrap_or_else(default_baud_rate),
            data_bits: self.data_bits.unwrap_or_default(),
            parity: self.parity.unwrap_or_default(),
            stop_bits: self.stop_bits.unwrap_or_default(),
            unit_id: self.unit_id.unwrap_or_else(default_unit_id),
            timeout: self.timeout.unwrap_or_else(default_operation_timeout),
            inter_frame_delay: self.inter_frame_delay,
            max_retries: self.max_retries.unwrap_or_else(default_max_retries),
            byte_order: self.byte_order.unwrap_or_default(),
        };

        config.validate()?;
        Ok(config)
    }
}

// =============================================================================
// Serial Port Settings
// =============================================================================

/// Data bits configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DataBits {
    /// 5 data bits.
    Five,
    /// 6 data bits.
    Six,
    /// 7 data bits.
    Seven,
    /// 8 data bits (default).
    #[default]
    Eight,
}

impl DataBits {
    /// Returns the number of bits.
    pub const fn bits(&self) -> u8 {
        match self {
            Self::Five => 5,
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
        }
    }
}

impl fmt::Display for DataBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.bits())
    }
}

/// Parity configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Parity {
    /// No parity (default).
    #[default]
    None,
    /// Odd parity.
    Odd,
    /// Even parity.
    Even,
}

impl Parity {
    /// Returns the number of parity bits.
    pub const fn bits(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Odd | Self::Even => 1,
        }
    }

    /// Returns the short character representation.
    pub const fn char(&self) -> char {
        match self {
            Self::None => 'N',
            Self::Odd => 'O',
            Self::Even => 'E',
        }
    }
}

impl fmt::Display for Parity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.char())
    }
}

/// Stop bits configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StopBits {
    /// 1 stop bit (default).
    #[default]
    One,
    /// 2 stop bits.
    Two,
}

impl StopBits {
    /// Returns the number of stop bits.
    pub const fn bits(&self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

impl fmt::Display for StopBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.bits())
    }
}

// =============================================================================
// ModbusConfig (Unified)
// =============================================================================

/// Unified Modbus configuration for TCP or RTU.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ModbusConfig {
    /// Modbus TCP configuration.
    Tcp(ModbusTcpConfig),

    /// Modbus RTU configuration.
    Rtu(ModbusRtuConfig),
}

impl ModbusConfig {
    /// Returns `true` if this is a TCP configuration.
    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    /// Returns `true` if this is an RTU configuration.
    pub const fn is_rtu(&self) -> bool {
        matches!(self, Self::Rtu(_))
    }

    /// Returns the unit ID.
    pub fn unit_id(&self) -> u8 {
        match self {
            Self::Tcp(c) => c.unit_id,
            Self::Rtu(c) => c.unit_id,
        }
    }

    /// Returns the byte order.
    pub fn byte_order(&self) -> ByteOrder {
        match self {
            Self::Tcp(c) => c.byte_order,
            Self::Rtu(c) => c.byte_order,
        }
    }

    /// Returns the operation timeout.
    pub fn timeout(&self) -> Duration {
        match self {
            Self::Tcp(c) => c.operation_timeout,
            Self::Rtu(c) => c.timeout,
        }
    }

    /// Returns the maximum retries.
    pub fn max_retries(&self) -> u32 {
        match self {
            Self::Tcp(c) => c.max_retries,
            Self::Rtu(c) => c.max_retries,
        }
    }

    /// Validates this configuration.
    pub fn validate(&self) -> Result<(), ModbusError> {
        match self {
            Self::Tcp(c) => c.validate(),
            Self::Rtu(c) => c.validate(),
        }
    }

    /// Attempts to get the TCP configuration.
    pub fn as_tcp(&self) -> Option<&ModbusTcpConfig> {
        match self {
            Self::Tcp(c) => Some(c),
            _ => None,
        }
    }

    /// Attempts to get the RTU configuration.
    pub fn as_rtu(&self) -> Option<&ModbusRtuConfig> {
        match self {
            Self::Rtu(c) => Some(c),
            _ => None,
        }
    }
}

impl From<ModbusTcpConfig> for ModbusConfig {
    fn from(config: ModbusTcpConfig) -> Self {
        Self::Tcp(config)
    }
}

impl From<ModbusRtuConfig> for ModbusConfig {
    fn from(config: ModbusRtuConfig) -> Self {
        Self::Rtu(config)
    }
}

// =============================================================================
// TagMapping
// =============================================================================

/// Maps a tag ID to a Modbus address with conversion settings.
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

    /// Modbus address.
    pub address: ModbusDataAddress,

    /// Engineering unit (e.g., "°C", "kWh").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,

    /// Polling interval override (None = use device default).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "option_duration")]
    pub poll_interval: Option<Duration>,

    /// Whether to subscribe to changes (for drivers that support it).
    #[serde(default)]
    pub subscribe: bool,

    /// Custom metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

impl TagMapping {
    /// Creates a new tag mapping.
    pub fn new(tag_id: impl Into<String>, address: ModbusDataAddress) -> Self {
        Self {
            tag_id: tag_id.into(),
            name: None,
            description: None,
            address,
            unit: None,
            poll_interval: None,
            subscribe: false,
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

    /// Sets the engineering unit.
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// Sets the polling interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = Some(interval);
        self
    }

    /// Sets subscribe mode.
    pub fn with_subscribe(mut self, subscribe: bool) -> Self {
        self.subscribe = subscribe;
        self
    }

    /// Returns the effective name (tag_id if name is not set).
    pub fn effective_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.tag_id)
    }

    /// Returns `true` if this tag is writable.
    pub fn is_writable(&self) -> bool {
        self.address.is_writable()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // RegisterType Tests
    // =========================================================================

    #[test]
    fn test_register_type_properties() {
        assert!(RegisterType::Coil.is_writable());
        assert!(RegisterType::HoldingRegister.is_writable());
        assert!(!RegisterType::DiscreteInput.is_writable());
        assert!(!RegisterType::InputRegister.is_writable());

        assert!(RegisterType::Coil.is_bit());
        assert!(RegisterType::DiscreteInput.is_bit());
        assert!(!RegisterType::HoldingRegister.is_bit());
        assert!(!RegisterType::InputRegister.is_bit());
    }

    #[test]
    fn test_register_type_function_codes() {
        assert_eq!(RegisterType::Coil.read_function_code(), 0x01);
        assert_eq!(RegisterType::DiscreteInput.read_function_code(), 0x02);
        assert_eq!(RegisterType::HoldingRegister.read_function_code(), 0x03);
        assert_eq!(RegisterType::InputRegister.read_function_code(), 0x04);

        assert_eq!(RegisterType::Coil.write_single_function_code(), Some(0x05));
        assert_eq!(RegisterType::HoldingRegister.write_single_function_code(), Some(0x06));
        assert_eq!(RegisterType::DiscreteInput.write_single_function_code(), None);
    }

    #[test]
    fn test_register_type_notation() {
        assert_eq!(
            RegisterType::from_notation_address(40001),
            Some((RegisterType::HoldingRegister, 0))
        );
        assert_eq!(
            RegisterType::from_notation_address(40100),
            Some((RegisterType::HoldingRegister, 99))
        );
        assert_eq!(
            RegisterType::from_notation_address(30001),
            Some((RegisterType::InputRegister, 0))
        );
        assert_eq!(
            RegisterType::from_notation_address(1),
            Some((RegisterType::Coil, 0))
        );

        assert_eq!(RegisterType::HoldingRegister.to_notation_address(0), 40001);
        assert_eq!(RegisterType::HoldingRegister.to_notation_address(99), 40100);
    }

    #[test]
    fn test_register_type_from_str() {
        assert_eq!("HR".parse::<RegisterType>().unwrap(), RegisterType::HoldingRegister);
        assert_eq!("holding".parse::<RegisterType>().unwrap(), RegisterType::HoldingRegister);
        assert_eq!("C".parse::<RegisterType>().unwrap(), RegisterType::Coil);
        assert_eq!("DI".parse::<RegisterType>().unwrap(), RegisterType::DiscreteInput);
        assert_eq!("IR".parse::<RegisterType>().unwrap(), RegisterType::InputRegister);
    }

    // =========================================================================
    // ModbusDataType Tests
    // =========================================================================

    #[test]
    fn test_data_type_register_count() {
        assert_eq!(ModbusDataType::Bool.register_count(), 1);
        assert_eq!(ModbusDataType::UInt16.register_count(), 1);
        assert_eq!(ModbusDataType::Float32.register_count(), 2);
        assert_eq!(ModbusDataType::Float64.register_count(), 4);
    }

    #[test]
    fn test_data_type_from_str() {
        assert_eq!("float32".parse::<ModbusDataType>().unwrap(), ModbusDataType::Float32);
        assert_eq!("real".parse::<ModbusDataType>().unwrap(), ModbusDataType::Float32);
        assert_eq!("int16".parse::<ModbusDataType>().unwrap(), ModbusDataType::Int16);
        assert_eq!("word".parse::<ModbusDataType>().unwrap(), ModbusDataType::Int16);
    }

    // =========================================================================
    // ModbusDataAddress Tests
    // =========================================================================

    #[test]
    fn test_address_creation() {
        let addr = ModbusDataAddress::holding_register(100);
        assert_eq!(addr.register_type, RegisterType::HoldingRegister);
        assert_eq!(addr.address, 100);
        assert_eq!(addr.count, 1);
        assert_eq!(addr.data_type, ModbusDataType::UInt16);
    }

    #[test]
    fn test_address_builder() {
        let addr = ModbusDataAddress::holding_register(100)
            .with_count(2)
            .with_data_type(ModbusDataType::Float32)
            .with_byte_order(ByteOrder::LittleEndian)
            .with_scale(0.1)
            .with_offset(10.0);

        assert_eq!(addr.count, 2);
        assert_eq!(addr.data_type, ModbusDataType::Float32);
        assert_eq!(addr.byte_order, ByteOrder::LittleEndian);
        assert_eq!(addr.effective_scale(), 0.1);
        assert_eq!(addr.effective_offset(), 10.0);
    }

    #[test]
    fn test_address_from_str() {
        let addr: ModbusDataAddress = "HR:100".parse().unwrap();
        assert_eq!(addr.register_type, RegisterType::HoldingRegister);
        assert_eq!(addr.address, 100);

        let addr: ModbusDataAddress = "HR:100:2:float32".parse().unwrap();
        assert_eq!(addr.count, 2);
        assert_eq!(addr.data_type, ModbusDataType::Float32);

        let addr: ModbusDataAddress = "40001".parse().unwrap();
        assert_eq!(addr.register_type, RegisterType::HoldingRegister);
        assert_eq!(addr.address, 0);
    }

    #[test]
    fn test_address_validation() {
        // Valid address
        let addr = ModbusDataAddress::holding_register(100).with_data_type(ModbusDataType::Float32);
        assert!(addr.validate().is_ok());

        // Invalid: bit type mismatch
        let addr = ModbusDataAddress::coil(100).with_data_type(ModbusDataType::Float32);
        assert!(addr.validate().is_err());

        // Invalid: insufficient count
        let mut addr = ModbusDataAddress::holding_register(100);
        addr.data_type = ModbusDataType::Float32;
        addr.count = 1; // Float32 needs 2 registers
        assert!(addr.validate().is_err());
    }

    #[test]
    fn test_address_overlap() {
        let addr1 = ModbusDataAddress::holding_register(100).with_count(10);
        let addr2 = ModbusDataAddress::holding_register(105).with_count(10);
        let addr3 = ModbusDataAddress::holding_register(110).with_count(5);
        let addr4 = ModbusDataAddress::input_register(100).with_count(10);

        assert!(addr1.overlaps(&addr2));
        assert!(!addr1.overlaps(&addr3));
        assert!(!addr1.overlaps(&addr4)); // Different register type
        assert!(addr1.is_contiguous_with(&addr3));
    }

    // =========================================================================
    // Config Tests
    // =========================================================================

    #[test]
    fn test_tcp_config_builder() {
        let config = ModbusTcpConfig::builder()
            .host("192.168.1.100")
            .port(502)
            .unit_id(1)
            .build()
            .unwrap();

        assert_eq!(config.host, "192.168.1.100");
        assert_eq!(config.port, 502);
        assert_eq!(config.unit_id, 1);
    }

    #[test]
    fn test_tcp_config_validation() {
        // Missing host
        let result = ModbusTcpConfig::builder().port(502).build();
        assert!(result.is_err());

        // Invalid unit ID
        let result = ModbusTcpConfig::builder()
            .host("localhost")
            .unit_id(0)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_rtu_config_builder() {
        let config = ModbusRtuConfig::builder()
            .port("/dev/ttyUSB0")
            .default_9600_8n1()
            .unit_id(1)
            .build()
            .unwrap();

        assert_eq!(config.port, "/dev/ttyUSB0");
        assert_eq!(config.baud_rate, 9600);
        assert_eq!(config.data_bits, DataBits::Eight);
        assert_eq!(config.parity, Parity::None);
        assert_eq!(config.stop_bits, StopBits::One);
    }

    #[test]
    fn test_inter_frame_delay() {
        let config = ModbusRtuConfig::new("/dev/ttyUSB0");
        let delay = config.calculated_inter_frame_delay();
        // At 9600 baud, should be approximately 4ms
        assert!(delay >= Duration::from_millis(1));
        assert!(delay <= Duration::from_millis(10));
    }

    // =========================================================================
    // TagMapping Tests
    // =========================================================================

    #[test]
    fn test_tag_mapping() {
        let mapping = TagMapping::new(
            "temperature",
            ModbusDataAddress::holding_register(100)
                .with_data_type(ModbusDataType::Float32)
                .with_scale(0.1),
        )
        .with_name("Room Temperature")
        .with_unit("°C");

        assert_eq!(mapping.tag_id, "temperature");
        assert_eq!(mapping.effective_name(), "Room Temperature");
        assert_eq!(mapping.unit, Some("°C".to_string()));
        assert!(mapping.is_writable());
    }

    // =========================================================================
    // ByteOrder Tests
    // =========================================================================

    #[test]
    fn test_byte_order_from_str() {
        assert_eq!("big_endian".parse::<ByteOrder>().unwrap(), ByteOrder::BigEndian);
        assert_eq!("ABCD".parse::<ByteOrder>().unwrap(), ByteOrder::BigEndian);
        assert_eq!("DCBA".parse::<ByteOrder>().unwrap(), ByteOrder::LittleEndian);
        assert_eq!("CDAB".parse::<ByteOrder>().unwrap(), ByteOrder::MidBigEndian);
    }
}
