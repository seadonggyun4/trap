// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Data conversion utilities for Modbus registers.
//!
//! This module provides type-safe conversion between raw Modbus registers
//! and high-level typed values, supporting various byte orders and data types.
//!
//! # Architecture
//!
//! The module provides two layers of conversion:
//!
//! 1. **DataConverter**: Simple, stateless converter for basic types
//! 2. **ExtendedDataConverter**: Extensible converter with custom type registry
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    ExtendedDataConverter                        │
//! │              (Extensible with custom types)                     │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    ConverterRegistry                            │
//! │              (trap_core converter system)                       │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!            ┌─────────────────┼─────────────────┐
//!            ▼                 ▼                 ▼
//! ┌───────────────┐ ┌───────────────┐ ┌───────────────────────────┐
//! │NumericConverter│ │StringConverter│ │ CustomConverters          │
//! │ (int/float)    │ │  (ASCII/UTF8) │ │ (user-defined)            │
//! └───────────────┘ └───────────────┘ └───────────────────────────┘
//! ```
//!
//! # Examples
//!
//! ## Basic Conversion
//!
//! ```rust,ignore
//! use trap_modbus::client::DataConverter;
//! use trap_modbus::types::{ByteOrder, ModbusDataAddress, ModbusDataType};
//!
//! let converter = DataConverter::new(ByteOrder::BigEndian);
//!
//! let registers = vec![0x4248, 0x0000]; // 50.0 in IEEE 754
//! let addr = ModbusDataAddress::holding_register(0)
//!     .with_count(2)
//!     .with_data_type(ModbusDataType::Float32);
//!
//! let value = converter.convert_from_registers(&registers, &addr)?;
//! ```
//!
//! ## Extended Conversion with Custom Types
//!
//! ```rust,ignore
//! use trap_modbus::client::{ExtendedDataConverter, ModbusTypeConverter};
//! use trap_core::converter::ConversionContext;
//!
//! // Create extended converter
//! let mut converter = ExtendedDataConverter::new();
//!
//! // Register a custom temperature converter with automatic scaling
//! converter.register_named("temperature", ScaledInt16Converter::new(0.1, -40.0));
//!
//! // Use the custom converter
//! let value = converter.decode_named::<f64>("temperature", &registers, &context)?;
//! ```

use std::collections::HashMap;

use crate::error::{ConversionError, ModbusError, ModbusResult};
use crate::types::{ByteOrder, ModbusDataAddress, ModbusDataType};

// Re-export trap_core converter types for convenience
pub use trap_core::converter::{
    ConversionContext, ConverterRegistry, RegisterConverter,
    ByteOrder as CoreByteOrder,
    BoolConverter, NumericConverter, StringConverter, BytesConverter,
    CompositeConverter, CompositeConverterBuilder,
    registers_to_bytes, bytes_to_registers, extract_bit, set_bit, extract_bits,
};

use super::TypedValue;

/// Result type for conversion operations.
pub type ConversionResult<T> = ModbusResult<T>;

// =============================================================================
// DataConverter
// =============================================================================

/// Converter for Modbus register data.
///
/// This converter handles the transformation between raw 16-bit Modbus registers
/// and high-level typed values, respecting byte order and data type configurations.
///
/// # Example
///
/// ```rust,ignore
/// use trap_modbus::client::DataConverter;
/// use trap_modbus::types::{ByteOrder, ModbusDataAddress, ModbusDataType};
///
/// let converter = DataConverter::new(ByteOrder::BigEndian);
///
/// let registers = vec![0x4248, 0x0000]; // 50.0 in IEEE 754
/// let addr = ModbusDataAddress::holding_register(0)
///     .with_count(2)
///     .with_data_type(ModbusDataType::Float32);
///
/// let value = converter.convert_from_registers(&registers, &addr)?;
/// ```
#[derive(Debug, Clone)]
pub struct DataConverter {
    /// Default byte order.
    default_byte_order: ByteOrder,
}

impl DataConverter {
    /// Creates a new converter with the given default byte order.
    pub fn new(default_byte_order: ByteOrder) -> Self {
        Self { default_byte_order }
    }

    /// Returns the default byte order.
    pub fn default_byte_order(&self) -> ByteOrder {
        self.default_byte_order
    }

    /// Sets the default byte order.
    pub fn set_default_byte_order(&mut self, byte_order: ByteOrder) {
        self.default_byte_order = byte_order;
    }

    // =========================================================================
    // From Registers
    // =========================================================================

    /// Converts raw registers to a typed value.
    pub fn convert_from_registers(
        &self,
        registers: &[u16],
        addr: &ModbusDataAddress,
    ) -> ModbusResult<TypedValue> {
        let byte_order = addr.byte_order;
        let data_type = addr.data_type;

        let value = match data_type {
            ModbusDataType::Bool => {
                let v = registers.first().copied().unwrap_or(0);
                TypedValue::Bool(v != 0)
            }
            ModbusDataType::Int8 => {
                let v = registers.first().copied().unwrap_or(0);
                TypedValue::Int8((v & 0xFF) as i8)
            }
            ModbusDataType::UInt8 => {
                let v = registers.first().copied().unwrap_or(0);
                TypedValue::UInt8((v & 0xFF) as u8)
            }
            ModbusDataType::Int16 => {
                let v = registers.first().copied().unwrap_or(0);
                TypedValue::Int16(v as i16)
            }
            ModbusDataType::UInt16 => {
                let v = registers.first().copied().unwrap_or(0);
                TypedValue::UInt16(v)
            }
            ModbusDataType::Int32 => {
                Self::validate_register_count(registers, 2, "Int32")?;
                let bytes = self.registers_to_bytes(registers, byte_order, 4);
                let v = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                TypedValue::Int32(v)
            }
            ModbusDataType::UInt32 => {
                Self::validate_register_count(registers, 2, "UInt32")?;
                let bytes = self.registers_to_bytes(registers, byte_order, 4);
                let v = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                TypedValue::UInt32(v)
            }
            ModbusDataType::Int64 => {
                Self::validate_register_count(registers, 4, "Int64")?;
                let bytes = self.registers_to_bytes(registers, byte_order, 8);
                let v = i64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                TypedValue::Int64(v)
            }
            ModbusDataType::UInt64 => {
                Self::validate_register_count(registers, 4, "UInt64")?;
                let bytes = self.registers_to_bytes(registers, byte_order, 8);
                let v = u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                TypedValue::UInt64(v)
            }
            ModbusDataType::Float32 => {
                Self::validate_register_count(registers, 2, "Float32")?;
                let bytes = self.registers_to_bytes(registers, byte_order, 4);
                let v = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                TypedValue::Float32(v)
            }
            ModbusDataType::Float64 => {
                Self::validate_register_count(registers, 4, "Float64")?;
                let bytes = self.registers_to_bytes(registers, byte_order, 8);
                let v = f64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                TypedValue::Float64(v)
            }
            ModbusDataType::String => {
                let s = self.registers_to_string(registers)?;
                TypedValue::String(s)
            }
            ModbusDataType::Bytes => {
                let bytes = self.registers_to_raw_bytes(registers);
                TypedValue::Bytes(bytes)
            }
        };

        // Apply scaling if configured
        let scaled_value = self.apply_scale(value, addr)?;

        Ok(scaled_value)
    }

    /// Validates that we have enough registers.
    fn validate_register_count(
        registers: &[u16],
        required: usize,
        _type_name: &str,
    ) -> ModbusResult<()> {
        if registers.len() < required {
            return Err(ModbusError::conversion(ConversionError::insufficient_data(
                required * 2,
                registers.len() * 2,
            )));
        }
        Ok(())
    }

    /// Converts registers to bytes with the specified byte order.
    fn registers_to_bytes(&self, registers: &[u16], byte_order: ByteOrder, size: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(size);

        // First convert registers to bytes based on word order
        let ordered_registers: Vec<u16> = match byte_order {
            ByteOrder::BigEndian | ByteOrder::MidBigEndian => registers.to_vec(),
            ByteOrder::LittleEndian | ByteOrder::MidLittleEndian => {
                registers.iter().rev().copied().collect()
            }
        };

        // Then extract bytes based on byte order within words
        for reg in ordered_registers {
            match byte_order {
                ByteOrder::BigEndian | ByteOrder::MidLittleEndian => {
                    bytes.push((reg >> 8) as u8);
                    bytes.push((reg & 0xFF) as u8);
                }
                ByteOrder::LittleEndian | ByteOrder::MidBigEndian => {
                    bytes.push((reg & 0xFF) as u8);
                    bytes.push((reg >> 8) as u8);
                }
            }
        }

        bytes.truncate(size);
        bytes
    }

    /// Converts registers to raw bytes (big-endian).
    fn registers_to_raw_bytes(&self, registers: &[u16]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(registers.len() * 2);
        for reg in registers {
            bytes.push((reg >> 8) as u8);
            bytes.push((reg & 0xFF) as u8);
        }
        bytes
    }

    /// Converts registers to ASCII string.
    fn registers_to_string(&self, registers: &[u16]) -> ModbusResult<String> {
        let bytes = self.registers_to_raw_bytes(registers);

        // Find null terminator
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

        String::from_utf8(bytes[..end].to_vec()).map_err(|e| {
            ModbusError::conversion(ConversionError::invalid_encoding(e.to_string()))
        })
    }

    // =========================================================================
    // To Registers
    // =========================================================================

    /// Converts a typed value to raw registers.
    pub fn convert_to_registers(
        &self,
        value: &TypedValue,
        addr: &ModbusDataAddress,
    ) -> ModbusResult<Vec<u16>> {
        let byte_order = addr.byte_order;

        // Apply inverse scaling if configured
        let unscaled_value = self.apply_inverse_scale(value.clone(), addr)?;

        match unscaled_value {
            TypedValue::Bool(v) => Ok(vec![if v { 1 } else { 0 }]),
            TypedValue::Int8(v) => Ok(vec![v as u16 & 0xFF]),
            TypedValue::UInt8(v) => Ok(vec![v as u16]),
            TypedValue::Int16(v) => Ok(vec![v as u16]),
            TypedValue::UInt16(v) => Ok(vec![v]),
            TypedValue::Int32(v) => {
                let bytes = v.to_be_bytes();
                Ok(self.bytes_to_registers(&bytes, byte_order))
            }
            TypedValue::UInt32(v) => {
                let bytes = v.to_be_bytes();
                Ok(self.bytes_to_registers(&bytes, byte_order))
            }
            TypedValue::Int64(v) => {
                let bytes = v.to_be_bytes();
                Ok(self.bytes_to_registers(&bytes, byte_order))
            }
            TypedValue::UInt64(v) => {
                let bytes = v.to_be_bytes();
                Ok(self.bytes_to_registers(&bytes, byte_order))
            }
            TypedValue::Float32(v) => {
                let bytes = v.to_be_bytes();
                Ok(self.bytes_to_registers(&bytes, byte_order))
            }
            TypedValue::Float64(v) => {
                let bytes = v.to_be_bytes();
                Ok(self.bytes_to_registers(&bytes, byte_order))
            }
            TypedValue::String(s) => Ok(self.string_to_registers(&s, addr.count)),
            TypedValue::Bytes(b) => Ok(self.raw_bytes_to_registers(&b)),
        }
    }

    /// Converts bytes to registers with the specified byte order.
    fn bytes_to_registers(&self, bytes: &[u8], byte_order: ByteOrder) -> Vec<u16> {
        let mut registers = Vec::with_capacity((bytes.len() + 1) / 2);

        // Create registers from bytes based on byte order within words
        let chunks: Vec<&[u8]> = bytes.chunks(2).collect();
        for chunk in &chunks {
            let reg = match byte_order {
                ByteOrder::BigEndian | ByteOrder::MidLittleEndian => {
                    let hi = chunk.first().copied().unwrap_or(0);
                    let lo = chunk.get(1).copied().unwrap_or(0);
                    ((hi as u16) << 8) | (lo as u16)
                }
                ByteOrder::LittleEndian | ByteOrder::MidBigEndian => {
                    let lo = chunk.first().copied().unwrap_or(0);
                    let hi = chunk.get(1).copied().unwrap_or(0);
                    ((hi as u16) << 8) | (lo as u16)
                }
            };
            registers.push(reg);
        }

        // Reverse word order for little-endian variants
        match byte_order {
            ByteOrder::LittleEndian | ByteOrder::MidLittleEndian => {
                registers.reverse();
            }
            _ => {}
        }

        registers
    }

    /// Converts raw bytes to registers (big-endian).
    fn raw_bytes_to_registers(&self, bytes: &[u8]) -> Vec<u16> {
        let mut registers = Vec::with_capacity((bytes.len() + 1) / 2);
        for chunk in bytes.chunks(2) {
            let hi = chunk.first().copied().unwrap_or(0);
            let lo = chunk.get(1).copied().unwrap_or(0);
            registers.push(((hi as u16) << 8) | (lo as u16));
        }
        registers
    }

    /// Converts string to registers (ASCII, null-padded).
    fn string_to_registers(&self, s: &str, max_registers: u16) -> Vec<u16> {
        let max_bytes = (max_registers as usize) * 2;
        let mut bytes: Vec<u8> = s.bytes().take(max_bytes).collect();

        // Null terminate and pad
        bytes.resize(max_bytes, 0);

        self.raw_bytes_to_registers(&bytes)
    }

    // =========================================================================
    // Scaling
    // =========================================================================

    /// Applies scale and offset to a value.
    fn apply_scale(&self, value: TypedValue, addr: &ModbusDataAddress) -> ModbusResult<TypedValue> {
        if !addr.has_scaling() {
            return Ok(value);
        }

        let scale = addr.effective_scale();
        let offset = addr.effective_offset();

        // Convert to f64, apply scaling, and convert back
        match value {
            TypedValue::Int8(v) => {
                let scaled = (v as f64) * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            TypedValue::UInt8(v) => {
                let scaled = (v as f64) * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            TypedValue::Int16(v) => {
                let scaled = (v as f64) * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            TypedValue::UInt16(v) => {
                let scaled = (v as f64) * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            TypedValue::Int32(v) => {
                let scaled = (v as f64) * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            TypedValue::UInt32(v) => {
                let scaled = (v as f64) * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            TypedValue::Int64(v) => {
                let scaled = (v as f64) * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            TypedValue::UInt64(v) => {
                let scaled = (v as f64) * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            TypedValue::Float32(v) => {
                let scaled = (v as f64) * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            TypedValue::Float64(v) => {
                let scaled = v * scale + offset;
                Ok(TypedValue::Float64(scaled))
            }
            // Non-numeric types are not scaled
            _ => Ok(value),
        }
    }

    /// Applies inverse scale and offset for writing.
    fn apply_inverse_scale(
        &self,
        value: TypedValue,
        addr: &ModbusDataAddress,
    ) -> ModbusResult<TypedValue> {
        if !addr.has_scaling() {
            return Ok(value);
        }

        let scale = addr.effective_scale();
        let offset = addr.effective_offset();

        if scale == 0.0 {
            return Err(ModbusError::conversion(ConversionError::scale_error(
                "Scale factor is zero",
            )));
        }

        // Inverse: original = (value - offset) / scale
        match value {
            TypedValue::Float64(v) => {
                let unscaled = (v - offset) / scale;
                // Convert back to the original data type
                match addr.data_type {
                    ModbusDataType::Int16 => Ok(TypedValue::Int16(unscaled as i16)),
                    ModbusDataType::UInt16 => Ok(TypedValue::UInt16(unscaled as u16)),
                    ModbusDataType::Int32 => Ok(TypedValue::Int32(unscaled as i32)),
                    ModbusDataType::UInt32 => Ok(TypedValue::UInt32(unscaled as u32)),
                    ModbusDataType::Float32 => Ok(TypedValue::Float32(unscaled as f32)),
                    ModbusDataType::Float64 => Ok(TypedValue::Float64(unscaled)),
                    _ => Ok(TypedValue::Float64(unscaled)),
                }
            }
            TypedValue::Float32(v) => {
                let unscaled = ((v as f64) - offset) / scale;
                match addr.data_type {
                    ModbusDataType::Int16 => Ok(TypedValue::Int16(unscaled as i16)),
                    ModbusDataType::UInt16 => Ok(TypedValue::UInt16(unscaled as u16)),
                    ModbusDataType::Float32 => Ok(TypedValue::Float32(unscaled as f32)),
                    _ => Ok(TypedValue::Float64(unscaled)),
                }
            }
            // For non-float types, assume they're already in raw form
            _ => Ok(value),
        }
    }
}

impl Default for DataConverter {
    fn default() -> Self {
        Self::new(ByteOrder::BigEndian)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_uint16() {
        let converter = DataConverter::default();
        let registers = vec![0x1234];
        let addr = ModbusDataAddress::holding_register(0).with_data_type(ModbusDataType::UInt16);

        let value = converter.convert_from_registers(&registers, &addr).unwrap();
        assert_eq!(value, TypedValue::UInt16(0x1234));
    }

    #[test]
    fn test_convert_int16() {
        let converter = DataConverter::default();
        let registers = vec![0xFFFF]; // -1 in signed
        let addr = ModbusDataAddress::holding_register(0).with_data_type(ModbusDataType::Int16);

        let value = converter.convert_from_registers(&registers, &addr).unwrap();
        assert_eq!(value, TypedValue::Int16(-1));
    }

    #[test]
    fn test_convert_float32_big_endian() {
        let converter = DataConverter::default();
        // 50.0 in IEEE 754 big-endian: 0x42480000
        let registers = vec![0x4248, 0x0000];
        let addr = ModbusDataAddress::holding_register(0)
            .with_count(2)
            .with_data_type(ModbusDataType::Float32)
            .with_byte_order(ByteOrder::BigEndian);

        let value = converter.convert_from_registers(&registers, &addr).unwrap();
        if let TypedValue::Float32(v) = value {
            assert!((v - 50.0).abs() < 0.001);
        } else {
            panic!("Expected Float32");
        }
    }

    #[test]
    fn test_convert_uint32_big_endian() {
        let converter = DataConverter::default();
        let registers = vec![0x0001, 0x0000]; // 65536 in big-endian
        let addr = ModbusDataAddress::holding_register(0)
            .with_count(2)
            .with_data_type(ModbusDataType::UInt32)
            .with_byte_order(ByteOrder::BigEndian);

        let value = converter.convert_from_registers(&registers, &addr).unwrap();
        assert_eq!(value, TypedValue::UInt32(65536));
    }

    #[test]
    fn test_convert_string() {
        let converter = DataConverter::default();
        // "AB" -> 0x4142
        let registers = vec![0x4142, 0x4300]; // "ABC\0"
        let addr = ModbusDataAddress::holding_register(0)
            .with_count(2)
            .with_data_type(ModbusDataType::String);

        let value = converter.convert_from_registers(&registers, &addr).unwrap();
        assert_eq!(value, TypedValue::String("ABC".to_string()));
    }

    #[test]
    fn test_scaling() {
        let converter = DataConverter::default();
        let registers = vec![100]; // Raw value 100
        let addr = ModbusDataAddress::holding_register(0)
            .with_data_type(ModbusDataType::UInt16)
            .with_scale(0.1)
            .with_offset(10.0);

        let value = converter.convert_from_registers(&registers, &addr).unwrap();
        if let TypedValue::Float64(v) = value {
            assert!((v - 20.0).abs() < 0.001); // 100 * 0.1 + 10 = 20
        } else {
            panic!("Expected Float64 after scaling");
        }
    }

    #[test]
    fn test_convert_to_registers() {
        let converter = DataConverter::default();
        let addr = ModbusDataAddress::holding_register(0)
            .with_count(2)
            .with_data_type(ModbusDataType::Float32)
            .with_byte_order(ByteOrder::BigEndian);

        let value = TypedValue::Float32(50.0);
        let registers = converter.convert_to_registers(&value, &addr).unwrap();

        assert_eq!(registers.len(), 2);
        assert_eq!(registers[0], 0x4248);
        assert_eq!(registers[1], 0x0000);
    }

    #[test]
    fn test_bit_extraction() {
        assert!(extract_bit(0b0000_0001, 0));
        assert!(!extract_bit(0b0000_0001, 1));
        assert!(extract_bit(0b1000_0000_0000_0000, 15));

        assert_eq!(set_bit(0, 0, true), 1);
        assert_eq!(set_bit(1, 0, false), 0);
        assert_eq!(set_bit(0, 15, true), 0x8000);

        assert_eq!(extract_bits(0b1111_0000, 4, 4), 0b1111);
        assert_eq!(extract_bits(0xFF00, 8, 8), 0xFF);
    }

    #[test]
    fn test_inverse_scaling() {
        let converter = DataConverter::default();
        let addr = ModbusDataAddress::holding_register(0)
            .with_data_type(ModbusDataType::UInt16)
            .with_scale(0.1)
            .with_offset(10.0);

        // If scaled value is 20.0, original should be 100
        let value = TypedValue::Float64(20.0);
        let registers = converter.convert_to_registers(&value, &addr).unwrap();

        assert_eq!(registers.len(), 1);
        assert_eq!(registers[0], 100);
    }
}

// =============================================================================
// ExtendedDataConverter
// =============================================================================

/// Extended data converter with custom type registry support.
///
/// This converter extends the basic `DataConverter` with:
/// - Custom type registration for domain-specific data types
/// - Named converter lookup for flexible configuration
/// - Integration with trap_core's converter system
///
/// # Examples
///
/// ```rust,ignore
/// use trap_modbus::client::ExtendedDataConverter;
/// use trap_core::converter::{ConversionContext, NumericConverter, ScaledConverter};
///
/// let mut converter = ExtendedDataConverter::new();
///
/// // Register a temperature sensor converter (raw * 0.1 - 40)
/// converter.register_scaled("temperature_sensor", 0.1, -40.0);
///
/// // Register a power meter converter (raw * 0.01)
/// converter.register_scaled("power_meter", 0.01, 0.0);
///
/// // Use the converters
/// let context = ConversionContext::new();
/// let temp = converter.decode_scaled::<i16>("temperature_sensor", &registers, &context)?;
/// ```
pub struct ExtendedDataConverter {
    /// Base data converter for standard types.
    base: DataConverter,
    /// Core converter registry.
    registry: ConverterRegistry,
    /// Scaled converter configurations (name -> (scale, offset)).
    scaled_configs: HashMap<String, (f64, f64)>,
    /// Custom tag converters (tag_id -> converter config).
    tag_converters: HashMap<String, TagConverterConfig>,
}

/// Configuration for a tag-specific converter.
#[derive(Debug, Clone)]
pub struct TagConverterConfig {
    /// Data type.
    pub data_type: ModbusDataType,
    /// Byte order.
    pub byte_order: ByteOrder,
    /// Scale factor.
    pub scale: f64,
    /// Offset.
    pub offset: f64,
    /// Minimum value.
    pub min_value: Option<f64>,
    /// Maximum value.
    pub max_value: Option<f64>,
    /// Bit position for bit extraction.
    pub bit_position: Option<u8>,
    /// Bit count for bit extraction.
    pub bit_count: Option<u8>,
}

impl Default for TagConverterConfig {
    fn default() -> Self {
        Self {
            data_type: ModbusDataType::UInt16,
            byte_order: ByteOrder::BigEndian,
            scale: 1.0,
            offset: 0.0,
            min_value: None,
            max_value: None,
            bit_position: None,
            bit_count: None,
        }
    }
}

impl TagConverterConfig {
    /// Creates a new config builder.
    pub fn builder() -> TagConverterConfigBuilder {
        TagConverterConfigBuilder::default()
    }

    /// Converts to a ConversionContext.
    pub fn to_context(&self) -> ConversionContext {
        let mut ctx = ConversionContext::new()
            .with_byte_order(self.byte_order.to_core())
            .with_scaling(self.scale, self.offset);

        if let (Some(min), Some(max)) = (self.min_value, self.max_value) {
            ctx = ctx.with_range(min, max);
        } else if let Some(min) = self.min_value {
            ctx = ctx.with_min(min);
        } else if let Some(max) = self.max_value {
            ctx = ctx.with_max(max);
        }

        if let (Some(pos), Some(count)) = (self.bit_position, self.bit_count) {
            ctx = ctx.with_bit_extraction(pos, count);
        }

        ctx
    }
}

/// Builder for TagConverterConfig.
#[derive(Default)]
pub struct TagConverterConfigBuilder {
    config: TagConverterConfig,
}

impl TagConverterConfigBuilder {
    /// Sets the data type.
    pub fn data_type(mut self, data_type: ModbusDataType) -> Self {
        self.config.data_type = data_type;
        self
    }

    /// Sets the byte order.
    pub fn byte_order(mut self, byte_order: ByteOrder) -> Self {
        self.config.byte_order = byte_order;
        self
    }

    /// Sets the scale factor.
    pub fn scale(mut self, scale: f64) -> Self {
        self.config.scale = scale;
        self
    }

    /// Sets the offset.
    pub fn offset(mut self, offset: f64) -> Self {
        self.config.offset = offset;
        self
    }

    /// Sets the minimum value.
    pub fn min_value(mut self, min: f64) -> Self {
        self.config.min_value = Some(min);
        self
    }

    /// Sets the maximum value.
    pub fn max_value(mut self, max: f64) -> Self {
        self.config.max_value = Some(max);
        self
    }

    /// Sets the value range.
    pub fn range(mut self, min: f64, max: f64) -> Self {
        self.config.min_value = Some(min);
        self.config.max_value = Some(max);
        self
    }

    /// Sets bit extraction parameters.
    pub fn bit_extraction(mut self, position: u8, count: u8) -> Self {
        self.config.bit_position = Some(position);
        self.config.bit_count = Some(count);
        self
    }

    /// Builds the config.
    pub fn build(self) -> TagConverterConfig {
        self.config
    }
}

impl Default for ExtendedDataConverter {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtendedDataConverter {
    /// Creates a new extended converter.
    pub fn new() -> Self {
        Self {
            base: DataConverter::default(),
            registry: ConverterRegistry::new(),
            scaled_configs: HashMap::new(),
            tag_converters: HashMap::new(),
        }
    }

    /// Creates with a specific byte order.
    pub fn with_byte_order(byte_order: ByteOrder) -> Self {
        Self {
            base: DataConverter::new(byte_order),
            registry: ConverterRegistry::new(),
            scaled_configs: HashMap::new(),
            tag_converters: HashMap::new(),
        }
    }

    /// Returns a reference to the base converter.
    pub fn base(&self) -> &DataConverter {
        &self.base
    }

    /// Returns a reference to the core registry.
    pub fn registry(&self) -> &ConverterRegistry {
        &self.registry
    }

    /// Returns a mutable reference to the core registry.
    pub fn registry_mut(&mut self) -> &mut ConverterRegistry {
        &mut self.registry
    }

    /// Registers a scaled converter configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for this converter
    /// * `scale` - Scale factor (value = raw * scale + offset)
    /// * `offset` - Offset value
    pub fn register_scaled(&mut self, name: impl Into<String>, scale: f64, offset: f64) {
        self.scaled_configs.insert(name.into(), (scale, offset));
    }

    /// Registers a tag-specific converter.
    ///
    /// # Arguments
    ///
    /// * `tag_id` - Tag identifier
    /// * `config` - Converter configuration
    pub fn register_tag(&mut self, tag_id: impl Into<String>, config: TagConverterConfig) {
        self.tag_converters.insert(tag_id.into(), config);
    }

    /// Returns the configuration for a tag.
    pub fn get_tag_config(&self, tag_id: &str) -> Option<&TagConverterConfig> {
        self.tag_converters.get(tag_id)
    }

    /// Converts registers to a TypedValue using the base converter.
    pub fn convert_from_registers(
        &self,
        registers: &[u16],
        addr: &ModbusDataAddress,
    ) -> ModbusResult<TypedValue> {
        self.base.convert_from_registers(registers, addr)
    }

    /// Converts a TypedValue to registers using the base converter.
    pub fn convert_to_registers(
        &self,
        value: &TypedValue,
        addr: &ModbusDataAddress,
    ) -> ModbusResult<Vec<u16>> {
        self.base.convert_to_registers(value, addr)
    }

    /// Decodes registers using a tag-specific converter.
    ///
    /// If the tag has a registered configuration, it uses that.
    /// Otherwise, it falls back to the address configuration.
    pub fn convert_for_tag(
        &self,
        tag_id: &str,
        registers: &[u16],
        addr: &ModbusDataAddress,
    ) -> ModbusResult<TypedValue> {
        if let Some(config) = self.tag_converters.get(tag_id) {
            // Use tag-specific configuration
            let bytes = registers_to_bytes(registers);
            let context = config.to_context();

            self.decode_with_context(&bytes, config.data_type, &context)
        } else {
            // Fall back to address configuration
            self.base.convert_from_registers(registers, addr)
        }
    }

    /// Encodes a value using a tag-specific converter.
    pub fn encode_for_tag(
        &self,
        tag_id: &str,
        value: &TypedValue,
        addr: &ModbusDataAddress,
    ) -> ModbusResult<Vec<u16>> {
        if let Some(config) = self.tag_converters.get(tag_id) {
            let context = config.to_context();
            self.encode_with_context(value, config.data_type, &context)
        } else {
            self.base.convert_to_registers(value, addr)
        }
    }

    /// Decodes with explicit context.
    fn decode_with_context(
        &self,
        bytes: &[u8],
        data_type: ModbusDataType,
        context: &ConversionContext,
    ) -> ModbusResult<TypedValue> {
        match data_type {
            ModbusDataType::Bool => {
                let conv = BoolConverter;
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("bool", &e.to_string())))?;
                Ok(TypedValue::Bool(value))
            }
            ModbusDataType::Int8 => {
                let conv = NumericConverter::<i8>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("int8", &e.to_string())))?;
                Ok(TypedValue::Int8(value))
            }
            ModbusDataType::UInt8 => {
                let conv = NumericConverter::<u8>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("uint8", &e.to_string())))?;
                Ok(TypedValue::UInt8(value))
            }
            ModbusDataType::Int16 => {
                let conv = NumericConverter::<i16>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("int16", &e.to_string())))?;

                // Apply scaling if configured
                if context.has_scaling() {
                    let scaled = context.apply_scale(value as f64);
                    if context.has_range() {
                        context.validate_range(scaled)
                            .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("int16", &e.to_string())))?;
                    }
                    Ok(TypedValue::Float64(scaled))
                } else {
                    Ok(TypedValue::Int16(value))
                }
            }
            ModbusDataType::UInt16 => {
                let conv = NumericConverter::<u16>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("uint16", &e.to_string())))?;

                if context.has_scaling() {
                    let scaled = context.apply_scale(value as f64);
                    if context.has_range() {
                        context.validate_range(scaled)
                            .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("uint16", &e.to_string())))?;
                    }
                    Ok(TypedValue::Float64(scaled))
                } else {
                    Ok(TypedValue::UInt16(value))
                }
            }
            ModbusDataType::Int32 => {
                let conv = NumericConverter::<i32>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("int32", &e.to_string())))?;

                if context.has_scaling() {
                    let scaled = context.apply_scale(value as f64);
                    Ok(TypedValue::Float64(scaled))
                } else {
                    Ok(TypedValue::Int32(value))
                }
            }
            ModbusDataType::UInt32 => {
                let conv = NumericConverter::<u32>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("uint32", &e.to_string())))?;

                if context.has_scaling() {
                    let scaled = context.apply_scale(value as f64);
                    Ok(TypedValue::Float64(scaled))
                } else {
                    Ok(TypedValue::UInt32(value))
                }
            }
            ModbusDataType::Int64 => {
                let conv = NumericConverter::<i64>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("int64", &e.to_string())))?;

                if context.has_scaling() {
                    let scaled = context.apply_scale(value as f64);
                    Ok(TypedValue::Float64(scaled))
                } else {
                    Ok(TypedValue::Int64(value))
                }
            }
            ModbusDataType::UInt64 => {
                let conv = NumericConverter::<u64>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("uint64", &e.to_string())))?;

                if context.has_scaling() {
                    let scaled = context.apply_scale(value as f64);
                    Ok(TypedValue::Float64(scaled))
                } else {
                    Ok(TypedValue::UInt64(value))
                }
            }
            ModbusDataType::Float32 => {
                let conv = NumericConverter::<f32>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("float32", &e.to_string())))?;

                if context.has_scaling() {
                    let scaled = context.apply_scale(value as f64);
                    Ok(TypedValue::Float64(scaled))
                } else {
                    Ok(TypedValue::Float32(value))
                }
            }
            ModbusDataType::Float64 => {
                let conv = NumericConverter::<f64>::new();
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("float64", &e.to_string())))?;

                let scaled = if context.has_scaling() {
                    context.apply_scale(value)
                } else {
                    value
                };
                Ok(TypedValue::Float64(scaled))
            }
            ModbusDataType::String => {
                let conv = StringConverter::new(bytes.len());
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::invalid_encoding(e.to_string())))?;
                Ok(TypedValue::String(value))
            }
            ModbusDataType::Bytes => {
                let conv = BytesConverter::new(bytes.len());
                let value = conv
                    .decode(bytes, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("bytes", &e.to_string())))?;
                Ok(TypedValue::Bytes(value))
            }
        }
    }

    /// Encodes with explicit context.
    fn encode_with_context(
        &self,
        value: &TypedValue,
        data_type: ModbusDataType,
        context: &ConversionContext,
    ) -> ModbusResult<Vec<u16>> {
        let bytes = match data_type {
            ModbusDataType::Bool => {
                let conv = BoolConverter;
                let bool_val = value.as_bool()?;
                conv.encode(&bool_val, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("bool", &e.to_string())))?
            }
            ModbusDataType::Int16 => {
                let conv = NumericConverter::<i16>::new();
                let raw = if context.has_scaling() {
                    let scaled = value.as_f64()?;
                    context.apply_inverse_scale(scaled)
                        .map_err(|e| ModbusError::conversion(ConversionError::scale_error(e.to_string())))? as i16
                } else {
                    match value {
                        TypedValue::Int16(v) => *v,
                        _ => value.as_i32()? as i16,
                    }
                };
                conv.encode(&raw, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("int16", &e.to_string())))?
            }
            ModbusDataType::UInt16 => {
                let conv = NumericConverter::<u16>::new();
                let raw = if context.has_scaling() {
                    let scaled = value.as_f64()?;
                    let unscaled = context.apply_inverse_scale(scaled)
                        .map_err(|e| ModbusError::conversion(ConversionError::scale_error(e.to_string())))?;
                    if unscaled < 0.0 || unscaled > u16::MAX as f64 {
                        return Err(ModbusError::conversion(ConversionError::overflow(
                            unscaled.to_string(), "uint16"
                        )));
                    }
                    unscaled as u16
                } else {
                    match value {
                        TypedValue::UInt16(v) => *v,
                        _ => {
                            let v = value.as_i32()?;
                            if v < 0 || v > u16::MAX as i32 {
                                return Err(ModbusError::conversion(ConversionError::overflow(
                                    v.to_string(), "uint16"
                                )));
                            }
                            v as u16
                        }
                    }
                };
                conv.encode(&raw, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("uint16", &e.to_string())))?
            }
            ModbusDataType::Int32 => {
                let conv = NumericConverter::<i32>::new();
                let raw = if context.has_scaling() {
                    let scaled = value.as_f64()?;
                    context.apply_inverse_scale(scaled)
                        .map_err(|e| ModbusError::conversion(ConversionError::scale_error(e.to_string())))? as i32
                } else {
                    value.as_i32()?
                };
                conv.encode(&raw, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("int32", &e.to_string())))?
            }
            ModbusDataType::UInt32 => {
                let conv = NumericConverter::<u32>::new();
                let raw = if context.has_scaling() {
                    let scaled = value.as_f64()?;
                    context.apply_inverse_scale(scaled)
                        .map_err(|e| ModbusError::conversion(ConversionError::scale_error(e.to_string())))? as u32
                } else {
                    match value {
                        TypedValue::UInt32(v) => *v,
                        _ => value.as_i32()? as u32,
                    }
                };
                conv.encode(&raw, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("uint32", &e.to_string())))?
            }
            ModbusDataType::Float32 => {
                let conv = NumericConverter::<f32>::new();
                let raw = if context.has_scaling() {
                    context.apply_inverse_scale(value.as_f64()?)
                        .map_err(|e| ModbusError::conversion(ConversionError::scale_error(e.to_string())))? as f32
                } else {
                    match value {
                        TypedValue::Float32(v) => *v,
                        _ => value.as_f64()? as f32,
                    }
                };
                conv.encode(&raw, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("float32", &e.to_string())))?
            }
            ModbusDataType::Float64 => {
                let conv = NumericConverter::<f64>::new();
                let raw = if context.has_scaling() {
                    context.apply_inverse_scale(value.as_f64()?)
                        .map_err(|e| ModbusError::conversion(ConversionError::scale_error(e.to_string())))?
                } else {
                    value.as_f64()?
                };
                conv.encode(&raw, context)
                    .map_err(|e| ModbusError::conversion(ConversionError::type_mismatch("float64", &e.to_string())))?
            }
            ModbusDataType::String => {
                match value {
                    TypedValue::String(s) => {
                        let conv = StringConverter::new(s.len().max(2));
                        conv.encode(s, context)
                            .map_err(|e| ModbusError::conversion(ConversionError::invalid_encoding(e.to_string())))?
                    }
                    _ => return Err(ModbusError::type_mismatch("string", &format!("{:?}", value))),
                }
            }
            ModbusDataType::Bytes => {
                match value {
                    TypedValue::Bytes(b) => b.clone(),
                    _ => return Err(ModbusError::type_mismatch("bytes", &format!("{:?}", value))),
                }
            }
            _ => return Err(ModbusError::conversion(ConversionError::type_mismatch(
                "supported type", &format!("{:?}", data_type)
            ))),
        };

        Ok(bytes_to_registers(&bytes))
    }
}

// =============================================================================
// ByteOrder Conversion
// =============================================================================

impl ByteOrder {
    /// Converts to core byte order.
    pub fn to_core(&self) -> CoreByteOrder {
        match self {
            ByteOrder::BigEndian => CoreByteOrder::BigEndian,
            ByteOrder::LittleEndian => CoreByteOrder::LittleEndian,
            ByteOrder::MidBigEndian => CoreByteOrder::MidBigEndian,
            ByteOrder::MidLittleEndian => CoreByteOrder::MidLittleEndian,
        }
    }

    /// Creates from core byte order.
    pub fn from_core(core: CoreByteOrder) -> Self {
        match core {
            CoreByteOrder::BigEndian => ByteOrder::BigEndian,
            CoreByteOrder::LittleEndian => ByteOrder::LittleEndian,
            CoreByteOrder::MidBigEndian => ByteOrder::MidBigEndian,
            CoreByteOrder::MidLittleEndian => ByteOrder::MidLittleEndian,
        }
    }
}

// =============================================================================
// Extended Converter Tests
// =============================================================================

#[cfg(test)]
mod extended_tests {
    use super::*;

    #[test]
    fn test_extended_converter_basic() {
        let converter = ExtendedDataConverter::new();
        let registers = vec![0x0064]; // 100
        let addr = ModbusDataAddress::holding_register(0)
            .with_data_type(ModbusDataType::UInt16);

        let value = converter.convert_from_registers(&registers, &addr).unwrap();
        assert_eq!(value, TypedValue::UInt16(100));
    }

    #[test]
    fn test_tag_converter_with_scaling() {
        let mut converter = ExtendedDataConverter::new();

        // Register a temperature sensor: raw * 0.1 - 40
        converter.register_tag(
            "temp_sensor",
            TagConverterConfig::builder()
                .data_type(ModbusDataType::Int16)
                .scale(0.1)
                .offset(-40.0)
                .range(-40.0, 85.0)
                .build(),
        );

        let registers = vec![250]; // Raw: 250, Scaled: 250 * 0.1 - 40 = -15
        let addr = ModbusDataAddress::holding_register(0);

        let value = converter.convert_for_tag("temp_sensor", &registers, &addr).unwrap();
        if let TypedValue::Float64(v) = value {
            assert!((v - (-15.0)).abs() < 0.001);
        } else {
            panic!("Expected Float64");
        }
    }

    #[test]
    fn test_tag_converter_fallback() {
        let converter = ExtendedDataConverter::new();
        let registers = vec![100];
        let addr = ModbusDataAddress::holding_register(0)
            .with_data_type(ModbusDataType::UInt16);

        // Unknown tag should fall back to address config
        let value = converter.convert_for_tag("unknown_tag", &registers, &addr).unwrap();
        assert_eq!(value, TypedValue::UInt16(100));
    }

    #[test]
    fn test_encode_with_tag_scaling() {
        let mut converter = ExtendedDataConverter::new();

        // Power meter: raw * 0.01 kW
        converter.register_tag(
            "power_meter",
            TagConverterConfig::builder()
                .data_type(ModbusDataType::UInt16)
                .scale(0.01)
                .build(),
        );

        let addr = ModbusDataAddress::holding_register(0);
        let value = TypedValue::Float64(10.0); // 10 kW -> raw 1000

        let registers = converter.encode_for_tag("power_meter", &value, &addr).unwrap();
        assert_eq!(registers[0], 1000);
    }

    #[test]
    fn test_byte_order_conversion() {
        assert_eq!(ByteOrder::BigEndian.to_core(), CoreByteOrder::BigEndian);
        assert_eq!(ByteOrder::LittleEndian.to_core(), CoreByteOrder::LittleEndian);
        assert_eq!(ByteOrder::MidBigEndian.to_core(), CoreByteOrder::MidBigEndian);
        assert_eq!(ByteOrder::MidLittleEndian.to_core(), CoreByteOrder::MidLittleEndian);

        assert_eq!(ByteOrder::from_core(CoreByteOrder::BigEndian), ByteOrder::BigEndian);
    }

    #[test]
    fn test_decode_float32_with_context() {
        let converter = ExtendedDataConverter::new();
        let bytes = [0x42, 0x48, 0x00, 0x00]; // 50.0 in IEEE 754
        let context = ConversionContext::new().with_byte_order(CoreByteOrder::BigEndian);

        let value = converter.decode_with_context(&bytes, ModbusDataType::Float32, &context).unwrap();
        if let TypedValue::Float32(v) = value {
            assert!((v - 50.0).abs() < 0.001);
        } else {
            panic!("Expected Float32");
        }
    }

    #[test]
    fn test_tag_config_builder() {
        let config = TagConverterConfig::builder()
            .data_type(ModbusDataType::Int16)
            .byte_order(ByteOrder::LittleEndian)
            .scale(0.5)
            .offset(100.0)
            .range(-50.0, 150.0)
            .bit_extraction(0, 8)
            .build();

        assert_eq!(config.data_type, ModbusDataType::Int16);
        assert_eq!(config.byte_order, ByteOrder::LittleEndian);
        assert_eq!(config.scale, 0.5);
        assert_eq!(config.offset, 100.0);
        assert_eq!(config.min_value, Some(-50.0));
        assert_eq!(config.max_value, Some(150.0));
        assert_eq!(config.bit_position, Some(0));
        assert_eq!(config.bit_count, Some(8));
    }
}
