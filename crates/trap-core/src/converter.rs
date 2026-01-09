// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Data type conversion system for industrial protocols.
//!
//! This module provides a flexible, extensible conversion system for transforming
//! raw protocol data (registers, bytes) into typed values and vice versa.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    ConverterRegistry                            │
//! │              (Central registry for converters)                  │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    RegisterConverter trait                      │
//! │              (Core conversion abstraction)                      │
//! └─────────────────────────────────────────────────────────────────┘
//!            │                 │                 │
//!            ▼                 ▼                 ▼
//! ┌───────────────┐ ┌───────────────┐ ┌───────────────────────────┐
//! │NumericConverter│ │StringConverter│ │  CompositeConverter       │
//! │ (int/float)    │ │  (ASCII/UTF8) │ │  (struct/array)           │
//! └───────────────┘ └───────────────┘ └───────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Type Safety**: Strong typing with compile-time checks
//! - **Extensibility**: Easy to add custom converters
//! - **Byte Order**: Full support for all Modbus byte orderings
//! - **Scaling**: Linear transformation (value * scale + offset)
//! - **Validation**: Range checking and value constraints
//! - **Composability**: Build complex types from primitives
//!
//! # Examples
//!
//! ```rust,ignore
//! use trap_core::converter::{
//!     ConverterRegistry, NumericConverter, ByteOrder, ConversionContext
//! };
//!
//! // Create registry with default converters
//! let registry = ConverterRegistry::default();
//!
//! // Convert registers to float32
//! let registers = vec![0x4248, 0x0000]; // 50.0 in IEEE 754
//! let context = ConversionContext::new()
//!     .with_byte_order(ByteOrder::BigEndian)
//!     .with_scale(1.0)
//!     .with_offset(0.0);
//!
//! let value = registry.decode::<f32>(&registers, &context)?;
//! assert!((value - 50.0).abs() < 0.001);
//! ```

use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::Value;

// =============================================================================
// Conversion Errors
// =============================================================================

/// Errors that can occur during data conversion.
#[derive(Debug, Error)]
pub enum ConversionError {
    /// Insufficient data for conversion.
    #[error("Insufficient data: need {required} bytes, have {available}")]
    InsufficientData {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },

    /// Value overflow during conversion.
    #[error("Value overflow: {value} cannot be represented as {target_type}")]
    Overflow {
        /// The value that overflowed.
        value: String,
        /// Target type name.
        target_type: &'static str,
    },

    /// Invalid encoding (for strings).
    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),

    /// Invalid byte order configuration.
    #[error("Invalid byte order: {0}")]
    InvalidByteOrder(String),

    /// Scale factor is zero (would cause division by zero).
    #[error("Scale factor cannot be zero")]
    ZeroScale,

    /// Type mismatch.
    #[error("Type mismatch: expected {expected}, got {actual}")]
    TypeMismatch {
        /// Expected type.
        expected: &'static str,
        /// Actual type.
        actual: &'static str,
    },

    /// Value out of range.
    #[error("Value {value} out of range [{min}, {max}]")]
    OutOfRange {
        /// The value.
        value: String,
        /// Minimum allowed.
        min: String,
        /// Maximum allowed.
        max: String,
    },

    /// No converter registered for the type.
    #[error("No converter registered for type: {0}")]
    NoConverter(String),

    /// Custom validation error.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// General conversion error.
    #[error("{0}")]
    Other(String),
}

/// Result type for conversion operations.
pub type ConversionResult<T> = Result<T, ConversionError>;

// =============================================================================
// Byte Order
// =============================================================================

/// Byte order for multi-byte values.
///
/// Different devices use different byte orderings. This enum covers all common
/// orderings found in industrial protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    /// Big-endian (ABCD): Most significant byte first.
    /// Word order: [MSW, LSW], Byte order within word: [MSB, LSB]
    #[default]
    BigEndian,

    /// Little-endian (DCBA): Least significant byte first.
    /// Word order: [LSW, MSW], Byte order within word: [LSB, MSB]
    LittleEndian,

    /// Mid-big-endian (CDAB): Big-endian words, little-endian word order.
    /// Word order: [MSW, LSW], Byte order within word: [LSB, MSB]
    MidBigEndian,

    /// Mid-little-endian (BADC): Little-endian words, big-endian word order.
    /// Word order: [LSW, MSW], Byte order within word: [MSB, LSB]
    MidLittleEndian,
}

impl ByteOrder {
    /// Reorders bytes from big-endian to this byte order.
    #[inline]
    pub fn reorder_from_be(&self, bytes: &mut [u8]) {
        let len = bytes.len();
        match self {
            ByteOrder::BigEndian => {}
            ByteOrder::LittleEndian => bytes.reverse(),
            ByteOrder::MidBigEndian => {
                // Swap bytes within each word, keep word order
                for chunk in bytes.chunks_exact_mut(2) {
                    chunk.swap(0, 1);
                }
            }
            ByteOrder::MidLittleEndian => {
                // Swap words, keep byte order within words
                if len >= 4 {
                    for i in 0..len / 4 {
                        let base = i * 4;
                        bytes.swap(base, base + 2);
                        bytes.swap(base + 1, base + 3);
                    }
                }
            }
        }
    }

    /// Reorders bytes to big-endian from this byte order.
    #[inline]
    pub fn reorder_to_be(&self, bytes: &mut [u8]) {
        // Inverse operations
        let len = bytes.len();
        match self {
            ByteOrder::BigEndian => {}
            ByteOrder::LittleEndian => bytes.reverse(),
            ByteOrder::MidBigEndian => {
                for chunk in bytes.chunks_exact_mut(2) {
                    chunk.swap(0, 1);
                }
            }
            ByteOrder::MidLittleEndian => {
                if len >= 4 {
                    for i in 0..len / 4 {
                        let base = i * 4;
                        bytes.swap(base, base + 2);
                        bytes.swap(base + 1, base + 3);
                    }
                }
            }
        }
    }
}

impl fmt::Display for ByteOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ByteOrder::BigEndian => write!(f, "big_endian"),
            ByteOrder::LittleEndian => write!(f, "little_endian"),
            ByteOrder::MidBigEndian => write!(f, "mid_big_endian"),
            ByteOrder::MidLittleEndian => write!(f, "mid_little_endian"),
        }
    }
}

// =============================================================================
// Conversion Context
// =============================================================================

/// Configuration for a single conversion operation.
///
/// This struct carries all the metadata needed to perform a conversion,
/// including byte order, scaling, and validation constraints.
#[derive(Debug, Clone)]
pub struct ConversionContext {
    /// Byte order for multi-byte values.
    pub byte_order: ByteOrder,

    /// Scale factor (applied as: raw_value * scale + offset).
    pub scale: f64,

    /// Offset (applied as: raw_value * scale + offset).
    pub offset: f64,

    /// Minimum allowed value (after scaling).
    pub min_value: Option<f64>,

    /// Maximum allowed value (after scaling).
    pub max_value: Option<f64>,

    /// Bit position for bit extraction (0-15 for 16-bit registers).
    pub bit_position: Option<u8>,

    /// Bit count for bit extraction.
    pub bit_count: Option<u8>,

    /// String encoding (for string conversions).
    pub encoding: StringEncoding,

    /// Whether to trim null bytes from strings.
    pub trim_nulls: bool,

    /// Custom metadata.
    pub metadata: HashMap<String, String>,
}

impl Default for ConversionContext {
    fn default() -> Self {
        Self {
            byte_order: ByteOrder::BigEndian,
            scale: 1.0,
            offset: 0.0,
            min_value: None,
            max_value: None,
            bit_position: None,
            bit_count: None,
            encoding: StringEncoding::Ascii,
            trim_nulls: true,
            metadata: HashMap::new(),
        }
    }
}

impl ConversionContext {
    /// Creates a new context with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the byte order.
    #[inline]
    pub fn with_byte_order(mut self, order: ByteOrder) -> Self {
        self.byte_order = order;
        self
    }

    /// Sets the scale factor.
    #[inline]
    pub fn with_scale(mut self, scale: f64) -> Self {
        self.scale = scale;
        self
    }

    /// Sets the offset.
    #[inline]
    pub fn with_offset(mut self, offset: f64) -> Self {
        self.offset = offset;
        self
    }

    /// Sets both scale and offset.
    #[inline]
    pub fn with_scaling(mut self, scale: f64, offset: f64) -> Self {
        self.scale = scale;
        self.offset = offset;
        self
    }

    /// Sets the minimum allowed value.
    #[inline]
    pub fn with_min(mut self, min: f64) -> Self {
        self.min_value = Some(min);
        self
    }

    /// Sets the maximum allowed value.
    #[inline]
    pub fn with_max(mut self, max: f64) -> Self {
        self.max_value = Some(max);
        self
    }

    /// Sets the value range.
    #[inline]
    pub fn with_range(mut self, min: f64, max: f64) -> Self {
        self.min_value = Some(min);
        self.max_value = Some(max);
        self
    }

    /// Sets bit extraction parameters.
    #[inline]
    pub fn with_bit_extraction(mut self, position: u8, count: u8) -> Self {
        self.bit_position = Some(position);
        self.bit_count = Some(count);
        self
    }

    /// Sets string encoding.
    #[inline]
    pub fn with_encoding(mut self, encoding: StringEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Sets whether to trim null bytes.
    #[inline]
    pub fn with_trim_nulls(mut self, trim: bool) -> Self {
        self.trim_nulls = trim;
        self
    }

    /// Adds custom metadata.
    #[inline]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Returns true if scaling is configured.
    #[inline]
    pub fn has_scaling(&self) -> bool {
        (self.scale - 1.0).abs() > f64::EPSILON || self.offset.abs() > f64::EPSILON
    }

    /// Returns true if range validation is configured.
    #[inline]
    pub fn has_range(&self) -> bool {
        self.min_value.is_some() || self.max_value.is_some()
    }

    /// Applies scaling to a value.
    #[inline]
    pub fn apply_scale(&self, value: f64) -> f64 {
        value * self.scale + self.offset
    }

    /// Applies inverse scaling (for encoding).
    #[inline]
    pub fn apply_inverse_scale(&self, value: f64) -> ConversionResult<f64> {
        if self.scale.abs() < f64::EPSILON {
            return Err(ConversionError::ZeroScale);
        }
        Ok((value - self.offset) / self.scale)
    }

    /// Validates a value against the configured range.
    pub fn validate_range(&self, value: f64) -> ConversionResult<()> {
        if let Some(min) = self.min_value {
            if value < min {
                return Err(ConversionError::OutOfRange {
                    value: value.to_string(),
                    min: min.to_string(),
                    max: self.max_value.map_or("∞".into(), |v| v.to_string()),
                });
            }
        }
        if let Some(max) = self.max_value {
            if value > max {
                return Err(ConversionError::OutOfRange {
                    value: value.to_string(),
                    min: self.min_value.map_or("-∞".into(), |v| v.to_string()),
                    max: max.to_string(),
                });
            }
        }
        Ok(())
    }
}

/// String encoding types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    /// ASCII encoding.
    #[default]
    Ascii,
    /// UTF-8 encoding.
    Utf8,
    /// UTF-16 big-endian.
    Utf16Be,
    /// UTF-16 little-endian.
    Utf16Le,
}

// =============================================================================
// Register Converter Trait
// =============================================================================

/// Core trait for converting between raw register data and typed values.
///
/// Implementors of this trait can convert raw byte/register data to a specific
/// Rust type and vice versa.
///
/// # Type Parameters
///
/// * `T` - The target Rust type for this converter
///
/// # Implementation Notes
///
/// - `decode` converts from raw bytes to the target type
/// - `encode` converts from the target type to raw bytes
/// - Both operations should respect the `ConversionContext` settings
pub trait RegisterConverter<T>: Send + Sync {
    /// The number of bytes this converter expects/produces.
    ///
    /// For variable-length types (like strings), this returns the minimum.
    fn byte_size(&self) -> usize;

    /// The number of 16-bit registers this converter expects/produces.
    fn register_count(&self) -> usize {
        (self.byte_size() + 1) / 2
    }

    /// Decodes raw bytes to the target type.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw bytes in big-endian format (before byte order adjustment)
    /// * `context` - Conversion context with byte order, scaling, etc.
    ///
    /// # Returns
    ///
    /// The decoded value or an error.
    fn decode(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<T>;

    /// Encodes the target type to raw bytes.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to encode
    /// * `context` - Conversion context with byte order, scaling, etc.
    ///
    /// # Returns
    ///
    /// The encoded bytes in big-endian format (before byte order adjustment).
    fn encode(&self, value: &T, context: &ConversionContext) -> ConversionResult<Vec<u8>>;

    /// Returns the type name for error messages.
    fn type_name(&self) -> &'static str;
}

// =============================================================================
// Numeric Converters
// =============================================================================

/// Converter for boolean values (single bit or full register).
#[derive(Debug, Clone, Default)]
pub struct BoolConverter;

impl RegisterConverter<bool> for BoolConverter {
    fn byte_size(&self) -> usize {
        1
    }

    fn decode(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<bool> {
        if bytes.is_empty() {
            return Err(ConversionError::InsufficientData {
                required: 1,
                available: 0,
            });
        }

        // Handle bit extraction if configured
        if let (Some(pos), Some(_count)) = (context.bit_position, context.bit_count) {
            if bytes.len() >= 2 {
                let word = u16::from_be_bytes([bytes[0], bytes[1]]);
                Ok((word >> pos) & 1 == 1)
            } else {
                Ok((bytes[0] >> pos) & 1 == 1)
            }
        } else {
            Ok(bytes[0] != 0)
        }
    }

    fn encode(&self, value: &bool, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        if let (Some(pos), Some(_count)) = (context.bit_position, context.bit_count) {
            // Bit-level encoding (need existing register value for proper operation)
            // For now, just set the bit in an otherwise zero register
            let word = if *value { 1u16 << pos } else { 0 };
            Ok(word.to_be_bytes().to_vec())
        } else {
            Ok(vec![if *value { 1 } else { 0 }])
        }
    }

    fn type_name(&self) -> &'static str {
        "bool"
    }
}

/// Generic numeric converter for primitive types.
#[derive(Debug, Clone)]
pub struct NumericConverter<T> {
    _marker: PhantomData<T>,
}

impl<T> Default for NumericConverter<T> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<T> NumericConverter<T> {
    /// Creates a new numeric converter.
    pub fn new() -> Self {
        Self::default()
    }
}

macro_rules! impl_numeric_converter {
    ($t:ty, $size:expr, $name:expr) => {
        impl RegisterConverter<$t> for NumericConverter<$t> {
            fn byte_size(&self) -> usize {
                $size
            }

            fn decode(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<$t> {
                if bytes.len() < $size {
                    return Err(ConversionError::InsufficientData {
                        required: $size,
                        available: bytes.len(),
                    });
                }

                let mut buf = [0u8; $size];
                buf.copy_from_slice(&bytes[..$size]);
                context.byte_order.reorder_to_be(&mut buf);

                Ok(<$t>::from_be_bytes(buf))
            }

            fn encode(&self, value: &$t, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
                let mut bytes = value.to_be_bytes().to_vec();
                context.byte_order.reorder_from_be(&mut bytes);
                Ok(bytes)
            }

            fn type_name(&self) -> &'static str {
                $name
            }
        }
    };
}

impl_numeric_converter!(i8, 1, "int8");
impl_numeric_converter!(u8, 1, "uint8");
impl_numeric_converter!(i16, 2, "int16");
impl_numeric_converter!(u16, 2, "uint16");
impl_numeric_converter!(i32, 4, "int32");
impl_numeric_converter!(u32, 4, "uint32");
impl_numeric_converter!(i64, 8, "int64");
impl_numeric_converter!(u64, 8, "uint64");
impl_numeric_converter!(f32, 4, "float32");
impl_numeric_converter!(f64, 8, "float64");

/// Converter for numeric values with automatic scaling.
///
/// This wraps another converter and applies scaling/offset transformations.
#[derive(Debug, Clone)]
pub struct ScaledConverter<T, C> {
    inner: C,
    _marker: PhantomData<T>,
}

impl<T, C> ScaledConverter<T, C>
where
    C: RegisterConverter<T>,
{
    /// Creates a new scaled converter wrapping the given converter.
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<C> RegisterConverter<f64> for ScaledConverter<i16, C>
where
    C: RegisterConverter<i16>,
{
    fn byte_size(&self) -> usize {
        self.inner.byte_size()
    }

    fn decode(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<f64> {
        let raw = self.inner.decode(bytes, context)?;
        let scaled = context.apply_scale(raw as f64);
        context.validate_range(scaled)?;
        Ok(scaled)
    }

    fn encode(&self, value: &f64, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        let unscaled = context.apply_inverse_scale(*value)?;
        let raw = unscaled.round() as i16;
        self.inner.encode(&raw, context)
    }

    fn type_name(&self) -> &'static str {
        "scaled_int16"
    }
}

impl<C> RegisterConverter<f64> for ScaledConverter<u16, C>
where
    C: RegisterConverter<u16>,
{
    fn byte_size(&self) -> usize {
        self.inner.byte_size()
    }

    fn decode(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<f64> {
        let raw = self.inner.decode(bytes, context)?;
        let scaled = context.apply_scale(raw as f64);
        context.validate_range(scaled)?;
        Ok(scaled)
    }

    fn encode(&self, value: &f64, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        let unscaled = context.apply_inverse_scale(*value)?;
        if unscaled < 0.0 {
            return Err(ConversionError::Overflow {
                value: value.to_string(),
                target_type: "uint16",
            });
        }
        let raw = unscaled.round() as u16;
        self.inner.encode(&raw, context)
    }

    fn type_name(&self) -> &'static str {
        "scaled_uint16"
    }
}

// =============================================================================
// String Converter
// =============================================================================

/// Converter for string values.
#[derive(Debug, Clone)]
pub struct StringConverter {
    /// Maximum length in bytes.
    max_length: usize,
}

impl StringConverter {
    /// Creates a new string converter with the given maximum length.
    pub fn new(max_length: usize) -> Self {
        Self { max_length }
    }

    /// Creates a string converter with default max length (256 bytes).
    pub fn default_length() -> Self {
        Self::new(256)
    }
}

impl Default for StringConverter {
    fn default() -> Self {
        Self::default_length()
    }
}

impl RegisterConverter<String> for StringConverter {
    fn byte_size(&self) -> usize {
        self.max_length
    }

    fn decode(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<String> {
        match context.encoding {
            StringEncoding::Ascii | StringEncoding::Utf8 => {
                let end = if context.trim_nulls {
                    bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())
                } else {
                    bytes.len()
                };

                String::from_utf8(bytes[..end].to_vec())
                    .map_err(|e| ConversionError::InvalidEncoding(e.to_string()))
            }
            StringEncoding::Utf16Be => {
                let chars: Result<Vec<u16>, _> = bytes
                    .chunks_exact(2)
                    .take_while(|chunk| !context.trim_nulls || chunk != &[0, 0])
                    .map(|chunk| Ok(u16::from_be_bytes([chunk[0], chunk[1]])))
                    .collect();
                String::from_utf16(&chars?)
                    .map_err(|e| ConversionError::InvalidEncoding(e.to_string()))
            }
            StringEncoding::Utf16Le => {
                let chars: Result<Vec<u16>, _> = bytes
                    .chunks_exact(2)
                    .take_while(|chunk| !context.trim_nulls || chunk != &[0, 0])
                    .map(|chunk| Ok(u16::from_le_bytes([chunk[0], chunk[1]])))
                    .collect();
                String::from_utf16(&chars?)
                    .map_err(|e| ConversionError::InvalidEncoding(e.to_string()))
            }
        }
    }

    fn encode(&self, value: &String, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        match context.encoding {
            StringEncoding::Ascii | StringEncoding::Utf8 => {
                let mut bytes = value.as_bytes().to_vec();
                bytes.truncate(self.max_length);
                // Pad with nulls to maintain consistent length
                bytes.resize(self.max_length, 0);
                Ok(bytes)
            }
            StringEncoding::Utf16Be => {
                let mut bytes = Vec::with_capacity(self.max_length);
                for c in value.encode_utf16() {
                    if bytes.len() + 2 > self.max_length {
                        break;
                    }
                    bytes.extend_from_slice(&c.to_be_bytes());
                }
                bytes.resize(self.max_length, 0);
                Ok(bytes)
            }
            StringEncoding::Utf16Le => {
                let mut bytes = Vec::with_capacity(self.max_length);
                for c in value.encode_utf16() {
                    if bytes.len() + 2 > self.max_length {
                        break;
                    }
                    bytes.extend_from_slice(&c.to_le_bytes());
                }
                bytes.resize(self.max_length, 0);
                Ok(bytes)
            }
        }
    }

    fn type_name(&self) -> &'static str {
        "string"
    }
}

// =============================================================================
// Bytes Converter
// =============================================================================

/// Converter for raw byte arrays.
#[derive(Debug, Clone)]
pub struct BytesConverter {
    /// Expected length (0 for variable).
    length: usize,
}

impl BytesConverter {
    /// Creates a new bytes converter with fixed length.
    pub fn new(length: usize) -> Self {
        Self { length }
    }

    /// Creates a variable-length bytes converter.
    pub fn variable() -> Self {
        Self { length: 0 }
    }
}

impl Default for BytesConverter {
    fn default() -> Self {
        Self::variable()
    }
}

impl RegisterConverter<Vec<u8>> for BytesConverter {
    fn byte_size(&self) -> usize {
        self.length
    }

    fn decode(&self, bytes: &[u8], _context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        if self.length > 0 && bytes.len() < self.length {
            return Err(ConversionError::InsufficientData {
                required: self.length,
                available: bytes.len(),
            });
        }
        Ok(bytes.to_vec())
    }

    fn encode(&self, value: &Vec<u8>, _context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        if self.length > 0 {
            let mut result = value.clone();
            result.resize(self.length, 0);
            Ok(result)
        } else {
            Ok(value.clone())
        }
    }

    fn type_name(&self) -> &'static str {
        "bytes"
    }
}

// =============================================================================
// Composite Converter
// =============================================================================

/// A field in a composite type.
#[derive(Clone)]
pub struct CompositeField {
    /// Field name.
    pub name: String,
    /// Field offset in bytes.
    pub offset: usize,
    /// Field converter (type-erased).
    pub converter: Arc<dyn ErasedConverter>,
    /// Field-specific context overrides.
    pub context_override: Option<ConversionContext>,
}

impl fmt::Debug for CompositeField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeField")
            .field("name", &self.name)
            .field("offset", &self.offset)
            .finish()
    }
}

/// Type-erased converter trait for use in composites.
pub trait ErasedConverter: Send + Sync {
    /// Decodes to a dynamic Value.
    fn decode_value(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<Value>;

    /// Encodes from a dynamic Value.
    fn encode_value(&self, value: &Value, context: &ConversionContext) -> ConversionResult<Vec<u8>>;

    /// Returns the byte size.
    fn byte_size(&self) -> usize;

    /// Returns the type name.
    fn type_name(&self) -> &'static str;
}

/// Wrapper to make typed converters type-erased.
#[derive(Clone)]
pub struct TypedConverterWrapper<T, C>
where
    C: RegisterConverter<T> + Clone,
{
    converter: C,
    _marker: PhantomData<T>,
}

impl<T, C> TypedConverterWrapper<T, C>
where
    C: RegisterConverter<T> + Clone,
{
    /// Creates a new wrapper.
    pub fn new(converter: C) -> Self {
        Self {
            converter,
            _marker: PhantomData,
        }
    }
}

// Implement ErasedConverter for common types
macro_rules! impl_erased_converter {
    ($t:ty, $variant:ident) => {
        impl<C> ErasedConverter for TypedConverterWrapper<$t, C>
        where
            C: RegisterConverter<$t> + Clone + Send + Sync,
        {
            fn decode_value(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<Value> {
                let value = self.converter.decode(bytes, context)?;
                Ok(Value::$variant(value))
            }

            fn encode_value(&self, value: &Value, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
                match value {
                    Value::$variant(v) => self.converter.encode(v, context),
                    _ => Err(ConversionError::TypeMismatch {
                        expected: stringify!($variant),
                        actual: value.type_name(),
                    }),
                }
            }

            fn byte_size(&self) -> usize {
                self.converter.byte_size()
            }

            fn type_name(&self) -> &'static str {
                self.converter.type_name()
            }
        }
    };
}

impl_erased_converter!(bool, Bool);
impl_erased_converter!(i8, Int8);
impl_erased_converter!(u8, UInt8);
impl_erased_converter!(i16, Int16);
impl_erased_converter!(u16, UInt16);
impl_erased_converter!(i32, Int32);
impl_erased_converter!(u32, UInt32);
impl_erased_converter!(i64, Int64);
impl_erased_converter!(u64, UInt64);
impl_erased_converter!(f32, Float32);
impl_erased_converter!(f64, Float64);
impl_erased_converter!(String, String);

impl<C> ErasedConverter for TypedConverterWrapper<Vec<u8>, C>
where
    C: RegisterConverter<Vec<u8>> + Clone + Send + Sync,
{
    fn decode_value(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<Value> {
        let value = self.converter.decode(bytes, context)?;
        Ok(Value::Bytes(value))
    }

    fn encode_value(&self, value: &Value, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        match value {
            Value::Bytes(v) => self.converter.encode(v, context),
            _ => Err(ConversionError::TypeMismatch {
                expected: "Bytes",
                actual: value.type_name(),
            }),
        }
    }

    fn byte_size(&self) -> usize {
        self.converter.byte_size()
    }

    fn type_name(&self) -> &'static str {
        self.converter.type_name()
    }
}

/// Converter for composite (struct-like) values.
#[derive(Debug, Clone)]
pub struct CompositeConverter {
    fields: Vec<CompositeField>,
    total_size: usize,
}

impl CompositeConverter {
    /// Creates a new composite converter builder.
    pub fn builder() -> CompositeConverterBuilder {
        CompositeConverterBuilder::new()
    }
}

impl RegisterConverter<Vec<(String, Value)>> for CompositeConverter {
    fn byte_size(&self) -> usize {
        self.total_size
    }

    fn decode(
        &self,
        bytes: &[u8],
        context: &ConversionContext,
    ) -> ConversionResult<Vec<(String, Value)>> {
        if bytes.len() < self.total_size {
            return Err(ConversionError::InsufficientData {
                required: self.total_size,
                available: bytes.len(),
            });
        }

        let mut result = Vec::with_capacity(self.fields.len());
        for field in &self.fields {
            let field_context = field.context_override.as_ref().unwrap_or(context);
            let field_bytes = &bytes[field.offset..field.offset + field.converter.byte_size()];
            let value = field.converter.decode_value(field_bytes, field_context)?;
            result.push((field.name.clone(), value));
        }
        Ok(result)
    }

    fn encode(
        &self,
        value: &Vec<(String, Value)>,
        context: &ConversionContext,
    ) -> ConversionResult<Vec<u8>> {
        let mut result = vec![0u8; self.total_size];

        for (name, val) in value {
            if let Some(field) = self.fields.iter().find(|f| &f.name == name) {
                let field_context = field.context_override.as_ref().unwrap_or(context);
                let encoded = field.converter.encode_value(val, field_context)?;
                let end = (field.offset + encoded.len()).min(self.total_size);
                result[field.offset..end].copy_from_slice(&encoded[..end - field.offset]);
            }
        }

        Ok(result)
    }

    fn type_name(&self) -> &'static str {
        "composite"
    }
}

/// Builder for composite converters.
#[derive(Default)]
pub struct CompositeConverterBuilder {
    fields: Vec<CompositeField>,
    current_offset: usize,
}

impl CompositeConverterBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a field at the current offset.
    pub fn field<T, C>(mut self, name: impl Into<String>, converter: C) -> Self
    where
        T: 'static,
        C: RegisterConverter<T> + Clone + Send + Sync + 'static,
        TypedConverterWrapper<T, C>: ErasedConverter,
    {
        let size = converter.byte_size();
        self.fields.push(CompositeField {
            name: name.into(),
            offset: self.current_offset,
            converter: Arc::new(TypedConverterWrapper::new(converter)),
            context_override: None,
        });
        self.current_offset += size;
        self
    }

    /// Adds a field with context override.
    pub fn field_with_context<T, C>(
        mut self,
        name: impl Into<String>,
        converter: C,
        context: ConversionContext,
    ) -> Self
    where
        T: 'static,
        C: RegisterConverter<T> + Clone + Send + Sync + 'static,
        TypedConverterWrapper<T, C>: ErasedConverter,
    {
        let size = converter.byte_size();
        self.fields.push(CompositeField {
            name: name.into(),
            offset: self.current_offset,
            converter: Arc::new(TypedConverterWrapper::new(converter)),
            context_override: Some(context),
        });
        self.current_offset += size;
        self
    }

    /// Adds padding bytes.
    pub fn padding(mut self, bytes: usize) -> Self {
        self.current_offset += bytes;
        self
    }

    /// Builds the composite converter.
    pub fn build(self) -> CompositeConverter {
        CompositeConverter {
            fields: self.fields,
            total_size: self.current_offset,
        }
    }
}

// =============================================================================
// Converter Registry
// =============================================================================

/// Registry for converter instances.
///
/// The registry provides pre-built converters for common types and allows
/// decoding/encoding operations using specific data types.
///
/// Rather than using type erasure with downcast, this registry provides
/// direct access to stateless converters for efficiency.
#[derive(Clone, Default)]
pub struct ConverterRegistry {
    /// Default string converter length.
    default_string_length: usize,
    /// Named scaled configurations (name -> (scale, offset)).
    scaled_configs: HashMap<String, (f64, f64)>,
}

impl ConverterRegistry {
    /// Creates a new registry with default settings.
    pub fn new() -> Self {
        Self {
            default_string_length: 256,
            scaled_configs: HashMap::new(),
        }
    }

    /// Creates a registry with custom default string length.
    pub fn with_string_length(mut self, length: usize) -> Self {
        self.default_string_length = length;
        self
    }

    /// Registers a named scaled converter configuration.
    pub fn register_scaled(&mut self, name: impl Into<String>, scale: f64, offset: f64) {
        self.scaled_configs.insert(name.into(), (scale, offset));
    }

    /// Gets a scaled configuration by name.
    pub fn get_scaled(&self, name: &str) -> Option<(f64, f64)> {
        self.scaled_configs.get(name).copied()
    }

    /// Decodes bool from bytes.
    pub fn decode_bool(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<bool> {
        BoolConverter.decode(bytes, context)
    }

    /// Decodes i8 from bytes.
    pub fn decode_i8(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<i8> {
        NumericConverter::<i8>::new().decode(bytes, context)
    }

    /// Decodes u8 from bytes.
    pub fn decode_u8(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<u8> {
        NumericConverter::<u8>::new().decode(bytes, context)
    }

    /// Decodes i16 from bytes.
    pub fn decode_i16(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<i16> {
        NumericConverter::<i16>::new().decode(bytes, context)
    }

    /// Decodes u16 from bytes.
    pub fn decode_u16(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<u16> {
        NumericConverter::<u16>::new().decode(bytes, context)
    }

    /// Decodes i32 from bytes.
    pub fn decode_i32(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<i32> {
        NumericConverter::<i32>::new().decode(bytes, context)
    }

    /// Decodes u32 from bytes.
    pub fn decode_u32(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<u32> {
        NumericConverter::<u32>::new().decode(bytes, context)
    }

    /// Decodes i64 from bytes.
    pub fn decode_i64(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<i64> {
        NumericConverter::<i64>::new().decode(bytes, context)
    }

    /// Decodes u64 from bytes.
    pub fn decode_u64(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<u64> {
        NumericConverter::<u64>::new().decode(bytes, context)
    }

    /// Decodes f32 from bytes.
    pub fn decode_f32(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<f32> {
        NumericConverter::<f32>::new().decode(bytes, context)
    }

    /// Decodes f64 from bytes.
    pub fn decode_f64(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<f64> {
        NumericConverter::<f64>::new().decode(bytes, context)
    }

    /// Decodes String from bytes.
    pub fn decode_string(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<String> {
        StringConverter::new(bytes.len().max(self.default_string_length)).decode(bytes, context)
    }

    /// Decodes raw bytes.
    pub fn decode_bytes(&self, bytes: &[u8], context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        BytesConverter::new(bytes.len()).decode(bytes, context)
    }

    /// Encodes bool to bytes.
    pub fn encode_bool(&self, value: bool, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        BoolConverter.encode(&value, context)
    }

    /// Encodes i16 to bytes.
    pub fn encode_i16(&self, value: i16, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        NumericConverter::<i16>::new().encode(&value, context)
    }

    /// Encodes u16 to bytes.
    pub fn encode_u16(&self, value: u16, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        NumericConverter::<u16>::new().encode(&value, context)
    }

    /// Encodes i32 to bytes.
    pub fn encode_i32(&self, value: i32, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        NumericConverter::<i32>::new().encode(&value, context)
    }

    /// Encodes u32 to bytes.
    pub fn encode_u32(&self, value: u32, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        NumericConverter::<u32>::new().encode(&value, context)
    }

    /// Encodes i64 to bytes.
    pub fn encode_i64(&self, value: i64, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        NumericConverter::<i64>::new().encode(&value, context)
    }

    /// Encodes u64 to bytes.
    pub fn encode_u64(&self, value: u64, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        NumericConverter::<u64>::new().encode(&value, context)
    }

    /// Encodes f32 to bytes.
    pub fn encode_f32(&self, value: f32, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        NumericConverter::<f32>::new().encode(&value, context)
    }

    /// Encodes f64 to bytes.
    pub fn encode_f64(&self, value: f64, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        NumericConverter::<f64>::new().encode(&value, context)
    }

    /// Encodes String to bytes.
    pub fn encode_string(&self, value: &str, context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        StringConverter::new(value.len().max(2)).encode(&value.to_string(), context)
    }

    /// Encodes raw bytes.
    pub fn encode_bytes(&self, value: &[u8], context: &ConversionContext) -> ConversionResult<Vec<u8>> {
        BytesConverter::new(value.len()).encode(&value.to_vec(), context)
    }

    /// Decodes with scaling using a named configuration.
    ///
    /// Returns the decoded value as f64 after applying scale and offset.
    pub fn decode_scaled_i16(&self, name: &str, bytes: &[u8], context: &ConversionContext) -> ConversionResult<f64> {
        let raw = self.decode_i16(bytes, context)?;
        if let Some((scale, offset)) = self.scaled_configs.get(name) {
            Ok(raw as f64 * scale + offset)
        } else {
            Ok(raw as f64)
        }
    }

    /// Decodes with scaling using a named configuration.
    pub fn decode_scaled_u16(&self, name: &str, bytes: &[u8], context: &ConversionContext) -> ConversionResult<f64> {
        let raw = self.decode_u16(bytes, context)?;
        if let Some((scale, offset)) = self.scaled_configs.get(name) {
            Ok(raw as f64 * scale + offset)
        } else {
            Ok(raw as f64)
        }
    }
}

impl fmt::Debug for ConverterRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConverterRegistry")
            .field("default_string_length", &self.default_string_length)
            .field("scaled_configs", &self.scaled_configs.keys().collect::<Vec<_>>())
            .finish()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Converts 16-bit registers to bytes (big-endian).
#[inline]
pub fn registers_to_bytes(registers: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(registers.len() * 2);
    for reg in registers {
        bytes.push((reg >> 8) as u8);
        bytes.push((reg & 0xFF) as u8);
    }
    bytes
}

/// Converts bytes to 16-bit registers (big-endian).
#[inline]
pub fn bytes_to_registers(bytes: &[u8]) -> Vec<u16> {
    let mut registers = Vec::with_capacity((bytes.len() + 1) / 2);
    for chunk in bytes.chunks(2) {
        let hi = chunk.first().copied().unwrap_or(0);
        let lo = chunk.get(1).copied().unwrap_or(0);
        registers.push(((hi as u16) << 8) | (lo as u16));
    }
    registers
}

/// Extracts a single bit from a register value.
#[inline]
pub fn extract_bit(value: u16, position: u8) -> bool {
    if position >= 16 {
        return false;
    }
    (value >> position) & 1 == 1
}

/// Sets a single bit in a register value.
#[inline]
pub fn set_bit(value: u16, position: u8, bit_value: bool) -> u16 {
    if position >= 16 {
        return value;
    }
    if bit_value {
        value | (1 << position)
    } else {
        value & !(1 << position)
    }
}

/// Extracts multiple bits from a register value.
#[inline]
pub fn extract_bits(value: u16, start: u8, count: u8) -> u16 {
    if start >= 16 || count == 0 {
        return 0;
    }
    let mask = ((1u32 << count) - 1) as u16;
    (value >> start) & mask
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_converter() {
        let converter = BoolConverter;
        let context = ConversionContext::default();

        assert!(converter.decode(&[1], &context).unwrap());
        assert!(!converter.decode(&[0], &context).unwrap());

        assert_eq!(converter.encode(&true, &context).unwrap(), vec![1]);
        assert_eq!(converter.encode(&false, &context).unwrap(), vec![0]);
    }

    #[test]
    fn test_numeric_converters() {
        let context = ConversionContext::default();

        // i16
        let i16_conv = NumericConverter::<i16>::new();
        let bytes = [0xFF, 0xFE]; // -2 in big-endian
        assert_eq!(i16_conv.decode(&bytes, &context).unwrap(), -2i16);

        let encoded = i16_conv.encode(&-2i16, &context).unwrap();
        assert_eq!(encoded, vec![0xFF, 0xFE]);

        // f32
        let f32_conv = NumericConverter::<f32>::new();
        let bytes = [0x42, 0x48, 0x00, 0x00]; // 50.0 in IEEE 754
        let value = f32_conv.decode(&bytes, &context).unwrap();
        assert!((value - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_byte_order() {
        let f32_conv = NumericConverter::<f32>::new();

        // Big-endian (default)
        let be_context = ConversionContext::new().with_byte_order(ByteOrder::BigEndian);
        let be_bytes = [0x42, 0x48, 0x00, 0x00];
        let value = f32_conv.decode(&be_bytes, &be_context).unwrap();
        assert!((value - 50.0).abs() < 0.001);

        // Little-endian
        let le_context = ConversionContext::new().with_byte_order(ByteOrder::LittleEndian);
        let le_bytes = [0x00, 0x00, 0x48, 0x42];
        let value = f32_conv.decode(&le_bytes, &le_context).unwrap();
        assert!((value - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_scaling() {
        let context = ConversionContext::new()
            .with_scale(0.1)
            .with_offset(10.0);

        // 100 * 0.1 + 10 = 20
        assert!((context.apply_scale(100.0) - 20.0).abs() < 0.001);

        // (20 - 10) / 0.1 = 100
        assert!((context.apply_inverse_scale(20.0).unwrap() - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_range_validation() {
        let context = ConversionContext::new().with_range(0.0, 100.0);

        assert!(context.validate_range(50.0).is_ok());
        assert!(context.validate_range(-1.0).is_err());
        assert!(context.validate_range(101.0).is_err());
    }

    #[test]
    fn test_string_converter() {
        let converter = StringConverter::new(10);
        let context = ConversionContext::default();

        let bytes = b"Hello\0\0\0\0\0";
        assert_eq!(converter.decode(bytes, &context).unwrap(), "Hello");

        let encoded = converter.encode(&"Hi".to_string(), &context).unwrap();
        assert_eq!(encoded.len(), 10);
        assert_eq!(&encoded[0..2], b"Hi");
    }

    #[test]
    fn test_registry() {
        let registry = ConverterRegistry::new();
        let context = ConversionContext::default();

        let bytes = [0x00, 0x64]; // 100 in big-endian
        let value = registry.decode_u16(&bytes, &context).unwrap();
        assert_eq!(value, 100);

        let encoded = registry.encode_u16(100, &context).unwrap();
        assert_eq!(encoded, vec![0x00, 0x64]);
    }

    #[test]
    fn test_registry_scaled() {
        let mut registry = ConverterRegistry::new();
        registry.register_scaled("temperature", 0.1, -40.0);

        let context = ConversionContext::default();
        let bytes = [0x01, 0x90]; // 400 in big-endian

        // 400 * 0.1 - 40 = 0.0
        let value = registry.decode_scaled_u16("temperature", &bytes, &context).unwrap();
        assert!((value - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_helper_functions() {
        let registers = vec![0x1234, 0x5678];
        let bytes = registers_to_bytes(&registers);
        assert_eq!(bytes, vec![0x12, 0x34, 0x56, 0x78]);

        let back = bytes_to_registers(&bytes);
        assert_eq!(back, registers);

        assert!(extract_bit(0b0001, 0));
        assert!(!extract_bit(0b0001, 1));
        assert_eq!(set_bit(0, 0, true), 1);
        assert_eq!(extract_bits(0xF0, 4, 4), 0x0F);
    }

    #[test]
    fn test_composite_converter() {
        let converter = CompositeConverter::builder()
            .field::<u16, _>("id", NumericConverter::<u16>::new())
            .field::<f32, _>("value", NumericConverter::<f32>::new())
            .build();

        let context = ConversionContext::default();

        // ID = 1, Value = 50.0
        let bytes = [0x00, 0x01, 0x42, 0x48, 0x00, 0x00];
        let result = converter.decode(&bytes, &context).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "id");
        assert_eq!(result[1].0, "value");

        if let Value::UInt16(id) = &result[0].1 {
            assert_eq!(*id, 1);
        } else {
            panic!("Expected UInt16");
        }

        if let Value::Float32(val) = &result[1].1 {
            assert!((*val - 50.0).abs() < 0.001);
        } else {
            panic!("Expected Float32");
        }
    }
}
