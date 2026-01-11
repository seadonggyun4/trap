// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA Variant ↔ trap_core::Value conversion system.
//!
//! This module provides a flexible, extensible conversion system for transforming
//! OPC UA Variant types to trap_core::Value and vice versa.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   VariantConverterRegistry                      │
//! │              (Central registry for converters)                  │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    VariantConverter trait                       │
//! │              (Core conversion abstraction)                      │
//! └─────────────────────────────────────────────────────────────────┘
//!            │                 │                 │
//!            ▼                 ▼                 ▼
//! ┌───────────────┐ ┌───────────────┐ ┌───────────────────────────┐
//! │  Primitives   │ │   Complex     │ │     Custom                │
//! │ (Bool, Int)   │ │ (Array, Guid) │ │  (User-defined)           │
//! └───────────────┘ └───────────────┘ └───────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Type Safety**: Strong typing with compile-time checks
//! - **Extensibility**: Easy to add custom converters via trait implementation
//! - **Bidirectional**: Supports both OpcUaValue → Value and Value → OpcUaValue
//! - **Quality Mapping**: OPC UA status codes ↔ trap_core::DataQuality
//! - **Scaling**: Linear transformation support for numeric values
//!
//! # Examples
//!
//! ```rust,ignore
//! use trap_opcua::client::conversion::{
//!     VariantConverterRegistry, ConversionOptions, TypedValue
//! };
//!
//! let registry = VariantConverterRegistry::default();
//!
//! // Convert OPC UA value to core value
//! let opc_value = OpcUaValue::Double(25.5);
//! let typed = TypedValue::new(opc_value);
//! let core_value = registry.to_core_value(&typed, &ConversionOptions::default())?;
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::error::{ConversionError, OpcUaError, OpcUaResult};
use crate::types::{OpcUaDataType, TagMapping};

use super::transport::OpcUaValue;

// =============================================================================
// ConversionOptions
// =============================================================================

/// Options for controlling value conversion behavior.
///
/// These options affect how values are transformed during conversion,
/// including scaling, type coercion, and validation.
#[derive(Debug, Clone)]
pub struct ConversionOptions {
    /// Scale factor for numeric values (applied as: raw * scale + offset).
    pub scale: f64,

    /// Offset for numeric values (applied as: raw * scale + offset).
    pub offset: f64,

    /// Whether to clamp values to type bounds instead of failing.
    pub clamp_values: bool,

    /// Whether to allow lossy numeric conversions.
    pub allow_lossy: bool,

    /// Whether to convert null to default values.
    pub null_to_default: bool,

    /// String length limit (0 = unlimited).
    pub max_string_length: usize,

    /// Custom metadata for converter-specific options.
    pub metadata: HashMap<String, String>,
}

impl Default for ConversionOptions {
    fn default() -> Self {
        Self {
            scale: 1.0,
            offset: 0.0,
            clamp_values: false,
            allow_lossy: false,
            null_to_default: false,
            max_string_length: 0,
            metadata: HashMap::new(),
        }
    }
}

impl ConversionOptions {
    /// Creates new conversion options with default settings.
    pub fn new() -> Self {
        Self::default()
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

    /// Enables value clamping.
    #[inline]
    pub fn with_clamping(mut self, clamp: bool) -> Self {
        self.clamp_values = clamp;
        self
    }

    /// Enables lossy conversions.
    #[inline]
    pub fn with_lossy(mut self, allow: bool) -> Self {
        self.allow_lossy = allow;
        self
    }

    /// Enables null to default conversion.
    #[inline]
    pub fn with_null_to_default(mut self, enable: bool) -> Self {
        self.null_to_default = enable;
        self
    }

    /// Sets maximum string length.
    #[inline]
    pub fn with_max_string_length(mut self, length: usize) -> Self {
        self.max_string_length = length;
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

    /// Applies scaling to a value.
    #[inline]
    pub fn apply_scale(&self, value: f64) -> f64 {
        value * self.scale + self.offset
    }

    /// Applies inverse scaling (for encoding).
    #[inline]
    pub fn apply_inverse_scale(&self, value: f64) -> OpcUaResult<f64> {
        if self.scale.abs() < f64::EPSILON {
            return Err(OpcUaError::conversion(ConversionError::invalid_scale(
                "Scale factor cannot be zero",
            )));
        }
        Ok((value - self.offset) / self.scale)
    }

    /// Creates options from a TagMapping.
    pub fn from_tag_mapping(mapping: &TagMapping) -> Self {
        let mut opts = Self::default();
        if mapping.has_scaling() {
            opts.scale = mapping.effective_scale();
            opts.offset = mapping.effective_offset();
        }
        opts
    }
}

// =============================================================================
// TypedValue
// =============================================================================

/// A typed value for OPC UA data with metadata.
///
/// This type wraps an OPC UA value with additional metadata like
/// quality, timestamps, and scaling information.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedValue {
    /// The underlying value.
    pub value: OpcUaValue,

    /// Data quality (OPC UA status code).
    pub quality: Quality,

    /// Server timestamp.
    pub server_timestamp: Option<chrono::DateTime<chrono::Utc>>,

    /// Source timestamp.
    pub source_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

impl TypedValue {
    /// Creates a new typed value.
    pub fn new(value: OpcUaValue) -> Self {
        Self {
            value,
            quality: Quality::Good,
            server_timestamp: Some(chrono::Utc::now()),
            source_timestamp: None,
        }
    }

    /// Creates a typed value with quality.
    pub fn with_quality(value: OpcUaValue, quality: Quality) -> Self {
        Self {
            value,
            quality,
            server_timestamp: Some(chrono::Utc::now()),
            source_timestamp: None,
        }
    }

    /// Creates a typed value with full metadata.
    pub fn full(
        value: OpcUaValue,
        quality: Quality,
        server_timestamp: Option<chrono::DateTime<chrono::Utc>>,
        source_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        Self {
            value,
            quality,
            server_timestamp,
            source_timestamp,
        }
    }

    /// Creates a null typed value.
    pub fn null() -> Self {
        Self::new(OpcUaValue::Null)
    }

    /// Returns `true` if the value quality is good.
    #[inline]
    pub fn is_good(&self) -> bool {
        self.quality.is_good()
    }

    /// Returns `true` if the value is null.
    #[inline]
    pub fn is_null(&self) -> bool {
        self.value.is_null()
    }

    /// Returns the data type.
    pub fn data_type(&self) -> OpcUaDataType {
        self.value.data_type()
    }

    /// Attempts to get the value as a boolean.
    pub fn as_bool(&self) -> OpcUaResult<bool> {
        self.value.as_bool().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch(
                "Boolean",
                self.data_type().name(),
            ))
        })
    }

    /// Attempts to get the value as an i64.
    pub fn as_i64(&self) -> OpcUaResult<i64> {
        self.value.as_i64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch(
                "Integer",
                self.data_type().name(),
            ))
        })
    }

    /// Attempts to get the value as an f64.
    pub fn as_f64(&self) -> OpcUaResult<f64> {
        self.value.as_f64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch(
                "Float",
                self.data_type().name(),
            ))
        })
    }

    /// Attempts to get the value as a string.
    pub fn as_str(&self) -> OpcUaResult<&str> {
        self.value.as_str().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch(
                "String",
                self.data_type().name(),
            ))
        })
    }

    /// Converts to a trap_core Value.
    ///
    /// This is a convenience method that performs a simple conversion
    /// using default options.
    pub fn to_core_value(&self) -> trap_core::Value {
        match &self.value {
            OpcUaValue::Null => trap_core::Value::Null,
            OpcUaValue::Boolean(v) => trap_core::Value::Bool(*v),
            OpcUaValue::SByte(v) => trap_core::Value::Int8(*v),
            OpcUaValue::Byte(v) => trap_core::Value::UInt8(*v),
            OpcUaValue::Int16(v) => trap_core::Value::Int16(*v),
            OpcUaValue::UInt16(v) => trap_core::Value::UInt16(*v),
            OpcUaValue::Int32(v) => trap_core::Value::Int32(*v),
            OpcUaValue::UInt32(v) => trap_core::Value::UInt32(*v),
            OpcUaValue::Int64(v) => trap_core::Value::Int64(*v),
            OpcUaValue::UInt64(v) => trap_core::Value::UInt64(*v),
            OpcUaValue::Float(v) => trap_core::Value::Float32(*v),
            OpcUaValue::Double(v) => trap_core::Value::Float64(*v),
            OpcUaValue::String(v) => trap_core::Value::String(v.clone()),
            OpcUaValue::DateTime(v) => trap_core::Value::DateTime(*v),
            OpcUaValue::Guid(v) => trap_core::Value::String(v.to_string()),
            OpcUaValue::ByteString(v) => trap_core::Value::Bytes(v.clone()),
            OpcUaValue::Array(arr) => {
                let values: Vec<trap_core::Value> = arr
                    .iter()
                    .map(|item| TypedValue::new(item.clone()).to_core_value())
                    .collect();
                trap_core::Value::Array(values)
            }
        }
    }
}

impl Default for TypedValue {
    fn default() -> Self {
        Self::null()
    }
}

impl fmt::Display for TypedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self.value, self.quality)
    }
}

// =============================================================================
// Quality
// =============================================================================

/// OPC UA data quality indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Quality {
    /// Good quality - value is usable.
    #[default]
    Good,

    /// Good with local override.
    GoodLocalOverride,

    /// Uncertain quality - value may be usable.
    Uncertain,

    /// Uncertain with last usable value.
    UncertainLastUsable,

    /// Uncertain with sensor not accurate.
    UncertainSensorNotAccurate,

    /// Bad quality - value should not be used.
    Bad,

    /// Bad with communication failure.
    BadCommFailure,

    /// Bad with sensor failure.
    BadSensorFailure,

    /// Bad with out of service.
    BadOutOfService,

    /// Bad with configuration error.
    BadConfigError,
}

impl Quality {
    /// Creates quality from OPC UA status code.
    pub fn from_status_code(status_code: u32) -> Self {
        if status_code == 0 {
            return Self::Good;
        }

        // Check if bad (high bit set)
        if status_code & 0x80000000 != 0 {
            match status_code {
                0x800A0000 => Self::BadCommFailure,
                0x800B0000 => Self::BadSensorFailure,
                0x800D0000 => Self::BadOutOfService,
                0x80430000 => Self::BadConfigError,
                _ => Self::Bad,
            }
        }
        // Check if uncertain
        else if status_code & 0x40000000 != 0 {
            match status_code {
                0x40A50000 => Self::UncertainLastUsable,
                0x40A70000 => Self::UncertainSensorNotAccurate,
                _ => Self::Uncertain,
            }
        }
        // Good variants
        else {
            match status_code {
                0x00D00000 => Self::GoodLocalOverride,
                _ => Self::Good,
            }
        }
    }

    /// Converts to OPC UA status code.
    pub fn to_status_code(&self) -> u32 {
        match self {
            Self::Good => 0,
            Self::GoodLocalOverride => 0x00D00000,
            Self::Uncertain => 0x40000000,
            Self::UncertainLastUsable => 0x40A50000,
            Self::UncertainSensorNotAccurate => 0x40A70000,
            Self::Bad => 0x80000000,
            Self::BadCommFailure => 0x800A0000,
            Self::BadSensorFailure => 0x800B0000,
            Self::BadOutOfService => 0x800D0000,
            Self::BadConfigError => 0x80430000,
        }
    }

    /// Converts to trap_core::DataQuality.
    pub fn to_core_quality(&self) -> trap_core::types::DataQuality {
        match self {
            Self::Good | Self::GoodLocalOverride => trap_core::types::DataQuality::Good,
            Self::Uncertain => {
                trap_core::types::DataQuality::Uncertain(trap_core::types::UncertainReason::Unknown)
            }
            Self::UncertainLastUsable => trap_core::types::DataQuality::Uncertain(
                trap_core::types::UncertainReason::LastKnownValue,
            ),
            Self::UncertainSensorNotAccurate => trap_core::types::DataQuality::Uncertain(
                trap_core::types::UncertainReason::SensorCalibration,
            ),
            Self::Bad => {
                trap_core::types::DataQuality::Bad(trap_core::types::BadReason::Unknown)
            }
            Self::BadCommFailure => trap_core::types::DataQuality::Bad(
                trap_core::types::BadReason::CommunicationFailure,
            ),
            Self::BadSensorFailure => {
                trap_core::types::DataQuality::Bad(trap_core::types::BadReason::SensorFailure)
            }
            Self::BadOutOfService => {
                trap_core::types::DataQuality::Bad(trap_core::types::BadReason::NotConnected)
            }
            Self::BadConfigError => trap_core::types::DataQuality::Bad(
                trap_core::types::BadReason::ConfigurationError,
            ),
        }
    }

    /// Creates from trap_core::DataQuality.
    pub fn from_core_quality(quality: &trap_core::types::DataQuality) -> Self {
        match quality {
            trap_core::types::DataQuality::Good => Self::Good,
            trap_core::types::DataQuality::Uncertain(reason) => match reason {
                trap_core::types::UncertainReason::LastKnownValue => Self::UncertainLastUsable,
                trap_core::types::UncertainReason::SensorCalibration => {
                    Self::UncertainSensorNotAccurate
                }
                _ => Self::Uncertain,
            },
            trap_core::types::DataQuality::Bad(reason) => match reason {
                trap_core::types::BadReason::CommunicationFailure => Self::BadCommFailure,
                trap_core::types::BadReason::SensorFailure => Self::BadSensorFailure,
                trap_core::types::BadReason::NotConnected => Self::BadOutOfService,
                trap_core::types::BadReason::ConfigurationError => Self::BadConfigError,
                _ => Self::Bad,
            },
        }
    }

    /// Returns `true` if the quality is good.
    #[inline]
    pub fn is_good(&self) -> bool {
        matches!(self, Self::Good | Self::GoodLocalOverride)
    }

    /// Returns `true` if the quality is uncertain.
    #[inline]
    pub fn is_uncertain(&self) -> bool {
        matches!(
            self,
            Self::Uncertain | Self::UncertainLastUsable | Self::UncertainSensorNotAccurate
        )
    }

    /// Returns `true` if the quality is bad.
    #[inline]
    pub fn is_bad(&self) -> bool {
        matches!(
            self,
            Self::Bad
                | Self::BadCommFailure
                | Self::BadSensorFailure
                | Self::BadOutOfService
                | Self::BadConfigError
        )
    }

    /// Returns `true` if the value is usable (good or uncertain).
    #[inline]
    pub fn is_usable(&self) -> bool {
        !self.is_bad()
    }
}

impl fmt::Display for Quality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Good => write!(f, "Good"),
            Self::GoodLocalOverride => write!(f, "Good (Local Override)"),
            Self::Uncertain => write!(f, "Uncertain"),
            Self::UncertainLastUsable => write!(f, "Uncertain (Last Usable)"),
            Self::UncertainSensorNotAccurate => write!(f, "Uncertain (Sensor Not Accurate)"),
            Self::Bad => write!(f, "Bad"),
            Self::BadCommFailure => write!(f, "Bad (Communication Failure)"),
            Self::BadSensorFailure => write!(f, "Bad (Sensor Failure)"),
            Self::BadOutOfService => write!(f, "Bad (Out of Service)"),
            Self::BadConfigError => write!(f, "Bad (Configuration Error)"),
        }
    }
}

// =============================================================================
// VariantConverter Trait
// =============================================================================

/// Core trait for converting between OPC UA values and trap_core values.
///
/// Implementors of this trait handle conversion for specific OPC UA data types.
/// The trait supports both directions: OpcUaValue → trap_core::Value and vice versa.
///
/// # Implementation Guidelines
///
/// - `to_core_value` should preserve data fidelity where possible
/// - `from_core_value` may need to handle type coercion
/// - Both methods should respect ConversionOptions settings
/// - Return appropriate errors for invalid conversions
///
/// # Examples
///
/// ```rust,ignore
/// struct CustomConverter;
///
/// impl VariantConverter for CustomConverter {
///     fn supported_types(&self) -> &[OpcUaDataType] {
///         &[OpcUaDataType::Double]
///     }
///
///     fn to_core_value(
///         &self,
///         value: &OpcUaValue,
///         options: &ConversionOptions,
///     ) -> OpcUaResult<trap_core::Value> {
///         match value {
///             OpcUaValue::Double(v) => {
///                 let scaled = options.apply_scale(*v);
///                 Ok(trap_core::Value::Float64(scaled))
///             }
///             _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
///                 "Double", value.data_type().name()
///             )))
///         }
///     }
///
///     fn from_core_value(
///         &self,
///         value: &trap_core::Value,
///         _target_type: OpcUaDataType,
///         options: &ConversionOptions,
///     ) -> OpcUaResult<OpcUaValue> {
///         let f = value.as_f64().ok_or_else(|| {
///             OpcUaError::conversion(ConversionError::type_mismatch(
///                 "Float64", value.type_name()
///             ))
///         })?;
///         let unscaled = options.apply_inverse_scale(f)?;
///         Ok(OpcUaValue::Double(unscaled))
///     }
/// }
/// ```
pub trait VariantConverter: Send + Sync {
    /// Returns the OPC UA data types this converter handles.
    fn supported_types(&self) -> &[OpcUaDataType];

    /// Converts an OPC UA value to a trap_core value.
    ///
    /// # Arguments
    ///
    /// * `value` - The OPC UA value to convert
    /// * `options` - Conversion options (scaling, clamping, etc.)
    ///
    /// # Returns
    ///
    /// The converted trap_core::Value or an error.
    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value>;

    /// Converts a trap_core value to an OPC UA value.
    ///
    /// # Arguments
    ///
    /// * `value` - The trap_core value to convert
    /// * `target_type` - The desired OPC UA data type
    /// * `options` - Conversion options (scaling, clamping, etc.)
    ///
    /// # Returns
    ///
    /// The converted OpcUaValue or an error.
    fn from_core_value(
        &self,
        value: &trap_core::Value,
        target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue>;

    /// Returns the converter name for logging/debugging.
    fn name(&self) -> &'static str;

    /// Returns the priority of this converter (higher = preferred).
    ///
    /// When multiple converters can handle a type, the one with
    /// highest priority is used.
    fn priority(&self) -> i32 {
        0
    }
}

// =============================================================================
// Primitive Type Converters
// =============================================================================

/// Converter for boolean values.
#[derive(Debug, Clone, Default)]
pub struct BooleanConverter;

impl VariantConverter for BooleanConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Boolean]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        _options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Boolean(v) => Ok(trap_core::Value::Bool(*v)),
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Boolean",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        _options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        match value {
            trap_core::Value::Bool(v) => Ok(OpcUaValue::Boolean(*v)),
            // Numeric to bool conversion
            v if v.is_numeric() => {
                let n = v.as_i64().unwrap_or(0);
                Ok(OpcUaValue::Boolean(n != 0))
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Bool",
                value.type_name(),
            ))),
        }
    }

    fn name(&self) -> &'static str {
        "BooleanConverter"
    }
}

/// Converter for signed byte (SByte/Int8) values.
#[derive(Debug, Clone, Default)]
pub struct SByteConverter;

impl VariantConverter for SByteConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::SByte]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::SByte(v) => {
                if options.has_scaling() {
                    Ok(trap_core::Value::Float64(options.apply_scale(*v as f64)))
                } else {
                    Ok(trap_core::Value::Int8(*v))
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "SByte",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_i64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch("Integer", value.type_name()))
        })?;

        let v = if options.has_scaling() {
            options.apply_inverse_scale(v as f64)? as i64
        } else {
            v
        };

        if options.clamp_values {
            Ok(OpcUaValue::SByte(v.clamp(i8::MIN as i64, i8::MAX as i64) as i8))
        } else if v < i8::MIN as i64 || v > i8::MAX as i64 {
            Err(OpcUaError::conversion(ConversionError::value_out_of_range(
                v,
                i8::MIN as i64,
                i8::MAX as i64,
            )))
        } else {
            Ok(OpcUaValue::SByte(v as i8))
        }
    }

    fn name(&self) -> &'static str {
        "SByteConverter"
    }
}

/// Converter for unsigned byte (Byte/UInt8) values.
#[derive(Debug, Clone, Default)]
pub struct ByteConverter;

impl VariantConverter for ByteConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Byte]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Byte(v) => {
                if options.has_scaling() {
                    Ok(trap_core::Value::Float64(options.apply_scale(*v as f64)))
                } else {
                    Ok(trap_core::Value::UInt8(*v))
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Byte",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_u64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch(
                "Unsigned Integer",
                value.type_name(),
            ))
        })?;

        let v = if options.has_scaling() {
            options.apply_inverse_scale(v as f64)? as u64
        } else {
            v
        };

        if options.clamp_values {
            Ok(OpcUaValue::Byte(v.min(u8::MAX as u64) as u8))
        } else if v > u8::MAX as u64 {
            Err(OpcUaError::conversion(ConversionError::value_out_of_range(
                v as i64,
                0,
                u8::MAX as i64,
            )))
        } else {
            Ok(OpcUaValue::Byte(v as u8))
        }
    }

    fn name(&self) -> &'static str {
        "ByteConverter"
    }
}

/// Converter for Int16 values.
#[derive(Debug, Clone, Default)]
pub struct Int16Converter;

impl VariantConverter for Int16Converter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Int16]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Int16(v) => {
                if options.has_scaling() {
                    Ok(trap_core::Value::Float64(options.apply_scale(*v as f64)))
                } else {
                    Ok(trap_core::Value::Int16(*v))
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Int16",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_i64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch("Integer", value.type_name()))
        })?;

        let v = if options.has_scaling() {
            options.apply_inverse_scale(v as f64)? as i64
        } else {
            v
        };

        if options.clamp_values {
            Ok(OpcUaValue::Int16(
                v.clamp(i16::MIN as i64, i16::MAX as i64) as i16,
            ))
        } else if v < i16::MIN as i64 || v > i16::MAX as i64 {
            Err(OpcUaError::conversion(ConversionError::value_out_of_range(
                v,
                i16::MIN as i64,
                i16::MAX as i64,
            )))
        } else {
            Ok(OpcUaValue::Int16(v as i16))
        }
    }

    fn name(&self) -> &'static str {
        "Int16Converter"
    }
}

/// Converter for UInt16 values.
#[derive(Debug, Clone, Default)]
pub struct UInt16Converter;

impl VariantConverter for UInt16Converter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::UInt16]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::UInt16(v) => {
                if options.has_scaling() {
                    Ok(trap_core::Value::Float64(options.apply_scale(*v as f64)))
                } else {
                    Ok(trap_core::Value::UInt16(*v))
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "UInt16",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_u64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch(
                "Unsigned Integer",
                value.type_name(),
            ))
        })?;

        let v = if options.has_scaling() {
            options.apply_inverse_scale(v as f64)? as u64
        } else {
            v
        };

        if options.clamp_values {
            Ok(OpcUaValue::UInt16(v.min(u16::MAX as u64) as u16))
        } else if v > u16::MAX as u64 {
            Err(OpcUaError::conversion(ConversionError::value_out_of_range(
                v as i64,
                0,
                u16::MAX as i64,
            )))
        } else {
            Ok(OpcUaValue::UInt16(v as u16))
        }
    }

    fn name(&self) -> &'static str {
        "UInt16Converter"
    }
}

/// Converter for Int32 values.
#[derive(Debug, Clone, Default)]
pub struct Int32Converter;

impl VariantConverter for Int32Converter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Int32]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Int32(v) => {
                if options.has_scaling() {
                    Ok(trap_core::Value::Float64(options.apply_scale(*v as f64)))
                } else {
                    Ok(trap_core::Value::Int32(*v))
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Int32",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_i64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch("Integer", value.type_name()))
        })?;

        let v = if options.has_scaling() {
            options.apply_inverse_scale(v as f64)? as i64
        } else {
            v
        };

        if options.clamp_values {
            Ok(OpcUaValue::Int32(
                v.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
            ))
        } else if v < i32::MIN as i64 || v > i32::MAX as i64 {
            Err(OpcUaError::conversion(ConversionError::value_out_of_range(
                v,
                i32::MIN as i64,
                i32::MAX as i64,
            )))
        } else {
            Ok(OpcUaValue::Int32(v as i32))
        }
    }

    fn name(&self) -> &'static str {
        "Int32Converter"
    }
}

/// Converter for UInt32 values.
#[derive(Debug, Clone, Default)]
pub struct UInt32Converter;

impl VariantConverter for UInt32Converter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::UInt32]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::UInt32(v) => {
                if options.has_scaling() {
                    Ok(trap_core::Value::Float64(options.apply_scale(*v as f64)))
                } else {
                    Ok(trap_core::Value::UInt32(*v))
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "UInt32",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_u64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch(
                "Unsigned Integer",
                value.type_name(),
            ))
        })?;

        let v = if options.has_scaling() {
            options.apply_inverse_scale(v as f64)? as u64
        } else {
            v
        };

        if options.clamp_values {
            Ok(OpcUaValue::UInt32(v.min(u32::MAX as u64) as u32))
        } else if v > u32::MAX as u64 {
            Err(OpcUaError::conversion(ConversionError::value_out_of_range(
                v as i64,
                0,
                u32::MAX as i64,
            )))
        } else {
            Ok(OpcUaValue::UInt32(v as u32))
        }
    }

    fn name(&self) -> &'static str {
        "UInt32Converter"
    }
}

/// Converter for Int64 values.
#[derive(Debug, Clone, Default)]
pub struct Int64Converter;

impl VariantConverter for Int64Converter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Int64]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Int64(v) => {
                if options.has_scaling() {
                    Ok(trap_core::Value::Float64(options.apply_scale(*v as f64)))
                } else {
                    Ok(trap_core::Value::Int64(*v))
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Int64",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_i64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch("Integer", value.type_name()))
        })?;

        if options.has_scaling() {
            let scaled = options.apply_inverse_scale(v as f64)?;
            Ok(OpcUaValue::Int64(scaled as i64))
        } else {
            Ok(OpcUaValue::Int64(v))
        }
    }

    fn name(&self) -> &'static str {
        "Int64Converter"
    }
}

/// Converter for UInt64 values.
#[derive(Debug, Clone, Default)]
pub struct UInt64Converter;

impl VariantConverter for UInt64Converter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::UInt64]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::UInt64(v) => {
                if options.has_scaling() {
                    Ok(trap_core::Value::Float64(options.apply_scale(*v as f64)))
                } else {
                    Ok(trap_core::Value::UInt64(*v))
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "UInt64",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_u64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch(
                "Unsigned Integer",
                value.type_name(),
            ))
        })?;

        if options.has_scaling() {
            let scaled = options.apply_inverse_scale(v as f64)?;
            Ok(OpcUaValue::UInt64(scaled as u64))
        } else {
            Ok(OpcUaValue::UInt64(v))
        }
    }

    fn name(&self) -> &'static str {
        "UInt64Converter"
    }
}

/// Converter for Float (f32) values.
#[derive(Debug, Clone, Default)]
pub struct FloatConverter;

impl VariantConverter for FloatConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Float]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Float(v) => {
                if options.has_scaling() {
                    Ok(trap_core::Value::Float64(options.apply_scale(*v as f64)))
                } else {
                    Ok(trap_core::Value::Float32(*v))
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Float",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_f64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch("Float", value.type_name()))
        })?;

        let v = if options.has_scaling() {
            options.apply_inverse_scale(v)?
        } else {
            v
        };

        Ok(OpcUaValue::Float(v as f32))
    }

    fn name(&self) -> &'static str {
        "FloatConverter"
    }
}

/// Converter for Double (f64) values.
#[derive(Debug, Clone, Default)]
pub struct DoubleConverter;

impl VariantConverter for DoubleConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Double]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Double(v) => {
                let scaled = if options.has_scaling() {
                    options.apply_scale(*v)
                } else {
                    *v
                };
                Ok(trap_core::Value::Float64(scaled))
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Double",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        let v = value.as_f64().ok_or_else(|| {
            OpcUaError::conversion(ConversionError::type_mismatch("Float", value.type_name()))
        })?;

        let v = if options.has_scaling() {
            options.apply_inverse_scale(v)?
        } else {
            v
        };

        Ok(OpcUaValue::Double(v))
    }

    fn name(&self) -> &'static str {
        "DoubleConverter"
    }
}

// =============================================================================
// Complex Type Converters
// =============================================================================

/// Converter for String values.
#[derive(Debug, Clone, Default)]
pub struct StringConverter;

impl VariantConverter for StringConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::String, OpcUaDataType::LocalizedText]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::String(v) => {
                let s = if options.max_string_length > 0 && v.len() > options.max_string_length {
                    v[..options.max_string_length].to_string()
                } else {
                    v.clone()
                };
                Ok(trap_core::Value::String(s))
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "String",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        match value {
            trap_core::Value::String(v) => {
                let s = if options.max_string_length > 0 && v.len() > options.max_string_length {
                    v[..options.max_string_length].to_string()
                } else {
                    v.clone()
                };
                Ok(OpcUaValue::String(s))
            }
            // Convert other types to string
            v => Ok(OpcUaValue::String(v.to_string())),
        }
    }

    fn name(&self) -> &'static str {
        "StringConverter"
    }
}

/// Converter for DateTime values.
#[derive(Debug, Clone, Default)]
pub struct DateTimeConverter;

impl VariantConverter for DateTimeConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::DateTime]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        _options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::DateTime(v) => Ok(trap_core::Value::DateTime(*v)),
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "DateTime",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        _options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        match value {
            trap_core::Value::DateTime(v) => Ok(OpcUaValue::DateTime(*v)),
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "DateTime",
                value.type_name(),
            ))),
        }
    }

    fn name(&self) -> &'static str {
        "DateTimeConverter"
    }
}

/// Converter for GUID values.
#[derive(Debug, Clone, Default)]
pub struct GuidConverter;

impl VariantConverter for GuidConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Guid]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        _options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Guid(v) => Ok(trap_core::Value::String(v.to_string())),
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Guid",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        _options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        match value {
            trap_core::Value::String(v) => {
                let uuid = uuid::Uuid::parse_str(v).map_err(|e| {
                    OpcUaError::conversion(ConversionError::invalid_format(format!(
                        "Invalid GUID format: {}",
                        e
                    )))
                })?;
                Ok(OpcUaValue::Guid(uuid))
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "String (GUID)",
                value.type_name(),
            ))),
        }
    }

    fn name(&self) -> &'static str {
        "GuidConverter"
    }
}

/// Converter for ByteString values.
#[derive(Debug, Clone, Default)]
pub struct ByteStringConverter;

impl VariantConverter for ByteStringConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::ByteString]
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        _options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::ByteString(v) => Ok(trap_core::Value::Bytes(v.clone())),
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "ByteString",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        _options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        match value {
            trap_core::Value::Bytes(v) => Ok(OpcUaValue::ByteString(v.clone())),
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Bytes",
                value.type_name(),
            ))),
        }
    }

    fn name(&self) -> &'static str {
        "ByteStringConverter"
    }
}

/// Converter for Array values.
#[derive(Debug, Clone)]
pub struct ArrayConverter {
    /// Inner converter registry for element conversion.
    registry: Arc<VariantConverterRegistry>,
}

impl ArrayConverter {
    /// Creates a new array converter with the given registry.
    pub fn new(registry: Arc<VariantConverterRegistry>) -> Self {
        Self { registry }
    }
}

impl VariantConverter for ArrayConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Variant] // Arrays can contain any variant
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Array(elements) => {
                let converted: Result<Vec<_>, _> = elements
                    .iter()
                    .map(|elem| self.registry.to_core_value_direct(elem, options))
                    .collect();
                Ok(trap_core::Value::Array(converted?))
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Array",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        match value {
            trap_core::Value::Array(elements) => {
                let converted: Result<Vec<_>, _> = elements
                    .iter()
                    .map(|elem| self.registry.from_core_value_direct(elem, target_type, options))
                    .collect();
                Ok(OpcUaValue::Array(converted?))
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Array",
                value.type_name(),
            ))),
        }
    }

    fn name(&self) -> &'static str {
        "ArrayConverter"
    }

    fn priority(&self) -> i32 {
        -10 // Lower priority - use specific converters when possible
    }
}

/// Converter for Null values.
#[derive(Debug, Clone, Default)]
pub struct NullConverter;

impl VariantConverter for NullConverter {
    fn supported_types(&self) -> &[OpcUaDataType] {
        &[OpcUaDataType::Variant] // Null is a variant state
    }

    fn to_core_value(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Null => {
                if options.null_to_default {
                    Ok(trap_core::Value::Int32(0)) // Default numeric value
                } else {
                    Ok(trap_core::Value::Null)
                }
            }
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Null",
                value.data_type().name(),
            ))),
        }
    }

    fn from_core_value(
        &self,
        value: &trap_core::Value,
        _target_type: OpcUaDataType,
        _options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        match value {
            trap_core::Value::Null => Ok(OpcUaValue::Null),
            _ => Err(OpcUaError::conversion(ConversionError::type_mismatch(
                "Null",
                value.type_name(),
            ))),
        }
    }

    fn name(&self) -> &'static str {
        "NullConverter"
    }

    fn priority(&self) -> i32 {
        -100 // Lowest priority
    }
}

// =============================================================================
// VariantConverterRegistry
// =============================================================================

/// Registry for variant converters.
///
/// The registry manages a collection of converters and provides methods
/// to convert between OPC UA values and trap_core values.
///
/// # Example
///
/// ```rust,ignore
/// use trap_opcua::client::conversion::VariantConverterRegistry;
///
/// let registry = VariantConverterRegistry::default();
///
/// // Convert OPC UA Double to core Float64
/// let opc_value = OpcUaValue::Double(25.5);
/// let core_value = registry.to_core_value_direct(&opc_value, &ConversionOptions::default())?;
/// ```
pub struct VariantConverterRegistry {
    /// Converters indexed by supported data type.
    converters: HashMap<OpcUaDataType, Vec<Arc<dyn VariantConverter>>>,

    /// Default conversion options.
    default_options: ConversionOptions,
}

impl VariantConverterRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            converters: HashMap::new(),
            default_options: ConversionOptions::default(),
        }
    }

    /// Creates a registry with all built-in converters registered.
    pub fn with_builtin_converters() -> Self {
        let mut registry = Self::new();

        // Register primitive converters
        registry.register(Arc::new(BooleanConverter));
        registry.register(Arc::new(SByteConverter));
        registry.register(Arc::new(ByteConverter));
        registry.register(Arc::new(Int16Converter));
        registry.register(Arc::new(UInt16Converter));
        registry.register(Arc::new(Int32Converter));
        registry.register(Arc::new(UInt32Converter));
        registry.register(Arc::new(Int64Converter));
        registry.register(Arc::new(UInt64Converter));
        registry.register(Arc::new(FloatConverter));
        registry.register(Arc::new(DoubleConverter));

        // Register complex converters
        registry.register(Arc::new(StringConverter));
        registry.register(Arc::new(DateTimeConverter));
        registry.register(Arc::new(GuidConverter));
        registry.register(Arc::new(ByteStringConverter));
        registry.register(Arc::new(NullConverter));

        registry
    }

    /// Sets the default conversion options.
    pub fn with_default_options(mut self, options: ConversionOptions) -> Self {
        self.default_options = options;
        self
    }

    /// Registers a converter.
    ///
    /// The converter will be used for all data types it supports.
    /// Multiple converters can be registered for the same type;
    /// the one with highest priority will be used.
    pub fn register(&mut self, converter: Arc<dyn VariantConverter>) {
        for dtype in converter.supported_types() {
            let converters = self.converters.entry(*dtype).or_default();
            converters.push(converter.clone());
            // Sort by priority (highest first)
            converters.sort_by_key(|c| std::cmp::Reverse(c.priority()));
        }
    }

    /// Returns the converter for a given data type.
    pub fn get_converter(&self, dtype: OpcUaDataType) -> Option<&Arc<dyn VariantConverter>> {
        self.converters.get(&dtype).and_then(|v| v.first())
    }

    /// Converts an OPC UA value to a trap_core value.
    pub fn to_core_value_direct(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        let dtype = value.data_type();

        // Handle Null specially
        if value.is_null() {
            return if options.null_to_default {
                Ok(trap_core::Value::Int32(0))
            } else {
                Ok(trap_core::Value::Null)
            };
        }

        // Handle Array specially
        if matches!(value, OpcUaValue::Array(_)) {
            return self.convert_array_to_core(value, options);
        }

        let converter = self.get_converter(dtype).ok_or_else(|| {
            OpcUaError::conversion(ConversionError::unsupported_type(dtype.name()))
        })?;

        converter.to_core_value(value, options)
    }

    /// Converts a trap_core value to an OPC UA value.
    pub fn from_core_value_direct(
        &self,
        value: &trap_core::Value,
        target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<OpcUaValue> {
        // Handle Null
        if matches!(value, trap_core::Value::Null) {
            return Ok(OpcUaValue::Null);
        }

        let converter = self.get_converter(target_type).ok_or_else(|| {
            OpcUaError::conversion(ConversionError::unsupported_type(target_type.name()))
        })?;

        converter.from_core_value(value, target_type, options)
    }

    /// Converts a TypedValue to a trap_core value.
    pub fn to_core_value(
        &self,
        typed_value: &TypedValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        self.to_core_value_direct(&typed_value.value, options)
    }

    /// Converts a trap_core value to a TypedValue.
    pub fn from_core_value(
        &self,
        value: &trap_core::Value,
        target_type: OpcUaDataType,
        options: &ConversionOptions,
    ) -> OpcUaResult<TypedValue> {
        let opc_value = self.from_core_value_direct(value, target_type, options)?;
        Ok(TypedValue::new(opc_value))
    }

    /// Converts a TypedValue to a DataPoint.
    pub fn to_data_point(
        &self,
        typed_value: &TypedValue,
        device_id: trap_core::types::DeviceId,
        tag_id: trap_core::types::TagId,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::types::DataPoint> {
        let value = self.to_core_value(typed_value, options)?;
        let quality = typed_value.quality.to_core_quality();

        let mut point = trap_core::types::DataPoint::new(device_id, tag_id, value, quality);

        if let Some(ts) = typed_value.server_timestamp {
            point.timestamp = ts;
        }
        if let Some(source_ts) = typed_value.source_timestamp {
            point.source_timestamp = Some(source_ts);
        }

        Ok(point)
    }

    /// Helper to convert arrays.
    fn convert_array_to_core(
        &self,
        value: &OpcUaValue,
        options: &ConversionOptions,
    ) -> OpcUaResult<trap_core::Value> {
        match value {
            OpcUaValue::Array(elements) => {
                let converted: Result<Vec<_>, _> = elements
                    .iter()
                    .map(|elem| self.to_core_value_direct(elem, options))
                    .collect();
                Ok(trap_core::Value::Array(converted?))
            }
            _ => unreachable!(),
        }
    }

    /// Applies tag mapping scaling and converts.
    pub fn convert_with_mapping(
        &self,
        value: &TypedValue,
        mapping: &TagMapping,
    ) -> OpcUaResult<trap_core::Value> {
        let options = ConversionOptions::from_tag_mapping(mapping);
        self.to_core_value(value, &options)
    }
}

impl Default for VariantConverterRegistry {
    fn default() -> Self {
        Self::with_builtin_converters()
    }
}

impl fmt::Debug for VariantConverterRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VariantConverterRegistry")
            .field("converter_count", &self.converters.len())
            .field(
                "types",
                &self.converters.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

// =============================================================================
// DataConverter (Legacy compatibility wrapper)
// =============================================================================

/// Legacy data converter wrapper for backwards compatibility.
///
/// This type wraps the new VariantConverterRegistry to provide
/// the same API as the old DataConverter.
#[derive(Debug, Clone)]
pub struct DataConverter {
    /// Default scale factor.
    pub default_scale: f64,

    /// Default offset.
    pub default_offset: f64,

    /// Whether to clamp values to valid ranges.
    pub clamp_values: bool,

    /// Inner registry.
    registry: Arc<VariantConverterRegistry>,
}

impl DataConverter {
    /// Creates a new data converter with default settings.
    pub fn new() -> Self {
        Self {
            default_scale: 1.0,
            default_offset: 0.0,
            clamp_values: false,
            registry: Arc::new(VariantConverterRegistry::default()),
        }
    }

    /// Creates a converter with scaling parameters.
    pub fn with_scaling(scale: f64, offset: f64) -> Self {
        Self {
            default_scale: scale,
            default_offset: offset,
            clamp_values: false,
            registry: Arc::new(VariantConverterRegistry::default()),
        }
    }

    /// Sets whether to clamp values to valid ranges.
    pub fn with_clamping(mut self, clamp: bool) -> Self {
        self.clamp_values = clamp;
        self
    }

    /// Converts an OPC UA value to the target data type.
    pub fn convert(
        &self,
        value: &OpcUaValue,
        target_type: OpcUaDataType,
    ) -> OpcUaResult<OpcUaValue> {
        let options = ConversionOptions::new().with_clamping(self.clamp_values);

        // First convert to core, then back to target type
        let core_value = self.registry.to_core_value_direct(value, &options)?;
        self.registry
            .from_core_value_direct(&core_value, target_type, &options)
    }

    /// Converts with scaling applied.
    ///
    /// Scaling is applied during the to_core_value step (raw → scaled).
    /// The from_core_value step converts the already-scaled value without re-applying scaling.
    pub fn convert_scaled(
        &self,
        value: &OpcUaValue,
        target_type: OpcUaDataType,
        scale: f64,
        offset: f64,
    ) -> OpcUaResult<OpcUaValue> {
        let options_with_scaling = ConversionOptions::new()
            .with_scaling(scale, offset)
            .with_clamping(self.clamp_values);

        let options_no_scaling = ConversionOptions::new().with_clamping(self.clamp_values);

        // Apply scaling when converting to core value
        let core_value = self.registry.to_core_value_direct(value, &options_with_scaling)?;
        // Do NOT apply inverse scaling when converting back
        self.registry
            .from_core_value_direct(&core_value, target_type, &options_no_scaling)
    }

    /// Applies scaling from a tag mapping.
    pub fn apply_tag_scaling(&self, value: &TypedValue, mapping: &TagMapping) -> TypedValue {
        if !mapping.has_scaling() {
            return value.clone();
        }

        let options = ConversionOptions::from_tag_mapping(mapping);

        if let Some(raw) = value.value.as_f64() {
            let scaled = options.apply_scale(raw);
            TypedValue::with_quality(OpcUaValue::Double(scaled), value.quality)
        } else {
            value.clone()
        }
    }

    /// Applies inverse scaling for writes.
    pub fn apply_inverse_scaling(&self, value: f64, mapping: &TagMapping) -> f64 {
        if !mapping.has_scaling() {
            return value;
        }
        mapping.apply_inverse_scaling(value)
    }
}

impl Default for DataConverter {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TypedValue Tests
    // =========================================================================

    #[test]
    fn test_typed_value() {
        let value = TypedValue::new(OpcUaValue::Double(25.5));
        assert!(value.is_good());
        assert!(!value.is_null());
        assert_eq!(value.data_type(), OpcUaDataType::Double);
        assert!((value.as_f64().unwrap() - 25.5).abs() < 0.001);
    }

    #[test]
    fn test_typed_value_with_quality() {
        let value = TypedValue::with_quality(OpcUaValue::Int32(42), Quality::Uncertain);
        assert!(!value.is_good());
        assert!(value.quality.is_uncertain());
        assert_eq!(value.as_i64().unwrap(), 42);
    }

    // =========================================================================
    // Quality Tests
    // =========================================================================

    #[test]
    fn test_quality() {
        assert!(Quality::Good.is_good());
        assert!(Quality::GoodLocalOverride.is_good());
        assert!(Quality::Uncertain.is_uncertain());
        assert!(Quality::Bad.is_bad());
        assert!(Quality::BadCommFailure.is_bad());

        assert!(Quality::Good.is_usable());
        assert!(Quality::Uncertain.is_usable());
        assert!(!Quality::Bad.is_usable());
    }

    #[test]
    fn test_quality_status_code() {
        assert_eq!(Quality::from_status_code(0), Quality::Good);
        assert_eq!(Quality::from_status_code(0x80000000), Quality::Bad);
        assert_eq!(Quality::from_status_code(0x40000000), Quality::Uncertain);

        assert_eq!(Quality::Good.to_status_code(), 0);
        assert_eq!(Quality::Bad.to_status_code(), 0x80000000);
    }

    #[test]
    fn test_quality_core_conversion() {
        let quality = Quality::BadCommFailure;
        let core_quality = quality.to_core_quality();
        assert!(matches!(
            core_quality,
            trap_core::types::DataQuality::Bad(trap_core::types::BadReason::CommunicationFailure)
        ));

        let back = Quality::from_core_quality(&core_quality);
        assert_eq!(back, Quality::BadCommFailure);
    }

    // =========================================================================
    // ConversionOptions Tests
    // =========================================================================

    #[test]
    fn test_conversion_options() {
        let opts = ConversionOptions::new()
            .with_scaling(0.1, 10.0)
            .with_clamping(true);

        assert!(opts.has_scaling());
        assert!(opts.clamp_values);

        // 100 * 0.1 + 10 = 20
        assert!((opts.apply_scale(100.0) - 20.0).abs() < 0.001);

        // (20 - 10) / 0.1 = 100
        assert!((opts.apply_inverse_scale(20.0).unwrap() - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_conversion_options_zero_scale() {
        let opts = ConversionOptions::new().with_scale(0.0);
        assert!(opts.apply_inverse_scale(10.0).is_err());
    }

    // =========================================================================
    // Converter Tests
    // =========================================================================

    #[test]
    fn test_boolean_converter() {
        let converter = BooleanConverter;
        let options = ConversionOptions::default();

        let opc_value = OpcUaValue::Boolean(true);
        let core_value = converter.to_core_value(&opc_value, &options).unwrap();
        assert_eq!(core_value, trap_core::Value::Bool(true));

        let back = converter
            .from_core_value(&core_value, OpcUaDataType::Boolean, &options)
            .unwrap();
        assert_eq!(back, OpcUaValue::Boolean(true));
    }

    #[test]
    fn test_int32_converter() {
        let converter = Int32Converter;
        let options = ConversionOptions::default();

        let opc_value = OpcUaValue::Int32(42);
        let core_value = converter.to_core_value(&opc_value, &options).unwrap();
        assert_eq!(core_value, trap_core::Value::Int32(42));
    }

    #[test]
    fn test_int32_converter_with_scaling() {
        let converter = Int32Converter;
        let options = ConversionOptions::new().with_scaling(0.1, 10.0);

        let opc_value = OpcUaValue::Int32(100);
        let core_value = converter.to_core_value(&opc_value, &options).unwrap();

        // 100 * 0.1 + 10 = 20
        if let trap_core::Value::Float64(v) = core_value {
            assert!((v - 20.0).abs() < 0.001);
        } else {
            panic!("Expected Float64");
        }
    }

    #[test]
    fn test_double_converter() {
        let converter = DoubleConverter;
        let options = ConversionOptions::default();

        let opc_value = OpcUaValue::Double(25.5);
        let core_value = converter.to_core_value(&opc_value, &options).unwrap();
        assert_eq!(core_value, trap_core::Value::Float64(25.5));

        let back = converter
            .from_core_value(&core_value, OpcUaDataType::Double, &options)
            .unwrap();
        if let OpcUaValue::Double(v) = back {
            assert!((v - 25.5).abs() < 0.001);
        } else {
            panic!("Expected Double");
        }
    }

    #[test]
    fn test_string_converter() {
        let converter = StringConverter;
        let options = ConversionOptions::default();

        let opc_value = OpcUaValue::String("Hello".to_string());
        let core_value = converter.to_core_value(&opc_value, &options).unwrap();
        assert_eq!(core_value, trap_core::Value::String("Hello".to_string()));
    }

    #[test]
    fn test_string_converter_max_length() {
        let converter = StringConverter;
        let options = ConversionOptions::new().with_max_string_length(5);

        let opc_value = OpcUaValue::String("HelloWorld".to_string());
        let core_value = converter.to_core_value(&opc_value, &options).unwrap();
        assert_eq!(core_value, trap_core::Value::String("Hello".to_string()));
    }

    #[test]
    fn test_datetime_converter() {
        let converter = DateTimeConverter;
        let options = ConversionOptions::default();

        let now = chrono::Utc::now();
        let opc_value = OpcUaValue::DateTime(now);
        let core_value = converter.to_core_value(&opc_value, &options).unwrap();
        assert_eq!(core_value, trap_core::Value::DateTime(now));
    }

    // =========================================================================
    // Registry Tests
    // =========================================================================

    #[test]
    fn test_registry_default() {
        let registry = VariantConverterRegistry::default();

        // Boolean
        let bool_val = OpcUaValue::Boolean(true);
        let core = registry
            .to_core_value_direct(&bool_val, &ConversionOptions::default())
            .unwrap();
        assert_eq!(core, trap_core::Value::Bool(true));

        // Int32
        let int_val = OpcUaValue::Int32(42);
        let core = registry
            .to_core_value_direct(&int_val, &ConversionOptions::default())
            .unwrap();
        assert_eq!(core, trap_core::Value::Int32(42));

        // Double
        let double_val = OpcUaValue::Double(25.5);
        let core = registry
            .to_core_value_direct(&double_val, &ConversionOptions::default())
            .unwrap();
        assert_eq!(core, trap_core::Value::Float64(25.5));
    }

    #[test]
    fn test_registry_null() {
        let registry = VariantConverterRegistry::default();

        let null_val = OpcUaValue::Null;
        let core = registry
            .to_core_value_direct(&null_val, &ConversionOptions::default())
            .unwrap();
        assert_eq!(core, trap_core::Value::Null);

        // With null_to_default
        let opts = ConversionOptions::new().with_null_to_default(true);
        let core = registry.to_core_value_direct(&null_val, &opts).unwrap();
        assert_eq!(core, trap_core::Value::Int32(0));
    }

    #[test]
    fn test_registry_array() {
        let registry = VariantConverterRegistry::default();

        let array_val = OpcUaValue::Array(vec![
            OpcUaValue::Int32(1),
            OpcUaValue::Int32(2),
            OpcUaValue::Int32(3),
        ]);

        let core = registry
            .to_core_value_direct(&array_val, &ConversionOptions::default())
            .unwrap();

        if let trap_core::Value::Array(elements) = core {
            assert_eq!(elements.len(), 3);
            assert_eq!(elements[0], trap_core::Value::Int32(1));
            assert_eq!(elements[1], trap_core::Value::Int32(2));
            assert_eq!(elements[2], trap_core::Value::Int32(3));
        } else {
            panic!("Expected Array");
        }
    }

    #[test]
    fn test_registry_to_data_point() {
        let registry = VariantConverterRegistry::default();

        let typed = TypedValue::with_quality(OpcUaValue::Double(25.5), Quality::Good);

        let device_id = trap_core::types::DeviceId::new("device-1");
        let tag_id = trap_core::types::TagId::new("temperature");

        let point = registry
            .to_data_point(&typed, device_id, tag_id, &ConversionOptions::default())
            .unwrap();

        assert_eq!(point.device_id.as_str(), "device-1");
        assert_eq!(point.tag_id.as_str(), "temperature");
        assert_eq!(point.value, trap_core::Value::Float64(25.5));
        assert!(point.quality.is_good());
    }

    // =========================================================================
    // DataConverter (Legacy) Tests
    // =========================================================================

    #[test]
    fn test_data_converter() {
        let converter = DataConverter::new();

        // Boolean conversion
        let int_val = OpcUaValue::Int32(1);
        let bool_val = converter
            .convert(&int_val, OpcUaDataType::Boolean)
            .unwrap();
        assert_eq!(bool_val, OpcUaValue::Boolean(true));

        // Integer conversion
        let double_val = OpcUaValue::Double(42.5);
        let int_val = converter.convert(&double_val, OpcUaDataType::Int32).unwrap();
        assert_eq!(int_val, OpcUaValue::Int32(42));
    }

    #[test]
    fn test_scaled_conversion() {
        let converter = DataConverter::new();

        let raw = OpcUaValue::Int32(100);
        let scaled = converter
            .convert_scaled(&raw, OpcUaDataType::Double, 0.1, 10.0)
            .unwrap();

        if let OpcUaValue::Double(v) = scaled {
            assert!((v - 20.0).abs() < 0.001); // 100 * 0.1 + 10 = 20
        } else {
            panic!("Expected Double");
        }
    }

    #[test]
    fn test_clamping() {
        let converter = DataConverter::new().with_clamping(true);

        // Value too large for i8
        let large = OpcUaValue::Int64(1000);
        let clamped = converter.convert(&large, OpcUaDataType::SByte).unwrap();
        assert_eq!(clamped, OpcUaValue::SByte(127)); // Clamped to i8::MAX
    }

    #[test]
    fn test_typed_value_to_core() {
        let registry = VariantConverterRegistry::default();
        let typed = TypedValue::new(OpcUaValue::Int32(42));
        let core = registry
            .to_core_value(&typed, &ConversionOptions::default())
            .unwrap();
        assert_eq!(core, trap_core::Value::Int32(42));
    }
}
