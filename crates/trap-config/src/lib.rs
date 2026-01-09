// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # trap-config
//!
//! Configuration management for TRAP industrial protocol gateway.
//!
//! This crate provides comprehensive configuration handling for TRAP,
//! including schema definitions, validation, parsing, encryption utilities,
//! and protocol address parsing.
//!
//! ## Features
//!
//! - **Schema Definition**: Complete configuration schema with validation
//! - **Multi-Format Support**: YAML, TOML, and JSON configuration files
//! - **Environment Overrides**: Override config values via environment variables
//! - **Address Parsing**: Parse protocol-specific addresses (Modbus, OPC UA, BACnet, KNX)
//! - **Encryption**: AES-256-GCM encryption for sensitive configuration values
//! - **Hot Reload**: Configuration file watching and reloading
//!
//! ## Quick Start
//!
//! ```no_run
//! use trap_config::loader::load_config;
//!
//! // Load configuration from file
//! let config = load_config("trap.yaml").unwrap();
//!
//! println!("Gateway ID: {}", config.gateway.id);
//! println!("Devices: {}", config.devices.len());
//! ```
//!
//! ## Configuration Schema
//!
//! The configuration is organized into the following sections:
//!
//! - `gateway` - Gateway identification and metadata
//! - `devices` - Device and tag configurations
//! - `buffer` - Offline buffer settings
//! - `api` - REST API server settings
//! - `security` - JWT, TLS, rate limiting, and audit
//! - `logging` - Logging configuration
//!
//! ## Address Parsing
//!
//! The address parser supports multiple protocol formats:
//!
//! ```
//! use trap_config::parser::UnifiedAddressParser;
//!
//! let parser = UnifiedAddressParser::new();
//!
//! // Modbus
//! let addr = parser.parse("HR:100").unwrap();
//! assert!(addr.is_modbus());
//!
//! // OPC UA
//! let addr = parser.parse("ns=2;s=Temperature").unwrap();
//! assert!(addr.is_opcua());
//!
//! // BACnet
//! let addr = parser.parse("AI:0").unwrap();
//! assert!(addr.is_bacnet());
//!
//! // KNX
//! let addr = parser.parse("1/2/3").unwrap();
//! assert!(addr.is_knx());
//! ```
//!
//! ## Encryption
//!
//! Sensitive values can be encrypted using AES-256-GCM:
//!
//! ```ignore
//! use trap_config::encryption::{Encryptor, generate_key};
//!
//! let key = generate_key();
//! let encryptor = Encryptor::new(key);
//!
//! // Encrypt a secret
//! let encrypted = encryptor.encrypt_with_prefix("my-secret").unwrap();
//! // Result: "ENC:base64-encoded-ciphertext"
//! ```
//!
//! In configuration files:
//!
//! ```yaml
//! security:
//!   jwt:
//!     secret: "ENC:base64-encoded-encrypted-secret"
//! ```
//!
//! ## Feature Flags
//!
//! - `encryption` - Enable AES-256-GCM encryption for sensitive values
//!
//! ## Environment Variables
//!
//! Configuration values can be overridden via environment variables:
//!
//! ```text
//! TRAP_GATEWAY_ID=my-gateway
//! TRAP_API_PORT=9090
//! TRAP_DEVICES_0_ENABLED=false
//! TRAP_LOG_LEVEL=debug
//! ```
//!
//! Values in config files can reference environment variables:
//!
//! ```yaml
//! gateway:
//!   id: "${GATEWAY_ID:default-gateway}"
//! ```

#![warn(missing_docs)]
#![deny(unsafe_code)]

// =============================================================================
// Modules
// =============================================================================

pub mod error;
pub mod schema;
pub mod parser;
pub mod loader;
pub mod encryption;

// =============================================================================
// Re-exports
// =============================================================================

pub use error::{ConfigError, ConfigResult};
pub use schema::{
    // Top-level config
    TrapConfig,
    GatewayConfig,
    DeviceConfig,
    TagConfig,
    // Protocol configs
    ProtocolConfig,
    ModbusTcpConfig,
    ModbusRtuConfig,
    OpcUaConfig,
    BacNetIpConfig,
    KnxConfig,
    // Protocol enums
    Parity,
    SecurityPolicy,
    SecurityMode,
    KnxConnectionType,
    DataType,
    // Buffer config
    BufferConfig,
    FlushConfig,
    CircuitBreakerConfig,
    // API config
    ApiConfig,
    CorsConfig,
    // Security config
    SecurityConfig,
    JwtConfig,
    JwtAlgorithm,
    TlsConfig,
    TlsVersion,
    RateLimitConfig,
    AuditConfig,
    AuditRotation,
    AuditEvent,
    // Logging config
    LoggingConfig,
    LogLevel,
    LogFormat,
    // Secret value
    SecretValue,
};

pub use parser::{
    AddressParser,
    UnifiedAddressParser,
    ProtocolHint,
    ModbusAddressParser,
    OpcUaAddressParser,
    BacNetAddressParser,
    KnxAddressParser,
    GenericAddressParser,
};

pub use loader::{
    ConfigLoader,
    ConfigLoaderBuilder,
    ConfigFormat,
    ConfigMerger,
    ConfigWatcher,
    load_config,
    load_config_str,
};

pub use encryption::{
    ENCRYPTED_PREFIX,
    KEY_LENGTH,
    NONCE_LENGTH,
    TAG_LENGTH,
    is_encrypted,
    get_encrypted_payload,
    encode_base64,
    decode_base64,
};

#[cfg(feature = "encryption")]
pub use encryption::{
    Encryptor,
    generate_key,
    generate_key_base64,
};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name
pub const NAME: &str = env!("CARGO_PKG_NAME");

// =============================================================================
// Prelude
// =============================================================================

/// Convenience re-exports for common use cases.
pub mod prelude {
    pub use crate::error::{ConfigError, ConfigResult};
    pub use crate::schema::{
        TrapConfig, DeviceConfig, TagConfig, ProtocolConfig, DataType, SecretValue,
    };
    pub use crate::loader::{ConfigLoader, load_config};
    pub use crate::parser::UnifiedAddressParser;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_name() {
        assert_eq!(NAME, "trap-config");
    }

    #[test]
    fn test_prelude_imports() {
        use prelude::*;
        let _config = TrapConfig::default();
    }
}
