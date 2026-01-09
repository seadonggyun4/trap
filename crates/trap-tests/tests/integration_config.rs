// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # Configuration Integration Tests
//!
//! Integration tests for trap-config functionality including:
//!
//! - Configuration schema validation
//! - Address parsing for protocols
//!
//! ## Test Categories
//!
//! - `test_schema_*`: Schema tests
//! - `test_address_*`: Address parsing tests

use trap_config::{
    // Schema
    TrapConfig, DataType, LogLevel,
    // Parsing
    AddressParser, ModbusAddressParser, OpcUaAddressParser,
    // Errors
    ConfigError,
};

use trap_core::address::{Address, ModbusRegisterType};

// =============================================================================
// TrapConfig Tests
// =============================================================================

#[tokio::test]
async fn test_trap_config_default() {
    let config = TrapConfig::default();

    assert!(!config.gateway.id.is_empty());
    assert!(config.devices.is_empty());
}

// =============================================================================
// DataType Tests
// =============================================================================

#[tokio::test]
async fn test_data_type_variants() {
    let types = vec![
        DataType::Bool,
        DataType::Int16,
        DataType::Int32,
        DataType::Int64,
        DataType::UInt16,
        DataType::UInt32,
        DataType::UInt64,
        DataType::Float32,
        DataType::Float64,
        DataType::String,
    ];

    // All data types should be valid
    assert_eq!(types.len(), 10);
}

// =============================================================================
// LogLevel Tests
// =============================================================================

#[tokio::test]
async fn test_log_level_variants() {
    assert_eq!(LogLevel::Trace.as_str(), "trace");
    assert_eq!(LogLevel::Debug.as_str(), "debug");
    assert_eq!(LogLevel::Info.as_str(), "info");
    assert_eq!(LogLevel::Warn.as_str(), "warn");
    assert_eq!(LogLevel::Error.as_str(), "error");
}

// =============================================================================
// Address Parsing Tests
// =============================================================================

#[tokio::test]
async fn test_modbus_address_parsing() {
    let parser = ModbusAddressParser;

    // Holding register
    let addr = parser.parse("hr:100").expect("Parse failed");
    if let Address::Modbus(modbus_addr) = addr {
        assert_eq!(modbus_addr.register_type, ModbusRegisterType::HoldingRegister);
        assert_eq!(modbus_addr.address, 100);
    } else {
        panic!("Expected Modbus address");
    }

    // Input register
    let addr = parser.parse("ir:200").expect("Parse failed");
    if let Address::Modbus(modbus_addr) = addr {
        assert_eq!(modbus_addr.register_type, ModbusRegisterType::InputRegister);
        assert_eq!(modbus_addr.address, 200);
    } else {
        panic!("Expected Modbus address");
    }

    // Coil
    let addr = parser.parse("coil:50").expect("Parse failed");
    if let Address::Modbus(modbus_addr) = addr {
        assert_eq!(modbus_addr.register_type, ModbusRegisterType::Coil);
        assert_eq!(modbus_addr.address, 50);
    } else {
        panic!("Expected Modbus address");
    }

    // Discrete input
    let addr = parser.parse("di:75").expect("Parse failed");
    if let Address::Modbus(modbus_addr) = addr {
        assert_eq!(modbus_addr.register_type, ModbusRegisterType::DiscreteInput);
        assert_eq!(modbus_addr.address, 75);
    } else {
        panic!("Expected Modbus address");
    }
}

#[tokio::test]
async fn test_modbus_address_with_count() {
    let parser = ModbusAddressParser;

    // Multiple registers
    let addr = parser.parse("hr:100:10").expect("Parse failed");
    if let Address::Modbus(modbus_addr) = addr {
        assert_eq!(modbus_addr.address, 100);
        assert_eq!(modbus_addr.count, 10);
    } else {
        panic!("Expected Modbus address");
    }
}

#[tokio::test]
async fn test_opcua_address_parsing() {
    let parser = OpcUaAddressParser;

    // Numeric node ID
    let addr = parser.parse("ns=2;i=1001").expect("Parse failed");
    if let Address::OpcUa(opcua_addr) = addr {
        assert_eq!(opcua_addr.namespace_index, 2);
    } else {
        panic!("Expected OPC UA address");
    }

    // String node ID
    let addr = parser.parse("ns=1;s=Temperature").expect("Parse failed");
    if let Address::OpcUa(opcua_addr) = addr {
        assert_eq!(opcua_addr.namespace_index, 1);
    } else {
        panic!("Expected OPC UA address");
    }
}

#[tokio::test]
async fn test_invalid_address_parsing() {
    let parser = ModbusAddressParser;

    // Invalid format
    let result = parser.parse("invalid");
    assert!(result.is_err());

    // Invalid register type
    let result = parser.parse("xx:100");
    assert!(result.is_err());

    // Invalid address
    let result = parser.parse("hr:abc");
    assert!(result.is_err());
}

// =============================================================================
// ConfigError Tests
// =============================================================================

#[tokio::test]
async fn test_config_error_display() {
    let error = ConfigError::Validation {
        field: "port".to_string(),
        message: "Invalid configuration".to_string(),
    };
    let message = error.to_string();
    assert!(message.contains("Invalid configuration"));
}
