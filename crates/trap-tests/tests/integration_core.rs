// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # Core Integration Tests
//!
//! Integration tests for trap-core functionality including:
//!
//! - Core types (DataPoint, Value, etc.)
//! - Address types
//! - Driver configuration
//! - Retry strategies
//!
//! ## Test Categories
//!
//! - `test_types_*`: Core type tests
//! - `test_address_*`: Address tests
//! - `test_driver_*`: Driver tests
//! - `test_retry_*`: Retry strategy tests

use std::time::Duration;

use trap_core::{
    // Types
    types::{DataPoint, DataQuality, DeviceId, Protocol, TagId, Value},
    address::{Address, ModbusAddress, ModbusRegisterType},
    // Driver
    driver::{DriverConfig, DriverRegistry},
    // Retry
    retry::{RetryConfig, ExponentialBackoff, RetryStrategy},
};

use trap_tests::common::fixtures::{DeviceFixtures, AddressFixtures, DataPointFixtures};

// =============================================================================
// DataPoint Tests
// =============================================================================

#[tokio::test]
async fn test_data_point_creation() {
    let dp = DataPoint::new(
        DeviceId::new("device-001"),
        TagId::new("tag-001"),
        Value::Float64(42.5),
        DataQuality::Good,
    );

    assert_eq!(dp.device_id.as_str(), "device-001");
    assert_eq!(dp.tag_id.as_str(), "tag-001");
    assert_eq!(dp.value.as_f64(), Some(42.5));
    assert!(matches!(dp.quality, DataQuality::Good));
}

#[tokio::test]
async fn test_data_point_with_quality() {
    let good_dp = DataPointFixtures::good_quality(
        DeviceFixtures::modbus_plc(),
        TagId::new("temp"),
        Value::Float64(25.0),
    );
    assert!(matches!(good_dp.quality, DataQuality::Good));

    let bad_dp = DataPointFixtures::bad_quality(
        DeviceFixtures::modbus_plc(),
        TagId::new("temp"),
        Value::Float64(25.0),
    );
    assert!(matches!(bad_dp.quality, DataQuality::Bad(_)));
}

// =============================================================================
// Value Tests
// =============================================================================

#[tokio::test]
async fn test_value_types() {
    // Integer values - as_i64 handles all integer types
    assert!(Value::Int32(42).as_i64().is_some());
    assert_eq!(Value::Int64(100).as_i64(), Some(100));

    // Float values - as_f64 handles all numeric types
    assert!(Value::Float32(3.14).as_f64().is_some());
    assert_eq!(Value::Float64(2.718).as_f64(), Some(2.718));

    // Boolean
    assert_eq!(Value::Bool(true).as_bool(), Some(true));
    assert_eq!(Value::Bool(false).as_bool(), Some(false));

    // String
    assert_eq!(Value::String("hello".to_string()).as_str(), Some("hello"));
}

#[tokio::test]
async fn test_value_type_name() {
    assert_eq!(Value::Int32(100).type_name(), "int32");
    assert_eq!(Value::Float64(100.5).type_name(), "float64");
    assert_eq!(Value::Bool(true).type_name(), "bool");
    assert_eq!(Value::String("test".to_string()).type_name(), "string");
}

#[tokio::test]
async fn test_value_is_numeric() {
    assert!(Value::Int32(100).is_numeric());
    assert!(Value::Float64(100.5).is_numeric());
    assert!(!Value::Bool(true).is_numeric());
    assert!(!Value::String("test".to_string()).is_numeric());
}

// =============================================================================
// Address Tests
// =============================================================================

#[tokio::test]
async fn test_modbus_address_creation() {
    let addr = ModbusAddress {
        register_type: ModbusRegisterType::HoldingRegister,
        address: 100,
        count: 1,
        is_tcp: true,
        unit_id: 1,
    };

    assert_eq!(addr.address, 100);
    assert_eq!(addr.register_type, ModbusRegisterType::HoldingRegister);
}

#[tokio::test]
async fn test_address_display() {
    let addr = Address::Modbus(ModbusAddress {
        register_type: ModbusRegisterType::HoldingRegister,
        address: 100,
        count: 1,
        is_tcp: true,
        unit_id: 1,
    });

    let display = addr.to_string();
    assert!(!display.is_empty());
}

#[tokio::test]
async fn test_fixtures_modbus_address() {
    let addr = AddressFixtures::modbus_holding_register(100);

    if let Address::Modbus(modbus_addr) = addr {
        assert_eq!(modbus_addr.address, 100);
        assert_eq!(modbus_addr.register_type, ModbusRegisterType::HoldingRegister);
    } else {
        panic!("Expected Modbus address");
    }
}

// =============================================================================
// Retry Strategy Tests
// =============================================================================

#[tokio::test]
async fn test_retry_config_creation() {
    let config = RetryConfig::default();

    assert!(config.max_attempts > 0);
    assert!(config.initial_delay > Duration::ZERO);
}

#[tokio::test]
async fn test_exponential_backoff_creation() {
    let config = RetryConfig::default();
    let strategy = ExponentialBackoff::new(config);

    // Strategy should have a name
    assert_eq!(strategy.name(), "exponential_backoff");
}

#[tokio::test]
async fn test_exponential_backoff_default() {
    // Test the default strategy constructor
    let strategy = ExponentialBackoff::default_strategy();
    assert_eq!(strategy.name(), "exponential_backoff");
}

// =============================================================================
// Driver Registry Tests
// =============================================================================

#[tokio::test]
async fn test_driver_registry_creation() {
    let registry = DriverRegistry::new();

    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
}

#[tokio::test]
async fn test_driver_config_creation() {
    let config = DriverConfig {
        id: "driver-001".to_string(),
        name: "Test Driver".to_string(),
        protocol: Protocol::ModbusTcp,
        protocol_config: serde_json::json!({}),
        timeout: Duration::from_secs(5),
        retries: 3,
    };

    assert_eq!(config.id, "driver-001");
    assert_eq!(config.retries, 3);
}

// =============================================================================
// Protocol Tests
// =============================================================================

#[tokio::test]
async fn test_protocol_variants() {
    let modbus_tcp = Protocol::ModbusTcp;
    let modbus_rtu = Protocol::ModbusRtu;
    let opcua = Protocol::OpcUa;
    let bacnet = Protocol::BacNetIp;

    assert!(matches!(modbus_tcp, Protocol::ModbusTcp));
    assert!(matches!(modbus_rtu, Protocol::ModbusRtu));
    assert!(matches!(opcua, Protocol::OpcUa));
    assert!(matches!(bacnet, Protocol::BacNetIp));
}

#[tokio::test]
async fn test_protocol_as_str() {
    assert_eq!(Protocol::ModbusTcp.as_str(), "modbus-tcp");
    assert_eq!(Protocol::ModbusRtu.as_str(), "modbus-rtu");
    assert_eq!(Protocol::OpcUa.as_str(), "opcua");
    assert_eq!(Protocol::BacNetIp.as_str(), "bacnet-ip");
}

// =============================================================================
// Device/Tag ID Tests
// =============================================================================

#[tokio::test]
async fn test_device_id() {
    let device = DeviceId::new("test-device");
    assert_eq!(device.as_str(), "test-device");
}

#[tokio::test]
async fn test_tag_id() {
    let tag = TagId::new("test-tag");
    assert_eq!(tag.as_str(), "test-tag");
}

#[tokio::test]
async fn test_fixtures_device_id() {
    let device = DeviceFixtures::modbus_plc();
    assert!(!device.as_str().is_empty());

    let opcua_device = DeviceFixtures::opcua_server();
    assert!(!opcua_device.as_str().is_empty());
}

// =============================================================================
// Data Point Batch Tests
// =============================================================================

#[tokio::test]
async fn test_fixtures_data_point_batch() {
    let device = DeviceFixtures::modbus_plc();
    let batch = DataPointFixtures::data_point_batch(device, 100);

    assert_eq!(batch.len(), 100);

    for dp in &batch {
        assert!(matches!(dp.quality, DataQuality::Good | DataQuality::Uncertain(_) | DataQuality::Bad(_)));
    }
}

// =============================================================================
// Quality Tests
// =============================================================================

#[tokio::test]
async fn test_data_quality_variants() {
    let good = DataQuality::Good;
    assert!(matches!(good, DataQuality::Good));
}
