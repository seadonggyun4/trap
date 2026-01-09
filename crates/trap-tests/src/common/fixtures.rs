// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # Test Fixtures
//!
//! Pre-built test data for consistent and reproducible testing.
//!
//! ## Design Principles
//!
//! - Fixtures are immutable and thread-safe
//! - Each fixture represents a realistic scenario
//! - Fixtures can be composed for complex test scenarios

use chrono::{DateTime, Utc};
use trap_core::{
    types::{DataPoint, DataQuality, DeviceId, Protocol, TagId, Value, UncertainReason, BadReason},
    address::{Address, ModbusAddress, ModbusRegisterType, GenericAddress},
    driver::DriverConfig,
};
use std::time::Duration;

// =============================================================================
// Device Fixtures
// =============================================================================

/// Fixture providing standard device configurations.
pub struct DeviceFixtures;

impl DeviceFixtures {
    /// A standard Modbus TCP PLC device.
    pub fn modbus_plc() -> DeviceId {
        DeviceId::new("modbus-plc-001")
    }

    /// A standard OPC UA server device.
    pub fn opcua_server() -> DeviceId {
        DeviceId::new("opcua-server-001")
    }

    /// Multiple devices for batch testing.
    pub fn device_batch(count: usize) -> Vec<DeviceId> {
        (0..count)
            .map(|i| DeviceId::new(format!("device-{:03}", i)))
            .collect()
    }

    /// Driver configuration for a Modbus device.
    pub fn modbus_driver_config() -> DriverConfig {
        DriverConfig {
            id: Self::modbus_plc().to_string(),
            name: "Test Modbus PLC".to_string(),
            protocol: Protocol::ModbusTcp,
            protocol_config: serde_json::json!({
                "host": "192.168.1.100",
                "port": 502,
                "unit_id": 1
            }),
            timeout: Duration::from_secs(5),
            retries: 3,
        }
    }

    /// Driver configuration for an OPC UA device.
    pub fn opcua_driver_config() -> DriverConfig {
        DriverConfig {
            id: Self::opcua_server().to_string(),
            name: "Test OPC UA Server".to_string(),
            protocol: Protocol::OpcUa,
            protocol_config: serde_json::json!({
                "endpoint": "opc.tcp://localhost:4840"
            }),
            timeout: Duration::from_secs(10),
            retries: 3,
        }
    }
}

// =============================================================================
// Tag Fixtures
// =============================================================================

/// Fixture providing standard tag configurations.
pub struct TagFixtures;

impl TagFixtures {
    /// A temperature sensor tag.
    pub fn temperature() -> TagId {
        TagId::new("temperature")
    }

    /// A humidity sensor tag.
    pub fn humidity() -> TagId {
        TagId::new("humidity")
    }

    /// A pressure sensor tag.
    pub fn pressure() -> TagId {
        TagId::new("pressure")
    }

    /// A status flag tag (boolean).
    pub fn status_flag() -> TagId {
        TagId::new("status_flag")
    }

    /// A counter tag (integer).
    pub fn counter() -> TagId {
        TagId::new("counter")
    }

    /// Multiple tags for batch testing.
    pub fn tag_batch(count: usize) -> Vec<TagId> {
        (0..count)
            .map(|i| TagId::new(format!("tag_{:04}", i)))
            .collect()
    }

    /// Standard industrial tags set.
    pub fn industrial_tags() -> Vec<TagId> {
        vec![
            Self::temperature(),
            Self::humidity(),
            Self::pressure(),
            Self::status_flag(),
            Self::counter(),
        ]
    }
}

// =============================================================================
// Address Fixtures
// =============================================================================

/// Fixture providing protocol-specific addresses.
pub struct AddressFixtures;

impl AddressFixtures {
    /// Modbus holding register address.
    pub fn modbus_holding_register(addr: u16) -> Address {
        Address::Modbus(ModbusAddress {
            register_type: ModbusRegisterType::HoldingRegister,
            address: addr,
            count: 1,
            is_tcp: true,
            unit_id: 1,
        })
    }

    /// Modbus input register address.
    pub fn modbus_input_register(addr: u16) -> Address {
        Address::Modbus(ModbusAddress {
            register_type: ModbusRegisterType::InputRegister,
            address: addr,
            count: 1,
            is_tcp: true,
            unit_id: 1,
        })
    }

    /// Modbus coil address.
    pub fn modbus_coil(addr: u16) -> Address {
        Address::Modbus(ModbusAddress {
            register_type: ModbusRegisterType::Coil,
            address: addr,
            count: 1,
            is_tcp: true,
            unit_id: 1,
        })
    }

    /// Generic string address.
    pub fn generic(addr: &str) -> Address {
        Address::Generic(GenericAddress::new("generic", addr))
    }

    /// Multiple addresses for batch testing.
    pub fn address_batch(count: usize) -> Vec<Address> {
        (0..count)
            .map(|i| Self::modbus_holding_register(100 + i as u16))
            .collect()
    }
}

// =============================================================================
// Value Fixtures
// =============================================================================

/// Fixture providing various data values.
pub struct ValueFixtures;

impl ValueFixtures {
    /// A typical temperature value (°C).
    pub fn temperature_celsius(value: f64) -> Value {
        Value::Float64(value)
    }

    /// A typical humidity value (%).
    pub fn humidity_percent(value: f64) -> Value {
        Value::Float64(value)
    }

    /// A boolean status value.
    pub fn boolean_status(active: bool) -> Value {
        Value::Bool(active)
    }

    /// An integer counter value.
    pub fn counter_value(count: i64) -> Value {
        Value::Int64(count)
    }

    /// A 16-bit register value.
    pub fn register_u16(value: u16) -> Value {
        Value::UInt16(value)
    }

    /// A 32-bit register value.
    pub fn register_u32(value: u32) -> Value {
        Value::UInt32(value)
    }

    /// Various value types for comprehensive testing.
    pub fn value_variety() -> Vec<Value> {
        vec![
            Value::Bool(true),
            Value::Int16(-100),
            Value::Int32(12345),
            Value::Int64(-9876543210),
            Value::UInt16(65535),
            Value::UInt32(4294967295),
            Value::UInt64(18446744073709551615),
            Value::Float32(3.14159),
            Value::Float64(2.718281828459045),
            Value::String("test_string".to_string()),
            Value::Null,
        ]
    }

    /// Edge case values for boundary testing.
    pub fn edge_case_values() -> Vec<Value> {
        vec![
            Value::Int16(i16::MIN),
            Value::Int16(i16::MAX),
            Value::Int32(i32::MIN),
            Value::Int32(i32::MAX),
            Value::Float64(f64::MIN),
            Value::Float64(f64::MAX),
            Value::Float64(f64::EPSILON),
            Value::Float64(f64::NAN),
            Value::Float64(f64::INFINITY),
            Value::Float64(f64::NEG_INFINITY),
            Value::String(String::new()),
            Value::String("a".repeat(10000)),
        ]
    }
}

// =============================================================================
// DataPoint Fixtures
// =============================================================================

/// Fixture providing complete data points.
pub struct DataPointFixtures;

impl DataPointFixtures {
    /// Create a basic data point with good quality.
    pub fn good_quality(device: DeviceId, tag: TagId, value: Value) -> DataPoint {
        DataPoint::new(device, tag, value, DataQuality::Good)
    }

    /// Create a data point with uncertain quality.
    pub fn uncertain_quality(device: DeviceId, tag: TagId, value: Value) -> DataPoint {
        DataPoint::new(device, tag, value, DataQuality::Uncertain(UncertainReason::LastKnownValue))
    }

    /// Create a data point with bad quality.
    pub fn bad_quality(device: DeviceId, tag: TagId, value: Value) -> DataPoint {
        DataPoint::new(device, tag, value, DataQuality::Bad(BadReason::CommunicationFailure))
    }

    /// Create a temperature data point.
    pub fn temperature_reading(device: DeviceId, celsius: f64) -> DataPoint {
        Self::good_quality(
            device,
            TagFixtures::temperature(),
            ValueFixtures::temperature_celsius(celsius),
        )
    }

    /// Create multiple data points for batch testing.
    pub fn data_point_batch(device: DeviceId, count: usize) -> Vec<DataPoint> {
        let tags = TagFixtures::tag_batch(count);
        tags.into_iter()
            .enumerate()
            .map(|(i, tag)| {
                Self::good_quality(device.clone(), tag, Value::Float64(i as f64 * 1.5))
            })
            .collect()
    }

    /// Create data points with varied qualities.
    pub fn varied_quality_batch(device: DeviceId, count: usize) -> Vec<DataPoint> {
        (0..count)
            .map(|i| {
                let quality = match i % 3 {
                    0 => DataQuality::Good,
                    1 => DataQuality::Uncertain(UncertainReason::LastKnownValue),
                    _ => DataQuality::Bad(BadReason::CommunicationFailure),
                };
                DataPoint::new(
                    device.clone(),
                    TagId::new(format!("tag_{}", i)),
                    Value::Float64(i as f64),
                    quality,
                )
            })
            .collect()
    }

    /// Create a data point with a specific timestamp.
    pub fn with_timestamp(
        device: DeviceId,
        tag: TagId,
        value: Value,
        timestamp: DateTime<Utc>,
    ) -> DataPoint {
        let mut dp = Self::good_quality(device, tag, value);
        dp.timestamp = timestamp;
        dp
    }
}

// =============================================================================
// Scenario Fixtures
// =============================================================================

/// Complete test scenarios combining multiple fixtures.
pub struct ScenarioFixtures;

impl ScenarioFixtures {
    /// A simple HVAC monitoring scenario.
    pub fn hvac_monitoring() -> HvacScenario {
        HvacScenario {
            device: DeviceId::new("hvac-controller-001"),
            temperature_tag: TagId::new("zone1_temperature"),
            humidity_tag: TagId::new("zone1_humidity"),
            setpoint_tag: TagId::new("zone1_setpoint"),
            fan_status_tag: TagId::new("zone1_fan_status"),
        }
    }

    /// A power meter monitoring scenario.
    pub fn power_monitoring() -> PowerMeterScenario {
        PowerMeterScenario {
            device: DeviceId::new("power-meter-001"),
            voltage_tag: TagId::new("voltage_l1"),
            current_tag: TagId::new("current_l1"),
            power_tag: TagId::new("active_power"),
            energy_tag: TagId::new("total_energy"),
        }
    }

    /// A multi-device factory scenario.
    pub fn factory_floor(device_count: usize) -> FactoryFloorScenario {
        FactoryFloorScenario {
            devices: DeviceFixtures::device_batch(device_count),
            common_tags: TagFixtures::industrial_tags(),
        }
    }
}

/// HVAC monitoring test scenario.
pub struct HvacScenario {
    pub device: DeviceId,
    pub temperature_tag: TagId,
    pub humidity_tag: TagId,
    pub setpoint_tag: TagId,
    pub fan_status_tag: TagId,
}

impl HvacScenario {
    /// Generate a complete set of data points for this scenario.
    pub fn generate_data_points(&self) -> Vec<DataPoint> {
        vec![
            DataPointFixtures::good_quality(
                self.device.clone(),
                self.temperature_tag.clone(),
                Value::Float64(22.5),
            ),
            DataPointFixtures::good_quality(
                self.device.clone(),
                self.humidity_tag.clone(),
                Value::Float64(45.0),
            ),
            DataPointFixtures::good_quality(
                self.device.clone(),
                self.setpoint_tag.clone(),
                Value::Float64(23.0),
            ),
            DataPointFixtures::good_quality(
                self.device.clone(),
                self.fan_status_tag.clone(),
                Value::Bool(true),
            ),
        ]
    }
}

/// Power meter monitoring test scenario.
pub struct PowerMeterScenario {
    pub device: DeviceId,
    pub voltage_tag: TagId,
    pub current_tag: TagId,
    pub power_tag: TagId,
    pub energy_tag: TagId,
}

impl PowerMeterScenario {
    /// Generate a complete set of data points for this scenario.
    pub fn generate_data_points(&self) -> Vec<DataPoint> {
        vec![
            DataPointFixtures::good_quality(
                self.device.clone(),
                self.voltage_tag.clone(),
                Value::Float64(230.5),
            ),
            DataPointFixtures::good_quality(
                self.device.clone(),
                self.current_tag.clone(),
                Value::Float64(12.3),
            ),
            DataPointFixtures::good_quality(
                self.device.clone(),
                self.power_tag.clone(),
                Value::Float64(2835.15),
            ),
            DataPointFixtures::good_quality(
                self.device.clone(),
                self.energy_tag.clone(),
                Value::Float64(15678.9),
            ),
        ]
    }
}

/// Multi-device factory floor test scenario.
pub struct FactoryFloorScenario {
    pub devices: Vec<DeviceId>,
    pub common_tags: Vec<TagId>,
}

impl FactoryFloorScenario {
    /// Generate data points for all devices.
    pub fn generate_all_data_points(&self) -> Vec<DataPoint> {
        let mut points = Vec::new();
        for device in &self.devices {
            for (i, tag) in self.common_tags.iter().enumerate() {
                points.push(DataPointFixtures::good_quality(
                    device.clone(),
                    tag.clone(),
                    Value::Float64(i as f64 * 10.0),
                ));
            }
        }
        points
    }
}

// =============================================================================
// Config Fixtures
// =============================================================================

/// Fixture providing configuration snippets.
pub struct ConfigFixtures;

impl ConfigFixtures {
    /// Minimal valid YAML configuration.
    pub fn minimal_yaml() -> &'static str {
        r#"
gateway:
  id: test-gateway
  name: Test Gateway

devices: []

buffer:
  path: /tmp/trap-buffer
  max_items: 1000

api:
  port: 8080
"#
    }

    /// Complete YAML configuration with all sections.
    pub fn complete_yaml() -> &'static str {
        r#"
gateway:
  id: trap-001
  name: Production Gateway
  location: Building A

devices:
  - id: plc-001
    name: Main PLC
    enabled: true
    protocol:
      type: modbus_tcp
      host: 192.168.1.100
      port: 502
      unit_id: 1
    tags:
      - id: temperature
        address: "HR:100"
        data_type: float32
      - id: status
        address: "CO:0"
        data_type: bool

buffer:
  path: /var/lib/trap/buffer
  max_items: 10000000
  max_size_bytes: 1073741824
  compression: true
  flush:
    interval_seconds: 5
    batch_size: 1000
    retries: 3

api:
  host: 0.0.0.0
  port: 8080
  cors:
    enabled: true
    allowed_origins:
      - "*"

security:
  jwt:
    secret: "test-secret-key-at-least-32-characters"
    expiration_hours: 24
  rate_limit:
    requests_per_second: 100
    burst_size: 200

logging:
  level: info
  format: json
"#
    }

    /// Invalid YAML configuration for error testing.
    pub fn invalid_yaml() -> &'static str {
        r#"
gateway:
  id: [invalid yaml
  name: Missing bracket
"#
    }

    /// Configuration with missing required fields.
    pub fn missing_required_fields_yaml() -> &'static str {
        r#"
gateway:
  name: No ID provided

devices: []
"#
    }
}
