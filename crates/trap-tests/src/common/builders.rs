// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # Test Builders
//!
//! Builder patterns for constructing complex test objects with sensible defaults.
//!
//! ## Design Principles
//!
//! - Type-safe construction with compile-time guarantees
//! - Sensible defaults for common test scenarios
//! - Chainable methods for fluent API
//! - Clear separation between required and optional fields

use std::sync::Arc;
use std::time::Duration;

use trap_core::{
    types::{DataPoint, DataQuality, DeviceId, Protocol, TagId, Value},
    bus::{DataBus, CommandBus},
    driver::{DriverConfig, DriverRegistry},
    circuit_breaker::{CircuitBreakerConfig, CircuitBreaker},
    retry::RetryConfig,
};

// =============================================================================
// DataPoint Builder
// =============================================================================

/// Builder for constructing DataPoint instances with sensible defaults.
#[derive(Debug, Clone)]
pub struct DataPointBuilder {
    device_id: Option<DeviceId>,
    tag_id: Option<TagId>,
    value: Option<Value>,
    quality: DataQuality,
    source_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for DataPointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DataPointBuilder {
    /// Create a new builder with defaults.
    pub fn new() -> Self {
        Self {
            device_id: None,
            tag_id: None,
            value: None,
            quality: DataQuality::Good,
            source_timestamp: None,
        }
    }

    /// Set the device ID.
    pub fn device_id(mut self, id: impl Into<String>) -> Self {
        self.device_id = Some(DeviceId::new(id));
        self
    }

    /// Set the tag ID.
    pub fn tag_id(mut self, id: impl Into<String>) -> Self {
        self.tag_id = Some(TagId::new(id));
        self
    }

    /// Set the value.
    pub fn value(mut self, value: Value) -> Self {
        self.value = Some(value);
        self
    }

    /// Set a float value.
    pub fn float_value(mut self, v: f64) -> Self {
        self.value = Some(Value::Float64(v));
        self
    }

    /// Set an integer value.
    pub fn int_value(mut self, v: i64) -> Self {
        self.value = Some(Value::Int64(v));
        self
    }

    /// Set a boolean value.
    pub fn bool_value(mut self, v: bool) -> Self {
        self.value = Some(Value::Bool(v));
        self
    }

    /// Set the quality.
    pub fn quality(mut self, quality: DataQuality) -> Self {
        self.quality = quality;
        self
    }

    /// Set the source timestamp.
    pub fn source_timestamp(mut self, ts: chrono::DateTime<chrono::Utc>) -> Self {
        self.source_timestamp = Some(ts);
        self
    }

    /// Build the DataPoint.
    ///
    /// # Panics
    /// Panics if required fields (device_id, tag_id, value) are not set.
    pub fn build(self) -> DataPoint {
        let device_id = self.device_id.expect("device_id is required");
        let tag_id = self.tag_id.expect("tag_id is required");
        let value = self.value.expect("value is required");

        let mut dp = DataPoint::new(device_id, tag_id, value, self.quality);
        dp.source_timestamp = self.source_timestamp;
        dp
    }

    /// Try to build, returning None if required fields are missing.
    pub fn try_build(self) -> Option<DataPoint> {
        let device_id = self.device_id?;
        let tag_id = self.tag_id?;
        let value = self.value?;

        let mut dp = DataPoint::new(device_id, tag_id, value, self.quality);
        dp.source_timestamp = self.source_timestamp;
        Some(dp)
    }
}

// =============================================================================
// DriverConfig Builder
// =============================================================================

/// Builder for constructing DriverConfig instances.
#[derive(Debug, Clone)]
pub struct DriverConfigBuilder {
    id: Option<String>,
    name: String,
    protocol: Protocol,
    protocol_config: serde_json::Value,
    timeout: Duration,
    retries: u32,
}

impl Default for DriverConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverConfigBuilder {
    /// Create a new builder with defaults.
    pub fn new() -> Self {
        Self {
            id: None,
            name: "Unnamed Device".to_string(),
            protocol: Protocol::ModbusTcp,
            protocol_config: serde_json::json!({}),
            timeout: Duration::from_secs(5),
            retries: 3,
        }
    }

    /// Set the device ID.
    pub fn device_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the device name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Configure for Modbus TCP.
    pub fn modbus_tcp(mut self) -> Self {
        self.protocol = Protocol::ModbusTcp;
        self
    }

    /// Configure for OPC UA.
    pub fn opcua(mut self) -> Self {
        self.protocol = Protocol::OpcUa;
        self
    }

    /// Set timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set retry count.
    pub fn retries(mut self, count: u32) -> Self {
        self.retries = count;
        self
    }

    /// Set protocol-specific configuration.
    pub fn protocol_config(mut self, config: serde_json::Value) -> Self {
        self.protocol_config = config;
        self
    }

    /// Build the DriverConfig.
    pub fn build(self) -> DriverConfig {
        DriverConfig {
            id: self.id.unwrap_or_else(|| "default-device".to_string()),
            name: self.name,
            protocol: self.protocol,
            protocol_config: self.protocol_config,
            timeout: self.timeout,
            retries: self.retries,
        }
    }
}

// =============================================================================
// CircuitBreaker Builder (Test-focused)
// =============================================================================

/// Builder for constructing CircuitBreaker configurations for testing.
#[derive(Debug, Clone)]
pub struct TestCircuitBreakerBuilder {
    failure_threshold: u32,
    success_threshold: u32,
    reset_timeout: Duration,
    half_open_max_calls: u32,
}

impl Default for TestCircuitBreakerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestCircuitBreakerBuilder {
    /// Create a new builder with test-friendly defaults.
    pub fn new() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 2,
            reset_timeout: Duration::from_millis(100), // Fast for testing
            half_open_max_calls: 2,
        }
    }

    /// Set failure threshold.
    pub fn failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Set success threshold.
    pub fn success_threshold(mut self, threshold: u32) -> Self {
        self.success_threshold = threshold;
        self
    }

    /// Set reset timeout.
    pub fn reset_timeout(mut self, timeout: Duration) -> Self {
        self.reset_timeout = timeout;
        self
    }

    /// Create an immediately-tripping circuit breaker.
    pub fn trip_immediately(mut self) -> Self {
        self.failure_threshold = 1;
        self
    }

    /// Create a circuit breaker that rarely trips.
    pub fn rarely_trips(mut self) -> Self {
        self.failure_threshold = 100;
        self
    }

    /// Build the CircuitBreakerConfig.
    pub fn build_config(self) -> CircuitBreakerConfig {
        CircuitBreakerConfig::builder()
            .failure_threshold(self.failure_threshold)
            .success_rate_threshold(self.success_threshold as f64 / 10.0)
            .reset_timeout(self.reset_timeout)
            .half_open_max_calls(self.half_open_max_calls)
            .build()
    }

    /// Build a CircuitBreaker instance.
    pub fn build(self) -> CircuitBreaker {
        CircuitBreaker::new(self.build_config())
    }
}

// =============================================================================
// RetryConfig Builder (Test-focused)
// =============================================================================

/// Builder for constructing RetryConfig for testing.
#[derive(Debug, Clone)]
pub struct TestRetryConfigBuilder {
    max_attempts: u32,
    initial_delay: Duration,
    max_delay: Duration,
    multiplier: f64,
    jitter: f64,
}

impl Default for TestRetryConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestRetryConfigBuilder {
    /// Create a new builder with test-friendly defaults.
    pub fn new() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
            multiplier: 2.0,
            jitter: 0.0, // Disable for deterministic testing
        }
    }

    /// Set maximum retry count.
    pub fn max_retries(mut self, count: u32) -> Self {
        self.max_attempts = count;
        self
    }

    /// Set initial delay.
    pub fn initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Set maximum delay.
    pub fn max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Enable/disable jitter.
    pub fn jitter(mut self, enabled: bool) -> Self {
        self.jitter = if enabled { 0.1 } else { 0.0 };
        self
    }

    /// Create a no-retry configuration.
    pub fn no_retries(mut self) -> Self {
        self.max_attempts = 0;
        self
    }

    /// Create a fast retry configuration for testing.
    pub fn fast_retries(mut self) -> Self {
        self.initial_delay = Duration::from_millis(1);
        self.max_delay = Duration::from_millis(10);
        self
    }

    /// Build the RetryConfig.
    pub fn build(self) -> RetryConfig {
        RetryConfig {
            max_attempts: self.max_attempts,
            initial_delay: self.initial_delay,
            max_delay: self.max_delay,
            multiplier: self.multiplier,
            jitter: self.jitter,
            retry_on_timeout: true,
            retry_on_connection: true,
            retry_on_protocol: false,
        }
    }
}

// =============================================================================
// Bus Builder
// =============================================================================

/// Builder for constructing message bus instances for testing.
pub struct TestBusBuilder {
    data_bus_capacity: usize,
    command_bus_capacity: usize,
}

impl Default for TestBusBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestBusBuilder {
    /// Create a new builder with test-friendly defaults.
    pub fn new() -> Self {
        Self {
            data_bus_capacity: 1024,
            command_bus_capacity: 256,
        }
    }

    /// Set data bus capacity.
    pub fn data_bus_capacity(mut self, capacity: usize) -> Self {
        self.data_bus_capacity = capacity;
        self
    }

    /// Set command bus capacity.
    pub fn command_bus_capacity(mut self, capacity: usize) -> Self {
        self.command_bus_capacity = capacity;
        self
    }

    /// Create a small bus for minimal tests.
    pub fn small(mut self) -> Self {
        self.data_bus_capacity = 16;
        self.command_bus_capacity = 8;
        self
    }

    /// Create a large bus for stress tests.
    pub fn large(mut self) -> Self {
        self.data_bus_capacity = 10000;
        self.command_bus_capacity = 1000;
        self
    }

    /// Build the DataBus.
    pub fn build_data_bus(self) -> DataBus {
        DataBus::new(self.data_bus_capacity)
    }

    /// Build the CommandBus and receiver.
    pub fn build_command_bus(self) -> (CommandBus, trap_core::bus::CommandReceiver) {
        CommandBus::channel(self.command_bus_capacity)
    }

    /// Build both buses.
    pub fn build_both(self) -> (DataBus, CommandBus, trap_core::bus::CommandReceiver) {
        let data_bus = DataBus::new(self.data_bus_capacity);
        let (cmd_bus, cmd_rx) = CommandBus::channel(self.command_bus_capacity);
        (data_bus, cmd_bus, cmd_rx)
    }
}

// =============================================================================
// Test Environment Builder
// =============================================================================

/// Builder for constructing a complete test environment.
pub struct TestEnvironmentBuilder {
    data_bus_capacity: usize,
    command_bus_capacity: usize,
    driver_configs: Vec<DriverConfig>,
    circuit_breaker_config: Option<CircuitBreakerConfig>,
}

impl Default for TestEnvironmentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestEnvironmentBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            data_bus_capacity: 1024,
            command_bus_capacity: 256,
            driver_configs: Vec::new(),
            circuit_breaker_config: None,
        }
    }

    /// Set data bus capacity.
    pub fn data_bus_capacity(mut self, capacity: usize) -> Self {
        self.data_bus_capacity = capacity;
        self
    }

    /// Set command bus capacity.
    pub fn command_bus_capacity(mut self, capacity: usize) -> Self {
        self.command_bus_capacity = capacity;
        self
    }

    /// Add a driver configuration.
    pub fn with_driver(mut self, config: DriverConfig) -> Self {
        self.driver_configs.push(config);
        self
    }

    /// Add multiple drivers.
    pub fn with_drivers(mut self, configs: Vec<DriverConfig>) -> Self {
        self.driver_configs.extend(configs);
        self
    }

    /// Set circuit breaker config.
    pub fn with_circuit_breaker(mut self, config: CircuitBreakerConfig) -> Self {
        self.circuit_breaker_config = Some(config);
        self
    }

    /// Build the test environment.
    pub fn build(self) -> TestEnvironment {
        let data_bus = Arc::new(DataBus::new(self.data_bus_capacity));
        let (command_bus, command_receiver) = CommandBus::channel(self.command_bus_capacity);
        let command_bus = Arc::new(command_bus);
        let driver_registry = Arc::new(DriverRegistry::new());

        TestEnvironment {
            data_bus,
            command_bus,
            command_receiver,
            driver_registry,
            driver_configs: self.driver_configs,
        }
    }
}

/// A complete test environment with all necessary components.
pub struct TestEnvironment {
    pub data_bus: Arc<DataBus>,
    pub command_bus: Arc<CommandBus>,
    pub command_receiver: trap_core::bus::CommandReceiver,
    pub driver_registry: Arc<DriverRegistry>,
    pub driver_configs: Vec<DriverConfig>,
}

impl TestEnvironment {
    /// Create a default test environment.
    pub fn default() -> Self {
        TestEnvironmentBuilder::new().build()
    }

    /// Create a minimal test environment.
    pub fn minimal() -> Self {
        TestEnvironmentBuilder::new()
            .data_bus_capacity(16)
            .command_bus_capacity(8)
            .build()
    }
}
