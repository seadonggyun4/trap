// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Driver lifecycle management.
//!
//! This module provides components for managing multiple protocol drivers,
//! including connection lifecycle, circuit breaker integration, and metrics.
//!
//! # Components
//!
//! - [`DriverWrapper`]: Wraps a driver with circuit breaker and metrics
//! - [`DriverManager`]: Manages multiple drivers with concurrent access
//! - [`DriverMetrics`]: Per-driver performance metrics
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_core::manager::DriverManager;
//!
//! let manager = DriverManager::new(registry, cb_config);
//!
//! // Add devices
//! manager.add_device(device_config).await?;
//!
//! // Connect all
//! let results = manager.connect_all().await;
//!
//! // Get a driver
//! if let Some(driver) = manager.get_driver(&device_id) {
//!     let value = driver.read(&address).await?;
//! }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitError};
use crate::driver::{
    CircuitState, DriverConfig, DriverRegistry, HealthStatus, ProtocolDriver, Subscription,
    SubscriptionId,
};
use crate::error::DriverError;
use crate::types::{DeviceId, Protocol, Value};

// =============================================================================
// Driver Metrics
// =============================================================================

/// Performance metrics for a single driver.
#[derive(Debug, Default)]
pub struct DriverMetrics {
    /// Total read operations.
    reads_total: AtomicU64,
    /// Successful read operations.
    reads_success: AtomicU64,
    /// Failed read operations.
    reads_failed: AtomicU64,
    /// Total read duration in microseconds.
    read_duration_us: AtomicU64,

    /// Total write operations.
    writes_total: AtomicU64,
    /// Successful write operations.
    writes_success: AtomicU64,
    /// Failed write operations.
    writes_failed: AtomicU64,
    /// Total write duration in microseconds.
    write_duration_us: AtomicU64,

    /// Last successful operation timestamp (unix timestamp).
    last_success: AtomicU64,
    /// Last error message (protected by RwLock for string access).
    last_error: RwLock<Option<String>>,
}

impl DriverMetrics {
    /// Creates new empty metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a read operation.
    pub fn record_read(&self, duration: Duration, success: bool) {
        self.reads_total.fetch_add(1, Ordering::Relaxed);
        self.read_duration_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);

        if success {
            self.reads_success.fetch_add(1, Ordering::Relaxed);
            self.last_success
                .store(Utc::now().timestamp() as u64, Ordering::Relaxed);
        } else {
            self.reads_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records a write operation.
    pub fn record_write(&self, duration: Duration, success: bool) {
        self.writes_total.fetch_add(1, Ordering::Relaxed);
        self.write_duration_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);

        if success {
            self.writes_success.fetch_add(1, Ordering::Relaxed);
            self.last_success
                .store(Utc::now().timestamp() as u64, Ordering::Relaxed);
        } else {
            self.writes_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records an error message.
    pub fn record_error(&self, error: &str) {
        let mut guard = self.last_error.write();
        *guard = Some(error.to_string());
    }

    /// Returns a snapshot of the metrics.
    pub fn snapshot(&self) -> DriverMetricsSnapshot {
        let reads_total = self.reads_total.load(Ordering::Relaxed);
        let reads_success = self.reads_success.load(Ordering::Relaxed);
        let read_duration_us = self.read_duration_us.load(Ordering::Relaxed);

        let writes_total = self.writes_total.load(Ordering::Relaxed);
        let writes_success = self.writes_success.load(Ordering::Relaxed);
        let write_duration_us = self.write_duration_us.load(Ordering::Relaxed);

        let last_success_ts = self.last_success.load(Ordering::Relaxed);

        DriverMetricsSnapshot {
            reads_total,
            reads_success,
            reads_failed: self.reads_failed.load(Ordering::Relaxed),
            read_avg_duration: if reads_total > 0 {
                Duration::from_micros(read_duration_us / reads_total)
            } else {
                Duration::ZERO
            },
            writes_total,
            writes_success,
            writes_failed: self.writes_failed.load(Ordering::Relaxed),
            write_avg_duration: if writes_total > 0 {
                Duration::from_micros(write_duration_us / writes_total)
            } else {
                Duration::ZERO
            },
            last_success: if last_success_ts > 0 {
                DateTime::from_timestamp(last_success_ts as i64, 0)
            } else {
                None
            },
            last_error: self.last_error.read().clone(),
        }
    }

    /// Converts metrics to a health status.
    pub fn to_health_status(&self, circuit_state: CircuitState) -> HealthStatus {
        let snapshot = self.snapshot();

        HealthStatus {
            healthy: circuit_state != CircuitState::Open,
            latency: Some(snapshot.read_avg_duration),
            last_success: snapshot.last_success,
            last_error: snapshot.last_error,
            circuit_state,
        }
    }
}

/// A snapshot of driver metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverMetricsSnapshot {
    /// Total read operations.
    pub reads_total: u64,
    /// Successful read operations.
    pub reads_success: u64,
    /// Failed read operations.
    pub reads_failed: u64,
    /// Average read duration.
    pub read_avg_duration: Duration,
    /// Total write operations.
    pub writes_total: u64,
    /// Successful write operations.
    pub writes_success: u64,
    /// Failed write operations.
    pub writes_failed: u64,
    /// Average write duration.
    pub write_avg_duration: Duration,
    /// Last successful operation time.
    pub last_success: Option<DateTime<Utc>>,
    /// Last error message.
    pub last_error: Option<String>,
}

// =============================================================================
// Driver Wrapper
// =============================================================================

/// A wrapper around a protocol driver that adds circuit breaker and metrics.
///
/// This wrapper:
/// - Protects the driver with a circuit breaker
/// - Records performance metrics
/// - Provides a safe interface for concurrent access
pub struct DriverWrapper {
    /// The underlying driver.
    driver: RwLock<Box<dyn ProtocolDriver>>,
    /// Circuit breaker for fault isolation.
    circuit_breaker: CircuitBreaker,
    /// Device identifier.
    device_id: DeviceId,
    /// Protocol type.
    protocol: Protocol,
    /// Performance metrics.
    metrics: DriverMetrics,
}

impl DriverWrapper {
    /// Creates a new driver wrapper.
    pub fn new(
        driver: Box<dyn ProtocolDriver>,
        device_id: DeviceId,
        circuit_breaker_config: CircuitBreakerConfig,
    ) -> Self {
        let protocol = driver.protocol();

        Self {
            driver: RwLock::new(driver),
            circuit_breaker: CircuitBreaker::new(circuit_breaker_config),
            device_id,
            protocol,
            metrics: DriverMetrics::new(),
        }
    }

    /// Returns the device ID.
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Returns the protocol type.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the driver name.
    pub fn name(&self) -> String {
        self.driver.read().name().to_string()
    }

    /// Returns `true` if connected.
    pub fn is_connected(&self) -> bool {
        self.driver.read().is_connected()
    }

    /// Connects to the device.
    pub async fn connect(&self) -> Result<(), DriverError> {
        let mut driver = self.driver.write();
        driver.connect().await
    }

    /// Disconnects from the device.
    pub async fn disconnect(&self) -> Result<(), DriverError> {
        let mut driver = self.driver.write();
        driver.disconnect().await
    }

    /// Reads a value from the device through the circuit breaker.
    pub async fn read(&self, address: &Address) -> Result<Value, DriverError> {
        let start = Instant::now();

        let result = self
            .circuit_breaker
            .call(|| async {
                let driver = self.driver.read();
                driver.read(address).await
            })
            .await;

        let duration = start.elapsed();
        let success = result.is_ok();
        self.metrics.record_read(duration, success);

        match result {
            Ok(value) => Ok(value),
            Err(CircuitError::Open) | Err(CircuitError::HalfOpenAtCapacity) => {
                let err = DriverError::circuit_open(self.device_id.as_str());
                self.metrics.record_error(&err.to_string());
                Err(err)
            }
            Err(CircuitError::Inner(e)) => {
                self.metrics.record_error(&e.to_string());
                Err(e)
            }
        }
    }

    /// Reads multiple values from the device.
    pub async fn read_batch(
        &self,
        addresses: &[Address],
    ) -> Result<Vec<(Address, Result<Value, DriverError>)>, DriverError> {
        let start = Instant::now();

        let result = self
            .circuit_breaker
            .call(|| async {
                let driver = self.driver.read();
                driver.read_batch(addresses).await
            })
            .await;

        let duration = start.elapsed();
        let success = result.is_ok();
        self.metrics.record_read(duration, success);

        match result {
            Ok(results) => Ok(results),
            Err(CircuitError::Open) | Err(CircuitError::HalfOpenAtCapacity) => {
                Err(DriverError::circuit_open(self.device_id.as_str()))
            }
            Err(CircuitError::Inner(e)) => Err(e),
        }
    }

    /// Writes a value to the device through the circuit breaker.
    pub async fn write(&self, address: &Address, value: Value) -> Result<(), DriverError> {
        let start = Instant::now();

        let result = self
            .circuit_breaker
            .call(|| async {
                let driver = self.driver.read();
                driver.write(address, value.clone()).await
            })
            .await;

        let duration = start.elapsed();
        let success = result.is_ok();
        self.metrics.record_write(duration, success);

        match result {
            Ok(()) => Ok(()),
            Err(CircuitError::Open) | Err(CircuitError::HalfOpenAtCapacity) => {
                let err = DriverError::circuit_open(self.device_id.as_str());
                self.metrics.record_error(&err.to_string());
                Err(err)
            }
            Err(CircuitError::Inner(e)) => {
                self.metrics.record_error(&e.to_string());
                Err(e)
            }
        }
    }

    /// Returns `true` if subscriptions are supported.
    pub fn supports_subscription(&self) -> bool {
        self.driver.read().supports_subscription()
    }

    /// Subscribes to address changes.
    pub async fn subscribe(&self, addresses: &[Address]) -> Result<Subscription, DriverError> {
        let driver = self.driver.read();
        driver.subscribe(addresses).await
    }

    /// Unsubscribes from changes.
    pub async fn unsubscribe(&self, subscription_id: &SubscriptionId) -> Result<(), DriverError> {
        let driver = self.driver.read();
        driver.unsubscribe(subscription_id).await
    }

    /// Returns the current health status.
    pub fn health_status(&self) -> HealthStatus {
        self.metrics
            .to_health_status(self.circuit_breaker.current_state())
    }

    /// Returns the circuit breaker state.
    pub fn circuit_state(&self) -> CircuitState {
        self.circuit_breaker.current_state()
    }

    /// Returns the metrics snapshot.
    pub fn metrics(&self) -> DriverMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Resets the circuit breaker.
    pub fn reset_circuit_breaker(&self) {
        self.circuit_breaker.reset();
    }
}

impl std::fmt::Debug for DriverWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriverWrapper")
            .field("device_id", &self.device_id)
            .field("protocol", &self.protocol)
            .field("connected", &self.is_connected())
            .field("circuit_state", &self.circuit_state())
            .finish()
    }
}

// =============================================================================
// Driver Manager
// =============================================================================

/// Manages multiple protocol drivers with concurrent access.
///
/// The manager uses `DashMap` for lock-free concurrent access to drivers,
/// making it safe to use from multiple tasks simultaneously.
pub struct DriverManager {
    /// Map of device ID to driver wrapper.
    drivers: DashMap<DeviceId, Arc<DriverWrapper>>,
    /// Driver factory registry.
    registry: Arc<DriverRegistry>,
    /// Default circuit breaker configuration.
    circuit_breaker_config: CircuitBreakerConfig,
}

impl DriverManager {
    /// Creates a new driver manager.
    pub fn new(registry: Arc<DriverRegistry>, circuit_breaker_config: CircuitBreakerConfig) -> Self {
        Self {
            drivers: DashMap::new(),
            registry,
            circuit_breaker_config,
        }
    }

    /// Adds a device from configuration.
    pub fn add_device(&self, config: DriverConfig) -> Result<DeviceId, DriverError> {
        let device_id = DeviceId::new(&config.id);

        // Check for duplicate
        if self.drivers.contains_key(&device_id) {
            return Err(DriverError::protocol(format!(
                "Device already exists: {}",
                device_id
            )));
        }

        // Create the driver
        let driver = self.registry.create(&config)?;

        // Wrap with circuit breaker
        let wrapper = Arc::new(DriverWrapper::new(
            driver,
            device_id.clone(),
            self.circuit_breaker_config.clone(),
        ));

        self.drivers.insert(device_id.clone(), wrapper);

        tracing::info!(
            device_id = %device_id,
            protocol = ?config.protocol,
            "Added device to manager"
        );

        Ok(device_id)
    }

    /// Adds a pre-created driver wrapper.
    pub fn add_driver(&self, wrapper: Arc<DriverWrapper>) -> Result<(), DriverError> {
        let device_id = wrapper.device_id().clone();

        if self.drivers.contains_key(&device_id) {
            return Err(DriverError::protocol(format!(
                "Device already exists: {}",
                device_id
            )));
        }

        self.drivers.insert(device_id.clone(), wrapper);

        tracing::info!(device_id = %device_id, "Added driver to manager");

        Ok(())
    }

    /// Removes a device.
    pub async fn remove_device(&self, device_id: &DeviceId) -> Option<Arc<DriverWrapper>> {
        if let Some((_, wrapper)) = self.drivers.remove(device_id) {
            // Disconnect before removing
            let _ = wrapper.disconnect().await;

            tracing::info!(device_id = %device_id, "Removed device from manager");

            Some(wrapper)
        } else {
            None
        }
    }

    /// Gets a driver by device ID.
    pub fn get_driver(&self, device_id: &DeviceId) -> Option<Arc<DriverWrapper>> {
        self.drivers.get(device_id).map(|r| r.value().clone())
    }

    /// Returns `true` if a device exists.
    pub fn has_device(&self, device_id: &DeviceId) -> bool {
        self.drivers.contains_key(device_id)
    }

    /// Returns all device IDs.
    pub fn device_ids(&self) -> Vec<DeviceId> {
        self.drivers.iter().map(|r| r.key().clone()).collect()
    }

    /// Returns the number of managed devices.
    pub fn device_count(&self) -> usize {
        self.drivers.len()
    }

    /// Returns `true` if no devices are managed.
    pub fn is_empty(&self) -> bool {
        self.drivers.is_empty()
    }

    /// Connects all devices.
    pub async fn connect_all(&self) -> Vec<(DeviceId, Result<(), DriverError>)> {
        let mut results = Vec::new();

        for entry in self.drivers.iter() {
            let device_id = entry.key().clone();
            let wrapper = entry.value().clone();

            let result = wrapper.connect().await;

            if let Err(ref e) = result {
                tracing::warn!(device_id = %device_id, error = %e, "Failed to connect device");
            } else {
                tracing::info!(device_id = %device_id, "Connected device");
            }

            results.push((device_id, result));
        }

        results
    }

    /// Disconnects all devices.
    pub async fn disconnect_all(&self) -> Vec<(DeviceId, Result<(), DriverError>)> {
        let mut results = Vec::new();

        for entry in self.drivers.iter() {
            let device_id = entry.key().clone();
            let wrapper = entry.value().clone();

            let result = wrapper.disconnect().await;
            results.push((device_id, result));
        }

        results
    }

    /// Returns health status for all devices.
    pub fn health_check_all(&self) -> Vec<(DeviceId, HealthStatus)> {
        self.drivers
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().health_status()))
            .collect()
    }

    /// Returns devices filtered by protocol.
    pub fn devices_by_protocol(&self, protocol: Protocol) -> Vec<Arc<DriverWrapper>> {
        self.drivers
            .iter()
            .filter(|entry| entry.value().protocol() == protocol)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Returns devices that are currently connected.
    pub fn connected_devices(&self) -> Vec<Arc<DriverWrapper>> {
        self.drivers
            .iter()
            .filter(|entry| entry.value().is_connected())
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Returns devices with open circuit breakers.
    pub fn devices_with_open_circuit(&self) -> Vec<Arc<DriverWrapper>> {
        self.drivers
            .iter()
            .filter(|entry| entry.value().circuit_state() == CircuitState::Open)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Resets circuit breakers for all devices.
    pub fn reset_all_circuit_breakers(&self) {
        for entry in self.drivers.iter() {
            entry.value().reset_circuit_breaker();
        }

        tracing::info!("Reset all circuit breakers");
    }
}

impl std::fmt::Debug for DriverManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriverManager")
            .field("device_count", &self.drivers.len())
            .field("device_ids", &self.device_ids())
            .finish()
    }
}

// =============================================================================
// Device Info
// =============================================================================

/// Information about a managed device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device ID.
    pub id: DeviceId,
    /// Device name.
    pub name: String,
    /// Protocol type.
    pub protocol: Protocol,
    /// Connection status.
    pub connected: bool,
    /// Circuit breaker state.
    pub circuit_state: CircuitState,
    /// Health status.
    pub health: HealthStatus,
    /// Performance metrics.
    pub metrics: DriverMetricsSnapshot,
}

impl DriverWrapper {
    /// Returns device info.
    pub fn info(&self) -> DeviceInfo {
        DeviceInfo {
            id: self.device_id.clone(),
            name: self.name(),
            protocol: self.protocol,
            connected: self.is_connected(),
            circuit_state: self.circuit_state(),
            health: self.health_status(),
            metrics: self.metrics(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    // Mock driver for testing
    struct MockDriver {
        name: String,
        connected: AtomicBool,
    }

    impl MockDriver {
        fn new(name: &str) -> Box<dyn ProtocolDriver> {
            Box::new(Self {
                name: name.to_string(),
                connected: AtomicBool::new(false),
            })
        }
    }

    #[async_trait::async_trait]
    impl ProtocolDriver for MockDriver {
        fn name(&self) -> &str {
            &self.name
        }

        fn protocol(&self) -> Protocol {
            Protocol::Unknown
        }

        async fn connect(&mut self) -> Result<(), DriverError> {
            self.connected.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn disconnect(&mut self) -> Result<(), DriverError> {
            self.connected.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::SeqCst)
        }

        async fn read(&self, _address: &Address) -> Result<Value, DriverError> {
            if !self.is_connected() {
                return Err(DriverError::NotConnected);
            }
            Ok(Value::Float64(42.0))
        }

        async fn write(&self, _address: &Address, _value: Value) -> Result<(), DriverError> {
            if !self.is_connected() {
                return Err(DriverError::NotConnected);
            }
            Ok(())
        }

        async fn health_check(&self) -> HealthStatus {
            if self.is_connected() {
                HealthStatus::healthy()
            } else {
                HealthStatus::unhealthy("Not connected")
            }
        }
    }

    #[test]
    fn test_driver_metrics() {
        let metrics = DriverMetrics::new();

        metrics.record_read(Duration::from_millis(10), true);
        metrics.record_read(Duration::from_millis(20), false);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.reads_total, 2);
        assert_eq!(snapshot.reads_success, 1);
        assert_eq!(snapshot.reads_failed, 1);
    }

    #[tokio::test]
    async fn test_driver_wrapper() {
        let driver = MockDriver::new("test-device");
        let device_id = DeviceId::new("test-device");
        let wrapper = DriverWrapper::new(driver, device_id.clone(), CircuitBreakerConfig::default());

        assert_eq!(wrapper.device_id(), &device_id);
        assert!(!wrapper.is_connected());

        // Connect
        wrapper.connect().await.unwrap();
        assert!(wrapper.is_connected());

        // Read
        use crate::address::GenericAddress;
        let address = Address::Generic(GenericAddress::new("test", "test-addr"));
        let value = wrapper.read(&address).await.unwrap();
        assert!(matches!(value, Value::Float64(_)));

        // Disconnect
        wrapper.disconnect().await.unwrap();
        assert!(!wrapper.is_connected());
    }

    #[test]
    fn test_driver_manager() {
        let registry = Arc::new(DriverRegistry::new());
        let manager = DriverManager::new(registry, CircuitBreakerConfig::default());

        assert!(manager.is_empty());
        assert_eq!(manager.device_count(), 0);
    }

    #[test]
    fn test_metrics_snapshot_serialization() {
        let snapshot = DriverMetricsSnapshot {
            reads_total: 100,
            reads_success: 95,
            reads_failed: 5,
            read_avg_duration: Duration::from_millis(15),
            writes_total: 50,
            writes_success: 48,
            writes_failed: 2,
            write_avg_duration: Duration::from_millis(25),
            last_success: Some(Utc::now()),
            last_error: None,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("reads_total"));
    }
}
