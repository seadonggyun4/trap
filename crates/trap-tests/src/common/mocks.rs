// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # Mock Implementations
//!
//! Mock implementations for testing TRAP components in isolation.
//!
//! ## Design Principles
//!
//! - Configurable behavior for different test scenarios
//! - Recording of interactions for verification
//! - Thread-safe for concurrent testing
//! - Easy to set up error injection

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

use trap_core::{
    types::{DataPoint, DataQuality, DeviceId, Protocol, TagId, Value},
    address::Address,
    error::DriverError,
    driver::{ProtocolDriver, DriverConfig, HealthStatus},
};

// =============================================================================
// Mock Protocol Driver
// =============================================================================

/// A highly configurable mock protocol driver for testing.
#[derive(Debug)]
pub struct MockProtocolDriver {
    /// Driver configuration.
    config: DriverConfig,

    /// Stored values keyed by address.
    values: Arc<RwLock<HashMap<Address, Value>>>,

    /// Connection state.
    connected: AtomicBool,

    /// Simulated read latency.
    read_latency: Arc<Mutex<Duration>>,

    /// Simulated write latency.
    write_latency: Arc<Mutex<Duration>>,

    /// Force next read to fail.
    fail_next_read: AtomicBool,

    /// Force next write to fail.
    fail_next_write: AtomicBool,

    /// Force all reads to fail.
    fail_all_reads: AtomicBool,

    /// Force all writes to fail.
    fail_all_writes: AtomicBool,

    /// Force connection to fail.
    fail_connection: AtomicBool,

    /// Read count for verification.
    read_count: AtomicU64,

    /// Write count for verification.
    write_count: AtomicU64,

    /// Connect count for verification.
    connect_count: AtomicU64,

    /// Disconnect count for verification.
    disconnect_count: AtomicU64,

    /// Write history for verification.
    write_history: Arc<Mutex<Vec<(Address, Value)>>>,
}

impl MockProtocolDriver {
    /// Create a new mock driver with default settings.
    pub fn new(device_id: impl Into<String>) -> Self {
        let id: String = device_id.into();
        Self {
            config: DriverConfig {
                id: id.clone(),
                name: "Mock Driver".to_string(),
                protocol: Protocol::Unknown,
                protocol_config: serde_json::json!({}),
                timeout: Duration::from_secs(5),
                retries: 3,
            },
            values: Arc::new(RwLock::new(HashMap::new())),
            connected: AtomicBool::new(false),
            read_latency: Arc::new(Mutex::new(Duration::from_millis(10))),
            write_latency: Arc::new(Mutex::new(Duration::from_millis(10))),
            fail_next_read: AtomicBool::new(false),
            fail_next_write: AtomicBool::new(false),
            fail_all_reads: AtomicBool::new(false),
            fail_all_writes: AtomicBool::new(false),
            fail_connection: AtomicBool::new(false),
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            connect_count: AtomicU64::new(0),
            disconnect_count: AtomicU64::new(0),
            write_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create with a specific configuration.
    pub fn with_config(config: DriverConfig) -> Self {
        let mut driver = Self::new(&config.id);
        driver.config = config;
        driver
    }

    /// Set a value for an address.
    pub async fn set_value(&self, address: Address, value: Value) {
        self.values.write().await.insert(address, value);
    }

    /// Set multiple values at once.
    pub async fn set_values(&self, values: impl IntoIterator<Item = (Address, Value)>) {
        let mut store = self.values.write().await;
        for (addr, val) in values {
            store.insert(addr, val);
        }
    }

    /// Set the read latency.
    pub async fn set_read_latency(&self, latency: Duration) {
        *self.read_latency.lock().await = latency;
    }

    /// Set the write latency.
    pub async fn set_write_latency(&self, latency: Duration) {
        *self.write_latency.lock().await = latency;
    }

    /// Force the next read to fail.
    pub fn fail_next_read(&self) {
        self.fail_next_read.store(true, Ordering::SeqCst);
    }

    /// Force the next write to fail.
    pub fn fail_next_write(&self) {
        self.fail_next_write.store(true, Ordering::SeqCst);
    }

    /// Force all reads to fail.
    pub fn fail_all_reads(&self, fail: bool) {
        self.fail_all_reads.store(fail, Ordering::SeqCst);
    }

    /// Force all writes to fail.
    pub fn fail_all_writes(&self, fail: bool) {
        self.fail_all_writes.store(fail, Ordering::SeqCst);
    }

    /// Force connection to fail.
    pub fn fail_connection(&self, fail: bool) {
        self.fail_connection.store(fail, Ordering::SeqCst);
    }

    /// Get the read count.
    pub fn get_read_count(&self) -> u64 {
        self.read_count.load(Ordering::SeqCst)
    }

    /// Get the write count.
    pub fn get_write_count(&self) -> u64 {
        self.write_count.load(Ordering::SeqCst)
    }

    /// Get the connect count.
    pub fn get_connect_count(&self) -> u64 {
        self.connect_count.load(Ordering::SeqCst)
    }

    /// Get the disconnect count.
    pub fn get_disconnect_count(&self) -> u64 {
        self.disconnect_count.load(Ordering::SeqCst)
    }

    /// Get the write history.
    pub async fn get_write_history(&self) -> Vec<(Address, Value)> {
        self.write_history.lock().await.clone()
    }

    /// Clear all counters and history.
    pub async fn reset(&self) {
        self.read_count.store(0, Ordering::SeqCst);
        self.write_count.store(0, Ordering::SeqCst);
        self.connect_count.store(0, Ordering::SeqCst);
        self.disconnect_count.store(0, Ordering::SeqCst);
        self.write_history.lock().await.clear();
        self.fail_next_read.store(false, Ordering::SeqCst);
        self.fail_next_write.store(false, Ordering::SeqCst);
        self.fail_all_reads.store(false, Ordering::SeqCst);
        self.fail_all_writes.store(false, Ordering::SeqCst);
        self.fail_connection.store(false, Ordering::SeqCst);
    }
}

#[async_trait]
impl ProtocolDriver for MockProtocolDriver {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn protocol(&self) -> Protocol {
        self.config.protocol.clone()
    }

    async fn connect(&mut self) -> Result<(), DriverError> {
        self.connect_count.fetch_add(1, Ordering::SeqCst);

        if self.fail_connection.load(Ordering::SeqCst) {
            return Err(DriverError::ConnectionFailed {
                message: "Mock connection failure".to_string(),
                source: None,
            });
        }

        self.connected.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), DriverError> {
        self.disconnect_count.fetch_add(1, Ordering::SeqCst);
        self.connected.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    async fn read(&self, address: &Address) -> Result<Value, DriverError> {
        self.read_count.fetch_add(1, Ordering::SeqCst);

        if !self.is_connected() {
            return Err(DriverError::NotConnected);
        }

        // Check for failure modes
        if self.fail_all_reads.load(Ordering::SeqCst) {
            return Err(DriverError::ReadFailed {
                address: address.to_string(),
                message: "Mock read failure".to_string(),
            });
        }

        if self.fail_next_read.swap(false, Ordering::SeqCst) {
            return Err(DriverError::ReadFailed {
                address: address.to_string(),
                message: "Mock single read failure".to_string(),
            });
        }

        // Simulate latency
        let latency = *self.read_latency.lock().await;
        tokio::time::sleep(latency).await;

        // Read value
        self.values
            .read()
            .await
            .get(address)
            .cloned()
            .ok_or_else(|| DriverError::AddressNotFound {
                address: address.to_string(),
            })
    }

    async fn write(&self, address: &Address, value: Value) -> Result<(), DriverError> {
        self.write_count.fetch_add(1, Ordering::SeqCst);

        if !self.is_connected() {
            return Err(DriverError::NotConnected);
        }

        // Check for failure modes
        if self.fail_all_writes.load(Ordering::SeqCst) {
            return Err(DriverError::WriteFailed {
                address: address.to_string(),
                message: "Mock write failure".to_string(),
            });
        }

        if self.fail_next_write.swap(false, Ordering::SeqCst) {
            return Err(DriverError::WriteFailed {
                address: address.to_string(),
                message: "Mock single write failure".to_string(),
            });
        }

        // Simulate latency
        let latency = *self.write_latency.lock().await;
        tokio::time::sleep(latency).await;

        // Record write
        self.write_history
            .lock()
            .await
            .push((address.clone(), value.clone()));

        // Store value
        self.values.write().await.insert(address.clone(), value);

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

// =============================================================================
// Mock Data Generator
// =============================================================================

/// Generates mock data points for testing.
pub struct MockDataGenerator {
    device_id: DeviceId,
    base_value: f64,
    variance: f64,
    counter: AtomicU64,
}

impl MockDataGenerator {
    /// Create a new generator.
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: DeviceId::new(device_id),
            base_value: 25.0,
            variance: 5.0,
            counter: AtomicU64::new(0),
        }
    }

    /// Set the base value.
    pub fn with_base_value(mut self, value: f64) -> Self {
        self.base_value = value;
        self
    }

    /// Set the variance.
    pub fn with_variance(mut self, variance: f64) -> Self {
        self.variance = variance;
        self
    }

    /// Generate a single data point.
    pub fn generate(&self, tag: impl Into<String>) -> DataPoint {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        let offset = (count as f64 * 0.1).sin() * self.variance;
        let value = self.base_value + offset;

        DataPoint::new(
            self.device_id.clone(),
            TagId::new(tag),
            Value::Float64(value),
            DataQuality::Good,
        )
    }

    /// Generate multiple data points.
    pub fn generate_batch(&self, tags: &[&str]) -> Vec<DataPoint> {
        tags.iter().map(|t| self.generate(*t)).collect()
    }

    /// Generate data points with varied quality.
    pub fn generate_varied_quality(&self, tag: impl Into<String>, quality: DataQuality) -> DataPoint {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        let offset = (count as f64 * 0.1).sin() * self.variance;
        let value = self.base_value + offset;

        DataPoint::new(
            self.device_id.clone(),
            TagId::new(tag),
            Value::Float64(value),
            quality,
        )
    }

    /// Generate sequential integer values.
    pub fn generate_sequential(&self, tag: impl Into<String>) -> DataPoint {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        DataPoint::new(
            self.device_id.clone(),
            TagId::new(tag),
            Value::Int64(count as i64),
            DataQuality::Good,
        )
    }
}

// =============================================================================
// Mock Time Controller
// =============================================================================

/// Controls time behavior in tests using tokio's time manipulation.
pub struct MockTimeController;

impl MockTimeController {
    /// Pause time to make tests deterministic.
    /// Note: Requires tokio test runtime with time features.
    pub fn pause() {
        tokio::time::pause();
    }

    /// Resume normal time progression.
    pub fn resume() {
        tokio::time::resume();
    }

    /// Advance time by a specific duration.
    pub async fn advance(duration: Duration) {
        tokio::time::advance(duration).await;
    }

    /// Advance time until all pending timers fire.
    pub async fn advance_until_idle() {
        // Keep advancing small increments until no more timers fire
        for _ in 0..100 {
            tokio::time::advance(Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
        }
    }
}

// =============================================================================
// Mock Failure Injector
// =============================================================================

/// Injects failures according to a pattern.
pub struct MockFailureInjector {
    /// Failure pattern: true = fail, false = succeed.
    pattern: Vec<bool>,
    /// Current index in the pattern.
    index: AtomicU64,
    /// Whether to cycle through the pattern or stop at the end.
    cycle: bool,
}

impl MockFailureInjector {
    /// Create a new injector with a failure pattern.
    pub fn new(pattern: Vec<bool>) -> Self {
        Self {
            pattern,
            index: AtomicU64::new(0),
            cycle: true,
        }
    }

    /// Create an injector that fails every Nth call.
    pub fn every_nth(n: usize) -> Self {
        let mut pattern = vec![false; n];
        if !pattern.is_empty() {
            pattern[n - 1] = true;
        }
        Self::new(pattern).with_cycle(true)
    }

    /// Create an injector that fails the first N calls.
    pub fn first_n(n: usize) -> Self {
        let mut pattern = vec![true; n];
        pattern.push(false);
        Self::new(pattern).with_cycle(false)
    }

    /// Create an injector that always fails.
    pub fn always_fail() -> Self {
        Self::new(vec![true]).with_cycle(true)
    }

    /// Create an injector that never fails.
    pub fn never_fail() -> Self {
        Self::new(vec![false]).with_cycle(true)
    }

    /// Set whether to cycle through the pattern.
    pub fn with_cycle(mut self, cycle: bool) -> Self {
        self.cycle = cycle;
        self
    }

    /// Check if the next operation should fail.
    pub fn should_fail(&self) -> bool {
        if self.pattern.is_empty() {
            return false;
        }

        let index = self.index.fetch_add(1, Ordering::SeqCst) as usize;
        let actual_index = if self.cycle {
            index % self.pattern.len()
        } else {
            index.min(self.pattern.len() - 1)
        };

        self.pattern[actual_index]
    }

    /// Reset the injector.
    pub fn reset(&self) {
        self.index.store(0, Ordering::SeqCst);
    }
}

// =============================================================================
// Mock Event Recorder
// =============================================================================

/// Records events for later verification.
#[derive(Debug, Default)]
pub struct MockEventRecorder<T: Clone + Send + Sync + 'static> {
    events: Arc<Mutex<Vec<(std::time::Instant, T)>>>,
}

impl<T: Clone + Send + Sync + 'static> MockEventRecorder<T> {
    /// Create a new recorder.
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record an event.
    pub async fn record(&self, event: T) {
        self.events
            .lock()
            .await
            .push((std::time::Instant::now(), event));
    }

    /// Get all recorded events.
    pub async fn events(&self) -> Vec<T> {
        self.events
            .lock()
            .await
            .iter()
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Get events with timestamps.
    pub async fn events_with_timestamps(&self) -> Vec<(std::time::Instant, T)> {
        self.events.lock().await.clone()
    }

    /// Get the event count.
    pub async fn count(&self) -> usize {
        self.events.lock().await.len()
    }

    /// Clear all recorded events.
    pub async fn clear(&self) {
        self.events.lock().await.clear();
    }

    /// Wait for a specific number of events.
    pub async fn wait_for_count(&self, count: usize, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.count().await >= count {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }
}
