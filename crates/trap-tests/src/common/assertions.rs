// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # Custom Test Assertions
//!
//! Domain-specific assertion helpers for TRAP integration tests.
//!
//! ## Design Principles
//!
//! - Provide clear, informative failure messages
//! - Support both synchronous and asynchronous assertions
//! - Chain-able assertions for complex validations

use std::time::Duration;
use trap_core::{
    types::{DataPoint, DataQuality, Value},
    bus::BusStats,
    driver::CircuitState,
};

// =============================================================================
// DataPoint Assertions
// =============================================================================

/// Assertion extensions for DataPoint.
pub trait DataPointAssertions {
    /// Assert that the data point has good quality.
    fn assert_good_quality(&self);

    /// Assert that the data point has a specific quality.
    fn assert_quality(&self, expected: DataQuality);

    /// Assert that the value matches.
    fn assert_value(&self, expected: &Value);

    /// Assert that the value is within a tolerance (for floats).
    fn assert_value_approx(&self, expected: f64, tolerance: f64);

    /// Assert that the timestamp is recent (within the given duration).
    fn assert_recent(&self, max_age: Duration);

    /// Assert device and tag IDs match.
    fn assert_identity(&self, device_id: &str, tag_id: &str);
}

impl DataPointAssertions for DataPoint {
    fn assert_good_quality(&self) {
        assert_eq!(
            self.quality,
            DataQuality::Good,
            "Expected Good quality, but got {:?} for {}:{}",
            self.quality,
            self.device_id,
            self.tag_id
        );
    }

    fn assert_quality(&self, expected: DataQuality) {
        assert_eq!(
            self.quality, expected,
            "Expected {:?} quality, but got {:?} for {}:{}",
            expected, self.quality, self.device_id, self.tag_id
        );
    }

    fn assert_value(&self, expected: &Value) {
        assert_eq!(
            &self.value, expected,
            "Expected value {:?}, but got {:?} for {}:{}",
            expected, self.value, self.device_id, self.tag_id
        );
    }

    fn assert_value_approx(&self, expected: f64, tolerance: f64) {
        let actual = self.value.as_f64().expect("Value is not convertible to f64");
        let diff = (actual - expected).abs();
        assert!(
            diff <= tolerance,
            "Expected value {} ± {}, but got {} (diff: {}) for {}:{}",
            expected,
            tolerance,
            actual,
            diff,
            self.device_id,
            self.tag_id
        );
    }

    fn assert_recent(&self, max_age: Duration) {
        let age = chrono::Utc::now()
            .signed_duration_since(self.timestamp)
            .to_std()
            .unwrap_or(Duration::from_secs(u64::MAX));
        assert!(
            age <= max_age,
            "DataPoint is too old: {:?} (max allowed: {:?}) for {}:{}",
            age,
            max_age,
            self.device_id,
            self.tag_id
        );
    }

    fn assert_identity(&self, device_id: &str, tag_id: &str) {
        assert_eq!(
            self.device_id.as_str(),
            device_id,
            "Expected device_id '{}', but got '{}'",
            device_id,
            self.device_id
        );
        assert_eq!(
            self.tag_id.as_str(),
            tag_id,
            "Expected tag_id '{}', but got '{}'",
            tag_id,
            self.tag_id
        );
    }
}

// =============================================================================
// Value Assertions
// =============================================================================

/// Assertion extensions for Value.
pub trait ValueAssertions {
    /// Assert that the value is a boolean.
    fn assert_is_bool(&self) -> bool;

    /// Assert that the value is a specific boolean.
    fn assert_bool(&self, expected: bool);

    /// Assert that the value is numeric.
    fn assert_is_numeric(&self) -> f64;

    /// Assert that the value is approximately equal to expected.
    fn assert_approx(&self, expected: f64, tolerance: f64);

    /// Assert that the value is within a range.
    fn assert_in_range(&self, min: f64, max: f64);

    /// Assert that the value is a string.
    fn assert_is_string(&self) -> String;

    /// Assert that the value is null.
    fn assert_is_null(&self);
}

impl ValueAssertions for Value {
    fn assert_is_bool(&self) -> bool {
        match self {
            Value::Bool(v) => *v,
            _ => panic!("Expected Bool, but got {:?}", self),
        }
    }

    fn assert_bool(&self, expected: bool) {
        let actual = self.assert_is_bool();
        assert_eq!(actual, expected, "Expected {}, but got {}", expected, actual);
    }

    fn assert_is_numeric(&self) -> f64 {
        self.as_f64()
            .unwrap_or_else(|| panic!("Expected numeric value, but got {:?}", self))
    }

    fn assert_approx(&self, expected: f64, tolerance: f64) {
        let actual = self.assert_is_numeric();
        let diff = (actual - expected).abs();
        assert!(
            diff <= tolerance,
            "Expected {} ± {}, but got {} (diff: {})",
            expected,
            tolerance,
            actual,
            diff
        );
    }

    fn assert_in_range(&self, min: f64, max: f64) {
        let actual = self.assert_is_numeric();
        assert!(
            actual >= min && actual <= max,
            "Expected value in range [{}, {}], but got {}",
            min,
            max,
            actual
        );
    }

    fn assert_is_string(&self) -> String {
        match self {
            Value::String(s) => s.clone(),
            _ => panic!("Expected String, but got {:?}", self),
        }
    }

    fn assert_is_null(&self) {
        assert!(
            matches!(self, Value::Null),
            "Expected Null, but got {:?}",
            self
        );
    }
}

// =============================================================================
// Circuit Breaker Assertions
// =============================================================================

/// Assertion extensions for CircuitState.
pub trait CircuitStateAssertions {
    /// Assert that the circuit is closed.
    fn assert_closed(&self);

    /// Assert that the circuit is open.
    fn assert_open(&self);

    /// Assert that the circuit is half-open.
    fn assert_half_open(&self);
}

impl CircuitStateAssertions for CircuitState {
    fn assert_closed(&self) {
        assert!(
            matches!(self, CircuitState::Closed),
            "Expected Closed circuit, but got {:?}",
            self
        );
    }

    fn assert_open(&self) {
        assert!(
            matches!(self, CircuitState::Open),
            "Expected Open circuit, but got {:?}",
            self
        );
    }

    fn assert_half_open(&self) {
        assert!(
            matches!(self, CircuitState::HalfOpen),
            "Expected HalfOpen circuit, but got {:?}",
            self
        );
    }
}

// =============================================================================
// Bus Stats Assertions
// =============================================================================

/// Assertion extensions for BusStats.
pub trait BusStatsAssertions {
    /// Assert that a certain number of messages were published.
    fn assert_published(&self, expected: u64);

    /// Assert that a certain number of messages were dropped.
    fn assert_dropped(&self, expected: u64);

    /// Assert that no messages were dropped.
    fn assert_no_drops(&self);

    /// Assert that all published messages were received.
    fn assert_all_received(&self);
}

impl BusStatsAssertions for BusStats {
    fn assert_published(&self, expected: u64) {
        assert_eq!(
            self.messages_published, expected,
            "Expected {} published messages, but got {}",
            expected, self.messages_published
        );
    }

    fn assert_dropped(&self, expected: u64) {
        assert_eq!(
            self.messages_dropped, expected,
            "Expected {} dropped messages, but got {}",
            expected, self.messages_dropped
        );
    }

    fn assert_no_drops(&self) {
        assert_eq!(
            self.messages_dropped, 0,
            "Expected no dropped messages, but {} were dropped",
            self.messages_dropped
        );
    }

    fn assert_all_received(&self) {
        self.assert_no_drops();
    }
}

// =============================================================================
// Collection Assertions
// =============================================================================

/// Assertion extensions for DataPoint collections.
pub trait DataPointCollectionAssertions {
    /// Assert that all data points have good quality.
    fn assert_all_good_quality(&self);

    /// Assert that all data points are from the same device.
    fn assert_same_device(&self, device_id: &str);

    /// Assert the collection size.
    fn assert_count(&self, expected: usize);

    /// Assert that data points are ordered by timestamp.
    fn assert_ordered_by_timestamp(&self);

    /// Assert that all values are within a range.
    fn assert_all_values_in_range(&self, min: f64, max: f64);
}

impl DataPointCollectionAssertions for Vec<DataPoint> {
    fn assert_all_good_quality(&self) {
        for (i, dp) in self.iter().enumerate() {
            assert_eq!(
                dp.quality,
                DataQuality::Good,
                "DataPoint at index {} has quality {:?}, expected Good",
                i,
                dp.quality
            );
        }
    }

    fn assert_same_device(&self, device_id: &str) {
        for (i, dp) in self.iter().enumerate() {
            assert_eq!(
                dp.device_id.as_str(),
                device_id,
                "DataPoint at index {} has device_id '{}', expected '{}'",
                i,
                dp.device_id,
                device_id
            );
        }
    }

    fn assert_count(&self, expected: usize) {
        assert_eq!(
            self.len(),
            expected,
            "Expected {} data points, but got {}",
            expected,
            self.len()
        );
    }

    fn assert_ordered_by_timestamp(&self) {
        for i in 1..self.len() {
            assert!(
                self[i].timestamp >= self[i - 1].timestamp,
                "DataPoints are not ordered by timestamp at index {}: {:?} < {:?}",
                i,
                self[i].timestamp,
                self[i - 1].timestamp
            );
        }
    }

    fn assert_all_values_in_range(&self, min: f64, max: f64) {
        for (i, dp) in self.iter().enumerate() {
            if let Some(v) = dp.value.as_f64() {
                assert!(
                    v >= min && v <= max,
                    "DataPoint at index {} has value {} outside range [{}, {}]",
                    i,
                    v,
                    min,
                    max
                );
            }
        }
    }
}

// =============================================================================
// Result Assertions
// =============================================================================

/// Assertion helper for Results.
pub trait ResultAssertions<T, E> {
    /// Assert that the result is Ok and return the value.
    fn assert_ok(self) -> T;

    /// Assert that the result is Err.
    fn assert_err(self) -> E;

    /// Assert that the result is Ok and matches a predicate.
    fn assert_ok_with<F>(self, predicate: F)
    where
        F: FnOnce(&T) -> bool;
}

impl<T: std::fmt::Debug, E: std::fmt::Debug> ResultAssertions<T, E> for Result<T, E> {
    fn assert_ok(self) -> T {
        match self {
            Ok(v) => v,
            Err(e) => panic!("Expected Ok, but got Err: {:?}", e),
        }
    }

    fn assert_err(self) -> E {
        match self {
            Ok(v) => panic!("Expected Err, but got Ok: {:?}", v),
            Err(e) => e,
        }
    }

    fn assert_ok_with<F>(self, predicate: F)
    where
        F: FnOnce(&T) -> bool,
    {
        let value = self.assert_ok();
        assert!(predicate(&value), "Ok value did not match predicate");
    }
}

// =============================================================================
// Async Assertion Helpers
// =============================================================================

/// Wait for a condition to become true within a timeout.
pub async fn wait_for<F, Fut>(
    timeout: Duration,
    interval: Duration,
    mut condition: F,
) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if condition().await {
            return true;
        }
        tokio::time::sleep(interval).await;
    }
    false
}

/// Wait for a condition to become true, panicking if it doesn't.
pub async fn wait_for_or_panic<F, Fut>(
    timeout: Duration,
    interval: Duration,
    message: &str,
    condition: F,
)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    if !wait_for(timeout, interval, condition).await {
        panic!("Condition not met within {:?}: {}", timeout, message);
    }
}

// =============================================================================
// Macro Assertions
// =============================================================================

/// Assert that an async operation completes within a timeout.
#[macro_export]
macro_rules! assert_completes_within {
    ($timeout:expr, $future:expr) => {{
        match tokio::time::timeout($timeout, $future).await {
            Ok(result) => result,
            Err(_) => panic!(
                "Operation did not complete within {:?}",
                $timeout
            ),
        }
    }};
}

/// Assert that an operation eventually succeeds with retries.
#[macro_export]
macro_rules! assert_eventually {
    ($max_attempts:expr, $delay:expr, $check:expr) => {{
        let mut attempts = 0;
        loop {
            attempts += 1;
            if $check {
                break;
            }
            if attempts >= $max_attempts {
                panic!(
                    "Condition not met after {} attempts",
                    $max_attempts
                );
            }
            tokio::time::sleep($delay).await;
        }
    }};
}
