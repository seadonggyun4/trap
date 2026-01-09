// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Retry strategy abstraction for protocol drivers.
//!
//! This module provides flexible retry policies that can be composed and customized
//! for different use cases in industrial protocol communication.
//!
//! # Design Principles
//!
//! - **Composable**: Strategies can be combined and decorated
//! - **Extensible**: Custom strategies can implement the `RetryStrategy` trait
//! - **Observable**: Built-in metrics and event hooks
//! - **Zero-cost**: No allocations in the hot path when disabled
//!
//! # Built-in Strategies
//!
//! - [`NoRetry`]: No retries, fail immediately
//! - [`FixedDelay`]: Fixed delay between retries
//! - [`ExponentialBackoff`]: Exponentially increasing delays
//! - [`LinearBackoff`]: Linearly increasing delays
//! - [`FibonacciBackoff`]: Fibonacci sequence delays
//! - [`DecorrelatedJitter`]: Randomized delays to prevent thundering herd
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_core::retry::{RetryStrategy, ExponentialBackoff, RetryConfig};
//! use std::time::Duration;
//!
//! let strategy = ExponentialBackoff::new(RetryConfig {
//!     max_attempts: 5,
//!     initial_delay: Duration::from_millis(100),
//!     max_delay: Duration::from_secs(30),
//!     multiplier: 2.0,
//!     ..Default::default()
//! });
//!
//! // Execute with retry
//! let result = strategy.execute(|| async {
//!     // Your operation here
//!     Ok::<_, DriverError>(42)
//! }).await;
//! ```

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::DriverError;

// =============================================================================
// Retry Configuration
// =============================================================================

/// Configuration for retry strategies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = no retries).
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Initial delay before the first retry.
    #[serde(default = "default_initial_delay")]
    #[serde(with = "duration_millis")]
    pub initial_delay: Duration,

    /// Maximum delay between retries.
    #[serde(default = "default_max_delay")]
    #[serde(with = "duration_millis")]
    pub max_delay: Duration,

    /// Multiplier for exponential/linear backoff.
    #[serde(default = "default_multiplier")]
    pub multiplier: f64,

    /// Jitter factor (0.0 to 1.0) to randomize delays.
    #[serde(default)]
    pub jitter: f64,

    /// Whether to retry on timeout errors.
    #[serde(default = "default_true")]
    pub retry_on_timeout: bool,

    /// Whether to retry on connection errors.
    #[serde(default = "default_true")]
    pub retry_on_connection: bool,

    /// Whether to retry on protocol errors.
    #[serde(default)]
    pub retry_on_protocol: bool,
}

fn default_max_attempts() -> u32 {
    3
}

fn default_initial_delay() -> Duration {
    Duration::from_millis(100)
}

fn default_max_delay() -> Duration {
    Duration::from_secs(30)
}

fn default_multiplier() -> f64 {
    2.0
}

fn default_true() -> bool {
    true
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_delay: default_initial_delay(),
            max_delay: default_max_delay(),
            multiplier: default_multiplier(),
            jitter: 0.0,
            retry_on_timeout: true,
            retry_on_connection: true,
            retry_on_protocol: false,
        }
    }
}

impl RetryConfig {
    /// Creates a new retry configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration with no retries.
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 0,
            ..Default::default()
        }
    }

    /// Creates an aggressive retry configuration for critical operations.
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 10,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(60),
            multiplier: 1.5,
            jitter: 0.1,
            retry_on_timeout: true,
            retry_on_connection: true,
            retry_on_protocol: true,
        }
    }

    /// Creates a conservative retry configuration.
    pub fn conservative() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            jitter: 0.2,
            retry_on_timeout: true,
            retry_on_connection: true,
            retry_on_protocol: false,
        }
    }

    /// Sets the maximum number of attempts.
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Sets the initial delay.
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Sets the maximum delay.
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Sets the multiplier.
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Sets the jitter factor.
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }
}

// Duration serialization helper
mod duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

// =============================================================================
// Retry Decision
// =============================================================================

/// Decision on whether to retry an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    /// Retry after the specified delay.
    Retry(Duration),
    /// Do not retry, return the error.
    DoNotRetry,
}

// =============================================================================
// Retry Strategy Trait
// =============================================================================

/// A strategy for determining when and how to retry failed operations.
///
/// Implementations should be `Send + Sync` to allow usage across threads.
#[async_trait]
pub trait RetryStrategy: Send + Sync {
    /// Returns the name of this strategy for logging/metrics.
    fn name(&self) -> &str;

    /// Determines whether to retry after a failure.
    ///
    /// # Arguments
    ///
    /// * `error` - The error that occurred
    /// * `attempt` - The current attempt number (1-based)
    ///
    /// # Returns
    ///
    /// A `RetryDecision` indicating whether to retry and the delay.
    fn should_retry(&self, error: &DriverError, attempt: u32) -> RetryDecision;

    /// Executes an async operation with retry logic.
    ///
    /// # Type Parameters
    ///
    /// * `F` - A factory function that creates a new future for each attempt
    /// * `Fut` - The future type returned by the factory
    /// * `T` - The success type
    ///
    /// # Returns
    ///
    /// The result of the operation, or the last error if all retries failed.
    async fn execute<F, Fut, T>(&self, mut operation: F) -> Result<T, DriverError>
    where
        F: FnMut() -> Fut + Send,
        Fut: Future<Output = Result<T, DriverError>> + Send,
        T: Send,
    {
        let mut attempt = 0u32;

        loop {
            attempt += 1;

            match operation().await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    match self.should_retry(&error, attempt) {
                        RetryDecision::Retry(delay) => {
                            tracing::debug!(
                                strategy = %self.name(),
                                attempt = attempt,
                                delay_ms = delay.as_millis() as u64,
                                error = %error,
                                "Retrying operation"
                            );
                            tokio::time::sleep(delay).await;
                        }
                        RetryDecision::DoNotRetry => {
                            return Err(error);
                        }
                    }
                }
            }
        }
    }

    /// Checks if the error type should be retried based on configuration.
    fn is_retryable_error(&self, error: &DriverError, config: &RetryConfig) -> bool {
        match error {
            DriverError::Timeout { .. } => config.retry_on_timeout,
            DriverError::ConnectionFailed { .. } | DriverError::NotConnected => {
                config.retry_on_connection
            }
            DriverError::Protocol { .. } => config.retry_on_protocol,
            DriverError::CircuitOpen { .. } => false, // Never retry circuit open
            _ => false,
        }
    }
}

// =============================================================================
// No Retry Strategy
// =============================================================================

/// A strategy that never retries - fail immediately on error.
#[derive(Debug, Clone, Default)]
pub struct NoRetry;

impl NoRetry {
    /// Creates a new no-retry strategy.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RetryStrategy for NoRetry {
    fn name(&self) -> &str {
        "no_retry"
    }

    fn should_retry(&self, _error: &DriverError, _attempt: u32) -> RetryDecision {
        RetryDecision::DoNotRetry
    }
}

// =============================================================================
// Fixed Delay Strategy
// =============================================================================

/// A strategy that waits a fixed duration between retries.
#[derive(Debug, Clone)]
pub struct FixedDelay {
    config: RetryConfig,
}

impl FixedDelay {
    /// Creates a new fixed delay strategy.
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Creates a simple fixed delay strategy.
    pub fn simple(max_attempts: u32, delay: Duration) -> Self {
        Self {
            config: RetryConfig {
                max_attempts,
                initial_delay: delay,
                ..Default::default()
            },
        }
    }
}

#[async_trait]
impl RetryStrategy for FixedDelay {
    fn name(&self) -> &str {
        "fixed_delay"
    }

    fn should_retry(&self, error: &DriverError, attempt: u32) -> RetryDecision {
        if attempt >= self.config.max_attempts {
            return RetryDecision::DoNotRetry;
        }

        if !self.is_retryable_error(error, &self.config) {
            return RetryDecision::DoNotRetry;
        }

        let delay = apply_jitter(self.config.initial_delay, self.config.jitter);
        RetryDecision::Retry(delay)
    }
}

// =============================================================================
// Exponential Backoff Strategy
// =============================================================================

/// A strategy with exponentially increasing delays.
///
/// Delay formula: `min(initial_delay * multiplier^(attempt-1), max_delay)`
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    config: RetryConfig,
}

impl ExponentialBackoff {
    /// Creates a new exponential backoff strategy.
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Creates a default exponential backoff strategy.
    pub fn default_strategy() -> Self {
        Self {
            config: RetryConfig::default(),
        }
    }

    /// Calculates the delay for a given attempt.
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base_delay = self.config.initial_delay.as_millis() as f64;
        let multiplied = base_delay * self.config.multiplier.powi(attempt.saturating_sub(1) as i32);
        let capped = multiplied.min(self.config.max_delay.as_millis() as f64);

        Duration::from_millis(capped as u64)
    }
}

#[async_trait]
impl RetryStrategy for ExponentialBackoff {
    fn name(&self) -> &str {
        "exponential_backoff"
    }

    fn should_retry(&self, error: &DriverError, attempt: u32) -> RetryDecision {
        if attempt >= self.config.max_attempts {
            return RetryDecision::DoNotRetry;
        }

        if !self.is_retryable_error(error, &self.config) {
            return RetryDecision::DoNotRetry;
        }

        let base_delay = self.calculate_delay(attempt);
        let delay = apply_jitter(base_delay, self.config.jitter);
        RetryDecision::Retry(delay)
    }
}

// =============================================================================
// Linear Backoff Strategy
// =============================================================================

/// A strategy with linearly increasing delays.
///
/// Delay formula: `min(initial_delay + (attempt-1) * initial_delay * multiplier, max_delay)`
#[derive(Debug, Clone)]
pub struct LinearBackoff {
    config: RetryConfig,
}

impl LinearBackoff {
    /// Creates a new linear backoff strategy.
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Calculates the delay for a given attempt.
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base_millis = self.config.initial_delay.as_millis() as f64;
        let increment = base_millis * self.config.multiplier * (attempt.saturating_sub(1) as f64);
        let total = (base_millis + increment).min(self.config.max_delay.as_millis() as f64);

        Duration::from_millis(total as u64)
    }
}

#[async_trait]
impl RetryStrategy for LinearBackoff {
    fn name(&self) -> &str {
        "linear_backoff"
    }

    fn should_retry(&self, error: &DriverError, attempt: u32) -> RetryDecision {
        if attempt >= self.config.max_attempts {
            return RetryDecision::DoNotRetry;
        }

        if !self.is_retryable_error(error, &self.config) {
            return RetryDecision::DoNotRetry;
        }

        let base_delay = self.calculate_delay(attempt);
        let delay = apply_jitter(base_delay, self.config.jitter);
        RetryDecision::Retry(delay)
    }
}

// =============================================================================
// Fibonacci Backoff Strategy
// =============================================================================

/// A strategy with Fibonacci sequence delays.
///
/// Uses Fibonacci numbers for a more gradual backoff than exponential.
#[derive(Debug, Clone)]
pub struct FibonacciBackoff {
    config: RetryConfig,
}

impl FibonacciBackoff {
    /// Creates a new Fibonacci backoff strategy.
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Calculates the nth Fibonacci number (capped).
    fn fibonacci(n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        if n == 1 {
            return 1;
        }

        let mut a: u64 = 0;
        let mut b: u64 = 1;

        for _ in 2..=n {
            let temp = a.saturating_add(b);
            a = b;
            b = temp;
        }

        b
    }

    /// Calculates the delay for a given attempt.
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let fib = Self::fibonacci(attempt);
        let base_millis = self.config.initial_delay.as_millis() as u64;
        let total_millis = base_millis.saturating_mul(fib);
        let capped = total_millis.min(self.config.max_delay.as_millis() as u64);

        Duration::from_millis(capped)
    }
}

#[async_trait]
impl RetryStrategy for FibonacciBackoff {
    fn name(&self) -> &str {
        "fibonacci_backoff"
    }

    fn should_retry(&self, error: &DriverError, attempt: u32) -> RetryDecision {
        if attempt >= self.config.max_attempts {
            return RetryDecision::DoNotRetry;
        }

        if !self.is_retryable_error(error, &self.config) {
            return RetryDecision::DoNotRetry;
        }

        let base_delay = self.calculate_delay(attempt);
        let delay = apply_jitter(base_delay, self.config.jitter);
        RetryDecision::Retry(delay)
    }
}

// =============================================================================
// Decorrelated Jitter Strategy
// =============================================================================

/// A strategy that uses decorrelated jitter to prevent thundering herd.
///
/// Based on AWS's decorrelated jitter algorithm:
/// `sleep = min(cap, random_between(base, sleep * 3))`
///
/// This provides good spread of retry times to prevent multiple clients
/// from retrying simultaneously.
#[derive(Debug)]
pub struct DecorrelatedJitter {
    config: RetryConfig,
    /// Last computed delay (for decorrelation).
    last_delay_ms: AtomicU64,
}

impl DecorrelatedJitter {
    /// Creates a new decorrelated jitter strategy.
    pub fn new(config: RetryConfig) -> Self {
        Self {
            last_delay_ms: AtomicU64::new(config.initial_delay.as_millis() as u64),
            config,
        }
    }

    /// Calculates the next delay using decorrelated jitter.
    fn calculate_delay(&self) -> Duration {
        let base_ms = self.config.initial_delay.as_millis() as u64;
        let last_ms = self.last_delay_ms.load(Ordering::Relaxed);
        let cap_ms = self.config.max_delay.as_millis() as u64;

        // Random value between base and last * 3
        let max_range = last_ms.saturating_mul(3);
        let random_factor = simple_random() as f64 / u32::MAX as f64;
        let range = max_range.saturating_sub(base_ms);
        let jittered = base_ms + (range as f64 * random_factor) as u64;

        let capped = jittered.min(cap_ms);
        self.last_delay_ms.store(capped, Ordering::Relaxed);

        Duration::from_millis(capped)
    }

    /// Resets the jitter state.
    pub fn reset(&self) {
        self.last_delay_ms
            .store(self.config.initial_delay.as_millis() as u64, Ordering::Relaxed);
    }
}

impl Clone for DecorrelatedJitter {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            last_delay_ms: AtomicU64::new(self.last_delay_ms.load(Ordering::Relaxed)),
        }
    }
}

#[async_trait]
impl RetryStrategy for DecorrelatedJitter {
    fn name(&self) -> &str {
        "decorrelated_jitter"
    }

    fn should_retry(&self, error: &DriverError, attempt: u32) -> RetryDecision {
        if attempt >= self.config.max_attempts {
            // Reset state for next retry sequence
            self.reset();
            return RetryDecision::DoNotRetry;
        }

        if !self.is_retryable_error(error, &self.config) {
            self.reset();
            return RetryDecision::DoNotRetry;
        }

        RetryDecision::Retry(self.calculate_delay())
    }
}

// =============================================================================
// Retry Metrics
// =============================================================================

/// Metrics for retry operations.
#[derive(Debug, Default)]
pub struct RetryMetrics {
    /// Total operations attempted.
    total_operations: AtomicU64,
    /// Operations that succeeded on first try.
    first_try_success: AtomicU64,
    /// Operations that succeeded after retry.
    retry_success: AtomicU64,
    /// Operations that exhausted all retries.
    exhausted: AtomicU64,
    /// Total retry attempts across all operations.
    total_retries: AtomicU64,
}

impl RetryMetrics {
    /// Creates new metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a successful first-try operation.
    pub fn record_first_try_success(&self) {
        self.total_operations.fetch_add(1, Ordering::Relaxed);
        self.first_try_success.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a successful operation after retries.
    pub fn record_retry_success(&self, retries: u32) {
        self.total_operations.fetch_add(1, Ordering::Relaxed);
        self.retry_success.fetch_add(1, Ordering::Relaxed);
        self.total_retries.fetch_add(retries as u64, Ordering::Relaxed);
    }

    /// Records an operation that exhausted all retries.
    pub fn record_exhausted(&self, retries: u32) {
        self.total_operations.fetch_add(1, Ordering::Relaxed);
        self.exhausted.fetch_add(1, Ordering::Relaxed);
        self.total_retries.fetch_add(retries as u64, Ordering::Relaxed);
    }

    /// Returns a snapshot of the metrics.
    pub fn snapshot(&self) -> RetryMetricsSnapshot {
        let total = self.total_operations.load(Ordering::Relaxed);
        let first_success = self.first_try_success.load(Ordering::Relaxed);
        let retry_success = self.retry_success.load(Ordering::Relaxed);
        let exhausted = self.exhausted.load(Ordering::Relaxed);
        let total_retries = self.total_retries.load(Ordering::Relaxed);

        let success_rate = if total > 0 {
            (first_success + retry_success) as f64 / total as f64
        } else {
            0.0
        };

        let avg_retries = if retry_success + exhausted > 0 {
            total_retries as f64 / (retry_success + exhausted) as f64
        } else {
            0.0
        };

        RetryMetricsSnapshot {
            total_operations: total,
            first_try_success: first_success,
            retry_success,
            exhausted,
            total_retries,
            success_rate,
            average_retries_per_failure: avg_retries,
        }
    }
}

/// A snapshot of retry metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryMetricsSnapshot {
    /// Total operations attempted.
    pub total_operations: u64,
    /// Operations that succeeded on first try.
    pub first_try_success: u64,
    /// Operations that succeeded after retry.
    pub retry_success: u64,
    /// Operations that exhausted all retries.
    pub exhausted: u64,
    /// Total retry attempts.
    pub total_retries: u64,
    /// Overall success rate (0.0 to 1.0).
    pub success_rate: f64,
    /// Average retries per failed first attempt.
    pub average_retries_per_failure: f64,
}

// =============================================================================
// Strategy with Metrics
// =============================================================================

/// A wrapper that adds metrics tracking to any retry strategy.
pub struct MeteredRetryStrategy<S: RetryStrategy> {
    inner: S,
    metrics: RetryMetrics,
    current_attempt: AtomicU32,
}

impl<S: RetryStrategy> MeteredRetryStrategy<S> {
    /// Creates a new metered retry strategy.
    pub fn new(strategy: S) -> Self {
        Self {
            inner: strategy,
            metrics: RetryMetrics::new(),
            current_attempt: AtomicU32::new(0),
        }
    }

    /// Returns the metrics.
    pub fn metrics(&self) -> &RetryMetrics {
        &self.metrics
    }

    /// Returns the inner strategy.
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

#[async_trait]
impl<S: RetryStrategy> RetryStrategy for MeteredRetryStrategy<S> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn should_retry(&self, error: &DriverError, attempt: u32) -> RetryDecision {
        self.current_attempt.store(attempt, Ordering::Relaxed);
        self.inner.should_retry(error, attempt)
    }

    async fn execute<F, Fut, T>(&self, mut operation: F) -> Result<T, DriverError>
    where
        F: FnMut() -> Fut + Send,
        Fut: Future<Output = Result<T, DriverError>> + Send,
        T: Send,
    {
        let mut attempt = 0u32;

        loop {
            attempt += 1;
            self.current_attempt.store(attempt, Ordering::Relaxed);

            match operation().await {
                Ok(value) => {
                    if attempt == 1 {
                        self.metrics.record_first_try_success();
                    } else {
                        self.metrics.record_retry_success(attempt - 1);
                    }
                    return Ok(value);
                }
                Err(error) => {
                    match self.should_retry(&error, attempt) {
                        RetryDecision::Retry(delay) => {
                            tracing::debug!(
                                strategy = %self.name(),
                                attempt = attempt,
                                delay_ms = delay.as_millis() as u64,
                                error = %error,
                                "Retrying operation"
                            );
                            tokio::time::sleep(delay).await;
                        }
                        RetryDecision::DoNotRetry => {
                            if attempt > 1 {
                                self.metrics.record_exhausted(attempt - 1);
                            }
                            return Err(error);
                        }
                    }
                }
            }
        }
    }
}

impl<S: RetryStrategy + fmt::Debug> fmt::Debug for MeteredRetryStrategy<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeteredRetryStrategy")
            .field("inner", &self.inner)
            .field("metrics", &self.metrics.snapshot())
            .finish()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Applies jitter to a duration.
fn apply_jitter(duration: Duration, jitter_factor: f64) -> Duration {
    if jitter_factor <= 0.0 {
        return duration;
    }

    let millis = duration.as_millis() as f64;
    let jitter_range = millis * jitter_factor;
    let random = (simple_random() as f64 / u32::MAX as f64) * 2.0 - 1.0; // -1.0 to 1.0
    let jittered = millis + (random * jitter_range);

    Duration::from_millis(jittered.max(0.0) as u64)
}

/// Simple pseudo-random number generator (not cryptographically secure).
/// Uses a basic xorshift algorithm for lightweight randomness.
fn simple_random() -> u32 {
    use std::time::SystemTime;

    static SEED: AtomicU32 = AtomicU32::new(0);

    let mut x = SEED.load(Ordering::Relaxed);
    if x == 0 {
        // Initialize seed from system time
        x = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(12345);
    }

    // Xorshift32
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;

    SEED.store(x, Ordering::Relaxed);
    x
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay, Duration::from_millis(100));
        assert_eq!(config.max_delay, Duration::from_secs(30));
        assert_eq!(config.multiplier, 2.0);
    }

    #[test]
    fn test_retry_config_builder() {
        let config = RetryConfig::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(200))
            .with_jitter(0.2);

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_delay, Duration::from_millis(200));
        assert_eq!(config.jitter, 0.2);
    }

    #[test]
    fn test_no_retry_strategy() {
        let strategy = NoRetry::new();
        let error = DriverError::Timeout {
            duration: Duration::from_secs(1),
        };

        assert_eq!(strategy.should_retry(&error, 1), RetryDecision::DoNotRetry);
    }

    #[test]
    fn test_fixed_delay_strategy() {
        let strategy = FixedDelay::simple(3, Duration::from_millis(100));
        let error = DriverError::Timeout {
            duration: Duration::from_secs(1),
        };

        // First two attempts should retry
        assert!(matches!(
            strategy.should_retry(&error, 1),
            RetryDecision::Retry(_)
        ));
        assert!(matches!(
            strategy.should_retry(&error, 2),
            RetryDecision::Retry(_)
        ));

        // Third attempt should not retry (max_attempts = 3)
        assert_eq!(strategy.should_retry(&error, 3), RetryDecision::DoNotRetry);
    }

    #[test]
    fn test_exponential_backoff_delays() {
        let strategy = ExponentialBackoff::new(RetryConfig {
            max_attempts: 5,
            initial_delay: Duration::from_millis(100),
            multiplier: 2.0,
            jitter: 0.0,
            ..Default::default()
        });

        // Verify exponential growth
        let delay1 = strategy.calculate_delay(1);
        let delay2 = strategy.calculate_delay(2);
        let delay3 = strategy.calculate_delay(3);

        assert_eq!(delay1, Duration::from_millis(100)); // 100 * 2^0
        assert_eq!(delay2, Duration::from_millis(200)); // 100 * 2^1
        assert_eq!(delay3, Duration::from_millis(400)); // 100 * 2^2
    }

    #[test]
    fn test_exponential_backoff_caps_at_max() {
        let strategy = ExponentialBackoff::new(RetryConfig {
            max_attempts: 10,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
            multiplier: 2.0,
            jitter: 0.0,
            ..Default::default()
        });

        // Should cap at max_delay
        let delay = strategy.calculate_delay(10);
        assert_eq!(delay, Duration::from_millis(500));
    }

    #[test]
    fn test_linear_backoff_delays() {
        let strategy = LinearBackoff::new(RetryConfig {
            max_attempts: 5,
            initial_delay: Duration::from_millis(100),
            multiplier: 1.0,
            jitter: 0.0,
            ..Default::default()
        });

        let delay1 = strategy.calculate_delay(1);
        let delay2 = strategy.calculate_delay(2);
        let delay3 = strategy.calculate_delay(3);

        assert_eq!(delay1, Duration::from_millis(100)); // 100 + 0 * 100
        assert_eq!(delay2, Duration::from_millis(200)); // 100 + 1 * 100
        assert_eq!(delay3, Duration::from_millis(300)); // 100 + 2 * 100
    }

    #[test]
    fn test_fibonacci_backoff_delays() {
        let strategy = FibonacciBackoff::new(RetryConfig {
            max_attempts: 10,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(60),
            jitter: 0.0,
            ..Default::default()
        });

        // Fibonacci: 1, 1, 2, 3, 5, 8, 13, 21, 34, 55
        let delay1 = strategy.calculate_delay(1);
        let delay2 = strategy.calculate_delay(2);
        let delay3 = strategy.calculate_delay(3);
        let delay5 = strategy.calculate_delay(5);

        assert_eq!(delay1, Duration::from_millis(10)); // 10 * 1
        assert_eq!(delay2, Duration::from_millis(10)); // 10 * 1
        assert_eq!(delay3, Duration::from_millis(20)); // 10 * 2
        assert_eq!(delay5, Duration::from_millis(50)); // 10 * 5
    }

    #[test]
    fn test_fibonacci_helper() {
        assert_eq!(FibonacciBackoff::fibonacci(0), 0);
        assert_eq!(FibonacciBackoff::fibonacci(1), 1);
        assert_eq!(FibonacciBackoff::fibonacci(2), 1);
        assert_eq!(FibonacciBackoff::fibonacci(3), 2);
        assert_eq!(FibonacciBackoff::fibonacci(4), 3);
        assert_eq!(FibonacciBackoff::fibonacci(5), 5);
        assert_eq!(FibonacciBackoff::fibonacci(10), 55);
    }

    #[test]
    fn test_non_retryable_errors() {
        let strategy = ExponentialBackoff::new(RetryConfig::default());

        // Circuit open should never be retried
        let circuit_error = DriverError::circuit_open("test");
        assert_eq!(
            strategy.should_retry(&circuit_error, 1),
            RetryDecision::DoNotRetry
        );

        // Protocol errors not retried by default
        let protocol_error = DriverError::protocol("test error");
        assert_eq!(
            strategy.should_retry(&protocol_error, 1),
            RetryDecision::DoNotRetry
        );
    }

    #[test]
    fn test_retry_metrics() {
        let metrics = RetryMetrics::new();

        metrics.record_first_try_success();
        metrics.record_first_try_success();
        metrics.record_retry_success(2);
        metrics.record_exhausted(3);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.total_operations, 4);
        assert_eq!(snapshot.first_try_success, 2);
        assert_eq!(snapshot.retry_success, 1);
        assert_eq!(snapshot.exhausted, 1);
        assert_eq!(snapshot.total_retries, 5); // 2 + 3
        assert_eq!(snapshot.success_rate, 0.75); // 3/4
    }

    #[test]
    fn test_jitter_application() {
        let base = Duration::from_millis(100);

        // No jitter
        let no_jitter = apply_jitter(base, 0.0);
        assert_eq!(no_jitter, base);

        // With jitter (should vary)
        let with_jitter1 = apply_jitter(base, 0.5);
        let with_jitter2 = apply_jitter(base, 0.5);

        // At least one should be different (probabilistically)
        // This is a weak test but avoids flakiness
        assert!(with_jitter1.as_millis() >= 50 && with_jitter1.as_millis() <= 150);
        assert!(with_jitter2.as_millis() >= 50 && with_jitter2.as_millis() <= 150);
    }

    #[test]
    fn test_config_serialization() {
        let config = RetryConfig::default();
        let json = serde_json::to_string(&config).unwrap();

        assert!(json.contains("max_attempts"));
        assert!(json.contains("initial_delay"));

        let parsed: RetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_attempts, config.max_attempts);
    }

    #[tokio::test]
    async fn test_retry_execution() {
        use std::sync::atomic::AtomicU32;

        let attempts = AtomicU32::new(0);
        let strategy = FixedDelay::simple(3, Duration::from_millis(1));

        let result: Result<i32, DriverError> = strategy
            .execute(|| {
                let current = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if current < 2 {
                        Err(DriverError::Timeout {
                            duration: Duration::from_secs(1),
                        })
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }
}
