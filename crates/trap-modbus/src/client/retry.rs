// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Retry and backoff strategies for Modbus operations.
//!
//! This module provides configurable retry strategies with exponential backoff
//! and jitter for resilient Modbus communication.

use std::time::Duration;

use rand::Rng;

// =============================================================================
// RetryConfig
// =============================================================================

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = no retries).
    pub max_retries: u32,
    /// Retry strategy to use.
    pub strategy: RetryStrategy,
    /// Whether to retry on timeout errors.
    pub retry_on_timeout: bool,
    /// Whether to retry on connection errors.
    pub retry_on_connection: bool,
}

impl RetryConfig {
    /// Creates a new retry configuration with the given max retries.
    pub fn new(max_retries: u32) -> Self {
        Self {
            max_retries,
            strategy: RetryStrategy::default(),
            retry_on_timeout: true,
            retry_on_connection: true,
        }
    }

    /// Creates a configuration with no retries.
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            strategy: RetryStrategy::Fixed(Duration::from_millis(0)),
            retry_on_timeout: false,
            retry_on_connection: false,
        }
    }

    /// Creates a configuration with exponential backoff.
    pub fn exponential(max_retries: u32, initial_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_retries,
            strategy: RetryStrategy::Exponential(ExponentialBackoff::new(initial_delay, max_delay)),
            retry_on_timeout: true,
            retry_on_connection: true,
        }
    }

    /// Creates a configuration with fixed delay.
    pub fn fixed(max_retries: u32, delay: Duration) -> Self {
        Self {
            max_retries,
            strategy: RetryStrategy::Fixed(delay),
            retry_on_timeout: true,
            retry_on_connection: true,
        }
    }

    /// Sets whether to retry on timeout errors.
    pub fn with_retry_on_timeout(mut self, retry: bool) -> Self {
        self.retry_on_timeout = retry;
        self
    }

    /// Sets whether to retry on connection errors.
    pub fn with_retry_on_connection(mut self, retry: bool) -> Self {
        self.retry_on_connection = retry;
        self
    }

    /// Sets the retry strategy.
    pub fn with_strategy(mut self, strategy: RetryStrategy) -> Self {
        self.strategy = strategy;
        self
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            strategy: RetryStrategy::default(),
            retry_on_timeout: true,
            retry_on_connection: true,
        }
    }
}

// =============================================================================
// RetryStrategy
// =============================================================================

/// Strategy for calculating retry delays.
#[derive(Debug, Clone)]
pub enum RetryStrategy {
    /// No delay between retries.
    Immediate,
    /// Fixed delay between retries.
    Fixed(Duration),
    /// Linear backoff (delay * attempt).
    Linear(LinearBackoff),
    /// Exponential backoff with optional jitter.
    Exponential(ExponentialBackoff),
    /// Custom delay function.
    Custom(CustomBackoff),
}

impl RetryStrategy {
    /// Calculates the delay for the given attempt number (0-based).
    pub fn delay(&self, attempt: u32) -> Duration {
        match self {
            Self::Immediate => Duration::ZERO,
            Self::Fixed(duration) => *duration,
            Self::Linear(linear) => linear.delay(attempt),
            Self::Exponential(exp) => exp.delay(attempt),
            Self::Custom(custom) => custom.delay(attempt),
        }
    }

    /// Creates an immediate retry strategy.
    pub fn immediate() -> Self {
        Self::Immediate
    }

    /// Creates a fixed delay strategy.
    pub fn fixed(delay: Duration) -> Self {
        Self::Fixed(delay)
    }

    /// Creates a linear backoff strategy.
    pub fn linear(base_delay: Duration, max_delay: Duration) -> Self {
        Self::Linear(LinearBackoff::new(base_delay, max_delay))
    }

    /// Creates an exponential backoff strategy.
    pub fn exponential(initial_delay: Duration, max_delay: Duration) -> Self {
        Self::Exponential(ExponentialBackoff::new(initial_delay, max_delay))
    }

    /// Creates an exponential backoff strategy with jitter.
    pub fn exponential_with_jitter(
        initial_delay: Duration,
        max_delay: Duration,
        jitter_factor: f64,
    ) -> Self {
        Self::Exponential(
            ExponentialBackoff::new(initial_delay, max_delay).with_jitter(jitter_factor),
        )
    }
}

impl Default for RetryStrategy {
    fn default() -> Self {
        Self::Exponential(ExponentialBackoff::default())
    }
}

// =============================================================================
// LinearBackoff
// =============================================================================

/// Linear backoff strategy.
///
/// Delay increases linearly with each attempt: base_delay * (attempt + 1).
#[derive(Debug, Clone)]
pub struct LinearBackoff {
    /// Base delay for the first retry.
    pub base_delay: Duration,
    /// Maximum delay cap.
    pub max_delay: Duration,
}

impl LinearBackoff {
    /// Creates a new linear backoff.
    pub fn new(base_delay: Duration, max_delay: Duration) -> Self {
        Self { base_delay, max_delay }
    }

    /// Calculates the delay for the given attempt.
    pub fn delay(&self, attempt: u32) -> Duration {
        let multiplier = (attempt + 1) as u32;
        let delay = self.base_delay.saturating_mul(multiplier);
        delay.min(self.max_delay)
    }
}

impl Default for LinearBackoff {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
        }
    }
}

// =============================================================================
// ExponentialBackoff
// =============================================================================

/// Exponential backoff strategy with optional jitter.
///
/// Delay doubles with each attempt: initial_delay * 2^attempt.
/// Optional jitter adds randomness to prevent thundering herd.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Initial delay for the first retry.
    pub initial_delay: Duration,
    /// Maximum delay cap.
    pub max_delay: Duration,
    /// Multiplier for each attempt (default: 2.0).
    pub multiplier: f64,
    /// Jitter factor (0.0 = no jitter, 1.0 = up to 100% jitter).
    pub jitter_factor: f64,
}

impl ExponentialBackoff {
    /// Creates a new exponential backoff.
    pub fn new(initial_delay: Duration, max_delay: Duration) -> Self {
        Self {
            initial_delay,
            max_delay,
            multiplier: 2.0,
            jitter_factor: 0.0,
        }
    }

    /// Sets the multiplier.
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Sets the jitter factor.
    pub fn with_jitter(mut self, jitter_factor: f64) -> Self {
        self.jitter_factor = jitter_factor.clamp(0.0, 1.0);
        self
    }

    /// Calculates the delay for the given attempt.
    pub fn delay(&self, attempt: u32) -> Duration {
        // Calculate base delay: initial * multiplier^attempt
        let base = self.initial_delay.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let max = self.max_delay.as_secs_f64();
        let capped = base.min(max);

        // Apply jitter if configured
        let final_delay = if self.jitter_factor > 0.0 {
            let mut rng = rand::thread_rng();
            let jitter_range = capped * self.jitter_factor;
            let jitter = rng.gen_range(-jitter_range..=jitter_range);
            (capped + jitter).max(0.0)
        } else {
            capped
        };

        Duration::from_secs_f64(final_delay)
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
            jitter_factor: 0.1, // 10% jitter by default
        }
    }
}

// =============================================================================
// CustomBackoff
// =============================================================================

/// Custom backoff strategy with a predefined delay sequence.
#[derive(Debug, Clone)]
pub struct CustomBackoff {
    /// Predefined delays for each attempt.
    delays: Vec<Duration>,
    /// Delay to use when attempts exceed the predefined sequence.
    fallback: Duration,
}

impl CustomBackoff {
    /// Creates a new custom backoff with the given delays.
    pub fn new(delays: Vec<Duration>, fallback: Duration) -> Self {
        Self { delays, fallback }
    }

    /// Creates a custom backoff from a slice of milliseconds.
    pub fn from_millis(delays: &[u64], fallback_ms: u64) -> Self {
        Self {
            delays: delays.iter().map(|&ms| Duration::from_millis(ms)).collect(),
            fallback: Duration::from_millis(fallback_ms),
        }
    }

    /// Calculates the delay for the given attempt.
    pub fn delay(&self, attempt: u32) -> Duration {
        self.delays
            .get(attempt as usize)
            .copied()
            .unwrap_or(self.fallback)
    }
}

impl Default for CustomBackoff {
    fn default() -> Self {
        Self::from_millis(&[100, 200, 500, 1000, 2000], 5000)
    }
}

// =============================================================================
// RetryResult
// =============================================================================

/// Result of a retry operation.
#[derive(Debug, Clone)]
pub enum RetryResult<T, E> {
    /// Operation succeeded.
    Success(T),
    /// Operation failed after all retries.
    Failed {
        /// The last error.
        error: E,
        /// Number of attempts made.
        attempts: u32,
        /// Total time spent.
        total_time: Duration,
    },
}

impl<T, E> RetryResult<T, E> {
    /// Returns `true` if the operation succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// Returns `true` if the operation failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Converts to a standard Result, discarding retry metadata.
    pub fn into_result(self) -> Result<T, E> {
        match self {
            Self::Success(value) => Ok(value),
            Self::Failed { error, .. } => Err(error),
        }
    }

    /// Returns the number of attempts made.
    pub fn attempts(&self) -> u32 {
        match self {
            Self::Success(_) => 1,
            Self::Failed { attempts, .. } => *attempts,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_strategy() {
        let strategy = RetryStrategy::fixed(Duration::from_millis(100));

        assert_eq!(strategy.delay(0), Duration::from_millis(100));
        assert_eq!(strategy.delay(1), Duration::from_millis(100));
        assert_eq!(strategy.delay(5), Duration::from_millis(100));
    }

    #[test]
    fn test_linear_backoff() {
        let backoff = LinearBackoff::new(Duration::from_millis(100), Duration::from_secs(1));

        assert_eq!(backoff.delay(0), Duration::from_millis(100));
        assert_eq!(backoff.delay(1), Duration::from_millis(200));
        assert_eq!(backoff.delay(2), Duration::from_millis(300));
        assert_eq!(backoff.delay(20), Duration::from_secs(1)); // Capped at max
    }

    #[test]
    fn test_exponential_backoff_no_jitter() {
        let backoff = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(10))
            .with_jitter(0.0);

        assert_eq!(backoff.delay(0), Duration::from_millis(100));
        assert_eq!(backoff.delay(1), Duration::from_millis(200));
        assert_eq!(backoff.delay(2), Duration::from_millis(400));
        assert_eq!(backoff.delay(3), Duration::from_millis(800));
        assert_eq!(backoff.delay(10), Duration::from_secs(10)); // Capped at max
    }

    #[test]
    fn test_exponential_backoff_with_jitter() {
        let backoff = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(10))
            .with_jitter(0.5);

        // With 50% jitter, delay should be in range [50ms, 150ms] for attempt 0
        let delay = backoff.delay(0);
        assert!(delay >= Duration::from_millis(50));
        assert!(delay <= Duration::from_millis(150));
    }

    #[test]
    fn test_custom_backoff() {
        let backoff = CustomBackoff::from_millis(&[100, 200, 500], 1000);

        assert_eq!(backoff.delay(0), Duration::from_millis(100));
        assert_eq!(backoff.delay(1), Duration::from_millis(200));
        assert_eq!(backoff.delay(2), Duration::from_millis(500));
        assert_eq!(backoff.delay(3), Duration::from_millis(1000)); // Fallback
        assert_eq!(backoff.delay(10), Duration::from_millis(1000)); // Fallback
    }

    #[test]
    fn test_retry_config_builders() {
        let config = RetryConfig::exponential(
            5,
            Duration::from_millis(100),
            Duration::from_secs(5),
        );
        assert_eq!(config.max_retries, 5);

        let no_retry = RetryConfig::no_retry();
        assert_eq!(no_retry.max_retries, 0);

        let fixed = RetryConfig::fixed(3, Duration::from_millis(500));
        assert_eq!(fixed.max_retries, 3);
    }

    #[test]
    fn test_retry_result() {
        let success: RetryResult<i32, &str> = RetryResult::Success(42);
        assert!(success.is_success());
        assert_eq!(success.attempts(), 1);
        assert_eq!(success.into_result(), Ok(42));

        let failed: RetryResult<i32, &str> = RetryResult::Failed {
            error: "error",
            attempts: 3,
            total_time: Duration::from_secs(1),
        };
        assert!(failed.is_failed());
        assert_eq!(failed.attempts(), 3);
        assert_eq!(failed.into_result(), Err("error"));
    }

    #[test]
    fn test_exponential_multiplier() {
        let backoff = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(10))
            .with_multiplier(3.0)
            .with_jitter(0.0);

        assert_eq!(backoff.delay(0), Duration::from_millis(100));
        assert_eq!(backoff.delay(1), Duration::from_millis(300));
        assert_eq!(backoff.delay(2), Duration::from_millis(900));
    }
}
