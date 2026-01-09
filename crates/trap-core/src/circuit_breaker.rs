// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Extensible Circuit Breaker implementation with Strategy Pattern.
//!
//! This module provides a highly extensible circuit breaker system that uses
//! atomic operations for lock-free state management while supporting:
//!
//! - **Custom Failure Predicates**: Define what constitutes a failure
//! - **Multiple Strategies**: Count-based, sliding window, health-based
//! - **Event Hooks**: Observable state transitions for monitoring
//! - **Composable Design**: Mix and match components
//!
//! # Circuit Breaker Pattern
//!
//! The circuit breaker pattern prevents cascading failures by temporarily
//! blocking requests to a failing service:
//!
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Failure threshold exceeded, requests fail immediately
//! - **Half-Open**: Testing if the service has recovered
//!
//! # State Transitions
//!
//! ```text
//!                    success
//!      ┌─────────────────────────────┐
//!      │                             │
//!      ▼                             │
//!   ┌──────┐   failure threshold  ┌──────┐   timeout   ┌─────────┐
//!   │Closed│ ─────────────────────▶│ Open │ ───────────▶│HalfOpen │
//!   └──────┘                       └──────┘             └─────────┘
//!      ▲                                                     │
//!      │                                                     │
//!      └─────────────────────────────────────────────────────┘
//!                        success in half-open
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    CircuitBreaker                            │
//! │  ┌─────────────────────┐  ┌─────────────────────────────┐   │
//! │  │   StateManager      │  │   FailurePredicate         │   │
//! │  │  (Lock-free state)  │  │  (Error classification)    │   │
//! │  └─────────────────────┘  └─────────────────────────────┘   │
//! │  ┌─────────────────────┐  ┌─────────────────────────────┐   │
//! │  │  TransitionStrategy │  │   EventDispatcher          │   │
//! │  │  (Decision logic)   │  │  (Observability hooks)     │   │
//! │  └─────────────────────┘  └─────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use trap_core::circuit_breaker::{
//!     CircuitBreaker, CircuitBreakerConfig, CircuitBreakerBuilder,
//!     CountBasedStrategy, DefaultFailurePredicate,
//! };
//!
//! // Simple usage with defaults
//! let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
//!
//! // Advanced usage with builder
//! let cb = CircuitBreakerBuilder::new()
//!     .config(CircuitBreakerConfig::default())
//!     .failure_predicate(DefaultFailurePredicate::new())
//!     .strategy(CountBasedStrategy::new(5))
//!     .on_state_change(|from, to| {
//!         tracing::info!("Circuit state: {:?} -> {:?}", from, to);
//!     })
//!     .build();
//!
//! let result = cb.call(|| async {
//!     // Your operation here
//!     Ok::<_, std::io::Error>(())
//! }).await;
//! ```

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::driver::CircuitState;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Time to wait before attempting to reset (move to half-open).
    #[serde(default = "default_reset_timeout")]
    #[serde(with = "duration_secs")]
    pub reset_timeout: Duration,

    /// Maximum number of test requests in half-open state.
    #[serde(default = "default_half_open_max_calls")]
    pub half_open_max_calls: u32,

    /// Success rate threshold in half-open to close the circuit (0.0-1.0).
    #[serde(default = "default_success_rate_threshold")]
    pub success_rate_threshold: f64,

    /// Minimum number of calls before calculating success rate.
    #[serde(default = "default_minimum_calls")]
    pub minimum_calls: u32,

    /// Sliding window size for rate-based strategies (in seconds).
    #[serde(default = "default_sliding_window_size")]
    pub sliding_window_size: u32,

    /// Whether to allow concurrent half-open probes.
    #[serde(default)]
    pub permit_half_open_concurrent: bool,
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_reset_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_half_open_max_calls() -> u32 {
    3
}

fn default_success_rate_threshold() -> f64 {
    0.5
}

fn default_minimum_calls() -> u32 {
    5
}

fn default_sliding_window_size() -> u32 {
    60
}

mod duration_secs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            reset_timeout: default_reset_timeout(),
            half_open_max_calls: default_half_open_max_calls(),
            success_rate_threshold: default_success_rate_threshold(),
            minimum_calls: default_minimum_calls(),
            sliding_window_size: default_sliding_window_size(),
            permit_half_open_concurrent: false,
        }
    }
}

impl CircuitBreakerConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> CircuitBreakerConfigBuilder {
        CircuitBreakerConfigBuilder::default()
    }

    /// Creates a configuration for aggressive failure detection.
    pub fn aggressive() -> Self {
        Self {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(10),
            half_open_max_calls: 2,
            success_rate_threshold: 0.6,
            minimum_calls: 3,
            sliding_window_size: 30,
            permit_half_open_concurrent: false,
        }
    }

    /// Creates a configuration for conservative failure detection.
    pub fn conservative() -> Self {
        Self {
            failure_threshold: 10,
            reset_timeout: Duration::from_secs(60),
            half_open_max_calls: 5,
            success_rate_threshold: 0.4,
            minimum_calls: 10,
            sliding_window_size: 120,
            permit_half_open_concurrent: false,
        }
    }
}

/// Builder for CircuitBreakerConfig.
#[derive(Debug, Default)]
pub struct CircuitBreakerConfigBuilder {
    config: CircuitBreakerConfig,
}

impl CircuitBreakerConfigBuilder {
    /// Sets the failure threshold.
    pub fn failure_threshold(mut self, threshold: u32) -> Self {
        self.config.failure_threshold = threshold;
        self
    }

    /// Sets the reset timeout.
    pub fn reset_timeout(mut self, timeout: Duration) -> Self {
        self.config.reset_timeout = timeout;
        self
    }

    /// Sets the half-open max calls.
    pub fn half_open_max_calls(mut self, max_calls: u32) -> Self {
        self.config.half_open_max_calls = max_calls;
        self
    }

    /// Sets the success rate threshold.
    pub fn success_rate_threshold(mut self, threshold: f64) -> Self {
        self.config.success_rate_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Sets the minimum calls before calculating success rate.
    pub fn minimum_calls(mut self, calls: u32) -> Self {
        self.config.minimum_calls = calls;
        self
    }

    /// Sets the sliding window size.
    pub fn sliding_window_size(mut self, size: u32) -> Self {
        self.config.sliding_window_size = size;
        self
    }

    /// Sets whether to permit concurrent half-open probes.
    pub fn permit_half_open_concurrent(mut self, permit: bool) -> Self {
        self.config.permit_half_open_concurrent = permit;
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> CircuitBreakerConfig {
        self.config
    }
}

// =============================================================================
// Circuit Breaker Error
// =============================================================================

/// Error returned when the circuit breaker rejects a request.
#[derive(Debug, Error)]
pub enum CircuitError<E> {
    /// The circuit breaker is open, request rejected.
    #[error("Circuit breaker is open")]
    Open,

    /// The circuit breaker is half-open and at capacity.
    #[error("Circuit breaker is half-open and at capacity")]
    HalfOpenAtCapacity,

    /// The inner operation failed.
    #[error("Inner operation failed: {0}")]
    Inner(#[source] E),
}

impl<E> CircuitError<E> {
    /// Returns `true` if this is an open circuit error.
    pub fn is_open(&self) -> bool {
        matches!(self, CircuitError::Open | CircuitError::HalfOpenAtCapacity)
    }

    /// Returns the inner error if present.
    pub fn inner(&self) -> Option<&E> {
        match self {
            CircuitError::Inner(e) => Some(e),
            _ => None,
        }
    }

    /// Consumes self and returns the inner error if present.
    pub fn into_inner(self) -> Option<E> {
        match self {
            CircuitError::Inner(e) => Some(e),
            _ => None,
        }
    }

    /// Maps the inner error type.
    pub fn map_inner<F, E2>(self, f: F) -> CircuitError<E2>
    where
        F: FnOnce(E) -> E2,
    {
        match self {
            CircuitError::Open => CircuitError::Open,
            CircuitError::HalfOpenAtCapacity => CircuitError::HalfOpenAtCapacity,
            CircuitError::Inner(e) => CircuitError::Inner(f(e)),
        }
    }
}

// =============================================================================
// Failure Predicate Trait
// =============================================================================

/// Trait for determining whether an error should be counted as a failure.
///
/// This allows customization of what constitutes a "failure" for circuit
/// breaker purposes. For example, you might want to ignore certain error
/// types (like validation errors) that shouldn't trip the circuit.
///
/// # Example
///
/// ```rust,ignore
/// use trap_core::circuit_breaker::FailurePredicate;
///
/// struct MyPredicate;
///
/// impl<E: std::error::Error> FailurePredicate<E> for MyPredicate {
///     fn is_failure(&self, error: &E) -> bool {
///         // Only count network errors as failures
///         error.to_string().contains("connection")
///     }
/// }
/// ```
pub trait FailurePredicate<E>: Send + Sync {
    /// Returns `true` if the error should be counted as a failure.
    fn is_failure(&self, error: &E) -> bool;

    /// Returns the predicate name for logging/metrics.
    fn name(&self) -> &str {
        "custom"
    }
}

/// Default failure predicate that counts all errors as failures.
#[derive(Debug, Clone, Default)]
pub struct DefaultFailurePredicate;

impl DefaultFailurePredicate {
    /// Creates a new default failure predicate.
    pub fn new() -> Self {
        Self
    }
}

impl<E> FailurePredicate<E> for DefaultFailurePredicate {
    fn is_failure(&self, _error: &E) -> bool {
        true
    }

    fn name(&self) -> &str {
        "default"
    }
}

/// A failure predicate that uses a closure.
pub struct ClosureFailurePredicate<F> {
    predicate: F,
    name: &'static str,
}

impl<F> ClosureFailurePredicate<F> {
    /// Creates a new closure-based failure predicate.
    pub fn new(predicate: F) -> Self {
        Self {
            predicate,
            name: "closure",
        }
    }

    /// Creates a new closure-based failure predicate with a name.
    pub fn with_name(predicate: F, name: &'static str) -> Self {
        Self { predicate, name }
    }
}

impl<E, F> FailurePredicate<E> for ClosureFailurePredicate<F>
where
    F: Fn(&E) -> bool + Send + Sync,
{
    fn is_failure(&self, error: &E) -> bool {
        (self.predicate)(error)
    }

    fn name(&self) -> &str {
        self.name
    }
}

impl<F> fmt::Debug for ClosureFailurePredicate<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosureFailurePredicate")
            .field("name", &self.name)
            .finish()
    }
}

/// A predicate that combines multiple predicates with OR logic.
pub struct AnyFailurePredicate<E> {
    predicates: Vec<Box<dyn FailurePredicate<E>>>,
}

impl<E> AnyFailurePredicate<E> {
    /// Creates a new composite predicate.
    pub fn new(predicates: Vec<Box<dyn FailurePredicate<E>>>) -> Self {
        Self { predicates }
    }
}

impl<E> FailurePredicate<E> for AnyFailurePredicate<E>
where
    E: Send + Sync,
{
    fn is_failure(&self, error: &E) -> bool {
        self.predicates.iter().any(|p| p.is_failure(error))
    }

    fn name(&self) -> &str {
        "any"
    }
}

impl<E> fmt::Debug for AnyFailurePredicate<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyFailurePredicate")
            .field("count", &self.predicates.len())
            .finish()
    }
}

/// A predicate that combines multiple predicates with AND logic.
pub struct AllFailurePredicate<E> {
    predicates: Vec<Box<dyn FailurePredicate<E>>>,
}

impl<E> AllFailurePredicate<E> {
    /// Creates a new composite predicate.
    pub fn new(predicates: Vec<Box<dyn FailurePredicate<E>>>) -> Self {
        Self { predicates }
    }
}

impl<E> FailurePredicate<E> for AllFailurePredicate<E>
where
    E: Send + Sync,
{
    fn is_failure(&self, error: &E) -> bool {
        self.predicates.iter().all(|p| p.is_failure(error))
    }

    fn name(&self) -> &str {
        "all"
    }
}

impl<E> fmt::Debug for AllFailurePredicate<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllFailurePredicate")
            .field("count", &self.predicates.len())
            .finish()
    }
}

// =============================================================================
// Transition Strategy Trait
// =============================================================================

/// Trait for customizing circuit breaker transition logic.
///
/// Different strategies can be used for different scenarios:
/// - **CountBased**: Simple consecutive failure counting
/// - **SlidingWindow**: Rate-based failures over a time window
/// - **Health**: External health check integration
///
/// # Example
///
/// ```rust,ignore
/// use trap_core::circuit_breaker::{TransitionStrategy, CircuitState};
///
/// struct MyStrategy { /* ... */ }
///
/// impl TransitionStrategy for MyStrategy {
///     fn should_open(&self, failure_count: u32, success_count: u32) -> bool {
///         // Custom logic
///         failure_count > 10
///     }
///
///     fn should_close(&self, success_count: u32, failure_count: u32) -> bool {
///         success_count >= 5
///     }
///
///     fn name(&self) -> &str {
///         "my_strategy"
///     }
/// }
/// ```
pub trait TransitionStrategy: Send + Sync + fmt::Debug {
    /// Returns the strategy name for logging/metrics.
    fn name(&self) -> &str;

    /// Determines if the circuit should transition from Closed to Open.
    ///
    /// Called after each failure while the circuit is closed.
    fn should_open(&self, failure_count: u32, success_count: u32, config: &CircuitBreakerConfig) -> bool;

    /// Determines if the circuit should transition from HalfOpen to Closed.
    ///
    /// Called after successes in half-open state.
    fn should_close(&self, success_count: u32, failure_count: u32, config: &CircuitBreakerConfig) -> bool;

    /// Determines if a request should be permitted in HalfOpen state.
    ///
    /// Returns true if the request should proceed, false to reject.
    fn permit_half_open_request(&self, attempt_count: u32, config: &CircuitBreakerConfig) -> bool;

    /// Called when state transitions occur, for strategy-specific cleanup.
    fn on_state_change(&self, _from: CircuitState, _to: CircuitState) {}
}

/// Count-based transition strategy.
///
/// Opens the circuit after N consecutive failures.
#[derive(Debug, Clone)]
pub struct CountBasedStrategy {
    /// Number of consecutive failures required to open.
    pub consecutive_failures: u32,
}

impl CountBasedStrategy {
    /// Creates a new count-based strategy.
    pub fn new(consecutive_failures: u32) -> Self {
        Self { consecutive_failures }
    }
}

impl Default for CountBasedStrategy {
    fn default() -> Self {
        Self {
            consecutive_failures: 5,
        }
    }
}

impl TransitionStrategy for CountBasedStrategy {
    fn name(&self) -> &str {
        "count_based"
    }

    fn should_open(&self, failure_count: u32, _success_count: u32, _config: &CircuitBreakerConfig) -> bool {
        failure_count >= self.consecutive_failures
    }

    fn should_close(&self, success_count: u32, _failure_count: u32, config: &CircuitBreakerConfig) -> bool {
        success_count >= config.half_open_max_calls
    }

    fn permit_half_open_request(&self, attempt_count: u32, config: &CircuitBreakerConfig) -> bool {
        attempt_count < config.half_open_max_calls
    }
}

/// Success rate-based transition strategy.
///
/// Opens the circuit when the success rate falls below a threshold.
#[derive(Debug, Clone)]
pub struct RateBasedStrategy {
    /// Minimum success rate required (0.0 - 1.0).
    pub min_success_rate: f64,
    /// Minimum number of calls before evaluating rate.
    pub min_calls: u32,
}

impl RateBasedStrategy {
    /// Creates a new rate-based strategy.
    pub fn new(min_success_rate: f64, min_calls: u32) -> Self {
        Self {
            min_success_rate: min_success_rate.clamp(0.0, 1.0),
            min_calls,
        }
    }
}

impl Default for RateBasedStrategy {
    fn default() -> Self {
        Self {
            min_success_rate: 0.5,
            min_calls: 5,
        }
    }
}

impl TransitionStrategy for RateBasedStrategy {
    fn name(&self) -> &str {
        "rate_based"
    }

    fn should_open(&self, failure_count: u32, success_count: u32, _config: &CircuitBreakerConfig) -> bool {
        let total = failure_count + success_count;
        if total < self.min_calls {
            return false;
        }

        let success_rate = success_count as f64 / total as f64;
        success_rate < self.min_success_rate
    }

    fn should_close(&self, success_count: u32, failure_count: u32, config: &CircuitBreakerConfig) -> bool {
        let total = success_count + failure_count;
        if total < config.half_open_max_calls {
            return false;
        }

        let success_rate = success_count as f64 / total as f64;
        success_rate >= config.success_rate_threshold
    }

    fn permit_half_open_request(&self, attempt_count: u32, config: &CircuitBreakerConfig) -> bool {
        attempt_count < config.half_open_max_calls
    }
}

/// Hybrid strategy combining count and rate approaches.
///
/// Opens on either consecutive failures OR low success rate.
#[derive(Debug, Clone)]
pub struct HybridStrategy {
    /// Count-based component.
    pub count_strategy: CountBasedStrategy,
    /// Rate-based component.
    pub rate_strategy: RateBasedStrategy,
}

impl HybridStrategy {
    /// Creates a new hybrid strategy.
    pub fn new(consecutive_failures: u32, min_success_rate: f64, min_calls: u32) -> Self {
        Self {
            count_strategy: CountBasedStrategy::new(consecutive_failures),
            rate_strategy: RateBasedStrategy::new(min_success_rate, min_calls),
        }
    }
}

impl Default for HybridStrategy {
    fn default() -> Self {
        Self {
            count_strategy: CountBasedStrategy::default(),
            rate_strategy: RateBasedStrategy::default(),
        }
    }
}

impl TransitionStrategy for HybridStrategy {
    fn name(&self) -> &str {
        "hybrid"
    }

    fn should_open(&self, failure_count: u32, success_count: u32, config: &CircuitBreakerConfig) -> bool {
        self.count_strategy.should_open(failure_count, success_count, config)
            || self.rate_strategy.should_open(failure_count, success_count, config)
    }

    fn should_close(&self, success_count: u32, failure_count: u32, config: &CircuitBreakerConfig) -> bool {
        // Both strategies must agree to close
        self.count_strategy.should_close(success_count, failure_count, config)
            && self.rate_strategy.should_close(success_count, failure_count, config)
    }

    fn permit_half_open_request(&self, attempt_count: u32, config: &CircuitBreakerConfig) -> bool {
        self.count_strategy.permit_half_open_request(attempt_count, config)
    }
}

// =============================================================================
// Event Types
// =============================================================================

/// Event emitted when circuit breaker state changes.
#[derive(Debug, Clone, Serialize)]
pub struct StateChangeEvent {
    /// Previous state.
    pub from: CircuitState,
    /// New state.
    pub to: CircuitState,
    /// Timestamp of the change.
    pub timestamp: DateTime<Utc>,
    /// Current failure count.
    pub failure_count: u32,
    /// Current success count.
    pub success_count: u32,
    /// Optional reason for the transition.
    pub reason: Option<String>,
}

/// Event emitted when an operation completes.
#[derive(Debug, Clone, Serialize)]
pub struct OperationEvent {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Duration of the operation.
    pub duration: Duration,
    /// Current circuit state.
    pub circuit_state: CircuitState,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Trait for handling circuit breaker events.
pub trait CircuitBreakerEventHandler: Send + Sync {
    /// Called when the circuit state changes.
    fn on_state_change(&self, event: &StateChangeEvent);

    /// Called when an operation completes (optional).
    fn on_operation(&self, _event: &OperationEvent) {}

    /// Called when a request is rejected due to open circuit (optional).
    fn on_rejection(&self, _state: CircuitState) {}
}

/// No-op event handler.
#[derive(Debug, Clone, Default)]
pub struct NoOpEventHandler;

impl CircuitBreakerEventHandler for NoOpEventHandler {
    fn on_state_change(&self, _event: &StateChangeEvent) {}
}

/// Logging event handler.
#[derive(Debug, Clone, Default)]
pub struct LoggingEventHandler;

impl CircuitBreakerEventHandler for LoggingEventHandler {
    fn on_state_change(&self, event: &StateChangeEvent) {
        match event.to {
            CircuitState::Open => {
                tracing::warn!(
                    from = ?event.from,
                    to = ?event.to,
                    failures = event.failure_count,
                    reason = ?event.reason,
                    "Circuit breaker opened"
                );
            }
            CircuitState::HalfOpen => {
                tracing::info!(
                    from = ?event.from,
                    to = ?event.to,
                    "Circuit breaker entering half-open state"
                );
            }
            CircuitState::Closed => {
                tracing::info!(
                    from = ?event.from,
                    to = ?event.to,
                    successes = event.success_count,
                    "Circuit breaker closed"
                );
            }
        }
    }

    fn on_rejection(&self, state: CircuitState) {
        tracing::debug!(state = ?state, "Circuit breaker rejected request");
    }
}

/// Closure-based event handler.
pub struct ClosureEventHandler<F> {
    handler: F,
}

impl<F> ClosureEventHandler<F> {
    /// Creates a new closure-based event handler.
    pub fn new(handler: F) -> Self {
        Self { handler }
    }
}

impl<F> CircuitBreakerEventHandler for ClosureEventHandler<F>
where
    F: Fn(&StateChangeEvent) + Send + Sync,
{
    fn on_state_change(&self, event: &StateChangeEvent) {
        (self.handler)(event);
    }
}

impl<F> fmt::Debug for ClosureEventHandler<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosureEventHandler").finish()
    }
}

/// Composite event handler that dispatches to multiple handlers.
pub struct CompositeEventHandler {
    handlers: Vec<Box<dyn CircuitBreakerEventHandler>>,
}

impl CompositeEventHandler {
    /// Creates a new composite handler.
    pub fn new(handlers: Vec<Box<dyn CircuitBreakerEventHandler>>) -> Self {
        Self { handlers }
    }

    /// Adds a handler.
    pub fn add(&mut self, handler: Box<dyn CircuitBreakerEventHandler>) {
        self.handlers.push(handler);
    }
}

impl CircuitBreakerEventHandler for CompositeEventHandler {
    fn on_state_change(&self, event: &StateChangeEvent) {
        for handler in &self.handlers {
            handler.on_state_change(event);
        }
    }

    fn on_operation(&self, event: &OperationEvent) {
        for handler in &self.handlers {
            handler.on_operation(event);
        }
    }

    fn on_rejection(&self, state: CircuitState) {
        for handler in &self.handlers {
            handler.on_rejection(state);
        }
    }
}

impl fmt::Debug for CompositeEventHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeEventHandler")
            .field("count", &self.handlers.len())
            .finish()
    }
}

// =============================================================================
// State Encoding
// =============================================================================

/// Encodes the circuit state into a u64.
///
/// Layout:
/// - Bits 0-7: State (0=Closed, 1=Open, 2=HalfOpen)
/// - Bits 8-23: Failure count (16 bits, max 65535)
/// - Bits 24-39: Success count (16 bits, max 65535)
/// - Bits 40-55: Half-open attempt count (16 bits)
/// - Bits 56-63: Reserved
#[derive(Debug, Clone, Copy)]
struct EncodedState {
    state: CircuitState,
    failure_count: u16,
    success_count: u16,
    half_open_attempts: u16,
}

impl EncodedState {
    fn new(state: CircuitState) -> Self {
        Self {
            state,
            failure_count: 0,
            success_count: 0,
            half_open_attempts: 0,
        }
    }

    fn encode(&self) -> u64 {
        let state_bits = self.state.as_u8() as u64;
        let failure_bits = (self.failure_count as u64) << 8;
        let success_bits = (self.success_count as u64) << 24;
        let half_open_bits = (self.half_open_attempts as u64) << 40;

        state_bits | failure_bits | success_bits | half_open_bits
    }

    fn decode(value: u64) -> Self {
        Self {
            state: CircuitState::from((value & 0xFF) as u8),
            failure_count: ((value >> 8) & 0xFFFF) as u16,
            success_count: ((value >> 24) & 0xFFFF) as u16,
            half_open_attempts: ((value >> 40) & 0xFFFF) as u16,
        }
    }
}

// =============================================================================
// Circuit Breaker
// =============================================================================

/// A lock-free, extensible circuit breaker.
///
/// This implementation uses atomic operations for all state transitions,
/// making it safe for concurrent use without locks.
pub struct CircuitBreaker<S = CountBasedStrategy, H = LoggingEventHandler>
where
    S: TransitionStrategy,
    H: CircuitBreakerEventHandler,
{
    /// Encoded state (state + counters)
    state: AtomicU64,

    /// Last failure timestamp (unix timestamp in seconds)
    last_failure_time: AtomicU64,

    /// Configuration
    config: CircuitBreakerConfig,

    /// Transition strategy
    strategy: S,

    /// Event handler
    event_handler: H,
}

impl CircuitBreaker<CountBasedStrategy, LoggingEventHandler> {
    /// Creates a new circuit breaker with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        let strategy = CountBasedStrategy::new(config.failure_threshold);
        Self::with_strategy_and_handler(config, strategy, LoggingEventHandler)
    }

    /// Creates a new circuit breaker with default configuration.
    pub fn default_config() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

impl<S, H> CircuitBreaker<S, H>
where
    S: TransitionStrategy,
    H: CircuitBreakerEventHandler,
{
    /// Creates a new circuit breaker with custom strategy and handler.
    pub fn with_strategy_and_handler(config: CircuitBreakerConfig, strategy: S, event_handler: H) -> Self {
        let initial_state = EncodedState::new(CircuitState::Closed);

        Self {
            state: AtomicU64::new(initial_state.encode()),
            last_failure_time: AtomicU64::new(0),
            config,
            strategy,
            event_handler,
        }
    }

    /// Executes an operation through the circuit breaker.
    ///
    /// If the circuit is open, the operation is not executed and
    /// `CircuitError::Open` is returned immediately.
    pub async fn call<F, Fut, T, E>(&self, f: F) -> Result<T, CircuitError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        // Check if we can proceed
        self.check_state()?;

        // Execute the operation
        let start = std::time::Instant::now();
        match f().await {
            Ok(result) => {
                let duration = start.elapsed();
                self.record_success();
                self.emit_operation_event(true, duration);
                Ok(result)
            }
            Err(e) => {
                let duration = start.elapsed();
                self.record_failure();
                self.emit_operation_event(false, duration);
                Err(CircuitError::Inner(e))
            }
        }
    }

    /// Executes an operation with a custom failure predicate.
    pub async fn call_with_predicate<F, Fut, T, E, P>(
        &self,
        f: F,
        predicate: &P,
    ) -> Result<T, CircuitError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        P: FailurePredicate<E>,
    {
        self.check_state()?;

        let start = std::time::Instant::now();
        match f().await {
            Ok(result) => {
                let duration = start.elapsed();
                self.record_success();
                self.emit_operation_event(true, duration);
                Ok(result)
            }
            Err(e) => {
                let duration = start.elapsed();
                if predicate.is_failure(&e) {
                    self.record_failure();
                    self.emit_operation_event(false, duration);
                } else {
                    // Not a "real" failure, don't affect circuit state
                    self.emit_operation_event(true, duration);
                }
                Err(CircuitError::Inner(e))
            }
        }
    }

    /// Executes a synchronous operation through the circuit breaker.
    pub fn call_sync<F, T, E>(&self, f: F) -> Result<T, CircuitError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        self.check_state()?;

        let start = std::time::Instant::now();
        match f() {
            Ok(result) => {
                let duration = start.elapsed();
                self.record_success();
                self.emit_operation_event(true, duration);
                Ok(result)
            }
            Err(e) => {
                let duration = start.elapsed();
                self.record_failure();
                self.emit_operation_event(false, duration);
                Err(CircuitError::Inner(e))
            }
        }
    }

    /// Checks if a request can proceed based on the current state.
    fn check_state<E>(&self) -> Result<(), CircuitError<E>> {
        let encoded = self.state.load(Ordering::SeqCst);
        let current = EncodedState::decode(encoded);

        match current.state {
            CircuitState::Closed => Ok(()),

            CircuitState::Open => {
                // Check if we should try to reset
                if self.should_try_reset() {
                    self.transition_to_half_open();
                    Ok(())
                } else {
                    self.event_handler.on_rejection(CircuitState::Open);
                    Err(CircuitError::Open)
                }
            }

            CircuitState::HalfOpen => {
                // Check if we can allow another test request
                if self.strategy.permit_half_open_request(current.half_open_attempts as u32, &self.config) {
                    // Increment half-open attempts atomically
                    let mut new_state = current;
                    new_state.half_open_attempts += 1;

                    // Try to update atomically
                    match self.state.compare_exchange(
                        encoded,
                        new_state.encode(),
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => Ok(()),
                        Err(_) => {
                            // State changed, retry check
                            self.check_state()
                        }
                    }
                } else {
                    self.event_handler.on_rejection(CircuitState::HalfOpen);
                    Err(CircuitError::HalfOpenAtCapacity)
                }
            }
        }
    }

    /// Records a successful operation.
    pub fn record_success(&self) {
        loop {
            let encoded = self.state.load(Ordering::SeqCst);
            let current = EncodedState::decode(encoded);

            let mut new_state = current;
            new_state.success_count = current.success_count.saturating_add(1);
            new_state.failure_count = 0; // Reset failure count on success

            // In half-open state, check if we should close
            if current.state == CircuitState::HalfOpen {
                if self.strategy.should_close(
                    new_state.success_count as u32,
                    current.failure_count as u32,
                    &self.config,
                ) {
                    // Transition to closed
                    new_state.state = CircuitState::Closed;
                    new_state.success_count = 0;
                    new_state.half_open_attempts = 0;

                    self.emit_state_change(current.state, CircuitState::Closed, &new_state, Some("Recovery successful"));
                    self.strategy.on_state_change(current.state, CircuitState::Closed);
                }
            }

            if self
                .state
                .compare_exchange(encoded, new_state.encode(), Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Records a failed operation.
    pub fn record_failure(&self) {
        // Update last failure time
        let now = Utc::now().timestamp() as u64;
        self.last_failure_time.store(now, Ordering::SeqCst);

        loop {
            let encoded = self.state.load(Ordering::SeqCst);
            let current = EncodedState::decode(encoded);

            let mut new_state = current;
            new_state.failure_count = current.failure_count.saturating_add(1);

            match current.state {
                CircuitState::Closed => {
                    // Check if we should open
                    if self.strategy.should_open(
                        new_state.failure_count as u32,
                        current.success_count as u32,
                        &self.config,
                    ) {
                        new_state.state = CircuitState::Open;
                        new_state.failure_count = 0;
                        new_state.success_count = 0;

                        self.emit_state_change(
                            current.state,
                            CircuitState::Open,
                            &new_state,
                            Some("Failure threshold exceeded"),
                        );
                        self.strategy.on_state_change(current.state, CircuitState::Open);
                    }
                }
                CircuitState::HalfOpen => {
                    // Failed during recovery test, reopen
                    new_state.state = CircuitState::Open;
                    new_state.failure_count = 0;
                    new_state.success_count = 0;
                    new_state.half_open_attempts = 0;

                    self.emit_state_change(
                        current.state,
                        CircuitState::Open,
                        &new_state,
                        Some("Failure in half-open state"),
                    );
                    self.strategy.on_state_change(current.state, CircuitState::Open);
                }
                CircuitState::Open => {
                    // Already open, just update counter
                }
            }

            if self
                .state
                .compare_exchange(encoded, new_state.encode(), Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Checks if enough time has passed to try resetting the circuit.
    fn should_try_reset(&self) -> bool {
        let last_failure = self.last_failure_time.load(Ordering::SeqCst);
        if last_failure == 0 {
            return true;
        }

        let now = Utc::now().timestamp() as u64;
        let elapsed = now.saturating_sub(last_failure);

        elapsed >= self.config.reset_timeout.as_secs()
    }

    /// Transitions to half-open state.
    fn transition_to_half_open(&self) {
        loop {
            let encoded = self.state.load(Ordering::SeqCst);
            let current = EncodedState::decode(encoded);

            if current.state != CircuitState::Open {
                return; // Already transitioned
            }

            let mut new_state = current;
            new_state.state = CircuitState::HalfOpen;
            new_state.failure_count = 0;
            new_state.success_count = 0;
            new_state.half_open_attempts = 0;

            if self
                .state
                .compare_exchange(encoded, new_state.encode(), Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.emit_state_change(
                    current.state,
                    CircuitState::HalfOpen,
                    &new_state,
                    Some("Reset timeout elapsed"),
                );
                self.strategy.on_state_change(current.state, CircuitState::HalfOpen);
                break;
            }
        }
    }

    /// Emits a state change event.
    fn emit_state_change(
        &self,
        from: CircuitState,
        to: CircuitState,
        state: &EncodedState,
        reason: Option<&str>,
    ) {
        let event = StateChangeEvent {
            from,
            to,
            timestamp: Utc::now(),
            failure_count: state.failure_count as u32,
            success_count: state.success_count as u32,
            reason: reason.map(String::from),
        };
        self.event_handler.on_state_change(&event);
    }

    /// Emits an operation event.
    fn emit_operation_event(&self, success: bool, duration: Duration) {
        let event = OperationEvent {
            success,
            duration,
            circuit_state: self.current_state(),
            timestamp: Utc::now(),
        };
        self.event_handler.on_operation(&event);
    }

    /// Returns the current circuit state.
    pub fn current_state(&self) -> CircuitState {
        let encoded = self.state.load(Ordering::SeqCst);
        EncodedState::decode(encoded).state
    }

    /// Returns the current failure count.
    pub fn failure_count(&self) -> u32 {
        let encoded = self.state.load(Ordering::SeqCst);
        EncodedState::decode(encoded).failure_count as u32
    }

    /// Returns the current success count.
    pub fn success_count(&self) -> u32 {
        let encoded = self.state.load(Ordering::SeqCst);
        EncodedState::decode(encoded).success_count as u32
    }

    /// Manually resets the circuit breaker to closed state.
    pub fn reset(&self) {
        let old_encoded = self.state.load(Ordering::SeqCst);
        let old_state = EncodedState::decode(old_encoded);

        let new_state = EncodedState::new(CircuitState::Closed);
        self.state.store(new_state.encode(), Ordering::SeqCst);
        self.last_failure_time.store(0, Ordering::SeqCst);

        self.emit_state_change(old_state.state, CircuitState::Closed, &new_state, Some("Manual reset"));
        self.strategy.on_state_change(old_state.state, CircuitState::Closed);
    }

    /// Manually opens the circuit breaker.
    pub fn trip(&self) {
        let old_encoded = self.state.load(Ordering::SeqCst);
        let old_state = EncodedState::decode(old_encoded);

        let mut new_state = EncodedState::new(CircuitState::Open);
        new_state.failure_count = 0;
        self.state.store(new_state.encode(), Ordering::SeqCst);
        self.last_failure_time
            .store(Utc::now().timestamp() as u64, Ordering::SeqCst);

        self.emit_state_change(old_state.state, CircuitState::Open, &new_state, Some("Manual trip"));
        self.strategy.on_state_change(old_state.state, CircuitState::Open);
    }

    /// Returns the configuration.
    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    /// Returns a reference to the strategy.
    pub fn strategy(&self) -> &S {
        &self.strategy
    }

    /// Returns detailed metrics about the circuit breaker state.
    pub fn metrics(&self) -> CircuitBreakerMetrics {
        let encoded = self.state.load(Ordering::SeqCst);
        let decoded = EncodedState::decode(encoded);
        let last_failure = self.last_failure_time.load(Ordering::SeqCst);

        CircuitBreakerMetrics {
            state: decoded.state,
            failure_count: decoded.failure_count as u32,
            success_count: decoded.success_count as u32,
            half_open_attempts: decoded.half_open_attempts as u32,
            last_failure_time: if last_failure > 0 {
                DateTime::from_timestamp(last_failure as i64, 0)
            } else {
                None
            },
            strategy_name: self.strategy.name().to_string(),
        }
    }

    /// Returns true if the circuit is allowing requests (closed or half-open with capacity).
    pub fn is_allowing_requests(&self) -> bool {
        let encoded = self.state.load(Ordering::SeqCst);
        let current = EncodedState::decode(encoded);

        match current.state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => {
                self.strategy.permit_half_open_request(current.half_open_attempts as u32, &self.config)
            }
            CircuitState::Open => self.should_try_reset(),
        }
    }
}

impl<S, H> Clone for CircuitBreaker<S, H>
where
    S: TransitionStrategy + Clone,
    H: CircuitBreakerEventHandler + Clone,
{
    fn clone(&self) -> Self {
        Self {
            state: AtomicU64::new(self.state.load(Ordering::SeqCst)),
            last_failure_time: AtomicU64::new(self.last_failure_time.load(Ordering::SeqCst)),
            config: self.config.clone(),
            strategy: self.strategy.clone(),
            event_handler: self.event_handler.clone(),
        }
    }
}

impl<S, H> fmt::Debug for CircuitBreaker<S, H>
where
    S: TransitionStrategy + fmt::Debug,
    H: CircuitBreakerEventHandler,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let metrics = self.metrics();
        f.debug_struct("CircuitBreaker")
            .field("state", &metrics.state)
            .field("failure_count", &metrics.failure_count)
            .field("success_count", &metrics.success_count)
            .field("strategy", &self.strategy)
            .finish()
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for creating customized CircuitBreaker instances.
pub struct CircuitBreakerBuilder<S = CountBasedStrategy, H = LoggingEventHandler>
where
    S: TransitionStrategy,
    H: CircuitBreakerEventHandler,
{
    config: CircuitBreakerConfig,
    strategy: S,
    event_handler: H,
}

impl Default for CircuitBreakerBuilder<CountBasedStrategy, LoggingEventHandler> {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreakerBuilder<CountBasedStrategy, LoggingEventHandler> {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        let config = CircuitBreakerConfig::default();
        Self {
            strategy: CountBasedStrategy::new(config.failure_threshold),
            event_handler: LoggingEventHandler,
            config,
        }
    }
}

impl<S, H> CircuitBreakerBuilder<S, H>
where
    S: TransitionStrategy,
    H: CircuitBreakerEventHandler,
{
    /// Sets the configuration.
    pub fn config(mut self, config: CircuitBreakerConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the transition strategy.
    pub fn strategy<S2: TransitionStrategy>(self, strategy: S2) -> CircuitBreakerBuilder<S2, H> {
        CircuitBreakerBuilder {
            config: self.config,
            strategy,
            event_handler: self.event_handler,
        }
    }

    /// Sets the event handler.
    pub fn event_handler<H2: CircuitBreakerEventHandler>(self, handler: H2) -> CircuitBreakerBuilder<S, H2> {
        CircuitBreakerBuilder {
            config: self.config,
            strategy: self.strategy,
            event_handler: handler,
        }
    }

    /// Adds a state change callback (convenience method).
    pub fn on_state_change<F>(self, f: F) -> CircuitBreakerBuilder<S, ClosureEventHandler<F>>
    where
        F: Fn(&StateChangeEvent) + Send + Sync,
    {
        CircuitBreakerBuilder {
            config: self.config,
            strategy: self.strategy,
            event_handler: ClosureEventHandler::new(f),
        }
    }

    /// Builds the circuit breaker.
    pub fn build(self) -> CircuitBreaker<S, H> {
        CircuitBreaker::with_strategy_and_handler(self.config, self.strategy, self.event_handler)
    }
}

// =============================================================================
// Metrics
// =============================================================================

/// Metrics about the circuit breaker state.
#[derive(Debug, Clone, Serialize)]
pub struct CircuitBreakerMetrics {
    /// Current state.
    pub state: CircuitState,
    /// Number of consecutive failures.
    pub failure_count: u32,
    /// Number of consecutive successes.
    pub success_count: u32,
    /// Number of half-open test attempts.
    pub half_open_attempts: u32,
    /// Last failure timestamp.
    pub last_failure_time: Option<DateTime<Utc>>,
    /// Strategy name.
    pub strategy_name: String,
}

// =============================================================================
// Shared Circuit Breaker
// =============================================================================

/// A thread-safe, reference-counted circuit breaker.
///
/// Use this when you need to share a circuit breaker across multiple tasks.
pub type SharedCircuitBreaker<S = CountBasedStrategy, H = LoggingEventHandler> = Arc<CircuitBreaker<S, H>>;

/// Creates a new shared circuit breaker.
pub fn shared(config: CircuitBreakerConfig) -> SharedCircuitBreaker {
    Arc::new(CircuitBreaker::new(config))
}

/// Creates a shared circuit breaker with custom strategy and handler.
pub fn shared_with<S, H>(config: CircuitBreakerConfig, strategy: S, handler: H) -> SharedCircuitBreaker<S, H>
where
    S: TransitionStrategy,
    H: CircuitBreakerEventHandler,
{
    Arc::new(CircuitBreaker::with_strategy_and_handler(config, strategy, handler))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let cb = CircuitBreaker::default_config();
        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
        assert_eq!(cb.success_count(), 0);
    }

    #[test]
    fn test_success_recording() {
        let cb = CircuitBreaker::default_config();

        cb.record_success();
        assert_eq!(cb.success_count(), 1);
        assert_eq!(cb.failure_count(), 0);

        cb.record_success();
        assert_eq!(cb.success_count(), 2);
    }

    #[test]
    fn test_failure_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        // Record failures below threshold
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Closed);

        // Third failure should open the circuit
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
    }

    #[test]
    fn test_success_resets_failure_count() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.failure_count(), 2);

        // Success should reset failure count
        cb.record_success();
        assert_eq!(cb.failure_count(), 0);
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[test]
    fn test_manual_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_manual_trip() {
        let cb = CircuitBreaker::default_config();

        cb.trip();
        assert_eq!(cb.current_state(), CircuitState::Open);
    }

    #[test]
    fn test_encoded_state_roundtrip() {
        let state = EncodedState {
            state: CircuitState::HalfOpen,
            failure_count: 123,
            success_count: 456,
            half_open_attempts: 2,
        };

        let encoded = state.encode();
        let decoded = EncodedState::decode(encoded);

        assert_eq!(decoded.state, CircuitState::HalfOpen);
        assert_eq!(decoded.failure_count, 123);
        assert_eq!(decoded.success_count, 456);
        assert_eq!(decoded.half_open_attempts, 2);
    }

    #[test]
    fn test_config_builder() {
        let config = CircuitBreakerConfig::builder()
            .failure_threshold(10)
            .reset_timeout(Duration::from_secs(60))
            .half_open_max_calls(5)
            .success_rate_threshold(0.8)
            .build();

        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.reset_timeout, Duration::from_secs(60));
        assert_eq!(config.half_open_max_calls, 5);
        assert_eq!(config.success_rate_threshold, 0.8);
    }

    #[test]
    fn test_rate_based_strategy() {
        let strategy = RateBasedStrategy::new(0.5, 5);

        // Not enough calls yet
        assert!(!strategy.should_open(2, 2, &CircuitBreakerConfig::default()));

        // Enough calls, but success rate is good (50%)
        assert!(!strategy.should_open(2, 3, &CircuitBreakerConfig::default()));

        // Enough calls and low success rate
        assert!(strategy.should_open(4, 1, &CircuitBreakerConfig::default()));
    }

    #[test]
    fn test_hybrid_strategy() {
        let strategy = HybridStrategy::new(3, 0.5, 5);
        let config = CircuitBreakerConfig::default();

        // Consecutive failures alone should trigger
        assert!(strategy.should_open(3, 0, &config));

        // Low success rate alone should trigger (with enough calls)
        assert!(strategy.should_open(4, 1, &config));

        // Neither condition met
        assert!(!strategy.should_open(2, 3, &config));
    }

    #[test]
    fn test_builder_pattern() {
        let cb = CircuitBreakerBuilder::new()
            .config(CircuitBreakerConfig::aggressive())
            .strategy(RateBasedStrategy::new(0.6, 3))
            .event_handler(NoOpEventHandler)
            .build();

        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert_eq!(cb.strategy().name(), "rate_based");
    }

    #[test]
    fn test_closure_failure_predicate() {
        let predicate = ClosureFailurePredicate::new(|s: &String| s.contains("error"));

        assert!(predicate.is_failure(&"network error".to_string()));
        assert!(!predicate.is_failure(&"success".to_string()));
    }

    #[test]
    fn test_any_failure_predicate() {
        let p1 = Box::new(ClosureFailurePredicate::new(|s: &String| s.contains("error")));
        let p2 = Box::new(ClosureFailurePredicate::new(|s: &String| s.contains("fail")));
        let any = AnyFailurePredicate::new(vec![p1, p2]);

        assert!(any.is_failure(&"error occurred".to_string()));
        assert!(any.is_failure(&"operation failed".to_string()));
        assert!(!any.is_failure(&"success".to_string()));
    }

    #[test]
    fn test_all_failure_predicate() {
        let p1 = Box::new(ClosureFailurePredicate::new(|s: &String| s.contains("error")));
        let p2 = Box::new(ClosureFailurePredicate::new(|s: &String| s.contains("critical")));
        let all = AllFailurePredicate::new(vec![p1, p2]);

        assert!(all.is_failure(&"critical error".to_string()));
        assert!(!all.is_failure(&"error".to_string()));
        assert!(!all.is_failure(&"critical".to_string()));
    }

    #[tokio::test]
    async fn test_call_success() {
        let cb = CircuitBreakerBuilder::new()
            .event_handler(NoOpEventHandler)
            .build();

        let result: Result<i32, CircuitError<&str>> = cb.call(|| async { Ok(42) }).await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(cb.success_count(), 1);
    }

    #[tokio::test]
    async fn test_call_failure() {
        let cb = CircuitBreakerBuilder::new()
            .event_handler(NoOpEventHandler)
            .build();

        let result: Result<i32, CircuitError<&str>> = cb.call(|| async { Err("error") }).await;

        assert!(matches!(result, Err(CircuitError::Inner("error"))));
        assert_eq!(cb.failure_count(), 1);
    }

    #[tokio::test]
    async fn test_open_circuit_blocks_requests() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            reset_timeout: Duration::from_secs(3600), // Long timeout for test
            ..Default::default()
        };
        let cb = CircuitBreakerBuilder::new()
            .config(config)
            .event_handler(NoOpEventHandler)
            .build();

        // Trip the circuit
        cb.trip();

        // Request should fail immediately
        let result: Result<i32, CircuitError<&str>> = cb.call(|| async { Ok(42) }).await;

        assert!(matches!(result, Err(CircuitError::Open)));
    }

    #[tokio::test]
    async fn test_call_with_predicate() {
        let cb = CircuitBreakerBuilder::new()
            .event_handler(NoOpEventHandler)
            .build();

        // Predicate that only counts "real" errors
        let predicate = ClosureFailurePredicate::new(|s: &&str| *s == "real_error");

        // This error is not a "real" error, shouldn't affect circuit
        let _ = cb
            .call_with_predicate(|| async { Err::<(), _>("not_real") }, &predicate)
            .await;
        assert_eq!(cb.failure_count(), 0);

        // This is a real error
        let _ = cb
            .call_with_predicate(|| async { Err::<(), _>("real_error") }, &predicate)
            .await;
        assert_eq!(cb.failure_count(), 1);
    }

    #[test]
    fn test_metrics() {
        let cb = CircuitBreaker::default_config();
        cb.record_failure();
        cb.record_failure();

        let metrics = cb.metrics();
        assert_eq!(metrics.state, CircuitState::Closed);
        assert_eq!(metrics.failure_count, 2);
        assert_eq!(metrics.success_count, 0);
        assert_eq!(metrics.strategy_name, "count_based");
    }

    #[test]
    fn test_is_allowing_requests() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        assert!(cb.is_allowing_requests());

        cb.record_failure();
        cb.record_failure();

        assert!(!cb.is_allowing_requests());
    }

    #[test]
    fn test_circuit_error_methods() {
        let err: CircuitError<String> = CircuitError::Inner("test".to_string());

        assert!(!err.is_open());
        assert_eq!(err.inner(), Some(&"test".to_string()));

        let mapped = err.map_inner(|s| s.len());
        assert!(matches!(mapped, CircuitError::Inner(4)));

        let open: CircuitError<String> = CircuitError::Open;
        assert!(open.is_open());
        assert_eq!(open.inner(), None);
    }

    #[test]
    fn test_shared_circuit_breaker() {
        let cb = shared(CircuitBreakerConfig::default());
        let cb2 = cb.clone();

        cb.record_failure();
        assert_eq!(cb2.failure_count(), 1);
    }

    #[test]
    fn test_config_presets() {
        let aggressive = CircuitBreakerConfig::aggressive();
        assert_eq!(aggressive.failure_threshold, 3);
        assert_eq!(aggressive.reset_timeout, Duration::from_secs(10));

        let conservative = CircuitBreakerConfig::conservative();
        assert_eq!(conservative.failure_threshold, 10);
        assert_eq!(conservative.reset_timeout, Duration::from_secs(60));
    }
}
