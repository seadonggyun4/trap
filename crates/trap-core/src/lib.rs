// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # trap-core
//!
//! Core abstractions and shared types for TRAP industrial protocol gateway.
//!
//! This crate provides the foundational types, traits, and utilities used across
//! all TRAP components including:
//!
//! - **Types**: Core data types like `DeviceId`, `TagId`, `Value`, `DataPoint`
//! - **Address**: Protocol-agnostic address abstraction
//! - **Error**: Unified error hierarchy
//! - **Driver**: Protocol driver traits and factory patterns
//! - **Bus**: Message bus for internal communication
//! - **Manager**: Driver lifecycle management
//! - **CircuitBreaker**: Fault isolation with lock-free state management
//! - **Message**: Data and system messages for the message bus
//! - **Audit**: Security audit logging
//!
//! ## Feature Flags
//!
//! - `enterprise`: Enables authentication, authorization, and audit logging
//! - `full`: Enables all features
//!
//! ## Example
//!
//! ```rust,ignore
//! use trap_core::types::{DeviceId, TagId, Value, DataPoint, DataQuality};
//! use trap_core::driver::{ProtocolDriver, DriverRegistry};
//! use trap_core::bus::{DataBus, CommandBus};
//! use chrono::Utc;
//!
//! let data_point = DataPoint::new(
//!     DeviceId::new("plc-001"),
//!     TagId::new("temperature"),
//!     Value::Float64(25.5),
//!     DataQuality::Good,
//! );
//!
//! // Create message buses
//! let data_bus = DataBus::new(1024);
//! let command_bus = CommandBus::new(256);
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]

// =============================================================================
// Core Modules
// =============================================================================

pub mod address;
pub mod error;
pub mod types;

// =============================================================================
// Driver & Manager Modules
// =============================================================================

pub mod driver;
pub mod circuit_breaker;
pub mod manager;
pub mod retry;
pub mod hooks;

// =============================================================================
// Message Bus Modules
// =============================================================================

pub mod message;
pub mod bus;
pub mod handler;

// =============================================================================
// Enterprise Modules
// =============================================================================

pub mod audit;

// =============================================================================
// Re-exports for convenience
// =============================================================================

pub use address::*;
pub use error::*;
pub use types::*;

// Re-export CommandError and CommandResult specifically
pub use error::{CommandError, CommandResult};

// Re-export commonly used driver types
pub use driver::{
    CircuitState, DataType, DriverConfig, DriverFactory, DriverRegistry, HealthStatus,
    ProtocolDriver, Subscription, SubscriptionId,
};

// Re-export circuit breaker types
pub use circuit_breaker::{
    // Core types
    CircuitBreaker, CircuitBreakerBuilder, CircuitBreakerConfig, CircuitBreakerConfigBuilder,
    CircuitBreakerMetrics, CircuitError, SharedCircuitBreaker,
    // Strategies
    CountBasedStrategy, HybridStrategy, RateBasedStrategy, TransitionStrategy,
    // Failure predicates
    AllFailurePredicate, AnyFailurePredicate, ClosureFailurePredicate, DefaultFailurePredicate,
    FailurePredicate,
    // Event handlers
    CircuitBreakerEventHandler, ClosureEventHandler, CompositeEventHandler, LoggingEventHandler,
    NoOpEventHandler, OperationEvent, StateChangeEvent,
    // Factory functions
    shared, shared_with,
};

// Re-export manager types
pub use manager::{DeviceInfo, DriverManager, DriverMetrics, DriverMetricsSnapshot, DriverWrapper};

// Re-export message types
pub use message::{ConnectionStatus, DataMessage, ErrorType, SystemEvent};

// Re-export bus types
pub use bus::{
    AuditContext, BusHandle, BusStats, CommandBus, CommandBusStats, CommandReceiver, CommandSender,
    DataBus, DataSubscriber, DeviceFilteredSubscriber, WriteCommand, WriteResponse,
};

// Re-export handler types
pub use handler::{
    CommandHandler, CommandHandlerBuilder, HandlerConfig, HandlerMetrics, HandlerMetricsSnapshot,
    NoOpWriteHandler, WriteHandler,
};

// Re-export audit types
pub use audit::{
    // Core types
    ActionResult, AuditAction, AuditError, AuditFilter, AuditLog, AuditLogger, AuditResource,
    AuditContext as AuditLogContext, AuditSeverity, SensitiveValue,
    // Loggers
    FileAuditLogger, InMemoryAuditLogger, NoOpAuditLogger,
    AsyncBatchAuditLogger, CompositeAuditLogger, BatchConfig,
    FilteringLogger, TeeLogger, RateLimitedLogger,
    // Formatters
    AuditFormatter, JsonFormatter, CompactJsonFormatter, TextFormatter,
    CefFormatter, SyslogFormatter,
    // Configuration
    RotationConfig, RotationStrategy,
    // Metrics
    AuditMetrics, AuditMetricsCollector,
};

// Re-export retry types
pub use retry::{
    DecorrelatedJitter, ExponentialBackoff, FibonacciBackoff, FixedDelay, LinearBackoff,
    MeteredRetryStrategy, NoRetry, RetryConfig, RetryDecision, RetryMetrics, RetryMetricsSnapshot,
    RetryStrategy,
};

// Re-export hooks types
pub use hooks::{
    CollectorHandler, DriverEvent, EventDispatcher, EventHandler, FilterHandler, HookCallback,
    HookContext, HookRegistry, ObservableOperations, TracingHandler, TracingLevel,
};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name
pub const NAME: &str = env!("CARGO_PKG_NAME");
