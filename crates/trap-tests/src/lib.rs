// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # TRAP Integration Tests
//!
//! This crate provides comprehensive integration tests for the TRAP
//! industrial protocol gateway. It includes test utilities, fixtures,
//! and helpers designed for extensibility and maintainability.
//!
//! ## Module Structure
//!
//! - [`common`]: Shared test utilities, fixtures, and helpers
//!   - `fixtures`: Pre-built test data for consistent testing
//!   - `builders`: Builder patterns for constructing test objects
//!   - `assertions`: Custom assertion helpers
//!   - `mocks`: Mock implementations for testing
//!   - `harness`: Test harness for integration tests
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all integration tests
//! cargo test -p trap-tests
//!
//! # Run specific test suite
//! cargo test -p trap-tests --test integration_core
//! cargo test -p trap-tests --test integration_buffer
//! cargo test -p trap-tests --test integration_config
//! cargo test -p trap-tests --test integration_api
//!
//! # Run with verbose output
//! cargo test -p trap-tests -- --nocapture
//!
//! # Run specific test
//! cargo test -p trap-tests test_bus_data_bus_publish_subscribe
//! ```
//!
//! ## Test Categories
//!
//! ### Core Tests (`integration_core.rs`)
//! - Data types and conversions
//! - Message bus operations (DataBus, CommandBus)
//! - Circuit breaker behavior
//! - Driver manager lifecycle
//! - Retry strategies
//!
//! ### Buffer Tests (`integration_buffer.rs`)
//! - Memory buffer operations
//! - Buffer manager with flush logic
//! - Capacity management and eviction
//! - Concurrent buffer operations
//!
//! ### Config Tests (`integration_config.rs`)
//! - Configuration parsing (YAML, TOML, JSON)
//! - Address parsing for all protocols
//! - Validation rules
//! - Environment variable overrides
//!
//! ### API Tests (`integration_api.rs`)
//! - JWT authentication
//! - RBAC authorization
//! - Rate limiting
//! - API response formatting
//!
//! ## Writing New Tests
//!
//! ### Using Fixtures
//!
//! ```rust,ignore
//! use trap_tests::common::fixtures::{DeviceFixtures, DataPointFixtures};
//!
//! #[tokio::test]
//! async fn test_something() {
//!     let device = DeviceFixtures::modbus_plc();
//!     let data_points = DataPointFixtures::data_point_batch(device, 100);
//!     // ... test logic
//! }
//! ```
//!
//! ### Using Builders
//!
//! ```rust,ignore
//! use trap_tests::common::builders::DataPointBuilder;
//!
//! #[tokio::test]
//! async fn test_something() {
//!     let dp = DataPointBuilder::new()
//!         .device_id("my-device")
//!         .tag_id("temperature")
//!         .float_value(25.5)
//!         .build();
//!     // ... test logic
//! }
//! ```
//!
//! ### Using Test Harness
//!
//! ```rust,ignore
//! use trap_tests::common::harness::{TestHarness, TestHarnessConfig};
//!
//! #[tokio::test]
//! async fn test_with_harness() {
//!     let harness = TestHarness::with_name("my_test");
//!     harness.run(|resources| async move {
//!         // Use resources.data_bus, resources.temp_path(), etc.
//!     }).await;
//! }
//! ```

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod common;

/// Re-export commonly used items for convenience.
pub mod prelude {
    pub use crate::common::fixtures::*;
    pub use crate::common::builders::*;
    pub use crate::common::assertions::*;
    pub use crate::common::mocks::*;
    pub use crate::common::harness::*;
}
