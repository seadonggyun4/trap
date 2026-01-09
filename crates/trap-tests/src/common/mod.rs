// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # Common Test Utilities
//!
//! This module provides shared test utilities, fixtures, and helpers for integration tests.
//!
//! ## Architecture
//!
//! The test infrastructure is designed with the following principles:
//!
//! - **Extensibility**: Easy to add new test helpers without modifying existing code
//! - **Reusability**: Common patterns extracted into reusable components
//! - **Isolation**: Each test runs in isolation with its own resources
//! - **Cleanup**: Automatic resource cleanup via RAII patterns
//!
//! ## Module Structure
//!
//! - `fixtures`: Pre-built test data and configurations
//! - `builders`: Builder patterns for constructing test objects
//! - `assertions`: Custom assertion helpers
//! - `mocks`: Mock implementations for testing
//! - `harness`: Test harness for running integration tests

pub mod fixtures;
pub mod builders;
pub mod assertions;
pub mod mocks;
pub mod harness;

// Re-exports for convenience
pub use fixtures::*;
pub use builders::*;
pub use assertions::*;
pub use mocks::*;
pub use harness::*;

use std::sync::Once;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

/// Initialize test logging. Call this at the start of each test module.
pub fn init_test_logging() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("warn,trap=debug")),
            )
            .with_test_writer()
            .init();
    });
}

/// Generate a unique test ID for resource isolation.
pub fn unique_test_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test_{}", timestamp)
}

/// Create a temporary directory for test data.
pub fn temp_test_dir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("Failed to create temp directory")
}
