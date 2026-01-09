// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # trap-bin
//!
//! CLI binary for TRAP industrial protocol gateway.
//!
//! This crate provides the main binary entry point for TRAP, including:
//!
//! - CLI argument parsing with clap
//! - Gateway runtime orchestration
//! - Graceful shutdown handling
//! - Logging initialization
//! - Command implementations (run, validate, version, etc.)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                         main.rs                              │
//! │                    (Entry Point)                             │
//! └─────────────────────────┬───────────────────────────────────┘
//!                           │
//!                    ┌──────▼──────┐
//!                    │    cli.rs   │
//!                    │ (Argument   │
//!                    │  Parsing)   │
//!                    └──────┬──────┘
//!                           │
//!               ┌───────────┼───────────┐
//!               ▼           ▼           ▼
//!        ┌──────────┐ ┌──────────┐ ┌──────────┐
//!        │ commands │ │ runtime  │ │ logging  │
//!        │          │ │          │ │          │
//!        └──────────┘ └──────────┘ └──────────┘
//!               │           │
//!               │    ┌──────▼──────┐
//!               │    │  shutdown   │
//!               │    │(Graceful)   │
//!               │    └─────────────┘
//!               │
//!        ┌──────┴──────┐
//!        │   trap-*    │
//!        │  (crates)   │
//!        └─────────────┘
//! ```
//!
//! ## Usage
//!
//! ```bash
//! # Start the gateway (default command)
//! trap
//!
//! # Start with custom config
//! trap -c /etc/trap/config.yaml
//!
//! # Validate configuration
//! trap validate
//!
//! # Show version
//! trap version
//!
//! # Generate encryption key
//! trap gen-key
//!
//! # Encrypt a secret
//! trap encrypt "my-secret" -k <key>
//! ```

#![warn(missing_docs)]
#![deny(unsafe_code)]

// =============================================================================
// Modules
// =============================================================================

pub mod cli;
pub mod commands;
pub mod error;
pub mod logging;
pub mod runtime;
pub mod shutdown;

// =============================================================================
// Re-exports
// =============================================================================

pub use cli::{Cli, Commands};
pub use error::{BinError, BinResult};
pub use logging::init_logging;
pub use runtime::{GatewayRuntime, RuntimeBuilder};
pub use shutdown::{ShutdownCoordinator, ShutdownSignal, ShutdownToken};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name.
pub const NAME: &str = env!("CARGO_PKG_NAME");
