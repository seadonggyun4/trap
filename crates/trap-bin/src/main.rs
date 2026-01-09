// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! TRAP - Transparent Rust Adapter for industrial Protocols
//!
//! Main binary entry point for the TRAP gateway.
//!
//! This is an enterprise-grade industrial IoT protocol gateway that provides
//! unified access to various industrial protocols including Modbus, OPC UA,
//! and BACnet.

use clap::Parser;

use trap_bin::cli::Cli;
use trap_bin::commands;
use trap_bin::error::report_error_and_exit;
use trap_bin::logging::init_logging;

/// Application entry point.
#[tokio::main]
async fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.effective_log_level(), cli.log_format);

    // Execute the command
    if let Err(error) = commands::execute(cli).await {
        report_error_and_exit(error);
    }
}
