// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Implementation of the `run` command.

use tracing::info;

use crate::cli::{Cli, RunArgs};
use crate::error::BinResult;
use crate::runtime::RuntimeBuilder;

/// Executes the `run` command to start the gateway.
pub async fn run(cli: &Cli, args: RunArgs) -> BinResult<()> {
    info!("Starting TRAP Gateway...");

    // Build the runtime
    let runtime = RuntimeBuilder::new()
        .config_path(&cli.config)
        .dev_mode(args.dev_mode)
        .skip_connect(args.skip_connect)
        .build()?;

    // Run the gateway
    runtime.run().await
}
