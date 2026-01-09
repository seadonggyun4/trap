// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! CLI command implementations.
//!
//! This module contains the implementation of all CLI commands:
//!
//! - `run`: Start the gateway server
//! - `validate`: Validate configuration file
//! - `version`: Show version information
//! - `gen-key`: Generate encryption key
//! - `encrypt`: Encrypt a secret value
//! - `decrypt`: Decrypt a secret value
//! - `health`: Check system health

mod encrypt;
mod health;
mod run;
mod validate;
mod version;

pub use encrypt::{decrypt, encrypt, gen_key};
pub use health::health_check;
pub use run::run;
pub use validate::validate;
pub use version::version;

use crate::cli::{Cli, Commands};
use crate::error::BinResult;

/// Executes the appropriate command based on CLI arguments.
pub async fn execute(cli: Cli) -> BinResult<()> {
    match cli.effective_command() {
        Commands::Run(args) => run::run(&cli, args).await,
        Commands::Validate(args) => validate::validate(&cli, args),
        Commands::Version => version::version(&cli),
        Commands::GenKey(args) => encrypt::gen_key(&cli, args),
        Commands::Encrypt(args) => encrypt::encrypt(&cli, args),
        Commands::Decrypt(args) => encrypt::decrypt(&cli, args),
        Commands::Health(args) => health::health_check(&cli, args).await,
    }
}
