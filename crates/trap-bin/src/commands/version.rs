// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Implementation of the `version` command.

use crate::cli::Cli;
use crate::error::BinResult;

/// Executes the `version` command to display version information.
pub fn version(_cli: &Cli) -> BinResult<()> {
    println!("TRAP - Transparent Rust Adapter for industrial Protocols");
    println!("Enterprise Edition");
    println!();
    println!("Version Information:");
    println!("  trap-bin:    {}", env!("CARGO_PKG_VERSION"));
    println!("  trap-core:   {}", trap_core::VERSION);
    println!("  trap-api:    {}", trap_api::VERSION);
    println!("  trap-config: {}", trap_config::VERSION);
    println!("  trap-buffer: {}", trap_buffer::VERSION);
    println!();
    println!("Build Information:");
    println!("  Rust Edition: 2024");
    println!("  Target:       {}", std::env::consts::ARCH);
    println!("  OS:           {}", std::env::consts::OS);
    println!();
    println!("Features:");
    println!("  TLS:          {}", if cfg!(feature = "tls") { "enabled" } else { "disabled" });
    println!("  Rate Limit:   {}", if cfg!(feature = "rate-limit") { "enabled" } else { "disabled" });
    println!("  RocksDB:      {}", if cfg!(feature = "rocksdb-backend") { "enabled" } else { "disabled" });
    println!("  Encryption:   {}", if cfg!(feature = "encryption") { "enabled" } else { "disabled" });
    println!();
    println!("License: PolyForm Noncommercial License 1.0.0");
    println!("Copyright (c) 2025 Sylvex. All rights reserved.");
    println!();
    println!("For commercial licensing, contact: contact@sylvex.io");

    Ok(())
}
