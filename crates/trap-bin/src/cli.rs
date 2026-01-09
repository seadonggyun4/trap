// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! CLI argument parsing and command definitions.
//!
//! This module provides the command-line interface for TRAP using clap.
//! It supports multiple subcommands for different operations:
//!
//! - `run`: Start the gateway (default)
//! - `validate`: Validate configuration file
//! - `version`: Show version information
//! - `gen-key`: Generate encryption key
//! - `encrypt`: Encrypt a secret value

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

// =============================================================================
// Main CLI Structure
// =============================================================================

/// TRAP - Transparent Rust Adapter for industrial Protocols
///
/// Enterprise-grade industrial IoT protocol gateway that provides unified
/// access to various industrial protocols including Modbus, OPC UA, and BACnet.
#[derive(Parser, Debug)]
#[command(
    name = "trap",
    author = "Sylvex <contact@sylvex.io>",
    version = trap_core::VERSION,
    about = "Transparent Rust Adapter for industrial Protocols (Enterprise Edition)",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Configuration file path
    #[arg(
        short,
        long,
        default_value = "trap.yaml",
        env = "TRAP_CONFIG",
        global = true
    )]
    pub config: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(
        short,
        long,
        default_value = "info",
        env = "TRAP_LOG_LEVEL",
        global = true
    )]
    pub log_level: String,

    /// Log format (text, json)
    #[arg(long, default_value = "text", env = "TRAP_LOG_FORMAT", global = true)]
    pub log_format: LogFormat,

    /// Enable quiet mode (minimal output)
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Option<Commands>,
}

// =============================================================================
// Subcommands
// =============================================================================

/// Available subcommands for the TRAP CLI.
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Start the gateway server
    ///
    /// This is the default command when no subcommand is specified.
    /// It starts the TRAP gateway with all configured drivers and the REST API server.
    Run(RunArgs),

    /// Validate the configuration file
    ///
    /// Parses and validates the configuration file without starting the gateway.
    /// Useful for checking configuration before deployment.
    Validate(ValidateArgs),

    /// Show detailed version information
    ///
    /// Displays version information for all components including
    /// build metadata and feature flags.
    Version,

    /// Generate a new encryption key
    ///
    /// Generates a cryptographically secure AES-256 key for encrypting
    /// sensitive configuration values.
    #[command(name = "gen-key")]
    GenKey(GenKeyArgs),

    /// Encrypt a secret value
    ///
    /// Encrypts a plaintext value using the provided encryption key.
    /// The output can be used in configuration files with the ENC: prefix.
    Encrypt(EncryptArgs),

    /// Decrypt a secret value
    ///
    /// Decrypts an encrypted value using the provided encryption key.
    /// Useful for debugging and verifying encrypted values.
    Decrypt(DecryptArgs),

    /// Check system health
    ///
    /// Performs health checks on all configured components and reports status.
    Health(HealthArgs),
}

// =============================================================================
// Command Arguments
// =============================================================================

/// Arguments for the `run` command.
#[derive(Args, Debug, Default, Clone)]
pub struct RunArgs {
    /// Run in daemon mode (detach from terminal)
    #[arg(short, long)]
    pub daemon: bool,

    /// PID file path for daemon mode
    #[arg(long, requires = "daemon")]
    pub pid_file: Option<PathBuf>,

    /// Skip driver connection on startup
    #[arg(long)]
    pub skip_connect: bool,

    /// Enable development mode (relaxed security, detailed errors)
    #[arg(long, env = "TRAP_DEV_MODE")]
    pub dev_mode: bool,
}

/// Arguments for the `validate` command.
#[derive(Args, Debug, Clone)]
pub struct ValidateArgs {
    /// Show parsed configuration after validation
    #[arg(short, long)]
    pub show_config: bool,

    /// Output format for validation results
    #[arg(short, long, default_value = "text")]
    pub format: OutputFormat,

    /// Strict mode: treat warnings as errors
    #[arg(long)]
    pub strict: bool,
}

/// Arguments for the `gen-key` command.
#[derive(Args, Debug, Clone)]
pub struct GenKeyArgs {
    /// Output format for the key
    #[arg(short, long, default_value = "base64")]
    pub format: KeyFormat,

    /// Output file path (default: stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Arguments for the `encrypt` command.
#[derive(Args, Debug, Clone)]
pub struct EncryptArgs {
    /// Value to encrypt
    #[arg(required_unless_present = "stdin")]
    pub value: Option<String>,

    /// Read value from stdin
    #[arg(long)]
    pub stdin: bool,

    /// Encryption key (base64 encoded)
    #[arg(short, long, env = "TRAP_ENCRYPTION_KEY")]
    pub key: Option<String>,

    /// Key file path
    #[arg(long, conflicts_with = "key")]
    pub key_file: Option<PathBuf>,
}

/// Arguments for the `decrypt` command.
#[derive(Args, Debug, Clone)]
pub struct DecryptArgs {
    /// Encrypted value (with or without ENC: prefix)
    #[arg(required_unless_present = "stdin")]
    pub value: Option<String>,

    /// Read value from stdin
    #[arg(long)]
    pub stdin: bool,

    /// Encryption key (base64 encoded)
    #[arg(short, long, env = "TRAP_ENCRYPTION_KEY")]
    pub key: Option<String>,

    /// Key file path
    #[arg(long, conflicts_with = "key")]
    pub key_file: Option<PathBuf>,
}

/// Arguments for the `health` command.
#[derive(Args, Debug, Clone)]
pub struct HealthArgs {
    /// Output format for health check results
    #[arg(short, long, default_value = "text")]
    pub format: OutputFormat,

    /// Timeout for health checks in seconds
    #[arg(short, long, default_value = "10")]
    pub timeout: u64,
}

// =============================================================================
// Enums
// =============================================================================

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    /// Human-readable text format
    #[default]
    Text,
    /// JSON format for structured logging
    Json,
    /// Compact format for minimal output
    Compact,
}

/// Output format for command results.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text format
    #[default]
    Text,
    /// JSON format for programmatic parsing
    Json,
    /// YAML format
    Yaml,
}

/// Encryption key output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum KeyFormat {
    /// Base64 encoded
    #[default]
    Base64,
    /// Hexadecimal encoded
    Hex,
    /// Raw bytes (binary)
    Raw,
}

// =============================================================================
// Helper Methods
// =============================================================================

impl Cli {
    /// Parse CLI arguments from the command line.
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Get the effective command, defaulting to `Run` if none specified.
    pub fn effective_command(&self) -> Commands {
        self.command
            .clone()
            .unwrap_or_else(|| Commands::Run(RunArgs::default()))
    }

    /// Check if verbose logging is enabled.
    pub fn is_verbose(&self) -> bool {
        self.verbose && !self.quiet
    }

    /// Get the effective log level based on flags.
    pub fn effective_log_level(&self) -> &str {
        if self.quiet {
            "warn"
        } else if self.verbose {
            "debug"
        } else {
            &self.log_level
        }
    }
}

impl Default for ValidateArgs {
    fn default() -> Self {
        Self {
            show_config: false,
            format: OutputFormat::Text,
            strict: false,
        }
    }
}

impl Default for GenKeyArgs {
    fn default() -> Self {
        Self {
            format: KeyFormat::Base64,
            output: None,
        }
    }
}

impl Default for HealthArgs {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            timeout: 10,
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
    fn test_default_command() {
        let cli = Cli::parse_from(["trap"]);
        assert!(cli.command.is_none());
        matches!(cli.effective_command(), Commands::Run(_));
    }

    #[test]
    fn test_run_command() {
        let cli = Cli::parse_from(["trap", "run"]);
        assert!(matches!(cli.command, Some(Commands::Run(_))));
    }

    #[test]
    fn test_validate_command() {
        let cli = Cli::parse_from(["trap", "validate", "--show-config"]);
        if let Some(Commands::Validate(args)) = cli.command {
            assert!(args.show_config);
        } else {
            panic!("Expected Validate command");
        }
    }

    #[test]
    fn test_config_path() {
        let cli = Cli::parse_from(["trap", "-c", "/etc/trap/config.yaml"]);
        assert_eq!(cli.config, PathBuf::from("/etc/trap/config.yaml"));
    }

    #[test]
    fn test_log_level() {
        let cli = Cli::parse_from(["trap", "-l", "debug"]);
        assert_eq!(cli.log_level, "debug");
    }

    #[test]
    fn test_quiet_mode() {
        let cli = Cli::parse_from(["trap", "-q"]);
        assert!(cli.quiet);
        assert_eq!(cli.effective_log_level(), "warn");
    }

    #[test]
    fn test_verbose_mode() {
        let cli = Cli::parse_from(["trap", "-v"]);
        assert!(cli.verbose);
        assert_eq!(cli.effective_log_level(), "debug");
    }

    #[test]
    fn test_gen_key_command() {
        let cli = Cli::parse_from(["trap", "gen-key", "-f", "hex"]);
        if let Some(Commands::GenKey(args)) = cli.command {
            assert_eq!(args.format, KeyFormat::Hex);
        } else {
            panic!("Expected GenKey command");
        }
    }

    #[test]
    fn test_encrypt_command() {
        let cli = Cli::parse_from(["trap", "encrypt", "my-secret", "-k", "base64key"]);
        if let Some(Commands::Encrypt(args)) = cli.command {
            assert_eq!(args.value, Some("my-secret".to_string()));
            assert_eq!(args.key, Some("base64key".to_string()));
        } else {
            panic!("Expected Encrypt command");
        }
    }
}
