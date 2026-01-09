// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Logging and tracing initialization.
//!
//! This module provides utilities for setting up structured logging
//! using the `tracing` ecosystem.

use tracing::Level;
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

use crate::cli::LogFormat;

// =============================================================================
// Logging Initialization
// =============================================================================

/// Initializes the logging subsystem.
///
/// # Arguments
///
/// * `level` - Log level string (trace, debug, info, warn, error)
/// * `format` - Log output format (text, json, compact)
///
/// # Example
///
/// ```ignore
/// use trap_bin::logging::init_logging;
/// use trap_bin::cli::LogFormat;
///
/// init_logging("info", LogFormat::Text);
/// ```
pub fn init_logging(level: &str, format: LogFormat) {
    // Build the filter from the level string and environment
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level))
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("axum=info".parse().unwrap())
        .add_directive("tokio=info".parse().unwrap());

    // Initialize based on format
    match format {
        LogFormat::Text => init_text_logging(env_filter),
        LogFormat::Json => init_json_logging(env_filter),
        LogFormat::Compact => init_compact_logging(env_filter),
    }
}

/// Initializes text-based logging (default).
fn init_text_logging(filter: EnvFilter) {
    let is_terminal = std::io::IsTerminal::is_terminal(&std::io::stdout());

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_ansi(is_terminal),
        );

    subscriber.init();
}

/// Initializes JSON logging (for production/log aggregation).
fn init_json_logging(filter: EnvFilter) {
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .json()
                .with_target(true)
                .with_file(true)
                .with_line_number(true)
                .with_current_span(true)
                .with_span_list(true),
        );

    subscriber.init();
}

/// Initializes compact logging (minimal output).
fn init_compact_logging(filter: EnvFilter) {
    let is_terminal = std::io::IsTerminal::is_terminal(&std::io::stdout());

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .compact()
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .with_ansi(is_terminal),
        );

    subscriber.init();
}

// =============================================================================
// Log Level Parsing
// =============================================================================

/// Parses a log level string into a `Level`.
pub fn parse_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" | "warning" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

/// Returns a human-readable description of log levels.
pub fn log_level_help() -> &'static str {
    r#"Log levels (from most to least verbose):
  trace  - Very detailed debugging information
  debug  - Debugging information
  info   - General informational messages (default)
  warn   - Warning messages
  error  - Error messages only"#
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_level() {
        assert_eq!(parse_level("trace"), Level::TRACE);
        assert_eq!(parse_level("DEBUG"), Level::DEBUG);
        assert_eq!(parse_level("Info"), Level::INFO);
        assert_eq!(parse_level("WARN"), Level::WARN);
        assert_eq!(parse_level("warning"), Level::WARN);
        assert_eq!(parse_level("error"), Level::ERROR);
        assert_eq!(parse_level("invalid"), Level::INFO);
    }
}
