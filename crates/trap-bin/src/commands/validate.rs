// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Implementation of the `validate` command.

use crate::cli::{Cli, OutputFormat, ValidateArgs};
use crate::error::{BinError, BinResult};

/// Executes the `validate` command to validate configuration.
pub fn validate(cli: &Cli, args: ValidateArgs) -> BinResult<()> {
    let config_path = &cli.config;

    // Check if file exists
    if !config_path.exists() {
        return Err(BinError::Configuration(format!(
            "Configuration file not found: {}",
            config_path.display()
        )));
    }

    // Load and validate configuration
    let config = trap_config::load_config(config_path).map_err(|e| {
        BinError::Configuration(format!("Configuration validation failed: {}", e))
    })?;

    // Collect validation warnings
    let mut warnings: Vec<String> = Vec::new();

    // Check for common issues
    if config.devices.is_empty() {
        warnings.push("No devices configured".to_string());
    }

    // Check if JWT secret is configured when JWT is enabled
    if config.security.jwt.enabled && config.security.jwt.secret.is_none() {
        warnings.push("JWT is enabled but no secret is configured".to_string());
    }

    // Check audit log directory
    if config.security.audit.enabled {
        if let Some(parent) = config.security.audit.path.parent() {
            if !parent.exists() {
                warnings.push(format!(
                    "Audit log directory does not exist: {}",
                    parent.display()
                ));
            }
        }
    }

    // Output results based on format
    match args.format {
        OutputFormat::Text => {
            println!("✓ Configuration is valid: {}", config_path.display());
            println!();
            println!("Summary:");
            println!("  Gateway ID: {}", config.gateway.id);
            println!("  Gateway Name: {}", config.gateway.name);
            println!("  Devices: {}", config.devices.len());
            println!("  API: {}:{}", config.api.bind_address, config.api.port);
            println!("  TLS: {}", if config.security.tls.is_some() { "enabled" } else { "disabled" });
            println!("  Audit: {}", if config.security.audit.enabled { "enabled" } else { "disabled" });

            if !warnings.is_empty() {
                println!();
                println!("Warnings:");
                for warning in &warnings {
                    println!("  ⚠ {}", warning);
                }
            }

            if args.show_config {
                println!();
                println!("Parsed configuration:");
                println!("{}", serde_json::to_string_pretty(&config).unwrap_or_else(|_| "(serialization error)".to_string()));
            }
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "valid": true,
                "config_path": config_path.display().to_string(),
                "summary": {
                    "gateway_id": config.gateway.id,
                    "gateway_name": config.gateway.name,
                    "device_count": config.devices.len(),
                    "api_bind_address": config.api.bind_address.to_string(),
                    "api_port": config.api.port,
                    "tls_enabled": config.security.tls.is_some(),
                    "audit_enabled": config.security.audit.enabled,
                },
                "warnings": warnings,
                "config": if args.show_config { Some(&config) } else { None },
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        OutputFormat::Yaml => {
            // Simple YAML-like format
            println!("valid: true");
            println!("config_path: {}", config_path.display());
            println!("gateway_id: {}", config.gateway.id);
            println!("gateway_name: {}", config.gateway.name);
            println!("device_count: {}", config.devices.len());
            if !warnings.is_empty() {
                println!("warnings:");
                for warning in &warnings {
                    println!("  - {}", warning);
                }
            }
        }
    }

    // In strict mode, treat warnings as errors
    if args.strict && !warnings.is_empty() {
        return Err(BinError::Configuration(format!(
            "Strict mode: {} warning(s) found",
            warnings.len()
        )));
    }

    Ok(())
}
