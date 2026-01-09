// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Implementation of the `health` command.

use std::time::Duration;

use crate::cli::{Cli, HealthArgs, OutputFormat};
use crate::error::{BinError, BinResult};

/// Executes the `health` command to check system health.
pub async fn health_check(cli: &Cli, args: HealthArgs) -> BinResult<()> {
    let config_path = &cli.config;
    let timeout = Duration::from_secs(args.timeout);

    // Load configuration
    let config = if config_path.exists() {
        Some(trap_config::load_config(config_path).ok())
    } else {
        None
    };

    let mut checks = Vec::new();

    // Check 1: Configuration file
    let config_check = HealthCheck {
        name: "Configuration".to_string(),
        status: if config.is_some() && config.as_ref().unwrap().is_some() {
            HealthStatus::Healthy
        } else if config_path.exists() {
            HealthStatus::Unhealthy("Configuration file is invalid".to_string())
        } else {
            HealthStatus::Unhealthy("Configuration file not found".to_string())
        },
        latency_ms: None,
    };
    checks.push(config_check);

    // Check 2: Data directory
    let data_dir_check = if let Some(Some(ref cfg)) = config {
        let path = &cfg.buffer.path;
        HealthCheck {
            name: "Data Directory".to_string(),
            status: if path.exists() {
                if path.is_dir() {
                    // Check if writable
                    let test_file = path.join(".trap_health_check");
                    match std::fs::write(&test_file, b"test") {
                        Ok(_) => {
                            let _ = std::fs::remove_file(&test_file);
                            HealthStatus::Healthy
                        }
                        Err(e) => HealthStatus::Unhealthy(format!("Not writable: {}", e)),
                    }
                } else {
                    HealthStatus::Unhealthy("Path exists but is not a directory".to_string())
                }
            } else {
                HealthStatus::Warning("Directory does not exist (will be created)".to_string())
            },
            latency_ms: None,
        }
    } else {
        HealthCheck {
            name: "Data Directory".to_string(),
            status: HealthStatus::Unknown,
            latency_ms: None,
        }
    };
    checks.push(data_dir_check);

    // Check 3: API endpoint (if running)
    let api_check = if let Some(Some(ref cfg)) = config {
        let url = format!("http://{}:{}/health", cfg.api.bind_address, cfg.api.port);
        let start = std::time::Instant::now();

        let status = match tokio::time::timeout(timeout, check_http_endpoint(&url)).await {
            Ok(Ok(true)) => HealthStatus::Healthy,
            Ok(Ok(false)) => HealthStatus::Unhealthy("Health check failed".to_string()),
            Ok(Err(e)) => HealthStatus::Unhealthy(format!("Connection failed: {}", e)),
            Err(_) => HealthStatus::Unhealthy("Timeout".to_string()),
        };

        HealthCheck {
            name: "API Server".to_string(),
            status,
            latency_ms: Some(start.elapsed().as_millis() as u64),
        }
    } else {
        HealthCheck {
            name: "API Server".to_string(),
            status: HealthStatus::Unknown,
            latency_ms: None,
        }
    };
    checks.push(api_check);

    // Output results
    let all_healthy = checks.iter().all(|c| matches!(c.status, HealthStatus::Healthy | HealthStatus::Warning(_)));

    match args.format {
        OutputFormat::Text => {
            println!("TRAP Gateway Health Check");
            println!("========================");
            println!();

            for check in &checks {
                let (icon, status_text) = match &check.status {
                    HealthStatus::Healthy => ("✓", "healthy".to_string()),
                    HealthStatus::Unhealthy(msg) => ("✗", format!("unhealthy: {}", msg)),
                    HealthStatus::Warning(msg) => ("⚠", format!("warning: {}", msg)),
                    HealthStatus::Unknown => ("?", "unknown".to_string()),
                };

                let latency = check
                    .latency_ms
                    .map(|ms| format!(" ({}ms)", ms))
                    .unwrap_or_default();

                println!("{} {}: {}{}", icon, check.name, status_text, latency);
            }

            println!();
            if all_healthy {
                println!("Overall: ✓ Healthy");
            } else {
                println!("Overall: ✗ Unhealthy");
            }
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "healthy": all_healthy,
                "checks": checks.iter().map(|c| {
                    serde_json::json!({
                        "name": c.name,
                        "status": match &c.status {
                            HealthStatus::Healthy => "healthy",
                            HealthStatus::Unhealthy(_) => "unhealthy",
                            HealthStatus::Warning(_) => "warning",
                            HealthStatus::Unknown => "unknown",
                        },
                        "message": match &c.status {
                            HealthStatus::Unhealthy(msg) => Some(msg.clone()),
                            HealthStatus::Warning(msg) => Some(msg.clone()),
                            _ => None,
                        },
                        "latency_ms": c.latency_ms,
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        OutputFormat::Yaml => {
            println!("healthy: {}", all_healthy);
            println!("checks:");
            for check in &checks {
                println!("  - name: {}", check.name);
                println!("    status: {}", match &check.status {
                    HealthStatus::Healthy => "healthy",
                    HealthStatus::Unhealthy(_) => "unhealthy",
                    HealthStatus::Warning(_) => "warning",
                    HealthStatus::Unknown => "unknown",
                });
                if let Some(ms) = check.latency_ms {
                    println!("    latency_ms: {}", ms);
                }
            }
        }
    }

    if all_healthy {
        Ok(())
    } else {
        Err(BinError::Health("One or more health checks failed".to_string()))
    }
}

/// Checks if an HTTP endpoint is healthy.
async fn check_http_endpoint(url: &str) -> Result<bool, String> {
    // Simple TCP connection check since we don't have reqwest in trap-bin
    let addr = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .ok_or_else(|| "Invalid URL".to_string())?;

    match tokio::net::TcpStream::connect(addr).await {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

/// Health check result.
struct HealthCheck {
    name: String,
    status: HealthStatus,
    latency_ms: Option<u64>,
}

/// Health check status.
enum HealthStatus {
    Healthy,
    Unhealthy(String),
    Warning(String),
    Unknown,
}
