// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Gateway runtime orchestration.
//!
//! This module provides the core runtime that orchestrates all TRAP components:
//!
//! - Configuration loading and validation
//! - Driver manager initialization
//! - Message bus setup
//! - API server with security middleware
//! - Graceful shutdown coordination

use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};

use trap_config::{load_config, TrapConfig};
use trap_core::{
    AuditLog, AuditLogger,
    CommandBus, DataBus, DriverManager, DriverRegistry,
    FileAuditLogger, NoOpAuditLogger, RotationConfig, CircuitBreakerConfig,
};

use crate::error::{BinError, BinResult};
use crate::shutdown::ShutdownCoordinator;

// =============================================================================
// GatewayRuntime
// =============================================================================

/// The main gateway runtime that orchestrates all components.
///
/// The runtime is responsible for:
/// - Loading and validating configuration
/// - Initializing all components in the correct order
/// - Starting background tasks
/// - Coordinating graceful shutdown
pub struct GatewayRuntime {
    config: Arc<TrapConfig>,
    shutdown: ShutdownCoordinator,
    dev_mode: bool,
}

impl GatewayRuntime {
    /// Creates a new gateway runtime.
    pub fn new(config: TrapConfig) -> Self {
        Self {
            config: Arc::new(config),
            shutdown: ShutdownCoordinator::new(),
            dev_mode: false,
        }
    }

    /// Enables development mode (relaxed security, detailed errors).
    pub fn with_dev_mode(mut self, enabled: bool) -> Self {
        self.dev_mode = enabled;
        self
    }

    /// Runs the gateway until shutdown is signaled.
    pub async fn run(self) -> BinResult<()> {
        info!(
            "Starting TRAP Gateway v{} (Enterprise Edition)",
            trap_core::VERSION
        );

        // Initialize components
        let components = self.initialize_components().await?;

        // Log startup
        self.log_startup(&components).await;

        // Run the main loop
        let result = self.run_main_loop(components).await;

        info!("TRAP Gateway shutdown complete");

        result
    }

    /// Initializes all gateway components.
    async fn initialize_components(&self) -> BinResult<GatewayComponents> {
        info!("Initializing gateway components...");

        // 1. Create audit logger
        let audit_logger = self.create_audit_logger()?;

        // 2. Create message buses
        let data_bus = Arc::new(DataBus::new(
            self.config.buffer.flush.batch_size as usize,
        ));
        let (command_bus, _command_receiver) = CommandBus::channel(500);

        // 3. Create driver registry and manager
        let driver_registry = Arc::new(DriverRegistry::new());
        let circuit_breaker_config = CircuitBreakerConfig::default();
        let driver_manager = Arc::new(DriverManager::new(driver_registry, circuit_breaker_config));

        Ok(GatewayComponents {
            _config: self.config.clone(),
            audit_logger,
            _data_bus: data_bus,
            _command_bus: command_bus,
            driver_manager,
        })
    }

    /// Creates the audit logger based on configuration.
    fn create_audit_logger(&self) -> BinResult<Arc<dyn AuditLogger>> {
        if !self.config.security.audit.enabled {
            info!("Audit logging disabled");
            return Ok(Arc::new(NoOpAuditLogger));
        }

        let log_path = &self.config.security.audit.path;

        // Ensure parent directory exists
        if let Some(parent) = log_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    BinError::Initialization(format!(
                        "Failed to create audit log directory: {}",
                        e
                    ))
                })?;
            }
        }

        let rotation_config = RotationConfig::daily();
        let logger = FileAuditLogger::new(log_path, rotation_config).map_err(|e| {
            BinError::Initialization(format!("Failed to create audit logger: {}", e))
        })?;

        info!("Audit logging enabled: {}", log_path.display());
        Ok(Arc::new(logger))
    }

    /// Logs the startup event to the audit log.
    async fn log_startup(&self, components: &GatewayComponents) {
        let audit_log = AuditLog::system_start(trap_core::VERSION)
            .with_details(serde_json::json!({
                "dev_mode": self.dev_mode,
                "devices_configured": self.config.devices.len(),
                "gateway_id": &self.config.gateway.id,
            }));

        if let Err(e) = components.audit_logger.log(audit_log).await {
            warn!("Failed to log startup event: {}", e);
        }
    }

    /// Runs the main event loop.
    async fn run_main_loop(&self, components: GatewayComponents) -> BinResult<()> {
        // Wait for shutdown signal
        info!(
            "TRAP Gateway is ready (API: {}:{})",
            self.config.api.bind_address,
            self.config.api.port
        );
        self.shutdown.wait_for_shutdown().await;

        // Initiate shutdown
        info!("Shutdown initiated, cleaning up...");

        // Log shutdown event
        let audit_log = AuditLog::system_shutdown(Some("User-initiated shutdown".to_string()));

        if let Err(e) = components.audit_logger.log(audit_log).await {
            warn!("Failed to log shutdown event: {}", e);
        }

        // Disconnect all drivers
        components.driver_manager.disconnect_all().await;

        Ok(())
    }
}

// =============================================================================
// GatewayComponents
// =============================================================================

/// Container for all gateway components.
struct GatewayComponents {
    _config: Arc<TrapConfig>,
    audit_logger: Arc<dyn AuditLogger>,
    _data_bus: Arc<DataBus>,
    _command_bus: CommandBus,
    driver_manager: Arc<DriverManager>,
}

// =============================================================================
// RuntimeBuilder
// =============================================================================

/// Builder for constructing the gateway runtime.
pub struct RuntimeBuilder {
    config_path: Option<std::path::PathBuf>,
    config: Option<TrapConfig>,
    dev_mode: bool,
    _skip_connect: bool,
}

impl RuntimeBuilder {
    /// Creates a new runtime builder.
    pub fn new() -> Self {
        Self {
            config_path: None,
            config: None,
            dev_mode: false,
            _skip_connect: false,
        }
    }

    /// Sets the configuration file path.
    pub fn config_path(mut self, path: impl AsRef<Path>) -> Self {
        self.config_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Sets the configuration directly.
    pub fn config(mut self, config: TrapConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Enables development mode.
    pub fn dev_mode(mut self, enabled: bool) -> Self {
        self.dev_mode = enabled;
        self
    }

    /// Skips driver connection on startup.
    pub fn skip_connect(mut self, skip: bool) -> Self {
        self._skip_connect = skip;
        self
    }

    /// Builds the runtime.
    pub fn build(self) -> BinResult<GatewayRuntime> {
        let config = match self.config {
            Some(cfg) => cfg,
            None => {
                let path = self
                    .config_path
                    .ok_or_else(|| BinError::Configuration("No configuration provided".into()))?;

                load_config(&path).map_err(|e| {
                    BinError::Configuration(format!("Failed to load config from {:?}: {}", path, e))
                })?
            }
        };

        Ok(GatewayRuntime::new(config).with_dev_mode(self.dev_mode))
    }
}

impl Default for RuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TrapConfig {
        TrapConfig::default()
    }

    #[test]
    fn test_runtime_builder() {
        let runtime = RuntimeBuilder::new()
            .config(test_config())
            .dev_mode(true)
            .build()
            .unwrap();

        assert!(runtime.dev_mode);
    }

    #[test]
    fn test_runtime_builder_requires_config() {
        let result = RuntimeBuilder::new().build();
        assert!(result.is_err());
    }
}
