// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Application state shared across handlers.

use std::sync::Arc;

use trap_core::{AuditLogger, CommandSender, DataBus, DriverManager, NoOpAuditLogger};

use crate::auth::{JwtManager, RbacPolicy};
use crate::config::ApiConfig;

// =============================================================================
// AppState
// =============================================================================

/// Application state shared across all handlers.
///
/// This is the central state container that is passed to all handlers via
/// Axum's state extraction mechanism.
#[derive(Clone)]
pub struct AppState {
    /// API configuration.
    pub config: Arc<ApiConfig>,
    /// JWT manager for token operations.
    pub jwt_manager: Arc<JwtManager>,
    /// RBAC policy for authorization.
    pub rbac_policy: Arc<RbacPolicy>,
    /// Driver manager for device operations.
    pub driver_manager: Option<Arc<DriverManager>>,
    /// Command sender for write operations.
    pub command_sender: Option<CommandSender>,
    /// Data bus for subscribing to real-time data.
    pub data_bus: Option<Arc<DataBus>>,
    /// Audit logger.
    pub audit_logger: Arc<dyn AuditLogger>,
}

impl AppState {
    /// Creates a new app state builder.
    pub fn builder() -> AppStateBuilder {
        AppStateBuilder::new()
    }

    /// Returns the JWT manager.
    pub fn jwt(&self) -> &JwtManager {
        &self.jwt_manager
    }

    /// Returns the RBAC policy.
    pub fn rbac(&self) -> &RbacPolicy {
        &self.rbac_policy
    }

    /// Returns the driver manager if available.
    pub fn drivers(&self) -> Option<&Arc<DriverManager>> {
        self.driver_manager.as_ref()
    }

    /// Returns the command sender if available.
    pub fn commands(&self) -> Option<&CommandSender> {
        self.command_sender.as_ref()
    }

    /// Returns the data bus if available.
    pub fn data_bus(&self) -> Option<&Arc<DataBus>> {
        self.data_bus.as_ref()
    }

    /// Returns the audit logger.
    pub fn audit(&self) -> &Arc<dyn AuditLogger> {
        &self.audit_logger
    }
}

// =============================================================================
// AppStateBuilder
// =============================================================================

/// Builder for constructing AppState.
pub struct AppStateBuilder {
    config: Option<ApiConfig>,
    jwt_manager: Option<Arc<JwtManager>>,
    rbac_policy: Option<Arc<RbacPolicy>>,
    driver_manager: Option<Arc<DriverManager>>,
    command_sender: Option<CommandSender>,
    data_bus: Option<Arc<DataBus>>,
    audit_logger: Option<Arc<dyn AuditLogger>>,
}

impl AppStateBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {
            config: None,
            jwt_manager: None,
            rbac_policy: None,
            driver_manager: None,
            command_sender: None,
            data_bus: None,
            audit_logger: None,
        }
    }

    /// Sets the configuration.
    pub fn config(mut self, config: ApiConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the JWT manager.
    pub fn jwt_manager(mut self, manager: Arc<JwtManager>) -> Self {
        self.jwt_manager = Some(manager);
        self
    }

    /// Sets the RBAC policy.
    pub fn rbac_policy(mut self, policy: Arc<RbacPolicy>) -> Self {
        self.rbac_policy = Some(policy);
        self
    }

    /// Sets the driver manager.
    pub fn driver_manager(mut self, manager: Arc<DriverManager>) -> Self {
        self.driver_manager = Some(manager);
        self
    }

    /// Sets the command sender.
    pub fn command_sender(mut self, sender: CommandSender) -> Self {
        self.command_sender = Some(sender);
        self
    }

    /// Sets the data bus.
    pub fn data_bus(mut self, bus: Arc<DataBus>) -> Self {
        self.data_bus = Some(bus);
        self
    }

    /// Sets the audit logger.
    pub fn audit_logger(mut self, logger: Arc<dyn AuditLogger>) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Builds the AppState.
    ///
    /// # Panics
    ///
    /// Panics if required components are not set.
    pub fn build(self) -> crate::error::ApiResult<AppState> {
        let config = self.config.unwrap_or_default();

        let jwt_manager = match self.jwt_manager {
            Some(manager) => manager,
            None => {
                // Create from config
                Arc::new(JwtManager::new(config.jwt.clone())?)
            }
        };

        let rbac_policy = self.rbac_policy.unwrap_or_else(|| Arc::new(RbacPolicy::new()));

        let audit_logger = self
            .audit_logger
            .unwrap_or_else(|| Arc::new(NoOpAuditLogger));

        Ok(AppState {
            config: Arc::new(config),
            jwt_manager,
            rbac_policy,
            driver_manager: self.driver_manager,
            command_sender: self.command_sender,
            data_bus: self.data_bus,
            audit_logger,
        })
    }
}

impl Default for AppStateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// FromRef implementations for extracting parts of state
// =============================================================================

impl axum::extract::FromRef<AppState> for Arc<JwtManager> {
    fn from_ref(state: &AppState) -> Self {
        state.jwt_manager.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<RbacPolicy> {
    fn from_ref(state: &AppState) -> Self {
        state.rbac_policy.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<ApiConfig> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::JwtConfig;

    fn test_jwt_config() -> JwtConfig {
        JwtConfig::new("test-secret-key-that-is-long-enough-for-testing")
    }

    #[test]
    fn test_app_state_builder() {
        let mut config = ApiConfig::default();
        config.jwt = test_jwt_config();

        let state = AppState::builder()
            .config(config)
            .rbac_policy(Arc::new(RbacPolicy::new()))
            .build()
            .unwrap();

        assert!(state.drivers().is_none());
        assert!(state.commands().is_none());
    }

    #[test]
    fn test_app_state_with_components() {
        let mut config = ApiConfig::default();
        config.jwt = test_jwt_config();

        let data_bus = Arc::new(DataBus::new(1024));

        let state = AppState::builder()
            .config(config)
            .data_bus(data_bus)
            .build()
            .unwrap();

        assert!(state.data_bus().is_some());
    }
}
