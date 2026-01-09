// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! API server implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    http::{header, Method},
    routing::{get, post},
    Router,
};
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::info;

use crate::auth::{JwtManager, RbacPolicy};
use crate::config::ApiConfig;
use crate::error::ApiResult;
use crate::handlers;
use crate::middleware::{AuditLayer, AuthLayer, RateLimitLayer};
use crate::state::AppState;

// =============================================================================
// ApiServer
// =============================================================================

/// The API server.
///
/// This is the main entry point for creating and running the HTTP server.
pub struct ApiServer {
    state: AppState,
    config: Arc<ApiConfig>,
}

impl ApiServer {
    /// Creates a new API server with the given state.
    pub fn new(state: AppState) -> Self {
        let config = state.config.clone();
        Self { state, config }
    }

    /// Creates the router with all routes and middleware.
    pub fn router(&self) -> Router {
        // Create middleware layers
        let cors = create_cors_layer(&self.config);
        let rate_limit = RateLimitLayer::new(self.config.rate_limit.clone());
        let auth = AuthLayer::new(
            self.state.jwt_manager.clone(),
            self.state.rbac_policy.clone(),
        )
        .with_default_public_paths();
        let audit = AuditLayer::new(
            self.state.audit_logger.clone(),
            self.config.audit.clone(),
        );

        // Build the middleware stack
        let middleware_stack = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CompressionLayer::new())
            .layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                self.config.request_timeout,
            ))
            .layer(cors)
            .layer(rate_limit)
            .layer(auth)
            .layer(audit);

        // Create the router
        Router::new()
            // Health endpoints (public)
            .route("/health", get(handlers::health))
            .route("/ready", get(handlers::ready))
            .route("/health/detailed", get(handlers::health_detailed))
            // Metrics (public)
            .route("/metrics", get(handlers::prometheus_metrics))
            // Auth endpoints
            .route("/api/v1/auth/login", post(handlers::login))
            .route("/api/v1/auth/logout", post(handlers::logout))
            .route("/api/v1/auth/refresh", post(handlers::refresh_token))
            .route("/api/v1/auth/me", get(handlers::current_user))
            .route("/api/v1/auth/change-password", post(handlers::change_password))
            // Device endpoints
            .route("/api/v1/devices", get(handlers::list_devices))
            .route("/api/v1/devices/{device_id}", get(handlers::get_device))
            .route(
                "/api/v1/devices/{device_id}/tags/{tag_id}",
                get(handlers::read_tag_value).post(handlers::write_tag_value),
            )
            // Status endpoints
            .route("/api/v1/status", get(handlers::system_status))
            // Apply middleware and state
            .layer(middleware_stack)
            .with_state(self.state.clone())
    }

    /// Runs the server.
    pub async fn run(self) -> ApiResult<()> {
        let addr = self.config.socket_addr();
        let router = self.router();

        info!("Starting API server on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| crate::error::ApiError::internal(format!("Failed to bind: {}", e)))?;

        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| crate::error::ApiError::internal(format!("Server error: {}", e)))?;

        Ok(())
    }

    /// Runs the server with graceful shutdown.
    pub async fn run_with_shutdown(
        self,
        shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> ApiResult<()> {
        let addr = self.config.socket_addr();
        let router = self.router();

        info!("Starting API server on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| crate::error::ApiError::internal(format!("Failed to bind: {}", e)))?;

        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal)
        .await
        .map_err(|e| crate::error::ApiError::internal(format!("Server error: {}", e)))?;

        info!("API server shutdown complete");

        Ok(())
    }

    /// Returns the server address.
    pub fn addr(&self) -> SocketAddr {
        self.config.socket_addr()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Creates the CORS layer from configuration.
fn create_cors_layer(config: &ApiConfig) -> CorsLayer {
    let cors = &config.cors;

    let mut layer = CorsLayer::new()
        .max_age(Duration::from_secs(cors.max_age));

    // Origins
    if cors.allowed_origins.contains(&"*".to_string()) {
        layer = layer.allow_origin(Any);
    } else {
        // Would need to parse origins properly
        layer = layer.allow_origin(Any);
    }

    // Methods
    let methods: Vec<Method> = cors
        .allowed_methods
        .iter()
        .filter_map(|m| m.parse().ok())
        .collect();
    layer = layer.allow_methods(methods);

    // Headers
    if cors.allowed_headers.contains(&"*".to_string()) {
        layer = layer.allow_headers(Any);
    } else {
        layer = layer.allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
        ]);
    }

    // Credentials
    if cors.allow_credentials {
        layer = layer.allow_credentials(true);
    }

    layer
}

// =============================================================================
// Server Builder
// =============================================================================

/// Builder for creating the API server.
pub struct ApiServerBuilder {
    state_builder: crate::state::AppStateBuilder,
}

impl ApiServerBuilder {
    /// Creates a new server builder.
    pub fn new() -> Self {
        Self {
            state_builder: AppState::builder(),
        }
    }

    /// Sets the configuration.
    pub fn config(mut self, config: ApiConfig) -> Self {
        self.state_builder = self.state_builder.config(config);
        self
    }

    /// Sets the JWT manager.
    pub fn jwt_manager(mut self, manager: Arc<JwtManager>) -> Self {
        self.state_builder = self.state_builder.jwt_manager(manager);
        self
    }

    /// Sets the RBAC policy.
    pub fn rbac_policy(mut self, policy: Arc<RbacPolicy>) -> Self {
        self.state_builder = self.state_builder.rbac_policy(policy);
        self
    }

    /// Sets the driver manager.
    pub fn driver_manager(mut self, manager: Arc<trap_core::DriverManager>) -> Self {
        self.state_builder = self.state_builder.driver_manager(manager);
        self
    }

    /// Sets the command sender.
    pub fn command_sender(mut self, sender: trap_core::CommandSender) -> Self {
        self.state_builder = self.state_builder.command_sender(sender);
        self
    }

    /// Sets the data bus.
    pub fn data_bus(mut self, bus: Arc<trap_core::DataBus>) -> Self {
        self.state_builder = self.state_builder.data_bus(bus);
        self
    }

    /// Sets the audit logger.
    pub fn audit_logger(mut self, logger: Arc<dyn trap_core::AuditLogger>) -> Self {
        self.state_builder = self.state_builder.audit_logger(logger);
        self
    }

    /// Builds the server.
    pub fn build(self) -> ApiResult<ApiServer> {
        let state = self.state_builder.build()?;
        Ok(ApiServer::new(state))
    }
}

impl Default for ApiServerBuilder {
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
    use crate::auth::JwtConfig;

    fn test_config() -> ApiConfig {
        let mut config = ApiConfig::default();
        config.jwt = JwtConfig::new("test-secret-key-that-is-long-enough");
        config
    }

    #[test]
    fn test_server_builder() {
        let server = ApiServerBuilder::new()
            .config(test_config())
            .build()
            .unwrap();

        assert_eq!(server.addr().port(), 8080);
    }

    #[test]
    fn test_router_creation() {
        let server = ApiServerBuilder::new()
            .config(test_config())
            .build()
            .unwrap();

        let _router = server.router();
        // If we get here, router was created successfully
    }

    #[tokio::test]
    async fn test_cors_layer() {
        let config = test_config();
        let _layer = create_cors_layer(&config);
        // Layer should be created without errors
    }
}
