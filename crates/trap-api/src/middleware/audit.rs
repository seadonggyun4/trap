// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Audit logging middleware.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    response::Response,
};
use tower::{Layer, Service};
use trap_core::audit::{ActionResult, AuditAction, AuditLog, AuditLogger, AuditResource};

use crate::auth::AuthContext;
use crate::config::AuditConfig;

// =============================================================================
// AuditLayer
// =============================================================================

/// Layer for audit logging.
///
/// This layer wraps services to automatically log requests and responses
/// for security and compliance purposes.
#[derive(Clone)]
pub struct AuditLayer {
    logger: Arc<dyn AuditLogger>,
    config: Arc<AuditConfig>,
}

impl AuditLayer {
    /// Creates a new audit layer.
    pub fn new(logger: Arc<dyn AuditLogger>, config: AuditConfig) -> Self {
        Self {
            logger,
            config: Arc::new(config),
        }
    }

    /// Creates a no-op audit layer that doesn't log anything.
    pub fn noop() -> Self {
        Self {
            logger: Arc::new(trap_core::NoOpAuditLogger),
            config: Arc::new(AuditConfig::default()),
        }
    }
}

impl<S> Layer<S> for AuditLayer {
    type Service = AuditMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuditMiddleware {
            inner,
            logger: self.logger.clone(),
            config: self.config.clone(),
        }
    }
}

// =============================================================================
// AuditMiddleware
// =============================================================================

/// Middleware for audit logging.
#[derive(Clone)]
pub struct AuditMiddleware<S> {
    inner: S,
    logger: Arc<dyn AuditLogger>,
    config: Arc<AuditConfig>,
}

impl<S> AuditMiddleware<S> {
    /// Determines if the request should be audited based on method and path.
    fn should_audit(&self, method: &Method, path: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        let actions = &self.config.audit_actions;

        // Auth endpoints
        if path.contains("/auth/") {
            return actions.authentication;
        }

        // Write operations
        if matches!(*method, Method::POST | Method::PUT | Method::DELETE | Method::PATCH) {
            return actions.write_operations;
        }

        // Read operations
        if *method == Method::GET {
            // Config reads
            if path.contains("/config") {
                return actions.config_changes;
            }
            return actions.read_operations;
        }

        false
    }

    /// Maps HTTP method to audit action.
    fn method_to_action(method: &Method, path: &str) -> AuditAction {
        // Auth endpoints
        if path.contains("/auth/login") {
            return AuditAction::Login;
        }
        if path.contains("/auth/logout") {
            return AuditAction::Logout;
        }

        // Device operations
        if path.contains("/devices") {
            match *method {
                Method::GET => return AuditAction::Read,
                Method::POST if path.ends_with("/devices") => return AuditAction::DeviceAdd,
                Method::POST => return AuditAction::Write, // Write to tag
                Method::PUT | Method::PATCH => return AuditAction::DeviceUpdate,
                Method::DELETE => return AuditAction::DeviceRemove,
                _ => {}
            }
        }

        // Config operations
        if path.contains("/config") {
            return AuditAction::ConfigChange;
        }

        // Default based on method
        match *method {
            Method::GET => AuditAction::Read,
            Method::POST | Method::PUT | Method::PATCH => AuditAction::Write,
            Method::DELETE => AuditAction::DeviceRemove,
            _ => AuditAction::Custom,
        }
    }

    /// Maps status code to action result.
    fn status_to_result(status: StatusCode, _method: &Method, path: &str) -> ActionResult {
        if status.is_success() {
            ActionResult::Success
        } else if status == StatusCode::UNAUTHORIZED {
            if path.contains("/auth/login") {
                ActionResult::failure("Invalid credentials")
            } else {
                ActionResult::Denied
            }
        } else if status == StatusCode::FORBIDDEN {
            ActionResult::Denied
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            ActionResult::rejected("Rate limit exceeded")
        } else {
            ActionResult::failure(format!("HTTP {}", status.as_u16()))
        }
    }
}

impl<S> Service<Request<Body>> for AuditMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let logger = self.logger.clone();
        let _config = self.config.clone();
        let should_audit = self.should_audit(req.method(), req.uri().path());
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let auth_ctx = req.extensions().get::<AuthContext>().cloned();

        let mut inner = self.inner.clone();
        let start = Instant::now();

        Box::pin(async move {
            // Call the inner service
            let response = inner.call(req).await?;

            // Log if needed
            if should_audit {
                let status = response.status();
                let duration_ms = start.elapsed().as_millis() as u64;

                let action = Self::method_to_action(&method, &path);
                let result = Self::status_to_result(status, &method, &path);
                let resource = AuditResource::api(&path);

                let mut log = AuditLog::new(action, resource, result)
                    .with_duration(duration_ms)
                    .with_details(serde_json::json!({
                        "method": method.as_str(),
                        "path": path,
                        "status": status.as_u16(),
                    }));

                // Add user context if available
                if let Some(ctx) = auth_ctx {
                    log = log.with_user(&ctx.user_id, ctx.client_ip);
                    log = log.with_correlation_id(ctx.request_id);
                }

                // Fire and forget logging (non-blocking)
                let logger = logger.clone();
                tokio::spawn(async move {
                    if let Err(e) = logger.log(log).await {
                        tracing::warn!(error = %e, "Failed to write audit log");
                    }
                });
            }

            Ok(response)
        })
    }
}

// =============================================================================
// Audit Entry Builder
// =============================================================================

/// Builder for creating audit log entries in handlers.
pub struct AuditEntryBuilder {
    action: AuditAction,
    resource: AuditResource,
    auth_ctx: Option<AuthContext>,
    details: serde_json::Value,
    duration_ms: Option<u64>,
}

impl AuditEntryBuilder {
    /// Creates a new builder.
    pub fn new(action: AuditAction, resource: AuditResource) -> Self {
        Self {
            action,
            resource,
            auth_ctx: None,
            details: serde_json::Value::Null,
            duration_ms: None,
        }
    }

    /// Sets the auth context.
    pub fn with_auth(mut self, ctx: &AuthContext) -> Self {
        self.auth_ctx = Some(ctx.clone());
        self
    }

    /// Sets the details.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    /// Sets the duration.
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Builds the audit log for a successful operation.
    pub fn success(self) -> AuditLog {
        self.build(ActionResult::Success)
    }

    /// Builds the audit log for a failed operation.
    pub fn failure(self, reason: impl Into<String>) -> AuditLog {
        self.build(ActionResult::failure(reason))
    }

    /// Builds the audit log for a denied operation.
    pub fn denied(self) -> AuditLog {
        self.build(ActionResult::Denied)
    }

    fn build(self, result: ActionResult) -> AuditLog {
        let mut log = AuditLog::new(self.action, self.resource, result);

        if !self.details.is_null() {
            log = log.with_details(self.details);
        }

        if let Some(duration) = self.duration_ms {
            log = log.with_duration(duration);
        }

        if let Some(ctx) = self.auth_ctx {
            log = log.with_user(&ctx.user_id, ctx.client_ip);
            log = log.with_correlation_id(ctx.request_id);
        }

        log
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Creates an audit log for a write operation.
pub fn audit_write(
    auth_ctx: &AuthContext,
    device_id: &str,
    address: &str,
    value: &trap_core::Value,
    success: bool,
    duration_ms: u64,
) -> AuditLog {
    let resource = AuditResource::device_tag(device_id, address);
    let result = if success {
        ActionResult::Success
    } else {
        ActionResult::failure("Write failed")
    };

    AuditLog::new(AuditAction::Write, resource, result)
        .with_user(&auth_ctx.user_id, auth_ctx.client_ip)
        .with_correlation_id(auth_ctx.request_id)
        .with_duration(duration_ms)
        .with_details(serde_json::json!({
            "device_id": device_id,
            "address": address,
            "value": value.to_json(),
        }))
}

/// Creates an audit log for an access denied event.
pub fn audit_access_denied(
    auth_ctx: &AuthContext,
    resource: &str,
    required_permission: &str,
) -> AuditLog {
    AuditLog::access_denied(
        AuditAction::Read,
        AuditResource::api(resource),
        &auth_ctx.user_id,
        auth_ctx.client_ip,
        format!("Missing permission: {}", required_permission),
    )
    .with_correlation_id(auth_ctx.request_id)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_to_action() {
        assert!(matches!(
            AuditMiddleware::<()>::method_to_action(&Method::GET, "/api/v1/devices"),
            AuditAction::Read
        ));
        assert!(matches!(
            AuditMiddleware::<()>::method_to_action(&Method::POST, "/api/v1/devices"),
            AuditAction::DeviceAdd
        ));
        assert!(matches!(
            AuditMiddleware::<()>::method_to_action(&Method::POST, "/api/v1/auth/login"),
            AuditAction::Login
        ));
    }

    #[test]
    fn test_status_to_result() {
        assert!(AuditMiddleware::<()>::status_to_result(StatusCode::OK, &Method::GET, "/test")
            .is_success());
        assert!(AuditMiddleware::<()>::status_to_result(
            StatusCode::FORBIDDEN,
            &Method::GET,
            "/test"
        )
        .is_denied());
    }

    #[test]
    fn test_audit_entry_builder() {
        let log = AuditEntryBuilder::new(AuditAction::Write, AuditResource::device("test"))
            .with_details(serde_json::json!({"key": "value"}))
            .with_duration(100)
            .success();

        assert_eq!(log.action, AuditAction::Write);
        assert!(log.result.is_success());
        assert_eq!(log.duration_ms, Some(100));
    }
}
