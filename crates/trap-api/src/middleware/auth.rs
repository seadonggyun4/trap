// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! JWT authentication middleware.

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request},
    response::{IntoResponse, Response},
};
use tower::{Layer, Service};
use uuid::Uuid;

use crate::auth::{AuthContext, JwtManager, RbacPolicy};
use crate::error::ApiError;

// =============================================================================
// AuthLayer
// =============================================================================

/// Layer for JWT authentication.
///
/// This layer wraps services to provide JWT authentication. It extracts the
/// token from the Authorization header and validates it.
#[derive(Clone)]
pub struct AuthLayer {
    jwt_manager: Arc<JwtManager>,
    rbac_policy: Arc<RbacPolicy>,
    public_paths: Arc<HashSet<String>>,
}

impl AuthLayer {
    /// Creates a new auth layer.
    pub fn new(jwt_manager: Arc<JwtManager>, rbac_policy: Arc<RbacPolicy>) -> Self {
        Self {
            jwt_manager,
            rbac_policy,
            public_paths: Arc::new(HashSet::new()),
        }
    }

    /// Adds public paths that don't require authentication.
    pub fn with_public_paths(mut self, paths: Vec<String>) -> Self {
        self.public_paths = Arc::new(paths.into_iter().collect());
        self
    }

    /// Creates with default public paths.
    pub fn with_default_public_paths(self) -> Self {
        self.with_public_paths(vec![
            "/health".to_string(),
            "/ready".to_string(),
            "/metrics".to_string(),
            "/api/v1/auth/login".to_string(),
        ])
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            jwt_manager: self.jwt_manager.clone(),
            rbac_policy: self.rbac_policy.clone(),
            public_paths: self.public_paths.clone(),
        }
    }
}

// =============================================================================
// AuthMiddleware
// =============================================================================

/// Middleware for JWT authentication.
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    jwt_manager: Arc<JwtManager>,
    rbac_policy: Arc<RbacPolicy>,
    public_paths: Arc<HashSet<String>>,
}

impl<S> AuthMiddleware<S> {
    /// Checks if a path is public.
    fn is_public_path(&self, path: &str) -> bool {
        // Check exact matches
        if self.public_paths.contains(path) {
            return true;
        }

        // Check prefix matches for paths with parameters
        for public_path in self.public_paths.iter() {
            if public_path.ends_with('*') {
                let prefix = &public_path[..public_path.len() - 1];
                if path.starts_with(prefix) {
                    return true;
                }
            }
        }

        false
    }
}

impl<S> Service<Request<Body>> for AuthMiddleware<S>
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

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let jwt_manager = self.jwt_manager.clone();
        let rbac_policy = self.rbac_policy.clone();
        let is_public = self.is_public_path(req.uri().path());
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Generate request ID
            let request_id = Uuid::now_v7();

            // Extract client IP
            let client_ip = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0.ip());

            // Skip auth for public paths
            if is_public {
                let auth_ctx = AuthContext::anonymous()
                    .with_request_id(request_id);
                let auth_ctx = if let Some(ip) = client_ip {
                    auth_ctx.with_client_ip(ip)
                } else {
                    auth_ctx
                };
                req.extensions_mut().insert(auth_ctx);
                return inner.call(req).await;
            }

            // Extract token from Authorization header
            let token = extract_bearer_token(&req);

            let auth_ctx = match token {
                Some(token) => {
                    // Validate token
                    match jwt_manager.validate_token(&token) {
                        Ok(token_data) => {
                            let claims = token_data.claims;

                            // Get permissions for user's roles
                            let permissions = rbac_policy.get_combined_permissions(&claims.roles);

                            let mut auth_ctx = AuthContext::from_claims(&claims, permissions)
                                .with_request_id(request_id);

                            if let Some(ip) = client_ip {
                                auth_ctx = auth_ctx.with_client_ip(ip);
                            }

                            auth_ctx
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "Token validation failed");
                            return Ok(ApiError::unauthorized(e.to_string()).into_response());
                        }
                    }
                }
                None => {
                    tracing::debug!("No authorization token provided");
                    return Ok(ApiError::unauthorized("No authorization token provided").into_response());
                }
            };

            // Store auth context in request extensions
            req.extensions_mut().insert(auth_ctx);

            inner.call(req).await
        })
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Extracts the bearer token from the Authorization header.
fn extract_bearer_token<B>(req: &Request<B>) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer ").map(|s| s.to_string()))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        use axum::http::HeaderValue;

        let mut req = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        // No header
        assert!(extract_bearer_token(&req).is_none());

        // Invalid format
        req.headers_mut()
            .insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert!(extract_bearer_token(&req).is_none());

        // Valid bearer token
        req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer mytoken123"),
        );
        assert_eq!(extract_bearer_token(&req), Some("mytoken123".to_string()));
    }

    #[test]
    fn test_public_paths() {
        let jwt_manager = Arc::new(
            JwtManager::new(crate::auth::JwtConfig::new("test-secret-key-for-testing")).unwrap(),
        );
        let rbac_policy = Arc::new(RbacPolicy::new());

        let layer = AuthLayer::new(jwt_manager, rbac_policy)
            .with_public_paths(vec!["/health".to_string(), "/api/*".to_string()]);

        let middleware = layer.layer(tower::service_fn(|_req: Request<Body>| async {
            Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
        }));

        assert!(middleware.is_public_path("/health"));
        assert!(middleware.is_public_path("/api/anything"));
        assert!(!middleware.is_public_path("/private"));
    }
}
