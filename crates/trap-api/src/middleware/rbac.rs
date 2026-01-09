// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! RBAC (Role-Based Access Control) middleware.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    http::Request,
    response::{IntoResponse, Response},
};
use tower::{Layer, Service};

use crate::auth::{AuthContext, Permission};
use crate::error::ApiError;

// =============================================================================
// RbacLayer
// =============================================================================

/// Layer for role-based access control.
///
/// This layer checks if the authenticated user has the required permissions
/// to access an endpoint.
#[derive(Clone)]
pub struct RbacLayer {
    required_permissions: Arc<Vec<Permission>>,
    require_all: bool,
}

impl RbacLayer {
    /// Creates a layer requiring a single permission.
    pub fn require(permission: Permission) -> Self {
        Self {
            required_permissions: Arc::new(vec![permission]),
            require_all: true,
        }
    }

    /// Creates a layer requiring all specified permissions.
    pub fn require_all(permissions: Vec<Permission>) -> Self {
        Self {
            required_permissions: Arc::new(permissions),
            require_all: true,
        }
    }

    /// Creates a layer requiring any of the specified permissions.
    pub fn require_any(permissions: Vec<Permission>) -> Self {
        Self {
            required_permissions: Arc::new(permissions),
            require_all: false,
        }
    }
}

impl<S> Layer<S> for RbacLayer {
    type Service = RbacMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RbacMiddleware {
            inner,
            required_permissions: self.required_permissions.clone(),
            require_all: self.require_all,
        }
    }
}

// =============================================================================
// RbacMiddleware
// =============================================================================

/// Middleware for RBAC enforcement.
#[derive(Clone)]
pub struct RbacMiddleware<S> {
    inner: S,
    required_permissions: Arc<Vec<Permission>>,
    require_all: bool,
}

impl<S> Service<Request<Body>> for RbacMiddleware<S>
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
        let required = self.required_permissions.clone();
        let require_all = self.require_all;
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Get auth context from request extensions
            let auth_ctx = req.extensions().get::<AuthContext>().cloned();

            match auth_ctx {
                Some(ctx) => {
                    // Check permissions
                    let has_permission = if require_all {
                        ctx.has_all_permissions(&required)
                    } else {
                        ctx.has_any_permission(&required)
                    };

                    if has_permission {
                        inner.call(req).await
                    } else {
                        tracing::warn!(
                            user_id = %ctx.user_id,
                            required_permissions = ?required.as_slice(),
                            user_roles = ?ctx.roles,
                            "Permission denied"
                        );
                        Ok(ApiError::forbidden("Insufficient permissions").into_response())
                    }
                }
                None => {
                    tracing::warn!("No auth context found, denying access");
                    Ok(ApiError::unauthorized("Authentication required").into_response())
                }
            }
        })
    }
}

// =============================================================================
// Permission Requirement Types
// =============================================================================

/// Macro for creating RBAC layers with specific permissions.
#[macro_export]
macro_rules! require_permission {
    ($perm:expr) => {
        $crate::middleware::RbacLayer::require($perm)
    };
    (all: $($perm:expr),+ $(,)?) => {
        $crate::middleware::RbacLayer::require_all(vec![$($perm),+])
    };
    (any: $($perm:expr),+ $(,)?) => {
        $crate::middleware::RbacLayer::require_any(vec![$($perm),+])
    };
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::permission::PermissionSet;
    use std::convert::Infallible;
    use tower::ServiceExt;

    fn mock_service() -> impl Service<Request<Body>, Response = Response, Error = Infallible, Future = impl Future<Output = Result<Response, Infallible>> + Send> + Clone + Send {
        tower::service_fn(|_req| async {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        })
    }

    fn create_auth_context(permissions: Vec<Permission>) -> AuthContext {
        let mut ctx = AuthContext::anonymous();
        ctx.permissions = Arc::new(PermissionSet::from_permissions(permissions));
        ctx
    }

    #[tokio::test]
    async fn test_rbac_permission_granted() {
        let layer = RbacLayer::require(Permission::DeviceRead);
        let mut service = layer.layer(mock_service());

        let mut req = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        req.extensions_mut()
            .insert(create_auth_context(vec![Permission::DeviceRead]));

        let response = service.ready().await.unwrap().call(req).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rbac_permission_denied() {
        let layer = RbacLayer::require(Permission::DeviceWrite);
        let mut service = layer.layer(mock_service());

        let mut req = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        req.extensions_mut()
            .insert(create_auth_context(vec![Permission::DeviceRead]));

        let response = service.ready().await.unwrap().call(req).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_rbac_require_all() {
        let layer = RbacLayer::require_all(vec![Permission::DeviceRead, Permission::DeviceWrite]);
        let mut service = layer.layer(mock_service());

        // Only one permission - should fail
        let mut req = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(create_auth_context(vec![Permission::DeviceRead]));

        let response = service.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);

        // Both permissions - should pass
        let mut req = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(create_auth_context(vec![
            Permission::DeviceRead,
            Permission::DeviceWrite,
        ]));

        let response = service.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rbac_require_any() {
        let layer = RbacLayer::require_any(vec![Permission::DeviceAdmin, Permission::SystemAdmin]);
        let mut service = layer.layer(mock_service());

        // Has one of the permissions - should pass
        let mut req = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(create_auth_context(vec![Permission::DeviceAdmin]));

        let response = service.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rbac_no_auth_context() {
        let layer = RbacLayer::require(Permission::DeviceRead);
        let mut service = layer.layer(mock_service());

        let req = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = service.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}
