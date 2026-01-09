// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Custom extractors for API handlers.

use axum::{
    extract::{FromRequestParts, Path, Query},
    http::request::Parts,
    Json,
};
use serde::de::DeserializeOwned;

use crate::auth::AuthContext;
use crate::error::ApiError;

// =============================================================================
// Auth Extractor
// =============================================================================

/// Extractor for authenticated requests.
///
/// Extracts the `AuthContext` from the request extensions. Returns 401 if
/// the user is not authenticated.
///
/// # Example
///
/// ```rust,ignore
/// async fn handler(Auth(ctx): Auth) -> impl IntoResponse {
///     format!("Hello, {}", ctx.user_id)
/// }
/// ```
pub struct Auth(pub AuthContext);

impl<S> FromRequestParts<S> for Auth
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthContext>()
            .cloned()
            .filter(|ctx| !ctx.is_anonymous())
            .map(Auth)
            .ok_or_else(|| ApiError::unauthorized("Authentication required"))
    }
}

// =============================================================================
// Optional Auth Extractor
// =============================================================================

/// Extractor for optionally authenticated requests.
///
/// Extracts the `AuthContext` if available, returns `None` for unauthenticated requests.
pub struct OptionalAuth(pub Option<AuthContext>);

impl<S> FromRequestParts<S> for OptionalAuth
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ctx = parts
            .extensions
            .get::<AuthContext>()
            .cloned()
            .filter(|ctx| !ctx.is_anonymous());
        Ok(OptionalAuth(ctx))
    }
}

// =============================================================================
// Validated JSON Extractor
// =============================================================================

/// Extractor for validated JSON payloads.
///
/// Extracts and deserializes JSON, returning appropriate errors for malformed input.
pub struct ValidatedJson<T>(pub T);

impl<S, T> axum::extract::FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(
        req: axum::http::Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|e| ApiError::bad_request(format!("Invalid JSON: {}", e)))?;

        Ok(ValidatedJson(value))
    }
}

// =============================================================================
// Pagination Extractor
// =============================================================================

/// Query parameters for pagination.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PaginationParams {
    /// Page number (1-indexed).
    #[serde(default = "default_page")]
    pub page: u32,
    /// Items per page.
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 {
    1
}

fn default_per_page() -> u32 {
    20
}

impl PaginationParams {
    /// Returns the offset for database queries.
    pub fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.per_page
    }

    /// Returns the limit for database queries.
    pub fn limit(&self) -> u32 {
        self.per_page.min(100) // Cap at 100
    }

    /// Validates the pagination parameters.
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.page == 0 {
            return Err(ApiError::validation("Page must be greater than 0"));
        }
        if self.per_page == 0 || self.per_page > 100 {
            return Err(ApiError::validation("per_page must be between 1 and 100"));
        }
        Ok(())
    }
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 20,
        }
    }
}

/// Extractor for pagination parameters.
pub struct Pagination(pub PaginationParams);

impl<S> FromRequestParts<S> for Pagination
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(params) = Query::<PaginationParams>::from_request_parts(parts, state)
            .await
            .map_err(|e| ApiError::bad_request(format!("Invalid pagination parameters: {}", e)))?;

        params.validate()?;
        Ok(Pagination(params))
    }
}

// =============================================================================
// Device ID Extractor
// =============================================================================

/// Extractor for device ID from path.
pub struct DeviceIdPath(pub trap_core::DeviceId);

impl<S> FromRequestParts<S> for DeviceIdPath
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(device_id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|e| ApiError::bad_request(format!("Invalid device ID: {}", e)))?;

        if device_id.is_empty() {
            return Err(ApiError::bad_request("Device ID cannot be empty"));
        }

        Ok(DeviceIdPath(trap_core::DeviceId::new(device_id)))
    }
}

// =============================================================================
// Request ID Extractor
// =============================================================================

/// Extractor for the request ID.
pub struct RequestId(pub uuid::Uuid);

impl<S> FromRequestParts<S> for RequestId
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let id = parts
            .extensions
            .get::<AuthContext>()
            .map(|ctx| ctx.request_id)
            .unwrap_or_else(uuid::Uuid::now_v7);

        Ok(RequestId(id))
    }
}

// =============================================================================
// Client IP Extractor
// =============================================================================

/// Extractor for the client IP address.
pub struct ClientIp(pub Option<std::net::IpAddr>);

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try to get from X-Forwarded-For header
        let forwarded = parts
            .headers
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse().ok());

        if let Some(ip) = forwarded {
            return Ok(ClientIp(Some(ip)));
        }

        // Try to get from X-Real-IP header
        let real_ip = parts
            .headers
            .get("X-Real-IP")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        if let Some(ip) = real_ip {
            return Ok(ClientIp(Some(ip)));
        }

        // Fall back to AuthContext
        let from_ctx = parts
            .extensions
            .get::<AuthContext>()
            .and_then(|ctx| ctx.client_ip);

        Ok(ClientIp(from_ctx))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_params() {
        let params = PaginationParams {
            page: 2,
            per_page: 10,
        };

        assert_eq!(params.offset(), 10);
        assert_eq!(params.limit(), 10);
    }

    #[test]
    fn test_pagination_validation() {
        let valid = PaginationParams {
            page: 1,
            per_page: 20,
        };
        assert!(valid.validate().is_ok());

        let invalid_page = PaginationParams {
            page: 0,
            per_page: 20,
        };
        assert!(invalid_page.validate().is_err());

        let invalid_per_page = PaginationParams {
            page: 1,
            per_page: 200,
        };
        assert!(invalid_per_page.validate().is_err());
    }

    #[test]
    fn test_pagination_limit_cap() {
        let params = PaginationParams {
            page: 1,
            per_page: 500,
        };
        assert_eq!(params.limit(), 100); // Capped at 100
    }
}
