// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! API response types.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

// =============================================================================
// ApiResponse
// =============================================================================

/// Generic API response wrapper.
///
/// Provides consistent response structure across all endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the operation was successful.
    pub success: bool,
    /// Response data (if successful).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Error message (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Additional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ResponseMeta>,
}

impl<T> ApiResponse<T> {
    /// Creates a successful response with data.
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            meta: None,
        }
    }

    /// Creates an error response.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
            meta: None,
        }
    }

    /// Adds metadata to the response.
    pub fn with_meta(mut self, meta: ResponseMeta) -> Self {
        self.meta = Some(meta);
        self
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

// =============================================================================
// Response Meta
// =============================================================================

/// Response metadata for pagination and timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMeta {
    /// Total number of items (for paginated responses).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// Page number (1-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
    /// Items per page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,
    /// Total pages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_pages: Option<u32>,
    /// Request duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl ResponseMeta {
    /// Creates empty metadata.
    pub fn new() -> Self {
        Self {
            total: None,
            page: None,
            per_page: None,
            total_pages: None,
            duration_ms: None,
        }
    }

    /// Creates pagination metadata.
    pub fn pagination(total: u64, page: u32, per_page: u32) -> Self {
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        Self {
            total: Some(total),
            page: Some(page),
            per_page: Some(per_page),
            total_pages: Some(total_pages),
            duration_ms: None,
        }
    }

    /// Sets the duration.
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }
}

impl Default for ResponseMeta {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Error Response
// =============================================================================

/// Standard error response structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error details.
    pub error: ErrorDetails,
}

/// Error details.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetails {
    /// Error code for programmatic handling.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    /// Creates a new error response.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetails {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }

    /// Adds details to the error.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.error.details = Some(details);
        self
    }
}

// =============================================================================
// Typed Responses
// =============================================================================

/// Health check response.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall status.
    pub status: String,
    /// Version string.
    pub version: String,
}

impl HealthResponse {
    /// Creates a healthy response.
    pub fn healthy() -> Self {
        Self {
            status: "ok".to_string(),
            version: crate::VERSION.to_string(),
        }
    }
}

/// Readiness check response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadinessResponse {
    /// Whether the service is ready.
    pub ready: bool,
    /// Component statuses.
    pub components: Vec<ComponentStatus>,
}

/// Status of a system component.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentStatus {
    /// Component name.
    pub name: String,
    /// Whether the component is healthy.
    pub healthy: bool,
    /// Optional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Authentication response.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Access token.
    pub token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Expires in seconds.
    pub expires_in: i64,
    /// Refresh token (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl AuthResponse {
    /// Creates a new auth response.
    pub fn new(token: String, expires_in: i64) -> Self {
        Self {
            token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: None,
        }
    }

    /// Adds a refresh token.
    pub fn with_refresh_token(mut self, refresh_token: String) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_success() {
        let response = ApiResponse::success(42);
        assert!(response.success);
        assert_eq!(response.data, Some(42));
        assert!(response.error.is_none());
    }

    #[test]
    fn test_api_response_error() {
        let response: ApiResponse<()> = ApiResponse::error("Something went wrong");
        assert!(!response.success);
        assert!(response.data.is_none());
        assert_eq!(response.error, Some("Something went wrong".to_string()));
    }

    #[test]
    fn test_response_meta_pagination() {
        let meta = ResponseMeta::pagination(100, 2, 10);
        assert_eq!(meta.total, Some(100));
        assert_eq!(meta.page, Some(2));
        assert_eq!(meta.total_pages, Some(10));
    }

    #[test]
    fn test_error_response() {
        let response = ErrorResponse::new("NOT_FOUND", "Resource not found");
        assert_eq!(response.error.code, "NOT_FOUND");
    }
}
