// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! API error types and handling.
//!
//! This module provides a comprehensive error type that maps to HTTP status codes
//! and JSON error responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result type alias for API operations.
pub type ApiResult<T> = Result<T, ApiError>;

// =============================================================================
// ApiError
// =============================================================================

/// API error type with HTTP status code mapping.
///
/// This error type is designed to be returned from handlers and automatically
/// converted to appropriate HTTP responses.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Resource not found (404).
    #[error("Resource not found: {resource}")]
    NotFound {
        /// The resource that was not found.
        resource: String,
    },

    /// Bad request (400).
    #[error("Bad request: {message}")]
    BadRequest {
        /// Error message.
        message: String,
    },

    /// Unauthorized (401).
    #[error("Unauthorized: {message}")]
    Unauthorized {
        /// Error message.
        message: String,
    },

    /// Forbidden (403).
    #[error("Forbidden: {message}")]
    Forbidden {
        /// Error message.
        message: String,
    },

    /// Validation error (422).
    #[error("Validation error: {message}")]
    Validation {
        /// Error message.
        message: String,
        /// Field-specific errors.
        #[source]
        errors: Option<ValidationErrors>,
    },

    /// Rate limit exceeded (429).
    #[error("Rate limit exceeded")]
    RateLimitExceeded {
        /// Seconds until retry is allowed.
        retry_after: Option<u64>,
    },

    /// Conflict (409).
    #[error("Conflict: {message}")]
    Conflict {
        /// Error message.
        message: String,
    },

    /// Service unavailable (503).
    #[error("Service unavailable: {message}")]
    ServiceUnavailable {
        /// Error message.
        message: String,
    },

    /// Gateway timeout (504).
    #[error("Gateway timeout")]
    GatewayTimeout,

    /// Internal server error (500).
    #[error("Internal error: {message}")]
    Internal {
        /// Error message (for logging, not user-facing).
        message: String,
    },

    /// Driver error.
    #[error("Driver error: {0}")]
    Driver(#[from] trap_core::DriverError),

    /// Command error.
    #[error("Command error: {0}")]
    Command(#[from] trap_core::CommandError),
}

impl ApiError {
    // =========================================================================
    // Constructors
    // =========================================================================

    /// Creates a not found error.
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    /// Creates a bad request error.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
        }
    }

    /// Creates an unauthorized error.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized {
            message: message.into(),
        }
    }

    /// Creates a forbidden error.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden {
            message: message.into(),
        }
    }

    /// Creates a validation error.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
            errors: None,
        }
    }

    /// Creates a validation error with field errors.
    pub fn validation_with_errors(message: impl Into<String>, errors: ValidationErrors) -> Self {
        Self::Validation {
            message: message.into(),
            errors: Some(errors),
        }
    }

    /// Creates a rate limit exceeded error.
    pub fn rate_limit_exceeded(retry_after: Option<u64>) -> Self {
        Self::RateLimitExceeded { retry_after }
    }

    /// Creates a conflict error.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }

    /// Creates a service unavailable error.
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            message: message.into(),
        }
    }

    /// Creates an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    // =========================================================================
    // Properties
    // =========================================================================

    /// Returns the HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::NotFound { .. } => StatusCode::NOT_FOUND,
            ApiError::BadRequest { .. } => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden { .. } => StatusCode::FORBIDDEN,
            ApiError::Validation { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::RateLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Conflict { .. } => StatusCode::CONFLICT,
            ApiError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::GatewayTimeout => StatusCode::GATEWAY_TIMEOUT,
            ApiError::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Driver(e) => StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            ApiError::Command(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Returns the error code for categorization.
    pub fn error_code(&self) -> &'static str {
        match self {
            ApiError::NotFound { .. } => "NOT_FOUND",
            ApiError::BadRequest { .. } => "BAD_REQUEST",
            ApiError::Unauthorized { .. } => "UNAUTHORIZED",
            ApiError::Forbidden { .. } => "FORBIDDEN",
            ApiError::Validation { .. } => "VALIDATION_ERROR",
            ApiError::RateLimitExceeded { .. } => "RATE_LIMIT_EXCEEDED",
            ApiError::Conflict { .. } => "CONFLICT",
            ApiError::ServiceUnavailable { .. } => "SERVICE_UNAVAILABLE",
            ApiError::GatewayTimeout => "GATEWAY_TIMEOUT",
            ApiError::Internal { .. } => "INTERNAL_ERROR",
            ApiError::Driver(_) => "DRIVER_ERROR",
            ApiError::Command(_) => "COMMAND_ERROR",
        }
    }

    /// Returns a user-friendly error message.
    ///
    /// This message is safe to show to end users and does not expose
    /// internal implementation details.
    pub fn user_message(&self) -> String {
        match self {
            ApiError::NotFound { resource } => format!("{}을(를) 찾을 수 없습니다", resource),
            ApiError::BadRequest { message } => message.clone(),
            ApiError::Unauthorized { .. } => "인증이 필요합니다".to_string(),
            ApiError::Forbidden { .. } => "접근 권한이 없습니다".to_string(),
            ApiError::Validation { message, .. } => format!("입력 검증 실패: {}", message),
            ApiError::RateLimitExceeded { retry_after } => {
                if let Some(seconds) = retry_after {
                    format!("요청 한도를 초과했습니다. {}초 후 다시 시도해주세요", seconds)
                } else {
                    "요청 한도를 초과했습니다".to_string()
                }
            }
            ApiError::Conflict { message } => message.clone(),
            ApiError::ServiceUnavailable { .. } => "서비스를 일시적으로 사용할 수 없습니다".to_string(),
            ApiError::GatewayTimeout => "요청 시간이 초과되었습니다".to_string(),
            ApiError::Internal { .. } => "서버 내부 오류가 발생했습니다".to_string(),
            ApiError::Driver(e) => e.user_message(),
            ApiError::Command(e) => format!("명령 처리 오류: {}", e),
        }
    }

    /// Returns `true` if this error should be logged at error level.
    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            ApiError::Internal { .. }
                | ApiError::ServiceUnavailable { .. }
                | ApiError::GatewayTimeout
        )
    }

    /// Returns `true` if this error should be audited.
    pub fn should_audit(&self) -> bool {
        matches!(
            self,
            ApiError::Unauthorized { .. }
                | ApiError::Forbidden { .. }
                | ApiError::RateLimitExceeded { .. }
                | ApiError::Internal { .. }
        )
    }
}

// =============================================================================
// IntoResponse Implementation
// =============================================================================

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_code = self.error_code();
        let message = self.user_message();

        // Log server errors
        if self.is_server_error() {
            tracing::error!(
                error = %self,
                error_code = error_code,
                status = %status,
                "Server error occurred"
            );
        } else {
            tracing::debug!(
                error = %self,
                error_code = error_code,
                status = %status,
                "Client error occurred"
            );
        }

        let body = ErrorResponseBody {
            error: ErrorDetails {
                code: error_code.to_string(),
                message,
                details: self.error_details(),
            },
        };

        let mut response = (status, Json(body)).into_response();

        // Add Retry-After header for rate limiting
        if let ApiError::RateLimitExceeded {
            retry_after: Some(seconds),
        } = &self
        {
            response.headers_mut().insert(
                "Retry-After",
                seconds.to_string().parse().unwrap(),
            );
        }

        response
    }
}

impl ApiError {
    fn error_details(&self) -> Option<serde_json::Value> {
        match self {
            ApiError::Validation {
                errors: Some(errors),
                ..
            } => Some(serde_json::to_value(errors).unwrap_or_default()),
            ApiError::RateLimitExceeded { retry_after } => {
                retry_after.map(|s| serde_json::json!({ "retry_after": s }))
            }
            _ => None,
        }
    }
}

// =============================================================================
// Error Response Body
// =============================================================================

/// Error response body structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponseBody {
    /// Error details.
    pub error: ErrorDetails,
}

/// Error details within the response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetails {
    /// Error code for programmatic handling.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Additional error details (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

// =============================================================================
// Validation Errors
// =============================================================================

/// Collection of field validation errors.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationErrors {
    /// Field-specific errors.
    pub fields: Vec<FieldError>,
}

impl ValidationErrors {
    /// Creates a new validation errors collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a field error.
    pub fn add(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.fields.push(FieldError {
            field: field.into(),
            message: message.into(),
        });
    }

    /// Returns `true` if there are no errors.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Converts to an ApiError if there are errors.
    pub fn into_result<T>(self, success: T) -> ApiResult<T> {
        if self.is_empty() {
            Ok(success)
        } else {
            Err(ApiError::validation_with_errors(
                "Validation failed",
                self,
            ))
        }
    }
}

impl std::error::Error for ValidationErrors {}

impl std::fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} validation errors", self.fields.len())
    }
}

/// A single field validation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldError {
    /// Field name.
    pub field: String,
    /// Error message.
    pub message: String,
}

// =============================================================================
// From Implementations
// =============================================================================

impl From<trap_core::ApiError> for ApiError {
    fn from(err: trap_core::ApiError) -> Self {
        match err {
            trap_core::ApiError::NotFound { resource } => ApiError::not_found(resource),
            trap_core::ApiError::BadRequest { message } => ApiError::bad_request(message),
            trap_core::ApiError::Unauthorized => ApiError::unauthorized("Authentication required"),
            trap_core::ApiError::Forbidden => ApiError::forbidden("Access denied"),
            trap_core::ApiError::Validation { message } => ApiError::validation(message),
            trap_core::ApiError::RateLimitExceeded => ApiError::rate_limit_exceeded(None),
            trap_core::ApiError::Internal { message, .. } => ApiError::internal(message),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::bad_request(format!("Invalid JSON: {}", err))
    }
}

impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        ApiError::internal(format!("IO error: {}", err))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            ApiError::not_found("device").status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::bad_request("invalid").status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::unauthorized("no token").status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::forbidden("no access").status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ApiError::validation("invalid field").status_code(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            ApiError::rate_limit_exceeded(Some(60)).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ApiError::internal("crash").status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(ApiError::not_found("x").error_code(), "NOT_FOUND");
        assert_eq!(ApiError::unauthorized("x").error_code(), "UNAUTHORIZED");
        assert_eq!(ApiError::forbidden("x").error_code(), "FORBIDDEN");
    }

    #[test]
    fn test_validation_errors() {
        let mut errors = ValidationErrors::new();
        assert!(errors.is_empty());

        errors.add("email", "Invalid email format");
        errors.add("password", "Too short");

        assert!(!errors.is_empty());
        assert_eq!(errors.fields.len(), 2);
    }

    #[test]
    fn test_should_audit() {
        assert!(ApiError::unauthorized("x").should_audit());
        assert!(ApiError::forbidden("x").should_audit());
        assert!(ApiError::rate_limit_exceeded(None).should_audit());
        assert!(ApiError::internal("x").should_audit());
        assert!(!ApiError::not_found("x").should_audit());
        assert!(!ApiError::bad_request("x").should_audit());
    }
}
