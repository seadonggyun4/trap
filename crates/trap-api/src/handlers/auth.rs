// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Authentication handlers.

use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use trap_core::audit::{ActionResult, AuditAction, AuditLog, AuditResource};

use crate::error::{ApiError, ApiResult};
use crate::extractors::{Auth, ClientIp};
use crate::response::AuthResponse;
use crate::state::AppState;

// =============================================================================
// Login
// =============================================================================

/// Login request body.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Username or email.
    pub username: String,
    /// Password.
    pub password: String,
}

/// POST /api/v1/auth/login
///
/// Authenticates a user and returns a JWT token.
pub async fn login(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    Json(request): Json<LoginRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate input
    if request.username.is_empty() || request.password.is_empty() {
        return Err(ApiError::bad_request("Username and password are required"));
    }

    // TODO: In a real implementation, this would validate against a user store
    // For now, we'll accept a demo user for testing
    let (user_id, roles) = validate_credentials(&request.username, &request.password)?;

    // Create tokens
    let token = state.jwt().create_access_token(&user_id, roles.clone())?;
    let refresh_token = state.jwt().create_refresh_token(&user_id)?;

    // Audit log
    let audit_log = AuditLog::login(&user_id, client_ip, true);
    let logger = state.audit().clone();
    tokio::spawn(async move {
        if let Err(e) = logger.log(audit_log).await {
            tracing::warn!(error = %e, "Failed to log successful login");
        }
    });

    tracing::info!(user_id = %user_id, "User logged in successfully");

    Ok(Json(
        AuthResponse::new(token, state.jwt().expiration_secs()).with_refresh_token(refresh_token),
    ))
}

/// Validates user credentials.
///
/// TODO: Replace with actual user store validation.
fn validate_credentials(username: &str, password: &str) -> ApiResult<(String, Vec<String>)> {
    // Demo users for testing
    match (username, password) {
        ("admin", "admin") => Ok(("admin".to_string(), vec!["admin".to_string()])),
        ("operator", "operator") => Ok(("operator".to_string(), vec!["operator".to_string()])),
        ("reader", "reader") => Ok(("reader".to_string(), vec!["reader".to_string()])),
        _ => Err(ApiError::unauthorized("Invalid username or password")),
    }
}

// =============================================================================
// Logout
// =============================================================================

/// POST /api/v1/auth/logout
///
/// Logs out the current user.
pub async fn logout(
    State(state): State<AppState>,
    Auth(auth_ctx): Auth,
) -> ApiResult<impl IntoResponse> {
    // TODO: In a real implementation, this would invalidate the token
    // (e.g., add to a blocklist or remove from a session store)

    // Audit log
    let audit_log = AuditLog::logout(&auth_ctx.user_id, auth_ctx.client_ip);
    let logger = state.audit().clone();
    tokio::spawn(async move {
        if let Err(e) = logger.log(audit_log).await {
            tracing::warn!(error = %e, "Failed to log logout");
        }
    });

    tracing::info!(user_id = %auth_ctx.user_id, "User logged out");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Logged out successfully"
    })))
}

// =============================================================================
// Refresh Token
// =============================================================================

/// Refresh token request body.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    /// Refresh token.
    pub refresh_token: String,
}

/// POST /api/v1/auth/refresh
///
/// Refreshes an access token using a refresh token.
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(request): Json<RefreshRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate refresh token
    let token_data = state
        .jwt()
        .validate_token(&request.refresh_token)
        .map_err(|_| ApiError::unauthorized("Invalid or expired refresh token"))?;

    // Check if it's a refresh token
    if !token_data.claims.has_role("refresh") {
        return Err(ApiError::bad_request("Not a refresh token"));
    }

    // Get user info and create new access token
    // TODO: In a real implementation, we'd look up the user's current roles
    let user_id = token_data.claims.sub;
    let roles = vec!["user".to_string()]; // Would come from user store

    let new_token = state.jwt().create_access_token(&user_id, roles)?;

    tracing::debug!(user_id = %user_id, "Token refreshed");

    Ok(Json(
        AuthResponse::new(new_token, state.jwt().expiration_secs()),
    ))
}

// =============================================================================
// Current User
// =============================================================================

/// Current user response.
#[derive(Debug, Serialize)]
pub struct CurrentUserResponse {
    /// User ID.
    pub user_id: String,
    /// User roles.
    pub roles: Vec<String>,
    /// User's display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// User's email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Permissions granted to user.
    pub permissions: Vec<String>,
}

/// GET /api/v1/auth/me
///
/// Returns information about the currently authenticated user.
pub async fn current_user(Auth(auth_ctx): Auth) -> ApiResult<impl IntoResponse> {
    let permissions: Vec<String> = auth_ctx
        .permissions
        .iter()
        .map(|p| p.to_string())
        .collect();

    Ok(Json(CurrentUserResponse {
        user_id: auth_ctx.user_id,
        roles: auth_ctx.roles,
        name: auth_ctx.name,
        email: auth_ctx.email,
        permissions,
    }))
}

// =============================================================================
// Change Password
// =============================================================================

/// Change password request body.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    /// Current password.
    pub current_password: String,
    /// New password.
    pub new_password: String,
}

/// POST /api/v1/auth/change-password
///
/// Changes the password for the current user.
pub async fn change_password(
    State(state): State<AppState>,
    Auth(auth_ctx): Auth,
    Json(request): Json<ChangePasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate new password
    if request.new_password.len() < 8 {
        return Err(ApiError::validation("Password must be at least 8 characters"));
    }

    if request.new_password == request.current_password {
        return Err(ApiError::validation(
            "New password must be different from current password",
        ));
    }

    // TODO: Validate current password and update in user store

    // Audit log
    let audit_log = AuditLog::new(
        AuditAction::PasswordChange,
        AuditResource::user(&auth_ctx.user_id),
        ActionResult::Success,
    )
    .with_user(&auth_ctx.user_id, auth_ctx.client_ip);

    let logger = state.audit().clone();
    tokio::spawn(async move {
        if let Err(e) = logger.log(audit_log).await {
            tracing::warn!(error = %e, "Failed to log password change");
        }
    });

    tracing::info!(user_id = %auth_ctx.user_id, "Password changed");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Password changed successfully"
    })))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_credentials() {
        // Valid credentials
        let (user_id, roles) = validate_credentials("admin", "admin").unwrap();
        assert_eq!(user_id, "admin");
        assert!(roles.contains(&"admin".to_string()));

        // Invalid credentials
        assert!(validate_credentials("admin", "wrong").is_err());
        assert!(validate_credentials("unknown", "password").is_err());
    }
}
