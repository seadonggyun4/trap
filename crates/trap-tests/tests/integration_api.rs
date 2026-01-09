// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # API Integration Tests
//!
//! Integration tests for trap-api functionality including:
//!
//! - JWT authentication and token management
//! - RBAC authorization
//! - API response formatting
//! - Error handling
//!
//! ## Test Categories
//!
//! - `test_auth_*`: Authentication tests
//! - `test_rbac_*`: Role-based access control tests
//! - `test_response_*`: Response formatting tests
//! - `test_error_*`: Error handling tests

use trap_api::{
    // Auth
    auth::permission::PermissionSet,
    AuthContext, Claims, JwtConfig, JwtManager, Permission, Role, RbacPolicy,
    // Config
    ApiConfig,
    // Response
    ApiResponse,
    // Error
    ApiError,
};

// =============================================================================
// Test Helpers
// =============================================================================

/// Creates a test JWT configuration with a valid secret.
fn test_jwt_config() -> JwtConfig {
    JwtConfig {
        secret: "test-secret-key-for-jwt-signing-must-be-at-least-32-chars".to_string(),
        ..JwtConfig::default()
    }
}

// =============================================================================
// JWT Authentication Tests
// =============================================================================

#[tokio::test]
async fn test_auth_jwt_manager_creation() {
    let config = test_jwt_config();
    let manager = JwtManager::new(config);
    assert!(manager.is_ok());
}

#[tokio::test]
async fn test_auth_jwt_token_generation() {
    let config = test_jwt_config();
    let manager = JwtManager::new(config).expect("Failed to create JWT manager");

    let claims = Claims::new("user-001", vec!["admin".to_string()], 3600);
    let token = manager.create_token(&claims);
    assert!(token.is_ok());

    let token_str = token.unwrap();
    assert!(!token_str.is_empty());
    // JWT tokens have 3 parts separated by dots
    assert_eq!(token_str.split('.').count(), 3);
}

#[tokio::test]
async fn test_auth_jwt_token_validation() {
    let config = test_jwt_config();
    let manager = JwtManager::new(config).expect("Failed to create JWT manager");

    // Generate token
    let claims = Claims::new("user-001", vec!["admin".to_string(), "operator".to_string()], 3600);
    let token = manager.create_token(&claims).expect("Failed to generate token");

    // Validate token
    let validated = manager.validate_token(&token);
    assert!(validated.is_ok());

    let validated_data = validated.unwrap();
    assert_eq!(validated_data.claims.sub, "user-001");
    assert!(validated_data.claims.roles.contains(&"admin".to_string()));
    assert!(validated_data.claims.roles.contains(&"operator".to_string()));
}

#[tokio::test]
async fn test_auth_jwt_invalid_token() {
    let config = test_jwt_config();
    let manager = JwtManager::new(config).expect("Failed to create JWT manager");

    // Invalid token
    let result = manager.validate_token("invalid.token.here");
    assert!(result.is_err());

    // Tampered token (modified payload)
    let claims = Claims::new("user-001", vec!["admin".to_string()], 3600);
    let token = manager.create_token(&claims).expect("Failed to generate");
    let parts: Vec<&str> = token.split('.').collect();
    let tampered = format!("{}.tampered.{}", parts[0], parts[2]);

    let result = manager.validate_token(&tampered);
    assert!(result.is_err());
}

// =============================================================================
// RBAC Tests
// =============================================================================

#[tokio::test]
async fn test_rbac_default_roles() {
    let policy = RbacPolicy::new();

    // Reader role should have read permission
    assert!(policy.has_permission(&["reader".to_string()], Permission::DeviceRead));
    assert!(!policy.has_permission(&["reader".to_string()], Permission::DeviceWrite));

    // Operator role should have read and write permissions
    assert!(policy.has_permission(&["operator".to_string()], Permission::DeviceRead));
    assert!(policy.has_permission(&["operator".to_string()], Permission::DeviceWrite));

    // Admin role should have config permissions
    assert!(policy.has_permission(&["admin".to_string()], Permission::ConfigRead));
    assert!(policy.has_permission(&["admin".to_string()], Permission::ConfigWrite));
}

#[tokio::test]
async fn test_rbac_superadmin() {
    let policy = RbacPolicy::new();

    // Superadmin should have all permissions
    assert!(policy.has_permission(&["superadmin".to_string()], Permission::DeviceRead));
    assert!(policy.has_permission(&["superadmin".to_string()], Permission::DeviceWrite));
    assert!(policy.has_permission(&["superadmin".to_string()], Permission::ConfigRead));
    assert!(policy.has_permission(&["superadmin".to_string()], Permission::ConfigWrite));
    assert!(policy.has_permission(&["superadmin".to_string()], Permission::SystemAdmin));
}

#[tokio::test]
async fn test_rbac_multiple_roles() {
    let policy = RbacPolicy::new();

    // User with both reader and operator roles should have combined permissions
    let roles = vec!["reader".to_string(), "operator".to_string()];

    assert!(policy.has_permission(&roles, Permission::DeviceRead));
    assert!(policy.has_permission(&roles, Permission::DeviceWrite));
}

#[tokio::test]
async fn test_rbac_unknown_role() {
    let policy = RbacPolicy::new();

    // Unknown role should have no permissions
    assert!(!policy.has_permission(&["unknown_role".to_string()], Permission::DeviceRead));
    assert!(!policy.has_permission(&["unknown_role".to_string()], Permission::DeviceWrite));
}

#[tokio::test]
async fn test_rbac_no_roles() {
    let policy = RbacPolicy::new();

    // No roles = no permissions
    assert!(!policy.has_permission(&[], Permission::DeviceRead));
}

// =============================================================================
// Role Tests
// =============================================================================

#[tokio::test]
async fn test_role_as_str() {
    assert_eq!(Role::Reader.as_str(), "reader");
    assert_eq!(Role::Operator.as_str(), "operator");
    assert_eq!(Role::Admin.as_str(), "admin");
    assert_eq!(Role::Superadmin.as_str(), "superadmin");
}

#[tokio::test]
async fn test_role_default_permissions() {
    // Each role should have default permissions
    let reader_perms = Role::Reader.default_permissions();
    assert!(reader_perms.contains(&Permission::DeviceRead));

    let admin_perms = Role::Admin.default_permissions();
    assert!(admin_perms.contains(&Permission::ConfigWrite));
}

// =============================================================================
// API Response Tests
// =============================================================================

#[tokio::test]
async fn test_response_success() {
    let response: ApiResponse<i32> = ApiResponse::success(42);

    assert!(response.success);
    assert_eq!(response.data, Some(42));
    assert!(response.error.is_none());
}

#[tokio::test]
async fn test_response_error() {
    let response: ApiResponse<()> = ApiResponse::error("Something went wrong");

    assert!(!response.success);
    assert!(response.data.is_none());
    assert!(response.error.is_some());

    let error = response.error.unwrap();
    assert_eq!(error, "Something went wrong");
}

#[tokio::test]
async fn test_response_serialization() {
    let response: ApiResponse<Vec<i32>> = ApiResponse::success(vec![1, 2, 3]);

    let json = serde_json::to_string(&response).expect("Failed to serialize");
    assert!(json.contains("\"success\":true"));
    assert!(json.contains("\"data\":[1,2,3]"));
}

// =============================================================================
// API Error Tests
// =============================================================================

#[tokio::test]
async fn test_error_not_found() {
    let error = ApiError::not_found("device");

    assert_eq!(error.status_code(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_error_bad_request() {
    let error = ApiError::bad_request("Invalid input");

    assert_eq!(error.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(error.user_message(), "Invalid input");
}

#[tokio::test]
async fn test_error_unauthorized() {
    let error = ApiError::unauthorized("Missing token");

    assert_eq!(error.status_code(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_error_forbidden() {
    let error = ApiError::forbidden("Access denied");

    assert_eq!(error.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_error_internal() {
    let error = ApiError::internal("Database error");

    assert_eq!(error.status_code(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}

// =============================================================================
// API Config Tests
// =============================================================================

#[tokio::test]
async fn test_api_config_defaults() {
    let config = ApiConfig::default();

    assert!(config.port > 0);
}

// =============================================================================
// Permission Tests
// =============================================================================

#[tokio::test]
async fn test_permission_from_string() {
    assert_eq!(Permission::parse("device:read"), Some(Permission::DeviceRead));
    assert_eq!(Permission::parse("device:write"), Some(Permission::DeviceWrite));
    assert_eq!(Permission::parse("config:read"), Some(Permission::ConfigRead));
    assert_eq!(Permission::parse("config:write"), Some(Permission::ConfigWrite));
    assert_eq!(Permission::parse("system:admin"), Some(Permission::SystemAdmin));
    assert_eq!(Permission::parse("invalid"), None);
}

#[tokio::test]
async fn test_permission_as_str() {
    assert_eq!(Permission::DeviceRead.as_str(), "device:read");
    assert_eq!(Permission::DeviceWrite.as_str(), "device:write");
    assert_eq!(Permission::ConfigRead.as_str(), "config:read");
    assert_eq!(Permission::ConfigWrite.as_str(), "config:write");
    assert_eq!(Permission::SystemAdmin.as_str(), "system:admin");
}

// =============================================================================
// AuthContext Tests
// =============================================================================

#[tokio::test]
async fn test_auth_context_from_claims() {
    let claims = Claims::new("test-user", vec!["admin".to_string(), "operator".to_string()], 3600);
    let permissions = PermissionSet::new();
    let ctx = AuthContext::from_claims(&claims, permissions);

    assert_eq!(ctx.user_id, "test-user");
    assert_eq!(ctx.roles.len(), 2);
}

#[tokio::test]
async fn test_auth_context_has_role() {
    let claims = Claims::new("test-user", vec!["admin".to_string(), "operator".to_string()], 3600);
    let permissions = PermissionSet::new();
    let ctx = AuthContext::from_claims(&claims, permissions);

    assert!(ctx.has_role("admin"));
    assert!(ctx.has_role("operator"));
    assert!(!ctx.has_role("viewer"));
}

// =============================================================================
// Integration Scenarios
// =============================================================================

#[tokio::test]
async fn test_scenario_admin_full_access() {
    let config = test_jwt_config();
    let jwt_manager = JwtManager::new(config).expect("JWT manager");
    let rbac = RbacPolicy::new();

    // Generate admin token
    let claims = Claims::new("admin-user", vec!["admin".to_string()], 3600);

    let token = jwt_manager.create_token(&claims).expect("Token");
    let validated = jwt_manager.validate_token(&token).expect("Validate");

    // Admin should have device and config permissions
    assert!(rbac.has_permission(&validated.claims.roles, Permission::DeviceRead));
    assert!(rbac.has_permission(&validated.claims.roles, Permission::DeviceWrite));
    assert!(rbac.has_permission(&validated.claims.roles, Permission::ConfigRead));
    assert!(rbac.has_permission(&validated.claims.roles, Permission::ConfigWrite));
}

#[tokio::test]
async fn test_scenario_operator_limited_access() {
    let config = test_jwt_config();
    let jwt_manager = JwtManager::new(config).expect("JWT manager");
    let rbac = RbacPolicy::new();

    // Generate operator token
    let claims = Claims::new("operator-user", vec!["operator".to_string()], 3600);

    let token = jwt_manager.create_token(&claims).expect("Token");
    let validated = jwt_manager.validate_token(&token).expect("Validate");

    // Operator should have device permissions but not config
    assert!(rbac.has_permission(&validated.claims.roles, Permission::DeviceRead));
    assert!(rbac.has_permission(&validated.claims.roles, Permission::DeviceWrite));
    assert!(!rbac.has_permission(&validated.claims.roles, Permission::ConfigWrite));
}

#[tokio::test]
async fn test_scenario_reader_minimal_access() {
    let config = test_jwt_config();
    let jwt_manager = JwtManager::new(config).expect("JWT manager");
    let rbac = RbacPolicy::new();

    // Generate reader token
    let claims = Claims::new("reader-user", vec!["reader".to_string()], 3600);

    let token = jwt_manager.create_token(&claims).expect("Token");
    let validated = jwt_manager.validate_token(&token).expect("Validate");

    // Reader should only have read permission
    assert!(rbac.has_permission(&validated.claims.roles, Permission::DeviceRead));
    assert!(!rbac.has_permission(&validated.claims.roles, Permission::DeviceWrite));
    assert!(!rbac.has_permission(&validated.claims.roles, Permission::ConfigRead));
}
