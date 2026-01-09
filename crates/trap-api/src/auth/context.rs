// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Authentication context.

use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Claims, Permission};
use crate::auth::permission::PermissionSet;

/// Authentication context for a request.
///
/// This is attached to requests after successful authentication and contains
/// all necessary information for authorization and audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// User ID.
    pub user_id: String,
    /// User roles.
    pub roles: Vec<String>,
    /// Resolved permissions.
    #[serde(skip)]
    pub permissions: Arc<PermissionSet>,
    /// Client IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<IpAddr>,
    /// Request ID for tracing.
    pub request_id: Uuid,
    /// Session ID (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// User's display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// User's email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl AuthContext {
    /// Creates a new authentication context from JWT claims.
    pub fn from_claims(claims: &Claims, permissions: PermissionSet) -> Self {
        Self {
            user_id: claims.sub.clone(),
            roles: claims.roles.clone(),
            permissions: Arc::new(permissions),
            client_ip: None,
            request_id: Uuid::now_v7(),
            session_id: claims.session_id.clone(),
            name: claims.name.clone(),
            email: claims.email.clone(),
        }
    }

    /// Creates an anonymous context (for unauthenticated requests).
    pub fn anonymous() -> Self {
        Self {
            user_id: "anonymous".to_string(),
            roles: Vec::new(),
            permissions: Arc::new(PermissionSet::new()),
            client_ip: None,
            request_id: Uuid::now_v7(),
            session_id: None,
            name: None,
            email: None,
        }
    }

    /// Creates a system context (for internal operations).
    pub fn system() -> Self {
        Self {
            user_id: "system".to_string(),
            roles: vec!["system".to_string()],
            permissions: Arc::new(PermissionSet::from_permissions(Permission::all().iter().copied())),
            client_ip: None,
            request_id: Uuid::now_v7(),
            session_id: None,
            name: Some("System".to_string()),
            email: None,
        }
    }

    /// Sets the client IP address.
    pub fn with_client_ip(mut self, ip: IpAddr) -> Self {
        self.client_ip = Some(ip);
        self
    }

    /// Sets the request ID.
    pub fn with_request_id(mut self, request_id: Uuid) -> Self {
        self.request_id = request_id;
        self
    }

    /// Returns `true` if the context has the given role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Returns `true` if the context has any of the given roles.
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|role| self.has_role(role))
    }

    /// Returns `true` if the context has the given permission.
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Returns `true` if the context has all of the given permissions.
    pub fn has_all_permissions(&self, permissions: &[Permission]) -> bool {
        self.permissions.contains_all(permissions)
    }

    /// Returns `true` if the context has any of the given permissions.
    pub fn has_any_permission(&self, permissions: &[Permission]) -> bool {
        self.permissions.contains_any(permissions)
    }

    /// Returns `true` if this is an anonymous context.
    pub fn is_anonymous(&self) -> bool {
        self.user_id == "anonymous"
    }

    /// Returns `true` if this is a system context.
    pub fn is_system(&self) -> bool {
        self.user_id == "system"
    }

    /// Returns `true` if this context has admin privileges.
    pub fn is_admin(&self) -> bool {
        self.has_permission(Permission::SystemAdmin) || self.has_role("admin") || self.has_role("superadmin")
    }

    /// Converts to an audit context.
    pub fn to_audit_context(&self) -> trap_core::AuditContext {
        trap_core::AuditContext {
            user_id: Some(self.user_id.clone()),
            client_ip: self.client_ip,
            request_id: self.request_id,
            roles: self.roles.clone(),
            metadata: serde_json::Value::Null,
        }
    }

    /// Converts to trap_core's AuditContext for audit logging.
    pub fn to_core_audit_context(&self) -> trap_core::audit::AuditContext {
        trap_core::audit::AuditContext {
            user_id: Some(self.user_id.clone()),
            client_ip: self.client_ip,
            request_id: Some(self.request_id),
            session_id: self.session_id.clone(),
            roles: self.roles.clone(),
            user_agent: None,
        }
    }
}

impl Default for AuthContext {
    fn default() -> Self {
        Self::anonymous()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_context_from_claims() {
        let claims = Claims::new("user123", vec!["admin".to_string()], 3600);
        let mut permissions = PermissionSet::new();
        permissions.add(Permission::DeviceRead);
        permissions.add(Permission::DeviceWrite);

        let ctx = AuthContext::from_claims(&claims, permissions);

        assert_eq!(ctx.user_id, "user123");
        assert!(ctx.has_role("admin"));
        assert!(ctx.has_permission(Permission::DeviceRead));
        assert!(!ctx.has_permission(Permission::SystemAdmin));
    }

    #[test]
    fn test_anonymous_context() {
        let ctx = AuthContext::anonymous();

        assert!(ctx.is_anonymous());
        assert!(!ctx.is_admin());
        assert!(ctx.roles.is_empty());
    }

    #[test]
    fn test_system_context() {
        let ctx = AuthContext::system();

        assert!(ctx.is_system());
        assert!(ctx.has_permission(Permission::SystemAdmin));
        assert!(ctx.is_admin());
    }

    #[test]
    fn test_has_any_role() {
        let claims = Claims::new("user", vec!["operator".to_string(), "viewer".to_string()], 3600);
        let ctx = AuthContext::from_claims(&claims, PermissionSet::new());

        assert!(ctx.has_any_role(&["admin", "operator"]));
        assert!(!ctx.has_any_role(&["admin", "superadmin"]));
    }
}
