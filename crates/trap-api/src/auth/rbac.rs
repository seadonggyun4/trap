// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Role-Based Access Control (RBAC).

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::permission::PermissionSet;
use super::Permission;

// =============================================================================
// Role
// =============================================================================

/// Predefined roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only access to device data.
    Reader,
    /// Can read and write device data.
    Operator,
    /// Full device management plus configuration.
    Admin,
    /// Complete system access.
    Superadmin,
    /// Custom role (requires explicit permissions).
    Custom,
}

impl Role {
    /// Returns the role name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Reader => "reader",
            Role::Operator => "operator",
            Role::Admin => "admin",
            Role::Superadmin => "superadmin",
            Role::Custom => "custom",
        }
    }

    /// Parses a role from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "reader" | "viewer" => Some(Role::Reader),
            "operator" | "user" => Some(Role::Operator),
            "admin" | "administrator" => Some(Role::Admin),
            "superadmin" | "super_admin" | "root" => Some(Role::Superadmin),
            "custom" => Some(Role::Custom),
            _ => None,
        }
    }

    /// Returns the default permissions for this role.
    pub fn default_permissions(&self) -> Vec<Permission> {
        match self {
            Role::Reader => vec![Permission::DeviceRead],
            Role::Operator => vec![Permission::DeviceRead, Permission::DeviceWrite],
            Role::Admin => vec![
                Permission::DeviceRead,
                Permission::DeviceWrite,
                Permission::DeviceAdmin,
                Permission::ConfigRead,
                Permission::ConfigWrite,
                Permission::UserRead,
            ],
            Role::Superadmin => Permission::all().to_vec(),
            Role::Custom => vec![],
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Role Permissions
// =============================================================================

/// Permissions assigned to a role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermissions {
    /// Role name.
    pub role: String,
    /// Permissions assigned to this role.
    pub permissions: Vec<Permission>,
    /// Description of the role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl RolePermissions {
    /// Creates a new role permissions entry.
    pub fn new(role: impl Into<String>, permissions: Vec<Permission>) -> Self {
        Self {
            role: role.into(),
            permissions,
            description: None,
        }
    }

    /// Creates role permissions from a predefined role.
    pub fn from_role(role: Role) -> Self {
        Self {
            role: role.as_str().to_string(),
            permissions: role.default_permissions(),
            description: Some(Self::default_description(role)),
        }
    }

    /// Adds a description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    fn default_description(role: Role) -> String {
        match role {
            Role::Reader => "Read-only access to device data".to_string(),
            Role::Operator => "Read and write access to device data".to_string(),
            Role::Admin => "Full device management and configuration access".to_string(),
            Role::Superadmin => "Complete system administration access".to_string(),
            Role::Custom => "Custom role with explicit permissions".to_string(),
        }
    }
}

// =============================================================================
// RBAC Policy
// =============================================================================

/// RBAC policy for permission management.
///
/// This is the central component for managing role-to-permission mappings.
/// It is designed to be created once at startup and shared across all requests.
#[derive(Debug, Clone)]
pub struct RbacPolicy {
    /// Role to permissions mapping.
    role_permissions: Arc<HashMap<String, PermissionSet>>,
    /// Default role for new users.
    default_role: String,
}

impl RbacPolicy {
    /// Creates a new RBAC policy with default roles.
    pub fn new() -> Self {
        let mut role_permissions = HashMap::new();

        // Set up default role permissions
        for role in &[Role::Reader, Role::Operator, Role::Admin, Role::Superadmin] {
            let perms = PermissionSet::from_permissions(role.default_permissions());
            role_permissions.insert(role.as_str().to_string(), perms);
        }

        Self {
            role_permissions: Arc::new(role_permissions),
            default_role: Role::Reader.as_str().to_string(),
        }
    }

    /// Creates a policy builder.
    pub fn builder() -> RbacPolicyBuilder {
        RbacPolicyBuilder::new()
    }

    /// Returns the permissions for a given role.
    pub fn get_permissions(&self, role: &str) -> Option<&PermissionSet> {
        self.role_permissions.get(role)
    }

    /// Returns the combined permissions for multiple roles.
    pub fn get_combined_permissions(&self, roles: &[String]) -> PermissionSet {
        let mut combined = PermissionSet::new();

        for role in roles {
            if let Some(perms) = self.role_permissions.get(role) {
                combined.merge(perms);
            }
        }

        combined
    }

    /// Returns `true` if the given roles have the specified permission.
    pub fn has_permission(&self, roles: &[String], permission: Permission) -> bool {
        for role in roles {
            if let Some(perms) = self.role_permissions.get(role) {
                if perms.contains(permission) {
                    return true;
                }
            }
        }
        false
    }

    /// Returns `true` if the given roles have all the specified permissions.
    pub fn has_all_permissions(&self, roles: &[String], permissions: &[Permission]) -> bool {
        let combined = self.get_combined_permissions(roles);
        combined.contains_all(permissions)
    }

    /// Returns `true` if the given roles have any of the specified permissions.
    pub fn has_any_permission(&self, roles: &[String], permissions: &[Permission]) -> bool {
        let combined = self.get_combined_permissions(roles);
        combined.contains_any(permissions)
    }

    /// Returns the default role name.
    pub fn default_role(&self) -> &str {
        &self.default_role
    }

    /// Returns all registered role names.
    pub fn roles(&self) -> Vec<&str> {
        self.role_permissions.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for RbacPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// RBAC Policy Builder
// =============================================================================

/// Builder for constructing RBAC policies.
#[derive(Debug, Default)]
pub struct RbacPolicyBuilder {
    role_permissions: HashMap<String, PermissionSet>,
    default_role: Option<String>,
}

impl RbacPolicyBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds default roles with their standard permissions.
    pub fn with_default_roles(mut self) -> Self {
        for role in &[Role::Reader, Role::Operator, Role::Admin, Role::Superadmin] {
            let perms = PermissionSet::from_permissions(role.default_permissions());
            self.role_permissions.insert(role.as_str().to_string(), perms);
        }
        self
    }

    /// Adds a role with specific permissions.
    pub fn add_role(mut self, role: impl Into<String>, permissions: Vec<Permission>) -> Self {
        let perms = PermissionSet::from_permissions(permissions);
        self.role_permissions.insert(role.into(), perms);
        self
    }

    /// Adds a predefined role.
    pub fn add_predefined_role(mut self, role: Role) -> Self {
        let perms = PermissionSet::from_permissions(role.default_permissions());
        self.role_permissions.insert(role.as_str().to_string(), perms);
        self
    }

    /// Adds permissions to an existing role.
    pub fn add_permissions(
        mut self,
        role: impl Into<String>,
        permissions: Vec<Permission>,
    ) -> Self {
        let role = role.into();
        let entry = self
            .role_permissions
            .entry(role)
            .or_default();

        for perm in permissions {
            entry.add(perm);
        }
        self
    }

    /// Sets the default role.
    pub fn default_role(mut self, role: impl Into<String>) -> Self {
        self.default_role = Some(role.into());
        self
    }

    /// Builds the policy.
    pub fn build(self) -> RbacPolicy {
        RbacPolicy {
            role_permissions: Arc::new(self.role_permissions),
            default_role: self.default_role.unwrap_or_else(|| "reader".to_string()),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_default_permissions() {
        let reader_perms = Role::Reader.default_permissions();
        assert!(reader_perms.contains(&Permission::DeviceRead));
        assert!(!reader_perms.contains(&Permission::DeviceWrite));

        let superadmin_perms = Role::Superadmin.default_permissions();
        assert!(superadmin_perms.contains(&Permission::SystemAdmin));
    }

    #[test]
    fn test_rbac_policy_default() {
        let policy = RbacPolicy::new();

        assert!(policy.has_permission(
            &["reader".to_string()],
            Permission::DeviceRead
        ));
        assert!(!policy.has_permission(
            &["reader".to_string()],
            Permission::DeviceWrite
        ));
    }

    #[test]
    fn test_rbac_combined_permissions() {
        let policy = RbacPolicy::new();

        let combined = policy.get_combined_permissions(&[
            "reader".to_string(),
            "operator".to_string(),
        ]);

        assert!(combined.contains(Permission::DeviceRead));
        assert!(combined.contains(Permission::DeviceWrite));
    }

    #[test]
    fn test_rbac_policy_builder() {
        let policy = RbacPolicy::builder()
            .with_default_roles()
            .add_role("custom", vec![Permission::DeviceRead, Permission::ConfigRead])
            .default_role("custom")
            .build();

        assert!(policy.has_permission(
            &["custom".to_string()],
            Permission::DeviceRead
        ));
        assert!(policy.has_permission(
            &["custom".to_string()],
            Permission::ConfigRead
        ));
        assert!(!policy.has_permission(
            &["custom".to_string()],
            Permission::DeviceWrite
        ));
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!(Role::parse("reader"), Some(Role::Reader));
        assert_eq!(Role::parse("ADMIN"), Some(Role::Admin));
        assert_eq!(Role::parse("root"), Some(Role::Superadmin));
        assert_eq!(Role::parse("unknown"), None);
    }
}
