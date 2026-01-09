// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Permission definitions for RBAC.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Permissions for accessing API resources.
///
/// Permissions are fine-grained access controls that can be assigned to roles.
/// Each endpoint requires one or more permissions to access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // =========================================================================
    // Device Permissions
    // =========================================================================
    /// Read device information and values.
    DeviceRead,
    /// Write values to devices.
    DeviceWrite,
    /// Manage devices (add, remove, configure).
    DeviceAdmin,

    // =========================================================================
    // Configuration Permissions
    // =========================================================================
    /// Read system configuration.
    ConfigRead,
    /// Modify system configuration.
    ConfigWrite,

    // =========================================================================
    // User Permissions
    // =========================================================================
    /// Read user information.
    UserRead,
    /// Manage users (create, update, delete).
    UserAdmin,

    // =========================================================================
    // System Permissions
    // =========================================================================
    /// Full system administration.
    SystemAdmin,
    /// View system metrics and logs.
    SystemMonitor,
    /// Manage audit logs.
    AuditRead,
}

impl Permission {
    /// Returns the permission name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::DeviceRead => "device:read",
            Permission::DeviceWrite => "device:write",
            Permission::DeviceAdmin => "device:admin",
            Permission::ConfigRead => "config:read",
            Permission::ConfigWrite => "config:write",
            Permission::UserRead => "user:read",
            Permission::UserAdmin => "user:admin",
            Permission::SystemAdmin => "system:admin",
            Permission::SystemMonitor => "system:monitor",
            Permission::AuditRead => "audit:read",
        }
    }

    /// Parses a permission from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "device:read" | "DeviceRead" => Some(Permission::DeviceRead),
            "device:write" | "DeviceWrite" => Some(Permission::DeviceWrite),
            "device:admin" | "DeviceAdmin" => Some(Permission::DeviceAdmin),
            "config:read" | "ConfigRead" => Some(Permission::ConfigRead),
            "config:write" | "ConfigWrite" => Some(Permission::ConfigWrite),
            "user:read" | "UserRead" => Some(Permission::UserRead),
            "user:admin" | "UserAdmin" => Some(Permission::UserAdmin),
            "system:admin" | "SystemAdmin" => Some(Permission::SystemAdmin),
            "system:monitor" | "SystemMonitor" => Some(Permission::SystemMonitor),
            "audit:read" | "AuditRead" => Some(Permission::AuditRead),
            _ => None,
        }
    }

    /// Returns all available permissions.
    pub fn all() -> &'static [Permission] {
        &[
            Permission::DeviceRead,
            Permission::DeviceWrite,
            Permission::DeviceAdmin,
            Permission::ConfigRead,
            Permission::ConfigWrite,
            Permission::UserRead,
            Permission::UserAdmin,
            Permission::SystemAdmin,
            Permission::SystemMonitor,
            Permission::AuditRead,
        ]
    }

    /// Returns `true` if this is an admin-level permission.
    pub fn is_admin(&self) -> bool {
        matches!(
            self,
            Permission::DeviceAdmin
                | Permission::ConfigWrite
                | Permission::UserAdmin
                | Permission::SystemAdmin
        )
    }

    /// Returns the category of this permission.
    pub fn category(&self) -> &'static str {
        match self {
            Permission::DeviceRead | Permission::DeviceWrite | Permission::DeviceAdmin => "device",
            Permission::ConfigRead | Permission::ConfigWrite => "config",
            Permission::UserRead | Permission::UserAdmin => "user",
            Permission::SystemAdmin | Permission::SystemMonitor | Permission::AuditRead => "system",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Permission Set
// =============================================================================

/// A set of permissions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionSet {
    permissions: std::collections::HashSet<Permission>,
}

impl PermissionSet {
    /// Creates an empty permission set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a permission set from a list of permissions.
    pub fn from_permissions(permissions: impl IntoIterator<Item = Permission>) -> Self {
        Self {
            permissions: permissions.into_iter().collect(),
        }
    }

    /// Adds a permission to the set.
    pub fn add(&mut self, permission: Permission) {
        self.permissions.insert(permission);
    }

    /// Removes a permission from the set.
    pub fn remove(&mut self, permission: Permission) {
        self.permissions.remove(&permission);
    }

    /// Returns `true` if the set contains the given permission.
    pub fn contains(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Returns `true` if the set contains all of the given permissions.
    pub fn contains_all(&self, permissions: &[Permission]) -> bool {
        permissions.iter().all(|p| self.permissions.contains(p))
    }

    /// Returns `true` if the set contains any of the given permissions.
    pub fn contains_any(&self, permissions: &[Permission]) -> bool {
        permissions.iter().any(|p| self.permissions.contains(p))
    }

    /// Returns the number of permissions in the set.
    pub fn len(&self) -> usize {
        self.permissions.len()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
    }

    /// Returns an iterator over the permissions.
    pub fn iter(&self) -> impl Iterator<Item = &Permission> {
        self.permissions.iter()
    }

    /// Merges another permission set into this one.
    pub fn merge(&mut self, other: &PermissionSet) {
        self.permissions.extend(other.permissions.iter().copied());
    }
}

impl FromIterator<Permission> for PermissionSet {
    fn from_iter<I: IntoIterator<Item = Permission>>(iter: I) -> Self {
        Self::from_permissions(iter)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_as_str() {
        assert_eq!(Permission::DeviceRead.as_str(), "device:read");
        assert_eq!(Permission::SystemAdmin.as_str(), "system:admin");
    }

    #[test]
    fn test_permission_from_str() {
        assert_eq!(
            Permission::parse("device:read"),
            Some(Permission::DeviceRead)
        );
        assert_eq!(Permission::parse("invalid"), None);
    }

    #[test]
    fn test_permission_is_admin() {
        assert!(Permission::SystemAdmin.is_admin());
        assert!(Permission::DeviceAdmin.is_admin());
        assert!(!Permission::DeviceRead.is_admin());
    }

    #[test]
    fn test_permission_set() {
        let mut set = PermissionSet::new();
        set.add(Permission::DeviceRead);
        set.add(Permission::DeviceWrite);

        assert!(set.contains(Permission::DeviceRead));
        assert!(!set.contains(Permission::SystemAdmin));
        assert!(set.contains_all(&[Permission::DeviceRead, Permission::DeviceWrite]));
        assert!(!set.contains_all(&[Permission::DeviceRead, Permission::SystemAdmin]));
    }
}
