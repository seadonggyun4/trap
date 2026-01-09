// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Authentication and authorization module.
//!
//! This module provides:
//! - JWT token management and validation
//! - Role-Based Access Control (RBAC)
//! - Permission definitions
//! - Authentication context

mod claims;
mod context;
mod jwt;
pub mod permission;
mod rbac;

pub use claims::Claims;
pub use context::AuthContext;
pub use jwt::{JwtConfig, JwtManager};
pub use permission::Permission;
pub use rbac::{RbacPolicy, Role, RolePermissions};
