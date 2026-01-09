// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Middleware implementations for the API server.
//!
//! This module provides a layered middleware stack for security and observability:
//!
//! - [`AuthMiddleware`]: JWT authentication
//! - [`RbacLayer`]: Role-based access control
//! - [`RateLimitLayer`]: Rate limiting
//! - [`AuditMiddleware`]: Audit logging

mod auth;
pub mod audit;
mod rbac;
mod rate_limit;

pub use auth::{AuthLayer, AuthMiddleware};
pub use audit::{AuditLayer, AuditMiddleware};
pub use rbac::RbacLayer;
pub use rate_limit::{RateLimitConfig, RateLimitLayer};
