// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # trap-api
//!
//! REST API server for TRAP industrial protocol gateway.
//!
//! This crate provides a secure, high-performance HTTP API server with:
//!
//! - **JWT Authentication**: Token-based authentication with configurable expiration
//! - **RBAC Authorization**: Role-based access control with fine-grained permissions
//! - **Rate Limiting**: Configurable rate limiting with per-IP and global quotas
//! - **Audit Logging**: Comprehensive audit trail for security and compliance
//! - **TLS Support**: Optional HTTPS with rustls
//!
//! ## Architecture
//!
//! The API server is built on [axum](https://docs.rs/axum) with a layered middleware stack:
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │              Request                     │
//! └─────────────────┬───────────────────────┘
//!                   ▼
//! ┌─────────────────────────────────────────┐
//! │          Tracing Layer                   │
//! └─────────────────┬───────────────────────┘
//!                   ▼
//! ┌─────────────────────────────────────────┐
//! │         Rate Limit Layer                 │
//! └─────────────────┬───────────────────────┘
//!                   ▼
//! ┌─────────────────────────────────────────┐
//! │           Auth Layer (JWT)               │
//! └─────────────────┬───────────────────────┘
//!                   ▼
//! ┌─────────────────────────────────────────┐
//! │          RBAC Layer                      │
//! └─────────────────┬───────────────────────┘
//!                   ▼
//! ┌─────────────────────────────────────────┐
//! │         Audit Layer                      │
//! └─────────────────┬───────────────────────┘
//!                   ▼
//! ┌─────────────────────────────────────────┐
//! │           Handler                        │
//! └─────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use trap_api::{ApiServer, ApiConfig};
//!
//! let config = ApiConfig::default();
//! let server = ApiServer::new(config)
//!     .with_driver_manager(driver_manager)
//!     .with_audit_logger(audit_logger);
//!
//! server.run().await?;
//! ```

#![warn(missing_docs)]
#![deny(unsafe_code)]

// =============================================================================
// Modules
// =============================================================================

pub mod auth;
pub mod config;
pub mod error;
pub mod extractors;
pub mod handlers;
pub mod middleware;
pub mod response;
pub mod server;
pub mod state;

// =============================================================================
// Re-exports
// =============================================================================

pub use auth::{
    AuthContext, Claims, JwtConfig, JwtManager, Permission, RbacPolicy, Role, RolePermissions,
};
pub use config::ApiConfig;
pub use error::{ApiError, ApiResult};
pub use middleware::{
    AuditLayer, AuditMiddleware, AuthLayer, AuthMiddleware, RateLimitConfig, RateLimitLayer,
    RbacLayer,
};
pub use response::{ApiResponse, ErrorResponse};
pub use server::ApiServer;
pub use state::AppState;

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// API version prefix
pub const API_VERSION: &str = "v1";

/// Default server port
pub const DEFAULT_PORT: u16 = 8080;
