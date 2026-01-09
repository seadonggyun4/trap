// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # trap-api
//!
//! REST API server for TRAP industrial protocol gateway.
//!
//! This crate provides the HTTP API server with JWT authentication,
//! RBAC authorization, rate limiting, and TLS support.

#![warn(missing_docs)]
#![deny(unsafe_code)]

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
