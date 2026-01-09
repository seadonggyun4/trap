// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! API handlers for all endpoints.
//!
//! This module contains the handler implementations for all API endpoints:
//!
//! - [`health`]: Health check endpoints
//! - [`auth`]: Authentication endpoints
//! - [`devices`]: Device management endpoints
//! - [`status`]: System status endpoints

mod auth;
mod devices;
mod health;
mod status;

pub use auth::*;
pub use devices::*;
pub use health::*;
pub use status::*;
