// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # trap-buffer
//!
//! Offline buffering and data persistence for TRAP industrial protocol gateway.
//!
//! This crate provides persistent storage for data points when the upstream
//! connection is unavailable, ensuring no data loss during network outages.

#![warn(missing_docs)]
#![deny(unsafe_code)]

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
