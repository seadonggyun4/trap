// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Health check handlers.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::response::{ComponentStatus, HealthResponse, ReadinessResponse};
use crate::state::AppState;

// =============================================================================
// Health Check
// =============================================================================

/// GET /health
///
/// Simple liveness check. Returns 200 OK if the service is running.
pub async fn health() -> impl IntoResponse {
    Json(HealthResponse::healthy())
}

// =============================================================================
// Readiness Check
// =============================================================================

/// GET /ready
///
/// Readiness check that verifies all components are operational.
pub async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    let mut components = Vec::new();
    let mut all_healthy = true;

    // Check driver manager
    if let Some(driver_manager) = state.drivers() {
        let device_count = driver_manager.device_count();
        let connected_count = driver_manager.connected_devices().len();

        components.push(ComponentStatus {
            name: "driver_manager".to_string(),
            healthy: true,
            message: Some(format!("{}/{} devices connected", connected_count, device_count)),
        });

        // Consider unhealthy if no devices are connected and we expect some
        if device_count > 0 && connected_count == 0 {
            // This is a warning, not a failure
            components.last_mut().unwrap().message =
                Some(format!("Warning: 0/{} devices connected", device_count));
        }
    } else {
        components.push(ComponentStatus {
            name: "driver_manager".to_string(),
            healthy: true,
            message: Some("Not configured".to_string()),
        });
    }

    // Check data bus
    if let Some(data_bus) = state.data_bus() {
        let subscriber_count = data_bus.subscriber_count();
        components.push(ComponentStatus {
            name: "data_bus".to_string(),
            healthy: true,
            message: Some(format!("{} subscribers", subscriber_count)),
        });
    } else {
        components.push(ComponentStatus {
            name: "data_bus".to_string(),
            healthy: true,
            message: Some("Not configured".to_string()),
        });
    }

    // Check audit logger
    let audit_healthy = state.audit().health_check().await;
    components.push(ComponentStatus {
        name: "audit_logger".to_string(),
        healthy: audit_healthy,
        message: if audit_healthy {
            None
        } else {
            all_healthy = false;
            Some("Audit logger unhealthy".to_string())
        },
    });

    let response = ReadinessResponse {
        ready: all_healthy,
        components,
    };

    if all_healthy {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

// =============================================================================
// Detailed Health Check
// =============================================================================

/// Detailed health check response.
#[derive(Debug, Serialize, Deserialize)]
pub struct DetailedHealthResponse {
    /// Overall status.
    pub status: String,
    /// Version string.
    pub version: String,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
    /// Component statuses.
    pub components: Vec<ComponentHealthDetail>,
    /// System metrics.
    pub metrics: HealthMetrics,
}

/// Detailed component health.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentHealthDetail {
    /// Component name.
    pub name: String,
    /// Health status.
    pub status: String,
    /// Response time in milliseconds.
    pub response_time_ms: Option<u64>,
    /// Additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Health metrics.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// Number of connected devices.
    pub connected_devices: u32,
    /// Total devices.
    pub total_devices: u32,
    /// Messages per second (approximate).
    pub messages_per_second: f64,
    /// Active connections.
    pub active_connections: u32,
}

/// GET /health/detailed
///
/// Detailed health check with metrics.
pub async fn health_detailed(State(state): State<AppState>) -> impl IntoResponse {
    let _start = std::time::Instant::now();
    let mut components = Vec::new();

    // Check driver manager
    let (connected_devices, total_devices) = if let Some(dm) = state.drivers() {
        let check_start = std::time::Instant::now();
        let total = dm.device_count() as u32;
        let connected = dm.connected_devices().len() as u32;
        let response_time = check_start.elapsed().as_millis() as u64;

        components.push(ComponentHealthDetail {
            name: "driver_manager".to_string(),
            status: if connected > 0 || total == 0 {
                "healthy"
            } else {
                "degraded"
            }
            .to_string(),
            response_time_ms: Some(response_time),
            details: Some(serde_json::json!({
                "connected": connected,
                "total": total,
            })),
        });

        (connected, total)
    } else {
        (0, 0)
    };

    // Check data bus
    let messages_per_second = if let Some(db) = state.data_bus() {
        let stats = db.stats();
        components.push(ComponentHealthDetail {
            name: "data_bus".to_string(),
            status: "healthy".to_string(),
            response_time_ms: Some(0),
            details: Some(serde_json::json!({
                "messages_published": stats.messages_published,
                "messages_dropped": stats.messages_dropped,
                "subscriber_count": stats.subscriber_count,
            })),
        });
        0.0 // Would need historical data to calculate
    } else {
        0.0
    };

    let response = DetailedHealthResponse {
        status: "ok".to_string(),
        version: crate::VERSION.to_string(),
        uptime_seconds: 0, // Would need startup time tracking
        components,
        metrics: HealthMetrics {
            connected_devices,
            total_devices,
            messages_per_second,
            active_connections: 0,
        },
    };

    Json(response)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::JwtConfig;
    use crate::config::ApiConfig;

    fn test_state() -> AppState {
        let mut config = ApiConfig::default();
        config.jwt = JwtConfig::new("test-secret-key-that-is-long-enough");

        AppState::builder().config(config).build().unwrap()
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let response = health().await;
        let body = response.into_response();
        assert_eq!(body.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_ready_endpoint() {
        let state = test_state();
        let response = ready(State(state)).await;
        let body = response.into_response();
        assert_eq!(body.status(), StatusCode::OK);
    }
}
