// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! System status handlers.

use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::auth::Permission;
use crate::error::{ApiError, ApiResult};
use crate::extractors::Auth;
use crate::response::ApiResponse;
use crate::state::AppState;

// =============================================================================
// System Status
// =============================================================================

/// System status response.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStatus {
    /// Overall system status.
    pub status: String,
    /// Gateway version.
    pub version: String,
    /// Device statistics.
    pub devices: DeviceStats,
    /// Bus statistics.
    pub bus: BusStats,
    /// Buffer statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer: Option<BufferStats>,
}

/// Device statistics.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceStats {
    /// Total number of devices.
    pub total: u32,
    /// Number of connected devices.
    pub connected: u32,
    /// Number of disconnected devices.
    pub disconnected: u32,
    /// Number of devices in error state.
    pub error: u32,
}

/// Bus statistics.
#[derive(Debug, Serialize, Deserialize)]
pub struct BusStats {
    /// Data bus statistics.
    pub data_bus: DataBusStats,
    /// Command bus statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_bus: Option<CommandBusStats>,
}

/// Data bus statistics.
#[derive(Debug, Serialize, Deserialize)]
pub struct DataBusStats {
    /// Total messages published.
    pub messages_published: u64,
    /// Messages dropped due to lag.
    pub messages_dropped: u64,
    /// Current subscriber count.
    pub subscriber_count: u64,
}

/// Command bus statistics.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandBusStats {
    /// Total commands sent.
    pub commands_sent: u64,
    /// Commands succeeded.
    pub commands_succeeded: u64,
    /// Commands failed.
    pub commands_failed: u64,
    /// Commands timed out.
    pub commands_timed_out: u64,
}

/// Buffer statistics.
#[derive(Debug, Serialize, Deserialize)]
pub struct BufferStats {
    /// Whether the buffer is enabled.
    pub enabled: bool,
    /// Current item count.
    pub item_count: u64,
    /// Current size in bytes.
    pub size_bytes: u64,
    /// Maximum capacity.
    pub max_capacity: u64,
    /// Utilization percentage.
    pub utilization_percent: f64,
}

/// GET /api/v1/status
///
/// Returns the overall system status.
pub async fn system_status(
    State(state): State<AppState>,
    Auth(auth_ctx): Auth,
) -> ApiResult<impl IntoResponse> {
    if !auth_ctx.has_permission(Permission::DeviceRead) {
        return Err(ApiError::forbidden("Device read permission required"));
    }

    // Device stats
    let device_stats = if let Some(dm) = state.drivers() {
        let total = dm.device_count() as u32;
        let connected = dm.connected_devices().len() as u32;
        let error = dm.devices_with_open_circuit().len() as u32;

        DeviceStats {
            total,
            connected,
            disconnected: total.saturating_sub(connected).saturating_sub(error),
            error,
        }
    } else {
        DeviceStats {
            total: 0,
            connected: 0,
            disconnected: 0,
            error: 0,
        }
    };

    // Bus stats
    let data_bus_stats = if let Some(db) = state.data_bus() {
        let stats = db.stats();
        DataBusStats {
            messages_published: stats.messages_published,
            messages_dropped: stats.messages_dropped,
            subscriber_count: stats.subscriber_count,
        }
    } else {
        DataBusStats {
            messages_published: 0,
            messages_dropped: 0,
            subscriber_count: 0,
        }
    };

    // Command bus stats
    let command_bus_stats = state.commands().map(|_cs| {
        // Note: We'd need to expose stats from CommandSender
        CommandBusStats {
            commands_sent: 0,
            commands_succeeded: 0,
            commands_failed: 0,
            commands_timed_out: 0,
        }
    });

    let bus_stats = BusStats {
        data_bus: data_bus_stats,
        command_bus: command_bus_stats,
    };

    // Determine overall status
    let status = if device_stats.error > 0 {
        "degraded"
    } else if device_stats.total > 0 && device_stats.connected == 0 {
        "warning"
    } else {
        "healthy"
    };

    let response = SystemStatus {
        status: status.to_string(),
        version: crate::VERSION.to_string(),
        devices: device_stats,
        bus: bus_stats,
        buffer: None, // Would integrate with trap-buffer
    };

    Ok(Json(ApiResponse::success(response)))
}

// =============================================================================
// Metrics
// =============================================================================

/// GET /metrics
///
/// Returns Prometheus metrics.
pub async fn prometheus_metrics() -> impl IntoResponse {
    // TODO: Integrate with prometheus crate for actual metrics
    let metrics = r#"
# HELP trap_devices_total Total number of configured devices
# TYPE trap_devices_total gauge
trap_devices_total 0

# HELP trap_devices_connected Number of connected devices
# TYPE trap_devices_connected gauge
trap_devices_connected 0

# HELP trap_messages_published_total Total messages published to data bus
# TYPE trap_messages_published_total counter
trap_messages_published_total 0

# HELP trap_api_requests_total Total API requests
# TYPE trap_api_requests_total counter
trap_api_requests_total 0
"#;

    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        metrics.trim(),
    )
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_prometheus_metrics() {
        let response = prometheus_metrics().await;
        let body = response.into_response();
        assert_eq!(body.status(), axum::http::StatusCode::OK);
    }
}
