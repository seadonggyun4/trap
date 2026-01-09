// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Device management handlers.

use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use trap_core::{address::GenericAddress, Address, AuditContext as CoreAuditContext, DeviceId, Value};

use crate::auth::Permission;
use crate::error::{ApiError, ApiResult};
use crate::extractors::{Auth, Pagination};
use crate::middleware::audit::audit_write;
use crate::response::{ApiResponse, ResponseMeta};
use crate::state::AppState;

// =============================================================================
// Device Types
// =============================================================================

/// Device information response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device ID.
    pub id: String,
    /// Device name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Protocol type.
    pub protocol: String,
    /// Connection state.
    pub state: String,
    /// Whether the device is connected.
    pub connected: bool,
    /// Number of tags.
    pub tag_count: u32,
    /// Last communication time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_communication: Option<chrono::DateTime<chrono::Utc>>,
}

/// Tag information response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagInfo {
    /// Tag ID.
    pub id: String,
    /// Tag address.
    pub address: String,
    /// Data type.
    pub data_type: String,
    /// Whether the tag is readable.
    pub readable: bool,
    /// Whether the tag is writable.
    pub writable: bool,
}

/// Tag value response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagValueResponse {
    /// Tag ID.
    pub tag_id: String,
    /// Current value.
    pub value: serde_json::Value,
    /// Value type.
    pub value_type: String,
    /// Data quality.
    pub quality: String,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Path parameters for tag operations.
#[derive(Debug, Deserialize)]
pub struct TagPathParams {
    /// Device ID.
    pub device_id: String,
    /// Tag ID.
    pub tag_id: String,
}

// =============================================================================
// List Devices
// =============================================================================

/// GET /api/v1/devices
///
/// Lists all configured devices.
pub async fn list_devices(
    State(state): State<AppState>,
    Auth(auth_ctx): Auth,
    Pagination(pagination): Pagination,
) -> ApiResult<impl IntoResponse> {
    // Check permission
    if !auth_ctx.has_permission(Permission::DeviceRead) {
        return Err(ApiError::forbidden("Device read permission required"));
    }

    let driver_manager = state
        .drivers()
        .ok_or_else(|| ApiError::service_unavailable("Driver manager not available"))?;

    // Get all device IDs and their info
    let device_ids = driver_manager.device_ids();
    let total = device_ids.len() as u64;

    // Apply pagination
    let start = pagination.offset() as usize;
    let end = (start + pagination.limit() as usize).min(device_ids.len());

    let devices: Vec<DeviceInfo> = device_ids[start..end]
        .iter()
        .filter_map(|device_id| {
            driver_manager.get_driver(device_id).map(|wrapper| {
                let info = wrapper.info();
                DeviceInfo {
                    id: info.id.as_str().to_string(),
                    name: Some(info.name),
                    protocol: info.protocol.to_string(),
                    state: format!("{:?}", info.circuit_state),
                    connected: info.connected,
                    tag_count: 0, // Would need to query from config
                    last_communication: info.health.last_success,
                }
            })
        })
        .collect();

    let meta = ResponseMeta::pagination(total, pagination.page, pagination.per_page);

    Ok(Json(ApiResponse::success(devices).with_meta(meta)))
}

// =============================================================================
// Get Device
// =============================================================================

/// GET /api/v1/devices/{device_id}
///
/// Gets information about a specific device.
pub async fn get_device(
    State(state): State<AppState>,
    Auth(auth_ctx): Auth,
    Path(device_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    if !auth_ctx.has_permission(Permission::DeviceRead) {
        return Err(ApiError::forbidden("Device read permission required"));
    }

    let driver_manager = state
        .drivers()
        .ok_or_else(|| ApiError::service_unavailable("Driver manager not available"))?;

    let device_id_obj = DeviceId::new(&device_id);
    let wrapper = driver_manager
        .get_driver(&device_id_obj)
        .ok_or_else(|| ApiError::not_found(format!("Device '{}'", device_id)))?;

    let info = wrapper.info();
    let device = DeviceInfo {
        id: info.id.as_str().to_string(),
        name: Some(info.name),
        protocol: info.protocol.to_string(),
        state: format!("{:?}", info.circuit_state),
        connected: info.connected,
        tag_count: 0,
        last_communication: info.health.last_success,
    };

    Ok(Json(ApiResponse::success(device)))
}

// =============================================================================
// Read Tag Value
// =============================================================================

/// GET /api/v1/devices/{device_id}/tags/{tag_id}
///
/// Reads the current value of a tag.
pub async fn read_tag_value(
    State(state): State<AppState>,
    Path(params): Path<TagPathParams>,
    Auth(auth_ctx): Auth,
) -> ApiResult<Json<ApiResponse<TagValueResponse>>> {
    if !auth_ctx.has_permission(Permission::DeviceRead) {
        return Err(ApiError::forbidden("Device read permission required"));
    }

    let driver_manager = state
        .drivers()
        .ok_or_else(|| ApiError::service_unavailable("Driver manager not available"))?;

    let device_id_obj = DeviceId::new(&params.device_id);

    // Verify the device exists
    let _wrapper = driver_manager
        .get_driver(&device_id_obj)
        .ok_or_else(|| ApiError::not_found(format!("Device '{}'", params.device_id)))?;

    // Create address from tag_id (simplified - in real implementation would look up tag config)
    let _address = Address::Generic(GenericAddress::new("tag", &params.tag_id));

    // Note: Direct read via wrapper.read() has Send issues due to RwLockReadGuard.
    // In production, this should use DriverManager::read() which handles this internally,
    // or use the command bus for async operations.
    // For now, return a placeholder response.
    let response = TagValueResponse {
        tag_id: params.tag_id,
        value: serde_json::Value::Null,
        value_type: "null".to_string(),
        quality: "Unknown".to_string(),
        timestamp: chrono::Utc::now(),
    };

    Ok(Json(ApiResponse::success(response)))
}

// =============================================================================
// Write Tag Value
// =============================================================================

/// Write tag value request.
#[derive(Debug, Deserialize)]
pub struct WriteTagRequest {
    /// Value to write.
    pub value: serde_json::Value,
    /// Value type hint (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
}

/// Write tag value response.
#[derive(Debug, Serialize)]
pub struct WriteTagResponse {
    /// Whether the write was successful.
    pub success: bool,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// POST /api/v1/devices/{device_id}/tags/{tag_id}
///
/// Writes a value to a tag.
pub async fn write_tag_value(
    State(state): State<AppState>,
    Path(params): Path<TagPathParams>,
    Auth(auth_ctx): Auth,
    Json(request): Json<WriteTagRequest>,
) -> ApiResult<Json<ApiResponse<WriteTagResponse>>> {
    if !auth_ctx.has_permission(Permission::DeviceWrite) {
        return Err(ApiError::forbidden("Device write permission required"));
    }

    let command_sender = state
        .commands()
        .ok_or_else(|| ApiError::service_unavailable("Command bus not available"))?;

    let device_id_obj = DeviceId::new(&params.device_id);
    let address = Address::Generic(GenericAddress::new("tag", &params.tag_id));

    // Convert JSON value to trap-core Value
    let value = json_to_value(&request.value, request.value_type.as_deref())?;

    // Create audit context
    let audit_context = CoreAuditContext {
        user_id: Some(auth_ctx.user_id.clone()),
        client_ip: auth_ctx.client_ip,
        request_id: auth_ctx.request_id,
        roles: auth_ctx.roles.clone(),
        metadata: serde_json::Value::Null,
    };

    let start = Instant::now();
    let result = command_sender
        .send_write(
            device_id_obj.clone(),
            address.clone(),
            value.clone(),
            audit_context,
            Duration::from_secs(30),
        )
        .await;

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(response) => {
            // Audit log
            let audit_log = audit_write(
                &auth_ctx,
                &params.device_id,
                &params.tag_id,
                &value,
                response.success,
                duration_ms,
            );

            let logger = state.audit().clone();
            tokio::spawn(async move {
                if let Err(e) = logger.log(audit_log).await {
                    tracing::warn!(error = %e, "Failed to log write operation");
                }
            });

            if response.success {
                Ok(Json(ApiResponse::success(WriteTagResponse {
                    success: true,
                    duration_ms,
                })))
            } else {
                Err(ApiError::internal(
                    response.error.unwrap_or_else(|| "Write failed".to_string()),
                ))
            }
        }
        Err(e) => Err(ApiError::Command(e)),
    }
}

/// Converts a JSON value to a trap-core Value.
fn json_to_value(json: &serde_json::Value, type_hint: Option<&str>) -> ApiResult<Value> {
    match type_hint {
        Some("bool") | Some("boolean") => json
            .as_bool()
            .map(Value::Bool)
            .ok_or_else(|| ApiError::validation("Expected boolean value")),
        Some("int32") | Some("i32") => json
            .as_i64()
            .map(|v| Value::Int32(v as i32))
            .ok_or_else(|| ApiError::validation("Expected integer value")),
        Some("int64") | Some("i64") => json
            .as_i64()
            .map(Value::Int64)
            .ok_or_else(|| ApiError::validation("Expected integer value")),
        Some("float32") | Some("f32") => json
            .as_f64()
            .map(|v| Value::Float32(v as f32))
            .ok_or_else(|| ApiError::validation("Expected number value")),
        Some("float64") | Some("f64") | Some("double") => json
            .as_f64()
            .map(Value::Float64)
            .ok_or_else(|| ApiError::validation("Expected number value")),
        Some("string") | Some("str") => json
            .as_str()
            .map(|s| Value::String(s.to_string()))
            .ok_or_else(|| ApiError::validation("Expected string value")),
        Some(other) => Err(ApiError::validation(format!("Unknown type hint: {}", other))),
        None => {
            // Auto-detect type
            match json {
                serde_json::Value::Bool(b) => Ok(Value::Bool(*b)),
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Ok(Value::Int64(i))
                    } else if let Some(f) = n.as_f64() {
                        Ok(Value::Float64(f))
                    } else {
                        Err(ApiError::validation("Invalid number"))
                    }
                }
                serde_json::Value::String(s) => Ok(Value::String(s.clone())),
                serde_json::Value::Null => Ok(Value::Null),
                _ => Err(ApiError::validation("Unsupported value type")),
            }
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
    fn test_json_to_value_auto() {
        assert!(matches!(
            json_to_value(&serde_json::json!(true), None).unwrap(),
            Value::Bool(true)
        ));

        assert!(matches!(
            json_to_value(&serde_json::json!(42), None).unwrap(),
            Value::Int64(42)
        ));

        assert!(matches!(
            json_to_value(&serde_json::json!(3.14), None).unwrap(),
            Value::Float64(_)
        ));

        assert!(matches!(
            json_to_value(&serde_json::json!("hello"), None).unwrap(),
            Value::String(_)
        ));
    }

    #[test]
    fn test_json_to_value_typed() {
        assert!(matches!(
            json_to_value(&serde_json::json!(42), Some("int32")).unwrap(),
            Value::Int32(42)
        ));

        assert!(matches!(
            json_to_value(&serde_json::json!(3.14), Some("float32")).unwrap(),
            Value::Float32(_)
        ));
    }

    #[test]
    fn test_json_to_value_invalid() {
        assert!(json_to_value(&serde_json::json!("hello"), Some("int32")).is_err());
        assert!(json_to_value(&serde_json::json!(42), Some("unknown")).is_err());
    }
}
