// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Core audit log types.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::address::Address;
use crate::types::{DeviceId, Value};

// =============================================================================
// Audit Log Entry
// =============================================================================

/// A single audit log entry.
///
/// This is the core data structure for audit logging. Each entry captures
/// comprehensive information about a system operation for compliance and
/// security purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// Unique log entry ID.
    pub id: Uuid,

    /// When the event occurred.
    pub timestamp: DateTime<Utc>,

    /// Severity level of the event.
    pub severity: AuditSeverity,

    /// User who performed the action (if authenticated).
    pub user_id: Option<String>,

    /// Client IP address.
    pub client_ip: Option<IpAddr>,

    /// The action that was performed.
    pub action: AuditAction,

    /// The resource that was affected.
    pub resource: AuditResource,

    /// Additional details about the action.
    pub details: serde_json::Value,

    /// The result of the action.
    pub result: ActionResult,

    /// Duration of the operation in milliseconds.
    pub duration_ms: Option<u64>,

    /// Correlation ID for request tracing.
    pub correlation_id: Option<Uuid>,

    /// Session ID (if applicable).
    pub session_id: Option<String>,

    /// User agent string (for API requests).
    pub user_agent: Option<String>,

    /// Additional tags for categorization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl AuditLog {
    /// Creates a new audit log entry.
    pub fn new(action: AuditAction, resource: AuditResource, result: ActionResult) -> Self {
        Self {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            severity: action.default_severity(),
            user_id: None,
            client_ip: None,
            action,
            resource,
            details: serde_json::Value::Null,
            result,
            duration_ms: None,
            correlation_id: None,
            session_id: None,
            user_agent: None,
            tags: Vec::new(),
        }
    }

    /// Creates a builder for constructing audit logs.
    pub fn builder(action: AuditAction, resource: AuditResource) -> AuditLogBuilder {
        AuditLogBuilder::new(action, resource)
    }

    /// Sets the user information.
    pub fn with_user(mut self, user_id: impl Into<String>, client_ip: Option<IpAddr>) -> Self {
        self.user_id = Some(user_id.into());
        self.client_ip = client_ip;
        self
    }

    /// Sets the details.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    /// Sets the duration.
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Sets the correlation ID.
    pub fn with_correlation_id(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self
    }

    /// Sets the session ID.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets the severity.
    pub fn with_severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Adds a tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Adds multiple tags.
    pub fn with_tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags.extend(tags.into_iter().map(|t| t.into()));
        self
    }

    // =========================================================================
    // Factory methods for common actions
    // =========================================================================

    /// Creates an audit log for a login attempt.
    pub fn login(user_id: impl Into<String>, client_ip: Option<IpAddr>, success: bool) -> Self {
        let user_id = user_id.into();
        let result = if success {
            ActionResult::Success
        } else {
            ActionResult::Failure {
                reason: "Invalid credentials".to_string(),
            }
        };

        Self::new(AuditAction::Login, AuditResource::user(&user_id), result)
            .with_user(&user_id, client_ip)
            .with_severity(if success {
                AuditSeverity::Info
            } else {
                AuditSeverity::Warning
            })
    }

    /// Creates an audit log for a logout.
    pub fn logout(user_id: impl Into<String>, client_ip: Option<IpAddr>) -> Self {
        let user_id = user_id.into();
        Self::new(
            AuditAction::Logout,
            AuditResource::user(&user_id),
            ActionResult::Success,
        )
        .with_user(&user_id, client_ip)
    }

    /// Creates an audit log for a read operation.
    pub fn read_operation(
        device_id: &DeviceId,
        address: &Address,
        result: ActionResult,
        user_id: Option<&str>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        let mut log = Self::new(
            AuditAction::Read,
            AuditResource::device_tag(device_id.as_str(), &address.to_string()),
            result,
        );

        if let Some(uid) = user_id {
            log = log.with_user(uid, client_ip);
        }

        log
    }

    /// Creates an audit log for a write operation.
    pub fn write_operation(
        device_id: &DeviceId,
        address: &Address,
        value: &Value,
        result: ActionResult,
        user_id: Option<&str>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        let details = serde_json::json!({
            "address": address.to_string(),
            "value": value.to_json(),
            "value_type": value.type_name(),
        });

        let mut log = Self::new(
            AuditAction::Write,
            AuditResource::device_tag(device_id.as_str(), &address.to_string()),
            result,
        )
        .with_details(details)
        .with_severity(AuditSeverity::Notice);

        if let Some(uid) = user_id {
            log = log.with_user(uid, client_ip);
        }

        log
    }

    /// Creates an audit log for a configuration change.
    pub fn config_change(
        field: impl Into<String>,
        old_value: Option<&str>,
        new_value: &str,
        user_id: impl Into<String>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        let details = serde_json::json!({
            "old_value": old_value,
            "new_value": new_value,
        });

        Self::new(
            AuditAction::ConfigChange,
            AuditResource::config(field),
            ActionResult::Success,
        )
        .with_details(details)
        .with_user(user_id, client_ip)
        .with_severity(AuditSeverity::Notice)
    }

    /// Creates an audit log for device addition.
    pub fn device_added(
        device_id: &DeviceId,
        user_id: impl Into<String>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        Self::new(
            AuditAction::DeviceAdd,
            AuditResource::device(device_id.as_str()),
            ActionResult::Success,
        )
        .with_user(user_id, client_ip)
    }

    /// Creates an audit log for device removal.
    pub fn device_removed(
        device_id: &DeviceId,
        user_id: impl Into<String>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        Self::new(
            AuditAction::DeviceRemove,
            AuditResource::device(device_id.as_str()),
            ActionResult::Success,
        )
        .with_user(user_id, client_ip)
    }

    /// Creates an audit log for system start.
    pub fn system_start(version: impl Into<String>) -> Self {
        Self::new(
            AuditAction::SystemStart,
            AuditResource::system(),
            ActionResult::Success,
        )
        .with_details(serde_json::json!({
            "version": version.into(),
        }))
    }

    /// Creates an audit log for system shutdown.
    pub fn system_shutdown(reason: Option<String>) -> Self {
        let details = match reason {
            Some(r) => serde_json::json!({ "reason": r }),
            None => serde_json::Value::Null,
        };

        Self::new(
            AuditAction::SystemShutdown,
            AuditResource::system(),
            ActionResult::Success,
        )
        .with_details(details)
    }

    /// Creates an audit log for access denied.
    pub fn access_denied(
        action: AuditAction,
        resource: AuditResource,
        user_id: impl Into<String>,
        client_ip: Option<IpAddr>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(action, resource, ActionResult::Denied)
            .with_user(user_id, client_ip)
            .with_details(serde_json::json!({
                "reason": reason.into(),
            }))
            .with_severity(AuditSeverity::Warning)
    }

    /// Creates an audit log for a security event.
    pub fn security_event(
        event_type: impl Into<String>,
        description: impl Into<String>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        Self::new(
            AuditAction::SecurityEvent,
            AuditResource::system(),
            ActionResult::Success,
        )
        .with_details(serde_json::json!({
            "event_type": event_type.into(),
            "description": description.into(),
        }))
        .with_severity(AuditSeverity::Warning)
        .with_user("system", client_ip)
    }
}

// =============================================================================
// Audit Log Builder
// =============================================================================

/// Builder for constructing audit log entries.
#[derive(Debug)]
pub struct AuditLogBuilder {
    action: AuditAction,
    resource: AuditResource,
    result: ActionResult,
    severity: Option<AuditSeverity>,
    user_id: Option<String>,
    client_ip: Option<IpAddr>,
    details: Option<serde_json::Value>,
    duration_ms: Option<u64>,
    correlation_id: Option<Uuid>,
    session_id: Option<String>,
    user_agent: Option<String>,
    tags: Vec<String>,
}

impl AuditLogBuilder {
    /// Creates a new builder.
    pub fn new(action: AuditAction, resource: AuditResource) -> Self {
        Self {
            action,
            resource,
            result: ActionResult::Success,
            severity: None,
            user_id: None,
            client_ip: None,
            details: None,
            duration_ms: None,
            correlation_id: None,
            session_id: None,
            user_agent: None,
            tags: Vec::new(),
        }
    }

    /// Sets the result.
    pub fn result(mut self, result: ActionResult) -> Self {
        self.result = result;
        self
    }

    /// Sets the severity.
    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Sets the user ID.
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Sets the client IP.
    pub fn client_ip(mut self, ip: IpAddr) -> Self {
        self.client_ip = Some(ip);
        self
    }

    /// Sets the details.
    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Sets the duration.
    pub fn duration_ms(mut self, duration: u64) -> Self {
        self.duration_ms = Some(duration);
        self
    }

    /// Sets the correlation ID.
    pub fn correlation_id(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self
    }

    /// Sets the session ID.
    pub fn session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets the user agent.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Adds a tag.
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Builds the audit log.
    pub fn build(self) -> AuditLog {
        let mut log = AuditLog::new(self.action, self.resource, self.result);

        if let Some(severity) = self.severity {
            log.severity = severity;
        }
        log.user_id = self.user_id;
        log.client_ip = self.client_ip;
        if let Some(details) = self.details {
            log.details = details;
        }
        log.duration_ms = self.duration_ms;
        log.correlation_id = self.correlation_id;
        log.session_id = self.session_id;
        log.user_agent = self.user_agent;
        log.tags = self.tags;

        log
    }
}

// =============================================================================
// Audit Severity
// =============================================================================

/// Severity level for audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Debug level - detailed information for debugging.
    Debug,

    /// Info level - normal operations.
    #[default]
    Info,

    /// Notice level - normal but significant events.
    Notice,

    /// Warning level - potentially harmful situations.
    Warning,

    /// Error level - error events.
    Error,

    /// Critical level - critical conditions.
    Critical,
}

impl AuditSeverity {
    /// Returns the severity level as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditSeverity::Debug => "debug",
            AuditSeverity::Info => "info",
            AuditSeverity::Notice => "notice",
            AuditSeverity::Warning => "warning",
            AuditSeverity::Error => "error",
            AuditSeverity::Critical => "critical",
        }
    }

    /// Returns the numeric level (higher = more severe).
    pub fn level(&self) -> u8 {
        match self {
            AuditSeverity::Debug => 0,
            AuditSeverity::Info => 1,
            AuditSeverity::Notice => 2,
            AuditSeverity::Warning => 3,
            AuditSeverity::Error => 4,
            AuditSeverity::Critical => 5,
        }
    }
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Audit Action
// =============================================================================

/// Types of auditable actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // =========================================================================
    // Authentication
    // =========================================================================
    /// User login attempt.
    Login,
    /// User logout.
    Logout,
    /// Failed login attempt.
    LoginFailed,
    /// Token refresh.
    TokenRefresh,
    /// Token revocation.
    TokenRevoke,

    // =========================================================================
    // Data access
    // =========================================================================
    /// Read data from device.
    Read,
    /// Write data to device.
    Write,
    /// Batch read operation.
    BatchRead,
    /// Batch write operation.
    BatchWrite,
    /// Subscribe to data.
    Subscribe,
    /// Unsubscribe from data.
    Unsubscribe,

    // =========================================================================
    // Configuration
    // =========================================================================
    /// Configuration changed.
    ConfigChange,
    /// Device added.
    DeviceAdd,
    /// Device removed.
    DeviceRemove,
    /// Device updated.
    DeviceUpdate,
    /// Tag added.
    TagAdd,
    /// Tag removed.
    TagRemove,

    // =========================================================================
    // System
    // =========================================================================
    /// System started.
    SystemStart,
    /// System shutdown.
    SystemShutdown,
    /// System restart.
    SystemRestart,
    /// Health check performed.
    HealthCheck,

    // =========================================================================
    // Security
    // =========================================================================
    /// Permission changed.
    PermissionChange,
    /// User created.
    UserCreate,
    /// User deleted.
    UserDelete,
    /// Password changed.
    PasswordChange,
    /// API key created.
    ApiKeyCreate,
    /// API key revoked.
    ApiKeyRevoke,
    /// Security event.
    SecurityEvent,

    // =========================================================================
    // Extensibility
    // =========================================================================
    /// Custom action for extensions.
    Custom,
}

impl AuditAction {
    /// Returns the action name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Login => "login",
            AuditAction::Logout => "logout",
            AuditAction::LoginFailed => "login_failed",
            AuditAction::TokenRefresh => "token_refresh",
            AuditAction::TokenRevoke => "token_revoke",
            AuditAction::Read => "read",
            AuditAction::Write => "write",
            AuditAction::BatchRead => "batch_read",
            AuditAction::BatchWrite => "batch_write",
            AuditAction::Subscribe => "subscribe",
            AuditAction::Unsubscribe => "unsubscribe",
            AuditAction::ConfigChange => "config_change",
            AuditAction::DeviceAdd => "device_add",
            AuditAction::DeviceRemove => "device_remove",
            AuditAction::DeviceUpdate => "device_update",
            AuditAction::TagAdd => "tag_add",
            AuditAction::TagRemove => "tag_remove",
            AuditAction::SystemStart => "system_start",
            AuditAction::SystemShutdown => "system_shutdown",
            AuditAction::SystemRestart => "system_restart",
            AuditAction::HealthCheck => "health_check",
            AuditAction::PermissionChange => "permission_change",
            AuditAction::UserCreate => "user_create",
            AuditAction::UserDelete => "user_delete",
            AuditAction::PasswordChange => "password_change",
            AuditAction::ApiKeyCreate => "api_key_create",
            AuditAction::ApiKeyRevoke => "api_key_revoke",
            AuditAction::SecurityEvent => "security_event",
            AuditAction::Custom => "custom",
        }
    }

    /// Returns `true` if this is a security-sensitive action.
    pub fn is_security_sensitive(&self) -> bool {
        matches!(
            self,
            AuditAction::Login
                | AuditAction::LoginFailed
                | AuditAction::PermissionChange
                | AuditAction::UserCreate
                | AuditAction::UserDelete
                | AuditAction::PasswordChange
                | AuditAction::ApiKeyCreate
                | AuditAction::ApiKeyRevoke
                | AuditAction::SecurityEvent
                | AuditAction::TokenRevoke
        )
    }

    /// Returns `true` if this is a write action.
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            AuditAction::Write
                | AuditAction::BatchWrite
                | AuditAction::ConfigChange
                | AuditAction::DeviceAdd
                | AuditAction::DeviceRemove
                | AuditAction::DeviceUpdate
                | AuditAction::TagAdd
                | AuditAction::TagRemove
        )
    }

    /// Returns the default severity for this action.
    pub fn default_severity(&self) -> AuditSeverity {
        match self {
            AuditAction::Login | AuditAction::Logout | AuditAction::Read => AuditSeverity::Info,
            AuditAction::LoginFailed | AuditAction::SecurityEvent => AuditSeverity::Warning,
            AuditAction::Write
            | AuditAction::BatchWrite
            | AuditAction::ConfigChange
            | AuditAction::DeviceAdd
            | AuditAction::DeviceRemove => AuditSeverity::Notice,
            AuditAction::PermissionChange
            | AuditAction::UserCreate
            | AuditAction::UserDelete
            | AuditAction::PasswordChange => AuditSeverity::Notice,
            AuditAction::SystemStart | AuditAction::SystemShutdown => AuditSeverity::Notice,
            _ => AuditSeverity::Info,
        }
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Audit Resource
// =============================================================================

/// The resource that was affected by an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResource {
    /// Resource type.
    pub resource_type: String,
    /// Resource identifier.
    pub resource_id: String,
    /// Parent resource (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<Box<AuditResource>>,
}

impl AuditResource {
    /// Creates a new audit resource.
    pub fn new(resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            parent: None,
        }
    }

    /// Creates a device resource.
    pub fn device(device_id: impl Into<String>) -> Self {
        Self::new("device", device_id)
    }

    /// Creates a tag resource.
    pub fn tag(device_id: impl Into<String>, tag_id: impl Into<String>) -> Self {
        let mut resource = Self::new("tag", format!("{}:{}", device_id.into(), tag_id.into()));
        resource.parent = None; // Could set parent device here if needed
        resource
    }

    /// Creates a device:tag resource.
    pub fn device_tag(device_id: impl Into<String>, address: impl Into<String>) -> Self {
        Self::new("device_tag", format!("{}:{}", device_id.into(), address.into()))
    }

    /// Creates a user resource.
    pub fn user(user_id: impl Into<String>) -> Self {
        Self::new("user", user_id)
    }

    /// Creates a config resource.
    pub fn config(field: impl Into<String>) -> Self {
        Self::new("config", field)
    }

    /// Creates a system resource.
    pub fn system() -> Self {
        Self::new("system", "trap")
    }

    /// Creates an API resource.
    pub fn api(endpoint: impl Into<String>) -> Self {
        Self::new("api", endpoint)
    }

    /// Creates a session resource.
    pub fn session(session_id: impl Into<String>) -> Self {
        Self::new("session", session_id)
    }

    /// Sets the parent resource.
    pub fn with_parent(mut self, parent: AuditResource) -> Self {
        self.parent = Some(Box::new(parent));
        self
    }

    /// Returns the full resource path.
    pub fn full_path(&self) -> String {
        match &self.parent {
            Some(parent) => format!("{}/{}", parent.full_path(), self.resource_id),
            None => format!("{}:{}", self.resource_type, self.resource_id),
        }
    }
}

// =============================================================================
// Action Result
// =============================================================================

/// The result of an audited action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ActionResult {
    /// Action completed successfully.
    #[serde(rename = "success")]
    Success,

    /// Action failed.
    #[serde(rename = "failure")]
    Failure {
        /// Reason for failure.
        reason: String,
    },

    /// Action was denied (authorization).
    #[serde(rename = "denied")]
    Denied,

    /// Action was rejected (e.g., rate limiting).
    #[serde(rename = "rejected")]
    Rejected {
        /// Reason for rejection.
        reason: String,
    },
}

impl ActionResult {
    /// Creates a failure result.
    pub fn failure(reason: impl Into<String>) -> Self {
        Self::Failure {
            reason: reason.into(),
        }
    }

    /// Creates a rejected result.
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self::Rejected {
            reason: reason.into(),
        }
    }

    /// Returns `true` if the action was successful.
    pub fn is_success(&self) -> bool {
        matches!(self, ActionResult::Success)
    }

    /// Returns `true` if the action was denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, ActionResult::Denied)
    }

    /// Returns `true` if the action failed.
    pub fn is_failure(&self) -> bool {
        matches!(self, ActionResult::Failure { .. })
    }

    /// Returns the status as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionResult::Success => "success",
            ActionResult::Failure { .. } => "failure",
            ActionResult::Denied => "denied",
            ActionResult::Rejected { .. } => "rejected",
        }
    }
}

impl Default for ActionResult {
    fn default() -> Self {
        Self::Success
    }
}

// =============================================================================
// Audit Context
// =============================================================================

/// Context information for audit logging.
///
/// This is passed through the request pipeline and used to enrich audit logs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditContext {
    /// User ID.
    pub user_id: Option<String>,
    /// Client IP address.
    pub client_ip: Option<IpAddr>,
    /// Request/correlation ID.
    pub request_id: Option<Uuid>,
    /// Session ID.
    pub session_id: Option<String>,
    /// User roles.
    #[serde(default)]
    pub roles: Vec<String>,
    /// User agent.
    pub user_agent: Option<String>,
}

impl AuditContext {
    /// Creates a new empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a context with user information.
    pub fn with_user(user_id: impl Into<String>, client_ip: Option<IpAddr>) -> Self {
        Self {
            user_id: Some(user_id.into()),
            client_ip,
            ..Default::default()
        }
    }

    /// Sets the request ID.
    pub fn request_id(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Sets the session ID.
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Sets the roles.
    pub fn roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Applies this context to an audit log.
    pub fn apply_to(&self, mut log: AuditLog) -> AuditLog {
        if let Some(ref user_id) = self.user_id {
            log.user_id = Some(user_id.clone());
        }
        log.client_ip = self.client_ip;
        log.correlation_id = self.request_id;
        if let Some(ref session_id) = self.session_id {
            log.session_id = Some(session_id.clone());
        }
        log.user_agent = self.user_agent.clone();
        log
    }
}

// =============================================================================
// Audit Filter
// =============================================================================

/// Filter for querying audit logs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by user ID.
    pub user_id: Option<String>,
    /// Filter by action type.
    pub action: Option<AuditAction>,
    /// Filter by actions (multiple).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<AuditAction>,
    /// Filter by resource type.
    pub resource_type: Option<String>,
    /// Filter by resource ID.
    pub resource_id: Option<String>,
    /// Filter by result.
    pub success_only: Option<bool>,
    /// Filter by minimum severity.
    pub min_severity: Option<AuditSeverity>,
    /// Start time (inclusive).
    pub from: Option<DateTime<Utc>>,
    /// End time (exclusive).
    pub to: Option<DateTime<Utc>>,
    /// Filter by correlation ID.
    pub correlation_id: Option<Uuid>,
    /// Filter by session ID.
    pub session_id: Option<String>,
    /// Filter by tags (any match).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Maximum number of results.
    pub limit: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
    /// Sort order (true = descending by timestamp).
    #[serde(default)]
    pub descending: bool,
}

impl AuditFilter {
    /// Creates a new empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by user ID.
    pub fn user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Filters by action.
    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Filters by multiple actions.
    pub fn actions(mut self, actions: Vec<AuditAction>) -> Self {
        self.actions = actions;
        self
    }

    /// Filters by resource type.
    pub fn resource_type(mut self, resource_type: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.into());
        self
    }

    /// Filters by time range.
    pub fn time_range(mut self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.from = Some(from);
        self.to = Some(to);
        self
    }

    /// Filters by minimum severity.
    pub fn min_severity(mut self, severity: AuditSeverity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Sets the limit.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Sets the offset.
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Sets descending order.
    pub fn descending(mut self) -> Self {
        self.descending = true;
        self
    }

    /// Checks if a log entry matches this filter.
    pub fn matches(&self, log: &AuditLog) -> bool {
        if let Some(ref user_id) = self.user_id {
            if log.user_id.as_ref() != Some(user_id) {
                return false;
            }
        }

        if let Some(action) = self.action {
            if log.action != action {
                return false;
            }
        }

        if !self.actions.is_empty() && !self.actions.contains(&log.action) {
            return false;
        }

        if let Some(ref resource_type) = self.resource_type {
            if &log.resource.resource_type != resource_type {
                return false;
            }
        }

        if let Some(ref resource_id) = self.resource_id {
            if &log.resource.resource_id != resource_id {
                return false;
            }
        }

        if let Some(success_only) = self.success_only {
            if success_only && !log.result.is_success() {
                return false;
            }
        }

        if let Some(min_severity) = self.min_severity {
            if log.severity.level() < min_severity.level() {
                return false;
            }
        }

        if let Some(from) = self.from {
            if log.timestamp < from {
                return false;
            }
        }

        if let Some(to) = self.to {
            if log.timestamp >= to {
                return false;
            }
        }

        if let Some(correlation_id) = self.correlation_id {
            if log.correlation_id != Some(correlation_id) {
                return false;
            }
        }

        if let Some(ref session_id) = self.session_id {
            if log.session_id.as_ref() != Some(session_id) {
                return false;
            }
        }

        if !self.tags.is_empty() && !self.tags.iter().any(|t| log.tags.contains(t)) {
            return false;
        }

        true
    }
}

// =============================================================================
// Sensitive Value
// =============================================================================

/// A wrapper for sensitive values that should be masked in logs.
#[derive(Clone)]
pub struct SensitiveValue<T> {
    inner: T,
    mask: String,
}

impl<T> SensitiveValue<T> {
    /// Creates a new sensitive value with default mask.
    pub fn new(value: T) -> Self {
        Self {
            inner: value,
            mask: "[REDACTED]".to_string(),
        }
    }

    /// Creates a new sensitive value with custom mask.
    pub fn with_mask(value: T, mask: impl Into<String>) -> Self {
        Self {
            inner: value,
            mask: mask.into(),
        }
    }

    /// Gets the inner value.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Consumes the wrapper and returns the inner value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> std::fmt::Debug for SensitiveValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mask)
    }
}

impl<T> std::fmt::Display for SensitiveValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mask)
    }
}

impl<T: Serialize> Serialize for SensitiveValue<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.mask)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_creation() {
        let log = AuditLog::new(
            AuditAction::Read,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        );

        assert!(log.result.is_success());
        assert_eq!(log.action, AuditAction::Read);
        assert_eq!(log.severity, AuditSeverity::Info);
    }

    #[test]
    fn test_audit_log_builder() {
        let log = AuditLog::builder(AuditAction::Write, AuditResource::device("plc-001"))
            .result(ActionResult::Success)
            .user_id("admin")
            .severity(AuditSeverity::Notice)
            .tag("important")
            .build();

        assert_eq!(log.user_id, Some("admin".to_string()));
        assert_eq!(log.severity, AuditSeverity::Notice);
        assert!(log.tags.contains(&"important".to_string()));
    }

    #[test]
    fn test_audit_filter() {
        let log = AuditLog::new(
            AuditAction::Write,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        )
        .with_user("admin", None);

        let filter = AuditFilter::new().user("admin").action(AuditAction::Write);
        assert!(filter.matches(&log));

        let filter2 = AuditFilter::new().user("other");
        assert!(!filter2.matches(&log));
    }

    #[test]
    fn test_action_properties() {
        assert!(AuditAction::Login.is_security_sensitive());
        assert!(AuditAction::Write.is_write());
        assert!(!AuditAction::Read.is_write());
    }

    #[test]
    fn test_sensitive_value() {
        let secret = SensitiveValue::new("my_secret_password");
        assert_eq!(format!("{}", secret), "[REDACTED]");
        assert_eq!(*secret.inner(), "my_secret_password");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(AuditSeverity::Critical.level() > AuditSeverity::Error.level());
        assert!(AuditSeverity::Error.level() > AuditSeverity::Warning.level());
        assert!(AuditSeverity::Warning.level() > AuditSeverity::Info.level());
    }
}
