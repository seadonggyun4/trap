// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Audit log formatters.
//!
//! This module provides pluggable formatters for converting audit logs to
//! various output formats.

use super::error::{AuditError, AuditResult};
use super::types::AuditLog;

// =============================================================================
// Formatter Trait
// =============================================================================

/// Trait for audit log formatters.
///
/// Formatters convert audit log entries to string representations suitable
/// for storage or transmission.
///
/// # Implementing a Custom Formatter
///
/// ```rust,ignore
/// use trap_core::audit::{AuditFormatter, AuditLog, AuditResult};
///
/// struct CsvFormatter;
///
/// impl AuditFormatter for CsvFormatter {
///     fn format(&self, log: &AuditLog) -> AuditResult<String> {
///         Ok(format!(
///             "{},{},{},{}\n",
///             log.timestamp,
///             log.action,
///             log.user_id.as_deref().unwrap_or("-"),
///             log.result.as_str()
///         ))
///     }
///
///     fn content_type(&self) -> &'static str {
///         "text/csv"
///     }
///
///     fn file_extension(&self) -> &'static str {
///         "csv"
///     }
/// }
/// ```
pub trait AuditFormatter: Send + Sync {
    /// Formats an audit log entry.
    fn format(&self, log: &AuditLog) -> AuditResult<String>;

    /// Formats multiple audit log entries.
    fn format_batch(&self, logs: &[AuditLog]) -> AuditResult<String> {
        let mut output = String::new();
        for log in logs {
            output.push_str(&self.format(log)?);
            output.push('\n');
        }
        Ok(output)
    }

    /// Returns the content type for this format.
    fn content_type(&self) -> &'static str;

    /// Returns the file extension for this format.
    fn file_extension(&self) -> &'static str;

    /// Returns the formatter name.
    fn name(&self) -> &'static str;

    /// Returns `true` if this format supports streaming.
    fn supports_streaming(&self) -> bool {
        true
    }
}

impl std::fmt::Debug for dyn AuditFormatter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditFormatter")
            .field("name", &self.name())
            .field("content_type", &self.content_type())
            .finish()
    }
}

// =============================================================================
// JSON Formatter
// =============================================================================

/// JSON formatter with pretty printing option.
#[derive(Debug, Clone, Default)]
pub struct JsonFormatter {
    pretty: bool,
}

impl JsonFormatter {
    /// Creates a new JSON formatter.
    pub fn new() -> Self {
        Self { pretty: false }
    }

    /// Creates a new JSON formatter with pretty printing.
    pub fn pretty() -> Self {
        Self { pretty: true }
    }
}

impl AuditFormatter for JsonFormatter {
    fn format(&self, log: &AuditLog) -> AuditResult<String> {
        let result = if self.pretty {
            serde_json::to_string_pretty(log)
        } else {
            serde_json::to_string(log)
        };

        result.map_err(|e| AuditError::serialization(e.to_string()))
    }

    fn content_type(&self) -> &'static str {
        "application/json"
    }

    fn file_extension(&self) -> &'static str {
        "json"
    }

    fn name(&self) -> &'static str {
        "json"
    }
}

// =============================================================================
// Compact JSON Formatter
// =============================================================================

/// Compact JSON formatter optimized for log files (JSON Lines format).
///
/// Each log entry is formatted as a single line of JSON, suitable for
/// efficient storage and streaming.
#[derive(Debug, Clone, Default)]
pub struct CompactJsonFormatter;

impl CompactJsonFormatter {
    /// Creates a new compact JSON formatter.
    pub fn new() -> Self {
        Self
    }
}

impl AuditFormatter for CompactJsonFormatter {
    fn format(&self, log: &AuditLog) -> AuditResult<String> {
        serde_json::to_string(log).map_err(|e| AuditError::serialization(e.to_string()))
    }

    fn format_batch(&self, logs: &[AuditLog]) -> AuditResult<String> {
        let mut output = String::new();
        for log in logs {
            output.push_str(&self.format(log)?);
            output.push('\n');
        }
        // Remove trailing newline
        if output.ends_with('\n') {
            output.pop();
        }
        Ok(output)
    }

    fn content_type(&self) -> &'static str {
        "application/x-ndjson"
    }

    fn file_extension(&self) -> &'static str {
        "jsonl"
    }

    fn name(&self) -> &'static str {
        "compact_json"
    }
}

// =============================================================================
// Text Formatter
// =============================================================================

/// Human-readable text formatter.
#[derive(Debug, Clone)]
pub struct TextFormatter {
    /// Include timestamp.
    include_timestamp: bool,
    /// Include correlation ID.
    include_correlation_id: bool,
    /// Timestamp format.
    timestamp_format: String,
}

impl Default for TextFormatter {
    fn default() -> Self {
        Self {
            include_timestamp: true,
            include_correlation_id: false,
            timestamp_format: "%Y-%m-%d %H:%M:%S%.3f".to_string(),
        }
    }
}

impl TextFormatter {
    /// Creates a new text formatter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether to include timestamps.
    pub fn with_timestamp(mut self, include: bool) -> Self {
        self.include_timestamp = include;
        self
    }

    /// Sets whether to include correlation IDs.
    pub fn with_correlation_id(mut self, include: bool) -> Self {
        self.include_correlation_id = include;
        self
    }

    /// Sets the timestamp format.
    pub fn timestamp_format(mut self, format: impl Into<String>) -> Self {
        self.timestamp_format = format.into();
        self
    }
}

impl AuditFormatter for TextFormatter {
    fn format(&self, log: &AuditLog) -> AuditResult<String> {
        let mut parts = Vec::new();

        if self.include_timestamp {
            parts.push(log.timestamp.format(&self.timestamp_format).to_string());
        }

        parts.push(format!("[{}]", log.severity.as_str().to_uppercase()));
        parts.push(format!("[{}]", log.action));

        if let Some(ref user_id) = log.user_id {
            parts.push(format!("user={}", user_id));
        }

        parts.push(format!(
            "resource={}:{}",
            log.resource.resource_type, log.resource.resource_id
        ));

        parts.push(format!("result={}", log.result.as_str()));

        if let Some(duration_ms) = log.duration_ms {
            parts.push(format!("duration={}ms", duration_ms));
        }

        if self.include_correlation_id {
            if let Some(correlation_id) = log.correlation_id {
                parts.push(format!("correlation_id={}", correlation_id));
            }
        }

        if let Some(ref client_ip) = log.client_ip {
            parts.push(format!("client_ip={}", client_ip));
        }

        // Include non-null details
        if !log.details.is_null() {
            if let Ok(details_str) = serde_json::to_string(&log.details) {
                if details_str.len() <= 200 {
                    parts.push(format!("details={}", details_str));
                }
            }
        }

        Ok(parts.join(" "))
    }

    fn content_type(&self) -> &'static str {
        "text/plain"
    }

    fn file_extension(&self) -> &'static str {
        "log"
    }

    fn name(&self) -> &'static str {
        "text"
    }
}

// =============================================================================
// CEF Formatter (Common Event Format)
// =============================================================================

/// Common Event Format (CEF) formatter for SIEM integration.
///
/// CEF is a standardized format for security event logging that is widely
/// supported by SIEM systems.
#[derive(Debug, Clone)]
pub struct CefFormatter {
    /// Device vendor.
    vendor: String,
    /// Device product.
    product: String,
    /// Device version.
    version: String,
}

impl Default for CefFormatter {
    fn default() -> Self {
        Self {
            vendor: "Sylvex".to_string(),
            product: "TRAP".to_string(),
            version: "1.0".to_string(),
        }
    }
}

impl CefFormatter {
    /// Creates a new CEF formatter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the device vendor.
    pub fn vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = vendor.into();
        self
    }

    /// Sets the device product.
    pub fn product(mut self, product: impl Into<String>) -> Self {
        self.product = product.into();
        self
    }

    /// Sets the device version.
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    fn severity_to_cef(&self, log: &AuditLog) -> u8 {
        use super::types::AuditSeverity;
        match log.severity {
            AuditSeverity::Debug => 0,
            AuditSeverity::Info => 1,
            AuditSeverity::Notice => 3,
            AuditSeverity::Warning => 5,
            AuditSeverity::Error => 7,
            AuditSeverity::Critical => 10,
        }
    }

    fn escape_cef_value(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace('\n', "\\n")
    }
}

impl AuditFormatter for CefFormatter {
    fn format(&self, log: &AuditLog) -> AuditResult<String> {
        let severity = self.severity_to_cef(log);
        let event_id = log.action.as_str();
        let event_name = format!("{} {}", log.action, log.result.as_str());

        // CEF Header: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        let mut cef = format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|",
            Self::escape_cef_value(&self.vendor),
            Self::escape_cef_value(&self.product),
            Self::escape_cef_value(&self.version),
            event_id,
            Self::escape_cef_value(&event_name),
            severity
        );

        // Extension fields
        let mut extensions = Vec::new();

        // Standard CEF fields
        extensions.push(format!("rt={}", log.timestamp.timestamp_millis()));
        extensions.push(format!(
            "dvc={}",
            Self::escape_cef_value(&log.resource.resource_id)
        ));

        if let Some(ref user_id) = log.user_id {
            extensions.push(format!("suser={}", Self::escape_cef_value(user_id)));
        }

        if let Some(ref client_ip) = log.client_ip {
            extensions.push(format!("src={}", client_ip));
        }

        extensions.push(format!(
            "cs1Label=resourceType cs1={}",
            Self::escape_cef_value(&log.resource.resource_type)
        ));
        extensions.push(format!(
            "cs2Label=result cs2={}",
            Self::escape_cef_value(log.result.as_str())
        ));

        if let Some(correlation_id) = log.correlation_id {
            extensions.push(format!("cn1Label=correlationId cn1={}", correlation_id));
        }

        if let Some(duration_ms) = log.duration_ms {
            extensions.push(format!("cn2Label=durationMs cn2={}", duration_ms));
        }

        cef.push_str(&extensions.join(" "));

        Ok(cef)
    }

    fn content_type(&self) -> &'static str {
        "text/plain"
    }

    fn file_extension(&self) -> &'static str {
        "cef"
    }

    fn name(&self) -> &'static str {
        "cef"
    }
}

// =============================================================================
// Syslog Formatter
// =============================================================================

/// Syslog formatter (RFC 5424).
#[derive(Debug, Clone)]
pub struct SyslogFormatter {
    /// Application name.
    app_name: String,
    /// Hostname.
    hostname: Option<String>,
    /// Facility (default: 1 = user-level).
    facility: u8,
}

impl Default for SyslogFormatter {
    fn default() -> Self {
        Self {
            app_name: "trap".to_string(),
            hostname: None,
            facility: 1, // User-level messages
        }
    }
}

impl SyslogFormatter {
    /// Creates a new syslog formatter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the application name.
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = name.into();
        self
    }

    /// Sets the hostname.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Sets the facility.
    pub fn facility(mut self, facility: u8) -> Self {
        self.facility = facility;
        self
    }

    fn severity_to_syslog(&self, log: &AuditLog) -> u8 {
        use super::types::AuditSeverity;
        match log.severity {
            AuditSeverity::Debug => 7,
            AuditSeverity::Info => 6,
            AuditSeverity::Notice => 5,
            AuditSeverity::Warning => 4,
            AuditSeverity::Error => 3,
            AuditSeverity::Critical => 2,
        }
    }
}

impl AuditFormatter for SyslogFormatter {
    fn format(&self, log: &AuditLog) -> AuditResult<String> {
        let severity = self.severity_to_syslog(log);
        let priority = (self.facility << 3) | severity;

        let hostname = self
            .hostname
            .as_deref()
            .unwrap_or("-");

        let timestamp = log.timestamp.format("%Y-%m-%dT%H:%M:%S%.6fZ");

        let msg_id = log.action.as_str();

        // Build structured data
        let mut sd = String::new();
        sd.push_str("[audit@1 ");
        sd.push_str(&format!("action=\"{}\" ", log.action));
        sd.push_str(&format!("resourceType=\"{}\" ", log.resource.resource_type));
        sd.push_str(&format!("resourceId=\"{}\" ", log.resource.resource_id));
        sd.push_str(&format!("result=\"{}\"", log.result.as_str()));
        if let Some(ref user_id) = log.user_id {
            sd.push_str(&format!(" user=\"{}\"", user_id));
        }
        if let Some(ref client_ip) = log.client_ip {
            sd.push_str(&format!(" src=\"{}\"", client_ip));
        }
        sd.push(']');

        // RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        let syslog = format!(
            "<{}>1 {} {} {} {} {} {} {}",
            priority,
            timestamp,
            hostname,
            self.app_name,
            "-", // PROCID
            msg_id,
            sd,
            format!("{} on {}", log.action, log.resource.resource_id)
        );

        Ok(syslog)
    }

    fn content_type(&self) -> &'static str {
        "text/plain"
    }

    fn file_extension(&self) -> &'static str {
        "log"
    }

    fn name(&self) -> &'static str {
        "syslog"
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{ActionResult, AuditAction, AuditResource};

    fn create_test_log() -> AuditLog {
        AuditLog::new(
            AuditAction::Write,
            AuditResource::device("plc-001"),
            ActionResult::Success,
        )
        .with_user("admin", Some("192.168.1.100".parse().unwrap()))
        .with_duration(42)
    }

    #[test]
    fn test_json_formatter() {
        let formatter = JsonFormatter::new();
        let log = create_test_log();

        let output = formatter.format(&log).unwrap();
        assert!(output.contains("plc-001"));
        assert!(output.contains("write"));
        assert!(output.contains("admin"));
    }

    #[test]
    fn test_compact_json_formatter() {
        let formatter = CompactJsonFormatter::new();
        let log = create_test_log();

        let output = formatter.format(&log).unwrap();
        assert!(!output.contains('\n'));
        assert!(output.contains("plc-001"));
    }

    #[test]
    fn test_text_formatter() {
        let formatter = TextFormatter::new();
        let log = create_test_log();

        let output = formatter.format(&log).unwrap();
        assert!(output.contains("[NOTICE]"));
        assert!(output.contains("[write]"));
        assert!(output.contains("user=admin"));
        assert!(output.contains("result=success"));
    }

    #[test]
    fn test_cef_formatter() {
        let formatter = CefFormatter::new();
        let log = create_test_log();

        let output = formatter.format(&log).unwrap();
        assert!(output.starts_with("CEF:0|"));
        assert!(output.contains("Sylvex"));
        assert!(output.contains("TRAP"));
        assert!(output.contains("suser=admin"));
    }

    #[test]
    fn test_syslog_formatter() {
        let formatter = SyslogFormatter::new().hostname("gateway-01");
        let log = create_test_log();

        let output = formatter.format(&log).unwrap();
        assert!(output.contains("gateway-01"));
        assert!(output.contains("trap"));
        assert!(output.contains("[audit@1"));
    }

    #[test]
    fn test_batch_formatting() {
        let formatter = CompactJsonFormatter::new();
        let logs = vec![create_test_log(), create_test_log()];

        let output = formatter.format_batch(&logs).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
    }
}
