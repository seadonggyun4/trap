// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! API server configuration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::auth::JwtConfig;
use crate::middleware::RateLimitConfig;

// =============================================================================
// ApiConfig
// =============================================================================

/// Configuration for the API server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    /// Server host address.
    pub host: IpAddr,
    /// Server port.
    pub port: u16,
    /// Base path for API endpoints.
    pub base_path: String,
    /// CORS configuration.
    pub cors: CorsConfig,
    /// JWT configuration.
    pub jwt: JwtConfig,
    /// Rate limiting configuration.
    pub rate_limit: RateLimitConfig,
    /// TLS configuration.
    pub tls: Option<TlsConfig>,
    /// Audit logging configuration.
    pub audit: AuditConfig,
    /// Request timeout.
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    /// Graceful shutdown timeout.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    /// Maximum request body size in bytes.
    pub max_body_size: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 8080,
            base_path: "/api/v1".to_string(),
            cors: CorsConfig::default(),
            jwt: JwtConfig::default(),
            rate_limit: RateLimitConfig::default(),
            tls: None,
            audit: AuditConfig::default(),
            request_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(30),
            max_body_size: 1024 * 1024, // 1MB
        }
    }
}

impl ApiConfig {
    /// Creates a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the socket address to bind to.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }

    /// Sets the host address.
    pub fn with_host(mut self, host: IpAddr) -> Self {
        self.host = host;
        self
    }

    /// Sets the port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the JWT configuration.
    pub fn with_jwt(mut self, jwt: JwtConfig) -> Self {
        self.jwt = jwt;
        self
    }

    /// Sets the rate limit configuration.
    pub fn with_rate_limit(mut self, rate_limit: RateLimitConfig) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// Sets the TLS configuration.
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Returns `true` if TLS is enabled.
    pub fn is_tls_enabled(&self) -> bool {
        self.tls.is_some()
    }
}

// =============================================================================
// CorsConfig
// =============================================================================

/// CORS (Cross-Origin Resource Sharing) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CorsConfig {
    /// Allowed origins.
    pub allowed_origins: Vec<String>,
    /// Allowed methods.
    pub allowed_methods: Vec<String>,
    /// Allowed headers.
    pub allowed_headers: Vec<String>,
    /// Whether to allow credentials.
    pub allow_credentials: bool,
    /// Max age for preflight cache (seconds).
    pub max_age: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Request-ID".to_string(),
            ],
            allow_credentials: false,
            max_age: 3600,
        }
    }
}

impl CorsConfig {
    /// Creates a permissive CORS configuration for development.
    pub fn permissive() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "PATCH".to_string(),
                "OPTIONS".to_string(),
                "HEAD".to_string(),
            ],
            allowed_headers: vec!["*".to_string()],
            allow_credentials: true,
            max_age: 86400,
        }
    }

    /// Creates a restrictive CORS configuration for production.
    pub fn strict(origins: Vec<String>) -> Self {
        Self {
            allowed_origins: origins,
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
            ],
            allow_credentials: true,
            max_age: 3600,
        }
    }
}

// =============================================================================
// TlsConfig
// =============================================================================

/// TLS configuration for HTTPS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate file (PEM format).
    pub cert_path: PathBuf,
    /// Path to the private key file (PEM format).
    pub key_path: PathBuf,
    /// Optional client CA certificate for mutual TLS.
    pub client_ca_path: Option<PathBuf>,
    /// Whether to require client certificates.
    pub require_client_cert: bool,
}

impl TlsConfig {
    /// Creates a new TLS configuration.
    pub fn new(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            client_ca_path: None,
            require_client_cert: false,
        }
    }

    /// Enables mutual TLS with the given CA certificate.
    pub fn with_client_ca(mut self, ca_path: impl Into<PathBuf>) -> Self {
        self.client_ca_path = Some(ca_path.into());
        self.require_client_cert = true;
        self
    }
}

// =============================================================================
// AuditConfig
// =============================================================================

/// Audit logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Whether audit logging is enabled.
    pub enabled: bool,
    /// Path to the audit log file.
    pub log_path: Option<PathBuf>,
    /// Actions to audit.
    pub audit_actions: AuditActions,
    /// Whether to include request body in audit logs.
    pub include_request_body: bool,
    /// Whether to include response body in audit logs.
    pub include_response_body: bool,
    /// Maximum body size to log (bytes).
    pub max_body_log_size: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_path: None,
            audit_actions: AuditActions::default(),
            include_request_body: false,
            include_response_body: false,
            max_body_log_size: 4096,
        }
    }
}

impl AuditConfig {
    /// Creates a minimal audit configuration.
    pub fn minimal() -> Self {
        Self {
            enabled: true,
            audit_actions: AuditActions::security_only(),
            ..Default::default()
        }
    }

    /// Creates a comprehensive audit configuration.
    pub fn comprehensive() -> Self {
        Self {
            enabled: true,
            audit_actions: AuditActions::all(),
            include_request_body: true,
            include_response_body: true,
            ..Default::default()
        }
    }
}

// =============================================================================
// AuditActions
// =============================================================================

/// Configuration for which actions to audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditActions {
    /// Audit authentication attempts.
    pub authentication: bool,
    /// Audit authorization failures.
    pub authorization_failures: bool,
    /// Audit write operations.
    pub write_operations: bool,
    /// Audit read operations.
    pub read_operations: bool,
    /// Audit configuration changes.
    pub config_changes: bool,
    /// Audit system events.
    pub system_events: bool,
}

impl Default for AuditActions {
    fn default() -> Self {
        Self {
            authentication: true,
            authorization_failures: true,
            write_operations: true,
            read_operations: false,
            config_changes: true,
            system_events: true,
        }
    }
}

impl AuditActions {
    /// Creates a configuration that audits all actions.
    pub fn all() -> Self {
        Self {
            authentication: true,
            authorization_failures: true,
            write_operations: true,
            read_operations: true,
            config_changes: true,
            system_events: true,
        }
    }

    /// Creates a configuration that only audits security-related actions.
    pub fn security_only() -> Self {
        Self {
            authentication: true,
            authorization_failures: true,
            write_operations: false,
            read_operations: false,
            config_changes: true,
            system_events: false,
        }
    }

    /// Creates a configuration that audits nothing.
    pub fn none() -> Self {
        Self {
            authentication: false,
            authorization_failures: false,
            write_operations: false,
            read_operations: false,
            config_changes: false,
            system_events: false,
        }
    }
}

// =============================================================================
// humantime_serde module for Duration
// =============================================================================

mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as seconds
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ApiConfig::default();
        assert_eq!(config.port, 8080);
        assert_eq!(config.base_path, "/api/v1");
        assert!(!config.is_tls_enabled());
    }

    #[test]
    fn test_socket_addr() {
        let config = ApiConfig::default().with_port(9000);
        let addr = config.socket_addr();
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn test_cors_permissive() {
        let cors = CorsConfig::permissive();
        assert!(cors.allow_credentials);
        assert!(cors.allowed_origins.contains(&"*".to_string()));
    }

    #[test]
    fn test_audit_actions() {
        let all = AuditActions::all();
        assert!(all.read_operations);

        let security = AuditActions::security_only();
        assert!(!security.read_operations);
        assert!(security.authentication);
    }
}
