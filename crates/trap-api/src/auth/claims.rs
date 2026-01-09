// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! JWT claims structure.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT claims for authentication.
///
/// These claims are embedded in the JWT token and extracted during authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    // =========================================================================
    // Standard JWT Claims (RFC 7519)
    // =========================================================================
    /// Subject - typically the user ID.
    pub sub: String,

    /// Expiration time (Unix timestamp).
    pub exp: i64,

    /// Issued at time (Unix timestamp).
    pub iat: i64,

    /// Not before time (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// JWT ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    // =========================================================================
    // Custom Claims
    // =========================================================================
    /// User roles.
    #[serde(default)]
    pub roles: Vec<String>,

    /// User's display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User's email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Session ID for tracking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Additional metadata.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

impl Claims {
    /// Creates new claims for a user.
    pub fn new(user_id: impl Into<String>, roles: Vec<String>, expires_in_secs: i64) -> Self {
        let now = Utc::now().timestamp();

        Self {
            sub: user_id.into(),
            exp: now + expires_in_secs,
            iat: now,
            nbf: Some(now),
            iss: None,
            aud: None,
            jti: Some(Uuid::now_v7().to_string()),
            roles,
            name: None,
            email: None,
            session_id: None,
            metadata: serde_json::Value::Null,
        }
    }

    /// Creates a builder for constructing claims.
    pub fn builder(user_id: impl Into<String>) -> ClaimsBuilder {
        ClaimsBuilder::new(user_id)
    }

    /// Returns the user ID.
    pub fn user_id(&self) -> &str {
        &self.sub
    }

    /// Returns the roles.
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Returns `true` if the claims have the given role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Returns `true` if the token has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Returns the expiration time as a DateTime.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(self.exp, 0)
    }

    /// Returns the time remaining until expiration.
    pub fn time_until_expiration(&self) -> Option<std::time::Duration> {
        let now = Utc::now().timestamp();
        if self.exp > now {
            Some(std::time::Duration::from_secs((self.exp - now) as u64))
        } else {
            None
        }
    }

    /// Returns the issued at time as a DateTime.
    pub fn issued_at(&self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(self.iat, 0)
    }

    /// Sets the issuer.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.iss = Some(issuer.into());
        self
    }

    /// Sets the audience.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.aud = Some(audience.into());
        self
    }

    /// Sets the session ID.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets the user's name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the user's email.
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }
}

// =============================================================================
// Claims Builder
// =============================================================================

/// Builder for constructing JWT claims.
#[derive(Debug)]
pub struct ClaimsBuilder {
    user_id: String,
    roles: Vec<String>,
    expires_in_secs: i64,
    issuer: Option<String>,
    audience: Option<String>,
    name: Option<String>,
    email: Option<String>,
    session_id: Option<String>,
    metadata: serde_json::Value,
}

impl ClaimsBuilder {
    /// Creates a new builder.
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            roles: Vec::new(),
            expires_in_secs: 3600, // 1 hour default
            issuer: None,
            audience: None,
            name: None,
            email: None,
            session_id: None,
            metadata: serde_json::Value::Null,
        }
    }

    /// Sets the roles.
    pub fn roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Adds a role.
    pub fn add_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Sets the expiration time in seconds.
    pub fn expires_in(mut self, seconds: i64) -> Self {
        self.expires_in_secs = seconds;
        self
    }

    /// Sets the issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets the audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Sets the user's name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the user's email.
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Sets the session ID.
    pub fn session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets additional metadata.
    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// Builds the claims.
    pub fn build(self) -> Claims {
        let mut claims = Claims::new(self.user_id, self.roles, self.expires_in_secs);
        claims.iss = self.issuer;
        claims.aud = self.audience;
        claims.name = self.name;
        claims.email = self.email;
        claims.session_id = self.session_id;
        claims.metadata = self.metadata;
        claims
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_creation() {
        let claims = Claims::new("user123", vec!["admin".to_string()], 3600);

        assert_eq!(claims.user_id(), "user123");
        assert!(claims.has_role("admin"));
        assert!(!claims.has_role("guest"));
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_claims_builder() {
        let claims = Claims::builder("user456")
            .roles(vec!["operator".to_string()])
            .expires_in(7200)
            .issuer("trap")
            .name("Test User")
            .build();

        assert_eq!(claims.user_id(), "user456");
        assert_eq!(claims.iss, Some("trap".to_string()));
        assert_eq!(claims.name, Some("Test User".to_string()));
    }

    #[test]
    fn test_claims_expiration() {
        let claims = Claims::new("user", vec![], 3600);

        assert!(!claims.is_expired());
        assert!(claims.time_until_expiration().is_some());

        // Create expired claims
        let expired = Claims {
            sub: "user".to_string(),
            exp: Utc::now().timestamp() - 100,
            iat: Utc::now().timestamp() - 200,
            ..Claims::new("user", vec![], 0)
        };

        assert!(expired.is_expired());
        assert!(expired.time_until_expiration().is_none());
    }
}
