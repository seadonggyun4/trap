// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! JWT token management.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};

use super::Claims;
use crate::error::{ApiError, ApiResult};

// =============================================================================
// JwtConfig
// =============================================================================

/// JWT configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JwtConfig {
    /// Secret key for signing tokens.
    #[serde(skip_serializing)]
    pub secret: String,
    /// Token issuer.
    pub issuer: String,
    /// Token audience.
    pub audience: Option<String>,
    /// Token expiration time in seconds.
    pub expiration_secs: i64,
    /// Refresh token expiration time in seconds.
    pub refresh_expiration_secs: i64,
    /// Algorithm to use for signing.
    #[serde(with = "algorithm_serde")]
    pub algorithm: Algorithm,
    /// Whether to validate the issuer.
    pub validate_issuer: bool,
    /// Whether to validate the audience.
    pub validate_audience: bool,
    /// Clock skew tolerance in seconds.
    pub leeway_secs: u64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: String::new(), // Must be set by user
            issuer: "trap".to_string(),
            audience: None,
            expiration_secs: 3600, // 1 hour
            refresh_expiration_secs: 86400 * 7, // 7 days
            algorithm: Algorithm::HS256,
            validate_issuer: true,
            validate_audience: false,
            leeway_secs: 60,
        }
    }
}

impl JwtConfig {
    /// Creates a new configuration with the given secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            ..Default::default()
        }
    }

    /// Sets the issuer.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Sets the audience.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self.validate_audience = true;
        self
    }

    /// Sets the expiration time.
    pub fn with_expiration(mut self, duration: Duration) -> Self {
        self.expiration_secs = duration.as_secs() as i64;
        self
    }

    /// Validates the configuration.
    pub fn validate(&self) -> ApiResult<()> {
        if self.secret.is_empty() {
            return Err(ApiError::internal("JWT secret is not configured"));
        }
        if self.secret.len() < 32 {
            tracing::warn!("JWT secret is shorter than recommended (32 bytes)");
        }
        Ok(())
    }
}

// =============================================================================
// JwtManager
// =============================================================================

/// Manager for JWT token operations.
///
/// This is the central component for creating, validating, and decoding JWT tokens.
#[derive(Clone)]
pub struct JwtManager {
    config: Arc<JwtConfig>,
    encoding_key: Arc<EncodingKey>,
    decoding_key: Arc<DecodingKey>,
    validation: Arc<Validation>,
}

impl JwtManager {
    /// Creates a new JWT manager with the given configuration.
    pub fn new(config: JwtConfig) -> ApiResult<Self> {
        config.validate()?;

        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());

        let mut validation = Validation::new(config.algorithm);
        validation.set_issuer(&[&config.issuer]);
        validation.leeway = config.leeway_secs;

        if config.validate_audience {
            if let Some(ref audience) = config.audience {
                validation.set_audience(&[audience]);
            }
        } else {
            validation.validate_aud = false;
        }

        Ok(Self {
            config: Arc::new(config),
            encoding_key: Arc::new(encoding_key),
            decoding_key: Arc::new(decoding_key),
            validation: Arc::new(validation),
        })
    }

    /// Creates a new access token for the given claims.
    pub fn create_token(&self, claims: &Claims) -> ApiResult<String> {
        let header = Header::new(self.config.algorithm);

        encode(&header, claims, &self.encoding_key)
            .map_err(|e| ApiError::internal(format!("Failed to create token: {}", e)))
    }

    /// Creates a new access token for a user.
    pub fn create_access_token(&self, user_id: &str, roles: Vec<String>) -> ApiResult<String> {
        let claims = Claims::new(user_id, roles, self.config.expiration_secs)
            .with_issuer(&self.config.issuer);

        self.create_token(&claims)
    }

    /// Creates a new refresh token for a user.
    pub fn create_refresh_token(&self, user_id: &str) -> ApiResult<String> {
        let claims = Claims::new(user_id, vec!["refresh".to_string()], self.config.refresh_expiration_secs)
            .with_issuer(&self.config.issuer);

        self.create_token(&claims)
    }

    /// Validates and decodes a token.
    pub fn validate_token(&self, token: &str) -> ApiResult<TokenData<Claims>> {
        decode::<Claims>(token, &self.decoding_key, &self.validation).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    ApiError::unauthorized("Token has expired")
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    ApiError::unauthorized("Invalid token format")
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    ApiError::unauthorized("Invalid token signature")
                }
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    ApiError::unauthorized("Invalid token issuer")
                }
                jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                    ApiError::unauthorized("Invalid token audience")
                }
                _ => ApiError::unauthorized(format!("Token validation failed: {}", e)),
            }
        })
    }

    /// Extracts claims from a token without full validation.
    ///
    /// This is useful for getting user information from expired tokens.
    pub fn decode_without_validation(&self, token: &str) -> ApiResult<Claims> {
        let mut validation = Validation::new(self.config.algorithm);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.insecure_disable_signature_validation();

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| ApiError::unauthorized(format!("Failed to decode token: {}", e)))
    }

    /// Returns the token expiration time in seconds.
    pub fn expiration_secs(&self) -> i64 {
        self.config.expiration_secs
    }

    /// Returns the refresh token expiration time in seconds.
    pub fn refresh_expiration_secs(&self) -> i64 {
        self.config.refresh_expiration_secs
    }
}

impl std::fmt::Debug for JwtManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtManager")
            .field("issuer", &self.config.issuer)
            .field("algorithm", &self.config.algorithm)
            .field("expiration_secs", &self.config.expiration_secs)
            .finish()
    }
}

// =============================================================================
// Algorithm Serialization
// =============================================================================

mod algorithm_serde {
    use jsonwebtoken::Algorithm;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(algorithm: &Algorithm, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match algorithm {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
            Algorithm::EdDSA => "EdDSA",
        };
        s.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Algorithm, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            "HS512" => Ok(Algorithm::HS512),
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "PS256" => Ok(Algorithm::PS256),
            "PS384" => Ok(Algorithm::PS384),
            "PS512" => Ok(Algorithm::PS512),
            "EdDSA" => Ok(Algorithm::EdDSA),
            _ => Err(serde::de::Error::custom(format!(
                "Unknown algorithm: {}",
                s
            ))),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> JwtConfig {
        JwtConfig::new("test-secret-key-that-is-long-enough-for-testing")
    }

    #[test]
    fn test_create_and_validate_token() {
        let manager = JwtManager::new(test_config()).unwrap();

        let token = manager
            .create_access_token("user123", vec!["admin".to_string()])
            .unwrap();

        let token_data = manager.validate_token(&token).unwrap();

        assert_eq!(token_data.claims.sub, "user123");
        assert!(token_data.claims.has_role("admin"));
    }

    #[test]
    fn test_expired_token() {
        let config = JwtConfig::new("test-secret-key-that-is-long-enough-for-testing");
        let manager = JwtManager::new(config).unwrap();

        // Create a token with negative expiration (already expired)
        let claims = Claims::new("user", vec![], -3600);
        let token = manager.create_token(&claims).unwrap();

        let result = manager.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_token() {
        let manager = JwtManager::new(test_config()).unwrap();

        let result = manager.validate_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret() {
        let manager1 = JwtManager::new(JwtConfig::new("secret-one-for-testing-purposes")).unwrap();
        let manager2 = JwtManager::new(JwtConfig::new("secret-two-for-testing-purposes")).unwrap();

        let token = manager1
            .create_access_token("user", vec![])
            .unwrap();

        let result = manager2.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_without_validation() {
        let manager = JwtManager::new(test_config()).unwrap();

        // Create an expired token
        let claims = Claims::new("user123", vec!["admin".to_string()], -3600);
        let token = manager.create_token(&claims).unwrap();

        // Should fail normal validation
        assert!(manager.validate_token(&token).is_err());

        // But decode_without_validation should work
        let decoded = manager.decode_without_validation(&token).unwrap();
        assert_eq!(decoded.sub, "user123");
    }
}
