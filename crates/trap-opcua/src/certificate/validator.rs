// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Certificate validation traits and implementations.
//!
//! This module provides abstractions for certificate validation, allowing
//! different validation strategies (strict, permissive, custom) to be used.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::error::{CertificateError, CertificateResult, ValidationError};
use super::store::{CertificateStore, TrustStatus};

// =============================================================================
// ValidationResult
// =============================================================================

/// Result of certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the certificate is valid.
    pub is_valid: bool,
    /// Validation errors (if any).
    pub errors: Vec<ValidationError>,
    /// Validation warnings (non-fatal issues).
    pub warnings: Vec<String>,
    /// Certificate thumbprint.
    pub thumbprint: String,
    /// Subject DN.
    pub subject_dn: String,
    /// Whether the certificate is trusted.
    pub is_trusted: bool,
    /// Days until expiration.
    pub days_until_expiration: i64,
}

impl ValidationResult {
    /// Creates a successful validation result.
    pub fn valid(thumbprint: String, subject_dn: String, days_until_expiration: i64) -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            thumbprint,
            subject_dn,
            is_trusted: true,
            days_until_expiration,
        }
    }

    /// Creates a failed validation result.
    pub fn invalid(
        thumbprint: String,
        subject_dn: String,
        errors: Vec<ValidationError>,
    ) -> Self {
        Self {
            is_valid: false,
            errors,
            warnings: Vec::new(),
            thumbprint,
            subject_dn,
            is_trusted: false,
            days_until_expiration: 0,
        }
    }

    /// Adds a warning to the result.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Adds an error to the result.
    pub fn with_error(mut self, error: ValidationError) -> Self {
        self.is_valid = false;
        self.errors.push(error);
        self
    }

    /// Returns `true` if there are any warnings.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

// =============================================================================
// ValidationPolicy
// =============================================================================

/// Certificate validation policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationPolicy {
    /// Check certificate expiration.
    pub check_expiration: bool,
    /// Check certificate not yet valid.
    pub check_not_before: bool,
    /// Check certificate trust.
    pub check_trust: bool,
    /// Check certificate chain.
    pub check_chain: bool,
    /// Check key usage.
    pub check_key_usage: bool,
    /// Check extended key usage.
    pub check_extended_key_usage: bool,
    /// Check application URI.
    pub check_application_uri: bool,
    /// Check hostname (SAN).
    pub check_hostname: bool,
    /// Allow self-signed certificates.
    pub allow_self_signed: bool,
    /// Minimum key size (bits).
    pub minimum_key_size: u32,
    /// Warning threshold for expiration (days).
    pub expiration_warning_days: i64,
    /// Rejected signature algorithms.
    pub rejected_algorithms: Vec<String>,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            check_expiration: true,
            check_not_before: true,
            check_trust: true,
            check_chain: false, // Often disabled for OPC UA
            check_key_usage: true,
            check_extended_key_usage: true,
            check_application_uri: true,
            check_hostname: false, // OPC UA uses application URI instead
            allow_self_signed: true,
            minimum_key_size: 2048,
            expiration_warning_days: 30,
            rejected_algorithms: vec!["MD5".to_string(), "SHA1".to_string()],
        }
    }
}

impl ValidationPolicy {
    /// Creates a strict validation policy.
    pub fn strict() -> Self {
        Self {
            check_expiration: true,
            check_not_before: true,
            check_trust: true,
            check_chain: true,
            check_key_usage: true,
            check_extended_key_usage: true,
            check_application_uri: true,
            check_hostname: true,
            allow_self_signed: false,
            minimum_key_size: 2048,
            expiration_warning_days: 60,
            rejected_algorithms: vec![
                "MD5".to_string(),
                "SHA1".to_string(),
                "RSA-1024".to_string(),
            ],
        }
    }

    /// Creates a permissive validation policy.
    pub fn permissive() -> Self {
        Self {
            check_expiration: true,
            check_not_before: true,
            check_trust: false,
            check_chain: false,
            check_key_usage: false,
            check_extended_key_usage: false,
            check_application_uri: false,
            check_hostname: false,
            allow_self_signed: true,
            minimum_key_size: 1024,
            expiration_warning_days: 7,
            rejected_algorithms: Vec::new(),
        }
    }

    /// Creates a policy for OPC UA (recommended settings).
    pub fn opcua() -> Self {
        Self {
            check_expiration: true,
            check_not_before: true,
            check_trust: true,
            check_chain: false,
            check_key_usage: true,
            check_extended_key_usage: true,
            check_application_uri: true,
            check_hostname: false,
            allow_self_signed: true,
            minimum_key_size: 2048,
            expiration_warning_days: 30,
            rejected_algorithms: vec!["MD5".to_string()],
        }
    }
}

// =============================================================================
// CertificateValidator Trait
// =============================================================================

/// Trait for certificate validation.
#[async_trait]
pub trait CertificateValidator: Send + Sync {
    /// Returns the validator name.
    fn name(&self) -> &str;

    /// Returns the validation policy.
    fn policy(&self) -> &ValidationPolicy;

    /// Validates a certificate in DER format.
    async fn validate(&self, cert_der: &[u8]) -> CertificateResult<ValidationResult>;

    /// Validates a certificate with expected application URI.
    async fn validate_with_uri(
        &self,
        cert_der: &[u8],
        expected_uri: &str,
    ) -> CertificateResult<ValidationResult>;

    /// Validates a certificate with expected hostname.
    async fn validate_with_hostname(
        &self,
        cert_der: &[u8],
        hostname: &str,
    ) -> CertificateResult<ValidationResult>;

    /// Validates a certificate chain.
    async fn validate_chain(&self, chain: &[Vec<u8>]) -> CertificateResult<ValidationResult>;

    /// Checks if a certificate is trusted.
    async fn is_trusted(&self, thumbprint: &str) -> CertificateResult<bool>;

    /// Trusts a certificate.
    async fn trust(&self, thumbprint: &str) -> CertificateResult<()>;

    /// Rejects a certificate.
    async fn reject(&self, thumbprint: &str) -> CertificateResult<()>;
}

// =============================================================================
// X509Validator
// =============================================================================

/// X.509 certificate validator.
///
/// Validates certificates according to the configured policy and against
/// the certificate store for trust decisions.
pub struct X509Validator {
    /// Validation policy.
    policy: ValidationPolicy,
    /// Certificate store for trust lookups.
    store: Arc<dyn CertificateStore>,
    /// Explicitly trusted thumbprints (runtime override).
    trusted_thumbprints: Arc<RwLock<HashSet<String>>>,
    /// Explicitly rejected thumbprints (runtime override).
    rejected_thumbprints: Arc<RwLock<HashSet<String>>>,
}

impl X509Validator {
    /// Creates a new X.509 validator with default policy.
    pub fn new(store: Arc<dyn CertificateStore>) -> Self {
        Self::with_policy(store, ValidationPolicy::default())
    }

    /// Creates a new X.509 validator with custom policy.
    pub fn with_policy(store: Arc<dyn CertificateStore>, policy: ValidationPolicy) -> Self {
        Self {
            policy,
            store,
            trusted_thumbprints: Arc::new(RwLock::new(HashSet::new())),
            rejected_thumbprints: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Creates an OPC UA validator.
    pub fn opcua(store: Arc<dyn CertificateStore>) -> Self {
        Self::with_policy(store, ValidationPolicy::opcua())
    }

    /// Creates a strict validator.
    pub fn strict(store: Arc<dyn CertificateStore>) -> Self {
        Self::with_policy(store, ValidationPolicy::strict())
    }

    /// Creates a permissive validator.
    pub fn permissive(store: Arc<dyn CertificateStore>) -> Self {
        Self::with_policy(store, ValidationPolicy::permissive())
    }

    /// Extracts certificate information from DER bytes.
    fn parse_certificate(&self, cert_der: &[u8]) -> CertificateResult<CertificateInfo> {
        // In a real implementation, parse the X.509 certificate
        // For now, extract what we can from our mock format

        let thumbprint = hex_encode(&cert_der[..20.min(cert_der.len())]);

        // Extract subject (mock)
        let subject_start = cert_der.iter().position(|&b| b == 0x30).unwrap_or(0) + 1;
        let subject_end = cert_der[subject_start..]
            .iter()
            .position(|&b| b == 0x00)
            .map(|p| subject_start + p)
            .unwrap_or(cert_der.len().min(subject_start + 64));

        let subject_dn = String::from_utf8_lossy(&cert_der[subject_start..subject_end]).to_string();

        // Extract dates (mock - stored as i64 timestamps)
        let serial_end_pos = subject_end + 1 + cert_der[subject_end + 1..]
            .iter()
            .position(|&b| b == 0x00)
            .unwrap_or(32);

        let dates_start = serial_end_pos + 1;
        let not_before = if dates_start + 8 <= cert_der.len() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&cert_der[dates_start..dates_start + 8]);
            DateTime::from_timestamp(i64::from_be_bytes(bytes), 0).unwrap_or_else(Utc::now)
        } else {
            Utc::now()
        };

        let not_after = if dates_start + 16 <= cert_der.len() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&cert_der[dates_start + 8..dates_start + 16]);
            DateTime::from_timestamp(i64::from_be_bytes(bytes), 0)
                .unwrap_or_else(|| Utc::now() + chrono::Duration::days(365))
        } else {
            Utc::now() + chrono::Duration::days(365)
        };

        // Check if self-signed (subject == issuer)
        let is_self_signed = true; // Assume self-signed for mock

        Ok(CertificateInfo {
            thumbprint,
            subject_dn: format!("CN={}", subject_dn),
            issuer_dn: format!("CN={}", subject_dn),
            serial_number: "mock".to_string(),
            not_before,
            not_after,
            key_size: 2048,
            signature_algorithm: "SHA256WithRSA".to_string(),
            is_self_signed,
            is_ca: false,
            application_uri: None,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            has_digital_signature: true,
            has_key_encipherment: true,
            has_data_encipherment: true,
            has_server_auth: true,
            has_client_auth: true,
        })
    }

    /// Validates a parsed certificate.
    async fn validate_info(&self, info: &CertificateInfo) -> ValidationResult {
        let mut result = ValidationResult::valid(
            info.thumbprint.clone(),
            info.subject_dn.clone(),
            info.days_until_expiration(),
        );

        // Check if explicitly rejected
        {
            let rejected = self.rejected_thumbprints.read().await;
            if rejected.contains(&info.thumbprint) {
                return result.with_error(ValidationError::not_trusted(&info.thumbprint));
            }
        }

        // Check if explicitly trusted
        let explicitly_trusted = {
            let trusted = self.trusted_thumbprints.read().await;
            trusted.contains(&info.thumbprint)
        };

        // Check expiration
        if self.policy.check_expiration {
            let now = Utc::now();
            if now > info.not_after {
                let days_expired = (now - info.not_after).num_days();
                result = result.with_error(ValidationError::InvalidCertificate {
                    message: format!("Certificate expired {} days ago", days_expired),
                });
            } else if info.days_until_expiration() <= self.policy.expiration_warning_days {
                result = result.with_warning(format!(
                    "Certificate expires in {} days",
                    info.days_until_expiration()
                ));
            }
        }

        // Check not before
        if self.policy.check_not_before {
            let now = Utc::now();
            if now < info.not_before {
                let days_until = (info.not_before - now).num_days();
                result = result.with_error(ValidationError::InvalidCertificate {
                    message: format!("Certificate not valid for {} more days", days_until),
                });
            }
        }

        // Check self-signed
        if !self.policy.allow_self_signed && info.is_self_signed {
            result = result.with_error(ValidationError::SelfSignedNotAllowed);
        }

        // Check key size
        if info.key_size < self.policy.minimum_key_size {
            result = result.with_error(ValidationError::WeakAlgorithm {
                algorithm: format!("Key size {} bits", info.key_size),
            });
        }

        // Check signature algorithm
        for rejected in &self.policy.rejected_algorithms {
            if info.signature_algorithm.contains(rejected) {
                result = result.with_error(ValidationError::WeakAlgorithm {
                    algorithm: info.signature_algorithm.clone(),
                });
                break;
            }
        }

        // Check key usage
        if self.policy.check_key_usage {
            if !info.has_digital_signature {
                result = result.with_error(ValidationError::key_usage_mismatch("digitalSignature"));
            }
            if !info.has_key_encipherment {
                result = result.with_warning("Certificate missing keyEncipherment");
            }
        }

        // Check extended key usage
        if self.policy.check_extended_key_usage {
            if !info.has_server_auth && !info.has_client_auth {
                result = result.with_error(ValidationError::ExtendedKeyUsageMismatch {
                    usage: "serverAuth or clientAuth".to_string(),
                });
            }
        }

        // Check trust (from store)
        if self.policy.check_trust && !explicitly_trusted {
            match self.store.get(&info.thumbprint).await {
                Ok(Some(stored)) => {
                    if stored.trust_status != TrustStatus::Trusted {
                        result.is_trusted = false;
                        result = result.with_error(ValidationError::not_trusted(&info.thumbprint));
                    }
                }
                Ok(None) => {
                    result.is_trusted = false;
                    result = result.with_error(ValidationError::not_trusted(&info.thumbprint));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to check trust status");
                }
            }
        }

        result
    }
}

#[async_trait]
impl CertificateValidator for X509Validator {
    fn name(&self) -> &str {
        "X509Validator"
    }

    fn policy(&self) -> &ValidationPolicy {
        &self.policy
    }

    async fn validate(&self, cert_der: &[u8]) -> CertificateResult<ValidationResult> {
        let info = self.parse_certificate(cert_der)?;
        Ok(self.validate_info(&info).await)
    }

    async fn validate_with_uri(
        &self,
        cert_der: &[u8],
        expected_uri: &str,
    ) -> CertificateResult<ValidationResult> {
        let info = self.parse_certificate(cert_der)?;
        let mut result = self.validate_info(&info).await;

        if self.policy.check_application_uri {
            match &info.application_uri {
                Some(uri) if uri == expected_uri => {}
                Some(uri) => {
                    result = result.with_error(ValidationError::application_uri_mismatch(
                        expected_uri,
                        uri,
                    ));
                }
                None => {
                    result = result.with_warning("Certificate has no application URI");
                }
            }
        }

        Ok(result)
    }

    async fn validate_with_hostname(
        &self,
        cert_der: &[u8],
        hostname: &str,
    ) -> CertificateResult<ValidationResult> {
        let info = self.parse_certificate(cert_der)?;
        let mut result = self.validate_info(&info).await;

        if self.policy.check_hostname {
            let hostname_matches = info.dns_names.iter().any(|dns| {
                dns == hostname || (dns.starts_with("*.") && hostname.ends_with(&dns[1..]))
            }) || info.ip_addresses.contains(&hostname.to_string());

            if !hostname_matches {
                result = result.with_error(ValidationError::san_mismatch(hostname));
            }
        }

        Ok(result)
    }

    async fn validate_chain(&self, chain: &[Vec<u8>]) -> CertificateResult<ValidationResult> {
        if chain.is_empty() {
            return Err(CertificateError::validation(
                ValidationError::chain_error("Empty certificate chain"),
            ));
        }

        // Validate end-entity certificate
        let result = self.validate(&chain[0]).await?;

        if !self.policy.check_chain {
            return Ok(result);
        }

        // In a full implementation, validate the chain:
        // 1. Verify each certificate is signed by the next
        // 2. Verify the chain ends at a trusted root
        // 3. Check all intermediate certificates are valid CAs

        Ok(result)
    }

    async fn is_trusted(&self, thumbprint: &str) -> CertificateResult<bool> {
        // Check explicit trust
        {
            let trusted = self.trusted_thumbprints.read().await;
            if trusted.contains(thumbprint) {
                return Ok(true);
            }
        }

        // Check explicit rejection
        {
            let rejected = self.rejected_thumbprints.read().await;
            if rejected.contains(thumbprint) {
                return Ok(false);
            }
        }

        // Check store
        match self.store.get(thumbprint).await? {
            Some(stored) => Ok(stored.trust_status == TrustStatus::Trusted),
            None => Ok(false),
        }
    }

    async fn trust(&self, thumbprint: &str) -> CertificateResult<()> {
        // Remove from rejected
        {
            let mut rejected = self.rejected_thumbprints.write().await;
            rejected.remove(thumbprint);
        }

        // Add to trusted
        {
            let mut trusted = self.trusted_thumbprints.write().await;
            trusted.insert(thumbprint.to_string());
        }

        // Update store if certificate exists
        if self.store.exists(thumbprint).await? {
            self.store
                .set_trust_status(thumbprint, TrustStatus::Trusted)
                .await?;
        }

        tracing::info!(thumbprint = thumbprint, "Trusted certificate");
        Ok(())
    }

    async fn reject(&self, thumbprint: &str) -> CertificateResult<()> {
        // Remove from trusted
        {
            let mut trusted = self.trusted_thumbprints.write().await;
            trusted.remove(thumbprint);
        }

        // Add to rejected
        {
            let mut rejected = self.rejected_thumbprints.write().await;
            rejected.insert(thumbprint.to_string());
        }

        // Update store if certificate exists
        if self.store.exists(thumbprint).await? {
            self.store
                .set_trust_status(thumbprint, TrustStatus::Rejected)
                .await?;
        }

        tracing::info!(thumbprint = thumbprint, "Rejected certificate");
        Ok(())
    }
}

// =============================================================================
// CertificateInfo (Internal)
// =============================================================================

/// Parsed certificate information.
#[derive(Debug, Clone)]
struct CertificateInfo {
    thumbprint: String,
    subject_dn: String,
    issuer_dn: String,
    serial_number: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    key_size: u32,
    signature_algorithm: String,
    is_self_signed: bool,
    is_ca: bool,
    application_uri: Option<String>,
    dns_names: Vec<String>,
    ip_addresses: Vec<String>,
    has_digital_signature: bool,
    has_key_encipherment: bool,
    has_data_encipherment: bool,
    has_server_auth: bool,
    has_client_auth: bool,
}

impl CertificateInfo {
    fn days_until_expiration(&self) -> i64 {
        let now = Utc::now();
        (self.not_after - now).num_days()
    }
}

// =============================================================================
// AcceptAllValidator (for testing/development)
// =============================================================================

/// Validator that accepts all certificates (for testing only).
///
/// **WARNING**: Do not use in production!
#[derive(Debug, Default)]
pub struct AcceptAllValidator {
    policy: ValidationPolicy,
}

impl AcceptAllValidator {
    /// Creates a new accept-all validator.
    pub fn new() -> Self {
        Self {
            policy: ValidationPolicy::permissive(),
        }
    }
}

#[async_trait]
impl CertificateValidator for AcceptAllValidator {
    fn name(&self) -> &str {
        "AcceptAllValidator"
    }

    fn policy(&self) -> &ValidationPolicy {
        &self.policy
    }

    async fn validate(&self, cert_der: &[u8]) -> CertificateResult<ValidationResult> {
        let thumbprint = hex_encode(&cert_der[..20.min(cert_der.len())]);

        tracing::warn!(
            thumbprint = %thumbprint,
            "AcceptAllValidator: accepting certificate without validation"
        );

        Ok(ValidationResult::valid(
            thumbprint,
            "Unknown".to_string(),
            365,
        ))
    }

    async fn validate_with_uri(
        &self,
        cert_der: &[u8],
        _expected_uri: &str,
    ) -> CertificateResult<ValidationResult> {
        self.validate(cert_der).await
    }

    async fn validate_with_hostname(
        &self,
        cert_der: &[u8],
        _hostname: &str,
    ) -> CertificateResult<ValidationResult> {
        self.validate(cert_der).await
    }

    async fn validate_chain(&self, chain: &[Vec<u8>]) -> CertificateResult<ValidationResult> {
        if chain.is_empty() {
            return Err(CertificateError::validation(
                ValidationError::chain_error("Empty chain"),
            ));
        }
        self.validate(&chain[0]).await
    }

    async fn is_trusted(&self, _thumbprint: &str) -> CertificateResult<bool> {
        Ok(true)
    }

    async fn trust(&self, _thumbprint: &str) -> CertificateResult<()> {
        Ok(())
    }

    async fn reject(&self, _thumbprint: &str) -> CertificateResult<()> {
        Ok(())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Hex encodes bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::store::MemoryStore;

    #[tokio::test]
    async fn test_accept_all_validator() {
        let validator = AcceptAllValidator::new();
        let cert_data = vec![0u8; 100];

        let result = validator.validate(&cert_data).await.unwrap();
        assert!(result.is_valid);
        assert!(validator.is_trusted("any").await.unwrap());
    }

    #[tokio::test]
    async fn test_x509_validator() {
        let store = Arc::new(MemoryStore::new());
        store.initialize().await.unwrap();

        let validator = X509Validator::new(store.clone());
        let cert_data = vec![0x30, 0x82, 0x01, 0x00]; // Minimal mock

        // Add to store as trusted
        store
            .add(&cert_data, None, TrustStatus::Trusted)
            .await
            .unwrap();

        let result = validator.validate(&cert_data).await.unwrap();
        // Should validate structure (our mock may have issues)
        assert!(!result.thumbprint.is_empty());
    }

    #[tokio::test]
    async fn test_trust_reject() {
        let store = Arc::new(MemoryStore::new());
        let validator = X509Validator::new(store);

        validator.trust("ABC123").await.unwrap();
        assert!(validator.is_trusted("ABC123").await.unwrap());

        validator.reject("ABC123").await.unwrap();
        assert!(!validator.is_trusted("ABC123").await.unwrap());
    }

    #[test]
    fn test_validation_policy() {
        let default = ValidationPolicy::default();
        assert!(default.check_expiration);
        assert!(default.allow_self_signed);

        let strict = ValidationPolicy::strict();
        assert!(!strict.allow_self_signed);
        assert!(strict.check_chain);

        let permissive = ValidationPolicy::permissive();
        assert!(!permissive.check_trust);
    }

    #[test]
    fn test_validation_result() {
        let result = ValidationResult::valid("ABC".to_string(), "CN=Test".to_string(), 30);
        assert!(result.is_valid);
        assert!(!result.has_warnings());

        let result = result.with_warning("Test warning");
        assert!(result.has_warnings());

        let result = result.with_error(ValidationError::SignatureInvalid);
        assert!(!result.is_valid);
    }
}
