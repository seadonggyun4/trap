// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Certificate generation traits and implementations.
//!
//! This module provides abstractions for certificate generation, allowing
//! different implementations (self-signed, CA-signed, etc.) to be used
//! interchangeably.

use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::config::{CertificateConfig, CertificateFormat, KeyAlgorithm};
use super::error::{CertificateError, CertificateResult, GenerationError, StorageError};

// =============================================================================
// Certificate Data Types
// =============================================================================

/// Generated certificate data.
#[derive(Debug, Clone)]
pub struct GeneratedCertificate {
    /// Certificate bytes (DER or PEM encoded).
    pub certificate_der: Vec<u8>,
    /// Private key bytes (DER or PEM encoded).
    pub private_key_der: Vec<u8>,
    /// Certificate thumbprint (SHA-1).
    pub thumbprint_sha1: String,
    /// Certificate thumbprint (SHA-256).
    pub thumbprint_sha256: String,
    /// Certificate serial number.
    pub serial_number: String,
    /// Subject Distinguished Name.
    pub subject_dn: String,
    /// Issuer Distinguished Name.
    pub issuer_dn: String,
    /// Not valid before date.
    pub not_before: DateTime<Utc>,
    /// Not valid after date.
    pub not_after: DateTime<Utc>,
    /// Public key info.
    pub public_key_info: PublicKeyInfo,
}

impl GeneratedCertificate {
    /// Returns the certificate as PEM encoded string.
    pub fn certificate_pem(&self) -> String {
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &self.certificate_der,
        );
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            b64.chars()
                .collect::<Vec<_>>()
                .chunks(64)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Returns the private key as PEM encoded string.
    pub fn private_key_pem(&self) -> String {
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &self.private_key_der,
        );
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64.chars()
                .collect::<Vec<_>>()
                .chunks(64)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Returns `true` if the certificate is currently valid.
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Returns the number of days until expiration.
    pub fn days_until_expiration(&self) -> i64 {
        let now = Utc::now();
        (self.not_after - now).num_days()
    }

    /// Returns `true` if the certificate will expire within the given days.
    pub fn expires_within_days(&self, days: i64) -> bool {
        self.days_until_expiration() <= days
    }
}

/// Public key information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// Algorithm name.
    pub algorithm: String,
    /// Key size in bits.
    pub key_size: u32,
    /// Public key bytes.
    pub public_key: Vec<u8>,
}

// =============================================================================
// CertificateGenerator Trait
// =============================================================================

/// Trait for certificate generation.
///
/// Implementations can generate self-signed certificates, request certificates
/// from a CA, or use other methods.
#[async_trait]
pub trait CertificateGenerator: Send + Sync {
    /// Returns the generator name.
    fn name(&self) -> &str;

    /// Returns `true` if this generator can create CA certificates.
    fn supports_ca(&self) -> bool;

    /// Generates a certificate based on the configuration.
    async fn generate(&self, config: &CertificateConfig) -> CertificateResult<GeneratedCertificate>;

    /// Generates a certificate and saves it to files.
    async fn generate_and_save(
        &self,
        config: &CertificateConfig,
    ) -> CertificateResult<CertificatePaths> {
        let cert = self.generate(config).await?;
        save_certificate(&cert, config).await
    }
}

/// Paths to saved certificate files.
#[derive(Debug, Clone)]
pub struct CertificatePaths {
    /// Path to certificate file.
    pub certificate_path: PathBuf,
    /// Path to private key file.
    pub private_key_path: PathBuf,
    /// Certificate thumbprint.
    pub thumbprint: String,
}

// =============================================================================
// SelfSignedGenerator
// =============================================================================

/// Generator for self-signed certificates.
///
/// This is the primary generator for OPC UA client certificates where
/// a CA infrastructure is not available.
#[derive(Debug, Clone, Default)]
pub struct SelfSignedGenerator {
    /// Custom random seed (for testing).
    #[allow(dead_code)]
    seed: Option<[u8; 32]>,
}

impl SelfSignedGenerator {
    /// Creates a new self-signed generator.
    pub fn new() -> Self {
        Self { seed: None }
    }

    /// Creates a self-signed generator with a custom seed (for testing).
    #[cfg(test)]
    pub fn with_seed(seed: [u8; 32]) -> Self {
        Self { seed: Some(seed) }
    }

    /// Generates the key pair based on algorithm.
    fn generate_key_pair(
        &self,
        algorithm: KeyAlgorithm,
    ) -> CertificateResult<(Vec<u8>, Vec<u8>, PublicKeyInfo)> {
        // Note: This is a placeholder implementation.
        // In a real implementation, you would use a crypto library like
        // `ring`, `openssl`, or `rustls` to generate actual keys.
        //
        // For now, we create mock data that demonstrates the structure.

        let key_size = algorithm.key_size();
        let algorithm_name = algorithm.name().to_string();

        // Generate mock key data (in production, use proper crypto)
        let private_key = self.generate_mock_private_key(algorithm);
        let public_key = self.generate_mock_public_key(algorithm);

        let public_key_info = PublicKeyInfo {
            algorithm: algorithm_name,
            key_size,
            public_key: public_key.clone(),
        };

        Ok((private_key, public_key, public_key_info))
    }

    /// Generates mock private key data.
    fn generate_mock_private_key(&self, algorithm: KeyAlgorithm) -> Vec<u8> {
        // In production, use proper key generation
        let size = match algorithm {
            KeyAlgorithm::Rsa2048 => 1218,
            KeyAlgorithm::Rsa3072 => 1766,
            KeyAlgorithm::Rsa4096 => 2374,
            KeyAlgorithm::EcdsaP256 => 121,
            KeyAlgorithm::EcdsaP384 => 167,
        };

        let mut key = vec![0u8; size];
        // Fill with pseudo-random data
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = ((i * 17 + 31) % 256) as u8;
        }
        key
    }

    /// Generates mock public key data.
    fn generate_mock_public_key(&self, algorithm: KeyAlgorithm) -> Vec<u8> {
        // In production, extract from private key
        let size = match algorithm {
            KeyAlgorithm::Rsa2048 => 270,
            KeyAlgorithm::Rsa3072 => 398,
            KeyAlgorithm::Rsa4096 => 526,
            KeyAlgorithm::EcdsaP256 => 65,
            KeyAlgorithm::EcdsaP384 => 97,
        };

        let mut key = vec![0u8; size];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = ((i * 13 + 37) % 256) as u8;
        }
        key
    }

    /// Calculates SHA-1 thumbprint of certificate.
    fn calculate_sha1_thumbprint(data: &[u8]) -> String {
        // In production, use actual SHA-1
        // This is a placeholder
        let mut hash = [0u8; 20];
        for (i, byte) in data.iter().take(20).enumerate() {
            hash[i] = *byte;
        }
        hex_encode(&hash)
    }

    /// Calculates SHA-256 thumbprint of certificate.
    fn calculate_sha256_thumbprint(data: &[u8]) -> String {
        // In production, use actual SHA-256
        // This is a placeholder
        let mut hash = [0u8; 32];
        for (i, byte) in data.iter().take(32).enumerate() {
            hash[i] = *byte;
        }
        hex_encode(&hash)
    }

    /// Generates a serial number.
    fn generate_serial_number() -> String {
        // In production, use cryptographically secure random
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        format!("{:032X}", now % u128::MAX)
    }

    /// Creates mock DER encoded certificate.
    fn create_mock_certificate_der(
        &self,
        config: &CertificateConfig,
        public_key_info: &PublicKeyInfo,
        serial: &str,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> Vec<u8> {
        // In production, create actual X.509 certificate using ASN.1 DER encoding
        // This is a placeholder that creates a recognizable pattern

        let mut der = Vec::new();

        // SEQUENCE tag
        der.push(0x30);

        // Add subject info (mock)
        der.extend_from_slice(config.subject.common_name.as_bytes());
        der.push(0x00);

        // Add serial number
        der.extend_from_slice(serial.as_bytes());
        der.push(0x00);

        // Add validity dates
        der.extend_from_slice(&not_before.timestamp().to_be_bytes());
        der.extend_from_slice(&not_after.timestamp().to_be_bytes());

        // Add public key
        der.extend_from_slice(&public_key_info.public_key);

        // Add application URI
        der.extend_from_slice(config.application_uri.as_bytes());
        der.push(0x00);

        // Add SANs
        for san in &config.subject_alt_names {
            der.extend_from_slice(san.value().as_bytes());
            der.push(0x00);
        }

        // Update length (simplified)
        let len = der.len() - 1;
        if len < 128 {
            der.insert(1, len as u8);
        } else {
            der.insert(1, 0x82);
            der.insert(2, ((len >> 8) & 0xFF) as u8);
            der.insert(3, (len & 0xFF) as u8);
        }

        der
    }
}

#[async_trait]
impl CertificateGenerator for SelfSignedGenerator {
    fn name(&self) -> &str {
        "SelfSignedGenerator"
    }

    fn supports_ca(&self) -> bool {
        true
    }

    async fn generate(&self, config: &CertificateConfig) -> CertificateResult<GeneratedCertificate> {
        // Validate configuration
        config.validate()?;

        tracing::info!(
            common_name = %config.subject.common_name,
            algorithm = %config.key_algorithm,
            validity_days = config.validity_days,
            "Generating self-signed certificate"
        );

        // Generate key pair
        let (private_key_der, _public_key, public_key_info) =
            self.generate_key_pair(config.key_algorithm)?;

        // Calculate validity period
        let not_before = Utc::now();
        let not_after = not_before + chrono::Duration::days(config.validity_days as i64);

        // Generate serial number
        let serial_number = Self::generate_serial_number();

        // Create subject/issuer DN string
        let subject_dn = config.subject.to_dn_string();
        let issuer_dn = subject_dn.clone(); // Self-signed, so issuer = subject

        // Create certificate DER
        let certificate_der = self.create_mock_certificate_der(
            config,
            &public_key_info,
            &serial_number,
            not_before,
            not_after,
        );

        // Calculate thumbprints
        let thumbprint_sha1 = Self::calculate_sha1_thumbprint(&certificate_der);
        let thumbprint_sha256 = Self::calculate_sha256_thumbprint(&certificate_der);

        tracing::info!(
            thumbprint = %thumbprint_sha1,
            serial = %serial_number,
            "Generated self-signed certificate"
        );

        Ok(GeneratedCertificate {
            certificate_der,
            private_key_der,
            thumbprint_sha1,
            thumbprint_sha256,
            serial_number,
            subject_dn,
            issuer_dn,
            not_before,
            not_after,
            public_key_info,
        })
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Saves a generated certificate to files.
pub async fn save_certificate(
    cert: &GeneratedCertificate,
    config: &CertificateConfig,
) -> CertificateResult<CertificatePaths> {
    let cert_path = config.get_certificate_path();
    let key_path = config.get_private_key_path();

    // Create parent directories
    if let Some(parent) = cert_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            CertificateError::storage(StorageError::directory_creation_failed(
                parent.to_path_buf(),
                e.to_string(),
            ))
        })?;
    }

    if let Some(parent) = key_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            CertificateError::storage(StorageError::directory_creation_failed(
                parent.to_path_buf(),
                e.to_string(),
            ))
        })?;
    }

    // Check if files exist and overwrite is not set
    if !config.overwrite {
        if cert_path.exists() {
            return Err(CertificateError::storage(StorageError::already_exists(
                cert_path,
            )));
        }
        if key_path.exists() {
            return Err(CertificateError::storage(StorageError::already_exists(
                key_path,
            )));
        }
    }

    // Save based on format
    match config.format {
        CertificateFormat::Der => {
            tokio::fs::write(&cert_path, &cert.certificate_der)
                .await
                .map_err(|e| {
                    CertificateError::storage(StorageError::write_failed_with(
                        cert_path.clone(),
                        "Failed to write DER certificate",
                        e,
                    ))
                })?;

            tokio::fs::write(&key_path, &cert.private_key_der)
                .await
                .map_err(|e| {
                    CertificateError::storage(StorageError::write_failed_with(
                        key_path.clone(),
                        "Failed to write private key",
                        e,
                    ))
                })?;
        }
        CertificateFormat::Pem => {
            tokio::fs::write(&cert_path, cert.certificate_pem())
                .await
                .map_err(|e| {
                    CertificateError::storage(StorageError::write_failed_with(
                        cert_path.clone(),
                        "Failed to write PEM certificate",
                        e,
                    ))
                })?;

            tokio::fs::write(&key_path, cert.private_key_pem())
                .await
                .map_err(|e| {
                    CertificateError::storage(StorageError::write_failed_with(
                        key_path.clone(),
                        "Failed to write private key",
                        e,
                    ))
                })?;
        }
        CertificateFormat::Pkcs12 => {
            // PKCS#12 would require additional implementation
            return Err(CertificateError::generation(
                GenerationError::UnsupportedAlgorithm {
                    algorithm: "PKCS#12 export".to_string(),
                },
            ));
        }
    }

    // Set restrictive permissions on private key (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&key_path, permissions)
            .await
            .map_err(|e| {
                tracing::warn!(
                    path = %key_path.display(),
                    error = %e,
                    "Failed to set private key permissions"
                );
                // Don't fail on permission error, just warn
                e
            })
            .ok();
    }

    tracing::info!(
        certificate = %cert_path.display(),
        private_key = %key_path.display(),
        thumbprint = %cert.thumbprint_sha1,
        "Saved certificate files"
    );

    Ok(CertificatePaths {
        certificate_path: cert_path,
        private_key_path: key_path,
        thumbprint: cert.thumbprint_sha1.clone(),
    })
}

/// Hex encodes bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

// =============================================================================
// CaSignedGenerator (Placeholder)
// =============================================================================

/// Generator for CA-signed certificates.
///
/// This generator requests certificates from a Certificate Authority.
/// Currently a placeholder for future implementation.
#[derive(Debug)]
pub struct CaSignedGenerator {
    /// CA certificate path.
    pub ca_cert_path: PathBuf,
    /// CA private key path.
    pub ca_key_path: PathBuf,
}

impl CaSignedGenerator {
    /// Creates a new CA-signed generator.
    pub fn new(ca_cert_path: PathBuf, ca_key_path: PathBuf) -> Self {
        Self {
            ca_cert_path,
            ca_key_path,
        }
    }
}

#[async_trait]
impl CertificateGenerator for CaSignedGenerator {
    fn name(&self) -> &str {
        "CaSignedGenerator"
    }

    fn supports_ca(&self) -> bool {
        false
    }

    async fn generate(&self, _config: &CertificateConfig) -> CertificateResult<GeneratedCertificate> {
        // Placeholder - would load CA cert/key and sign the new certificate
        Err(CertificateError::generation(
            GenerationError::UnsupportedAlgorithm {
                algorithm: "CA-signed generation not yet implemented".to_string(),
            },
        ))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::config::CertificateConfigBuilder;

    #[tokio::test]
    async fn test_self_signed_generator() {
        let generator = SelfSignedGenerator::new();
        let config = CertificateConfigBuilder::new()
            .common_name("Test Certificate")
            .application_uri("urn:test:app")
            .validity_days(30)
            .build_unchecked();

        let cert = generator.generate(&config).await.unwrap();

        assert!(!cert.certificate_der.is_empty());
        assert!(!cert.private_key_der.is_empty());
        assert!(!cert.thumbprint_sha1.is_empty());
        assert!(!cert.thumbprint_sha256.is_empty());
        assert!(cert.subject_dn.contains("Test Certificate"));
        assert!(cert.is_valid());
    }

    #[tokio::test]
    async fn test_certificate_validity() {
        let generator = SelfSignedGenerator::new();
        let config = CertificateConfigBuilder::new()
            .common_name("Test")
            .application_uri("urn:test")
            .validity_days(365)
            .build_unchecked();

        let cert = generator.generate(&config).await.unwrap();

        assert!(cert.is_valid());
        assert!(cert.days_until_expiration() >= 364);
        assert!(cert.expires_within_days(366));
        assert!(!cert.expires_within_days(30));
    }

    #[tokio::test]
    async fn test_certificate_pem_format() {
        let generator = SelfSignedGenerator::new();
        let config = CertificateConfigBuilder::new()
            .common_name("Test")
            .application_uri("urn:test")
            .build_unchecked();

        let cert = generator.generate(&config).await.unwrap();

        let pem = cert.certificate_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));

        let key_pem = cert.private_key_pem();
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_public_key_info() {
        let info = PublicKeyInfo {
            algorithm: "RSA-2048".to_string(),
            key_size: 2048,
            public_key: vec![0u8; 270],
        };

        assert_eq!(info.algorithm, "RSA-2048");
        assert_eq!(info.key_size, 2048);
    }

    #[test]
    fn test_generator_traits() {
        let generator = SelfSignedGenerator::new();
        assert_eq!(generator.name(), "SelfSignedGenerator");
        assert!(generator.supports_ca());
    }
}
