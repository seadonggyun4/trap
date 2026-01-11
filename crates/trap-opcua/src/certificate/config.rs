// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Certificate configuration types and builders.
//!
//! This module provides configuration types for certificate generation and management.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::error::{CertConfigError, CertificateError, CertificateResult};

// =============================================================================
// KeyAlgorithm
// =============================================================================

/// Supported key algorithms for certificate generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyAlgorithm {
    /// RSA with specified key size.
    #[default]
    Rsa2048,
    /// RSA 3072-bit (higher security).
    Rsa3072,
    /// RSA 4096-bit (highest security, slower).
    Rsa4096,
    /// ECDSA with P-256 curve.
    EcdsaP256,
    /// ECDSA with P-384 curve.
    EcdsaP384,
}

impl KeyAlgorithm {
    /// Returns the key size in bits.
    pub fn key_size(&self) -> u32 {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::EcdsaP256 => 256,
            Self::EcdsaP384 => 384,
        }
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rsa2048 => "RSA-2048",
            Self::Rsa3072 => "RSA-3072",
            Self::Rsa4096 => "RSA-4096",
            Self::EcdsaP256 => "ECDSA-P256",
            Self::EcdsaP384 => "ECDSA-P384",
        }
    }

    /// Returns `true` if this is an RSA algorithm.
    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096)
    }

    /// Returns `true` if this is an ECDSA algorithm.
    pub fn is_ecdsa(&self) -> bool {
        matches!(self, Self::EcdsaP256 | Self::EcdsaP384)
    }

    /// Returns `true` if this algorithm is OPC UA compatible.
    ///
    /// OPC UA primarily uses RSA-2048 and RSA-4096 for security policies.
    pub fn is_opcua_compatible(&self) -> bool {
        // All listed algorithms are compatible with OPC UA
        true
    }
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// =============================================================================
// SignatureAlgorithm
// =============================================================================

/// Supported signature algorithms for certificate signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    /// SHA-256 with RSA.
    #[default]
    Sha256WithRsa,
    /// SHA-384 with RSA.
    Sha384WithRsa,
    /// SHA-512 with RSA.
    Sha512WithRsa,
    /// SHA-256 with ECDSA.
    Sha256WithEcdsa,
    /// SHA-384 with ECDSA.
    Sha384WithEcdsa,
}

impl SignatureAlgorithm {
    /// Returns the algorithm name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256WithRsa => "SHA256WithRSA",
            Self::Sha384WithRsa => "SHA384WithRSA",
            Self::Sha512WithRsa => "SHA512WithRSA",
            Self::Sha256WithEcdsa => "SHA256WithECDSA",
            Self::Sha384WithEcdsa => "SHA384WithECDSA",
        }
    }

    /// Returns the OID for this algorithm.
    pub fn oid(&self) -> &'static str {
        match self {
            Self::Sha256WithRsa => "1.2.840.113549.1.1.11",
            Self::Sha384WithRsa => "1.2.840.113549.1.1.12",
            Self::Sha512WithRsa => "1.2.840.113549.1.1.13",
            Self::Sha256WithEcdsa => "1.2.840.10045.4.3.2",
            Self::Sha384WithEcdsa => "1.2.840.10045.4.3.3",
        }
    }

    /// Returns `true` if this algorithm is compatible with the given key algorithm.
    pub fn is_compatible_with(&self, key_algorithm: KeyAlgorithm) -> bool {
        match self {
            Self::Sha256WithRsa | Self::Sha384WithRsa | Self::Sha512WithRsa => {
                key_algorithm.is_rsa()
            }
            Self::Sha256WithEcdsa | Self::Sha384WithEcdsa => key_algorithm.is_ecdsa(),
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// =============================================================================
// CertificateFormat
// =============================================================================

/// Certificate file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateFormat {
    /// DER (binary) format.
    #[default]
    Der,
    /// PEM (Base64) format.
    Pem,
    /// PKCS#12 (PFX) format - includes private key.
    Pkcs12,
}

impl CertificateFormat {
    /// Returns the typical file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Der => "der",
            Self::Pem => "pem",
            Self::Pkcs12 => "p12",
        }
    }

    /// Returns the MIME type for this format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Der => "application/x-x509-ca-cert",
            Self::Pem => "application/x-pem-file",
            Self::Pkcs12 => "application/x-pkcs12",
        }
    }

    /// Returns `true` if this format can contain a private key.
    pub fn can_contain_private_key(&self) -> bool {
        matches!(self, Self::Pem | Self::Pkcs12)
    }
}

impl std::fmt::Display for CertificateFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Der => write!(f, "DER"),
            Self::Pem => write!(f, "PEM"),
            Self::Pkcs12 => write!(f, "PKCS#12"),
        }
    }
}

// =============================================================================
// KeyUsage
// =============================================================================

/// X.509 Key Usage extension flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyUsage {
    /// Digital signature.
    pub digital_signature: bool,
    /// Non-repudiation.
    pub non_repudiation: bool,
    /// Key encipherment.
    pub key_encipherment: bool,
    /// Data encipherment.
    pub data_encipherment: bool,
    /// Key agreement.
    pub key_agreement: bool,
    /// Certificate signing (for CA certificates).
    pub key_cert_sign: bool,
    /// CRL signing (for CA certificates).
    pub crl_sign: bool,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self::opcua_client()
    }
}

impl KeyUsage {
    /// Creates key usage for OPC UA client certificates.
    pub fn opcua_client() -> Self {
        Self {
            digital_signature: true,
            non_repudiation: true,
            key_encipherment: true,
            data_encipherment: true,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
        }
    }

    /// Creates key usage for OPC UA server certificates.
    pub fn opcua_server() -> Self {
        Self::opcua_client()
    }

    /// Creates key usage for CA certificates.
    pub fn ca() -> Self {
        Self {
            digital_signature: true,
            non_repudiation: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: true,
            crl_sign: true,
        }
    }

    /// Returns `true` if this is a CA key usage.
    pub fn is_ca(&self) -> bool {
        self.key_cert_sign
    }

    /// Returns the key usage as a bitmask.
    pub fn as_bits(&self) -> u16 {
        let mut bits = 0u16;
        if self.digital_signature {
            bits |= 0x80;
        }
        if self.non_repudiation {
            bits |= 0x40;
        }
        if self.key_encipherment {
            bits |= 0x20;
        }
        if self.data_encipherment {
            bits |= 0x10;
        }
        if self.key_agreement {
            bits |= 0x08;
        }
        if self.key_cert_sign {
            bits |= 0x04;
        }
        if self.crl_sign {
            bits |= 0x02;
        }
        bits
    }
}

// =============================================================================
// ExtendedKeyUsage
// =============================================================================

/// X.509 Extended Key Usage extension.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExtendedKeyUsage {
    /// Server authentication (TLS server).
    pub server_auth: bool,
    /// Client authentication (TLS client).
    pub client_auth: bool,
    /// Code signing.
    pub code_signing: bool,
    /// Email protection.
    pub email_protection: bool,
    /// Time stamping.
    pub time_stamping: bool,
    /// OCSP signing.
    pub ocsp_signing: bool,
}

impl Default for ExtendedKeyUsage {
    fn default() -> Self {
        Self::opcua()
    }
}

impl ExtendedKeyUsage {
    /// Creates EKU for OPC UA certificates.
    pub fn opcua() -> Self {
        Self {
            server_auth: true,
            client_auth: true,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocsp_signing: false,
        }
    }

    /// Creates EKU for server-only certificates.
    pub fn server_only() -> Self {
        Self {
            server_auth: true,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocsp_signing: false,
        }
    }

    /// Creates EKU for client-only certificates.
    pub fn client_only() -> Self {
        Self {
            server_auth: false,
            client_auth: true,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocsp_signing: false,
        }
    }

    /// Returns the OIDs for enabled usages.
    pub fn oids(&self) -> Vec<&'static str> {
        let mut oids = Vec::new();
        if self.server_auth {
            oids.push("1.3.6.1.5.5.7.3.1");
        }
        if self.client_auth {
            oids.push("1.3.6.1.5.5.7.3.2");
        }
        if self.code_signing {
            oids.push("1.3.6.1.5.5.7.3.3");
        }
        if self.email_protection {
            oids.push("1.3.6.1.5.5.7.3.4");
        }
        if self.time_stamping {
            oids.push("1.3.6.1.5.5.7.3.8");
        }
        if self.ocsp_signing {
            oids.push("1.3.6.1.5.5.7.3.9");
        }
        oids
    }
}

// =============================================================================
// SubjectName
// =============================================================================

/// X.509 Subject/Issuer Distinguished Name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubjectName {
    /// Common Name (CN).
    pub common_name: String,
    /// Organization (O).
    pub organization: Option<String>,
    /// Organizational Unit (OU).
    pub organizational_unit: Option<String>,
    /// Locality (L).
    pub locality: Option<String>,
    /// State or Province (ST).
    pub state: Option<String>,
    /// Country (C) - 2 letter code.
    pub country: Option<String>,
}

impl SubjectName {
    /// Creates a new subject name with only common name.
    pub fn new(common_name: impl Into<String>) -> Self {
        Self {
            common_name: common_name.into(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state: None,
            country: None,
        }
    }

    /// Creates a subject name for TRAP gateway.
    pub fn trap_gateway() -> Self {
        Self {
            common_name: "TRAP Gateway".to_string(),
            organization: Some("Sylvex".to_string()),
            organizational_unit: None,
            locality: None,
            state: None,
            country: Some("KR".to_string()),
        }
    }

    /// Sets the organization.
    pub fn with_organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }

    /// Sets the organizational unit.
    pub fn with_organizational_unit(mut self, ou: impl Into<String>) -> Self {
        self.organizational_unit = Some(ou.into());
        self
    }

    /// Sets the locality.
    pub fn with_locality(mut self, locality: impl Into<String>) -> Self {
        self.locality = Some(locality.into());
        self
    }

    /// Sets the state.
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Sets the country code.
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }

    /// Returns the distinguished name as a string.
    pub fn to_dn_string(&self) -> String {
        let mut parts = vec![format!("CN={}", self.common_name)];

        if let Some(ref ou) = self.organizational_unit {
            parts.push(format!("OU={}", ou));
        }
        if let Some(ref o) = self.organization {
            parts.push(format!("O={}", o));
        }
        if let Some(ref l) = self.locality {
            parts.push(format!("L={}", l));
        }
        if let Some(ref st) = self.state {
            parts.push(format!("ST={}", st));
        }
        if let Some(ref c) = self.country {
            parts.push(format!("C={}", c));
        }

        parts.join(",")
    }

    /// Validates the subject name.
    pub fn validate(&self) -> CertificateResult<()> {
        if self.common_name.is_empty() {
            return Err(CertificateError::configuration(
                CertConfigError::missing_field("common_name"),
            ));
        }

        if self.common_name.len() > 64 {
            return Err(CertificateError::configuration(CertConfigError::invalid_value(
                "common_name",
                "must be 64 characters or less",
            )));
        }

        if let Some(ref country) = self.country {
            if country.len() != 2 {
                return Err(CertificateError::configuration(CertConfigError::invalid_value(
                    "country",
                    "must be a 2-letter ISO country code",
                )));
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for SubjectName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_dn_string())
    }
}

// =============================================================================
// SubjectAltName
// =============================================================================

/// Subject Alternative Name entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubjectAltName {
    /// DNS name.
    Dns(String),
    /// IP address.
    IpAddress(String),
    /// URI.
    Uri(String),
    /// Email address.
    Email(String),
}

impl SubjectAltName {
    /// Creates a DNS SAN.
    pub fn dns(name: impl Into<String>) -> Self {
        Self::Dns(name.into())
    }

    /// Creates an IP address SAN.
    pub fn ip(address: impl Into<String>) -> Self {
        Self::IpAddress(address.into())
    }

    /// Creates a URI SAN.
    pub fn uri(uri: impl Into<String>) -> Self {
        Self::Uri(uri.into())
    }

    /// Creates an email SAN.
    pub fn email(email: impl Into<String>) -> Self {
        Self::Email(email.into())
    }

    /// Returns the type name.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Dns(_) => "DNS",
            Self::IpAddress(_) => "IP",
            Self::Uri(_) => "URI",
            Self::Email(_) => "Email",
        }
    }

    /// Returns the value.
    pub fn value(&self) -> &str {
        match self {
            Self::Dns(v) | Self::IpAddress(v) | Self::Uri(v) | Self::Email(v) => v,
        }
    }
}

impl std::fmt::Display for SubjectAltName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.type_name(), self.value())
    }
}

// =============================================================================
// CertificateConfig
// =============================================================================

/// Configuration for certificate generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    /// Subject name.
    pub subject: SubjectName,
    /// Subject Alternative Names.
    pub subject_alt_names: Vec<SubjectAltName>,
    /// Application URI (required for OPC UA).
    pub application_uri: String,
    /// Key algorithm.
    pub key_algorithm: KeyAlgorithm,
    /// Signature algorithm.
    pub signature_algorithm: SignatureAlgorithm,
    /// Key usage.
    pub key_usage: KeyUsage,
    /// Extended key usage.
    pub extended_key_usage: ExtendedKeyUsage,
    /// Validity period in days.
    pub validity_days: u32,
    /// Certificate format for storage.
    pub format: CertificateFormat,
    /// Path to store certificate.
    pub certificate_path: Option<PathBuf>,
    /// Path to store private key.
    pub private_key_path: Option<PathBuf>,
    /// Whether this is a CA certificate.
    pub is_ca: bool,
    /// Maximum path length for CA certificates.
    pub path_length: Option<u32>,
    /// PKCS#12 password (if using PKCS#12 format).
    pub pkcs12_password: Option<String>,
    /// Whether to overwrite existing certificate.
    pub overwrite: bool,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            subject: SubjectName::trap_gateway(),
            subject_alt_names: vec![
                SubjectAltName::dns("localhost".to_string()),
                SubjectAltName::uri("urn:trap:gateway".to_string()),
            ],
            application_uri: "urn:trap:gateway".to_string(),
            key_algorithm: KeyAlgorithm::Rsa2048,
            signature_algorithm: SignatureAlgorithm::Sha256WithRsa,
            key_usage: KeyUsage::opcua_client(),
            extended_key_usage: ExtendedKeyUsage::opcua(),
            validity_days: 365,
            format: CertificateFormat::Der,
            certificate_path: None,
            private_key_path: None,
            is_ca: false,
            path_length: None,
            pkcs12_password: None,
            overwrite: false,
        }
    }
}

impl CertificateConfig {
    /// Creates a new certificate configuration builder.
    pub fn builder() -> CertificateConfigBuilder {
        CertificateConfigBuilder::new()
    }

    /// Validates the configuration.
    pub fn validate(&self) -> CertificateResult<()> {
        // Validate subject name
        self.subject.validate()?;

        // Validate algorithm compatibility
        if !self.signature_algorithm.is_compatible_with(self.key_algorithm) {
            return Err(CertificateError::configuration(
                CertConfigError::conflicting_options(format!(
                    "Signature algorithm {} is not compatible with key algorithm {}",
                    self.signature_algorithm, self.key_algorithm
                )),
            ));
        }

        // Validate validity period
        if self.validity_days == 0 {
            return Err(CertificateError::configuration(CertConfigError::invalid_value(
                "validity_days",
                "must be at least 1 day",
            )));
        }

        if self.validity_days > 3650 {
            // 10 years max
            return Err(CertificateError::configuration(CertConfigError::invalid_value(
                "validity_days",
                "must be 3650 days (10 years) or less",
            )));
        }

        // Validate application URI
        if self.application_uri.is_empty() {
            return Err(CertificateError::configuration(
                CertConfigError::missing_field("application_uri"),
            ));
        }

        // Validate CA settings
        if self.is_ca && !self.key_usage.is_ca() {
            return Err(CertificateError::configuration(
                CertConfigError::conflicting_options(
                    "CA certificate requires keyCertSign key usage".to_string(),
                ),
            ));
        }

        // Validate PKCS#12 password
        if self.format == CertificateFormat::Pkcs12 && self.pkcs12_password.is_none() {
            return Err(CertificateError::configuration(CertConfigError::missing_field(
                "pkcs12_password",
            )));
        }

        Ok(())
    }

    /// Returns the validity period as a Duration.
    pub fn validity_duration(&self) -> Duration {
        Duration::from_secs(self.validity_days as u64 * 24 * 60 * 60)
    }

    /// Returns the default certificate path based on common conventions.
    pub fn default_certificate_path(&self) -> PathBuf {
        let base_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("trap")
            .join("certs");

        base_dir.join(format!("client.{}", self.format.extension()))
    }

    /// Returns the default private key path based on common conventions.
    pub fn default_private_key_path(&self) -> PathBuf {
        let base_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("trap")
            .join("certs");

        base_dir.join("client.key")
    }

    /// Gets the certificate path, using default if not specified.
    pub fn get_certificate_path(&self) -> PathBuf {
        self.certificate_path
            .clone()
            .unwrap_or_else(|| self.default_certificate_path())
    }

    /// Gets the private key path, using default if not specified.
    pub fn get_private_key_path(&self) -> PathBuf {
        self.private_key_path
            .clone()
            .unwrap_or_else(|| self.default_private_key_path())
    }
}

// =============================================================================
// CertificateConfigBuilder
// =============================================================================

/// Builder for CertificateConfig.
#[derive(Debug, Clone, Default)]
pub struct CertificateConfigBuilder {
    config: CertificateConfig,
}

impl CertificateConfigBuilder {
    /// Creates a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: CertificateConfig::default(),
        }
    }

    /// Sets the subject name.
    pub fn subject(mut self, subject: SubjectName) -> Self {
        self.config.subject = subject;
        self
    }

    /// Sets the common name.
    pub fn common_name(mut self, name: impl Into<String>) -> Self {
        self.config.subject.common_name = name.into();
        self
    }

    /// Sets the organization.
    pub fn organization(mut self, org: impl Into<String>) -> Self {
        self.config.subject.organization = Some(org.into());
        self
    }

    /// Sets the country code.
    pub fn country(mut self, country: impl Into<String>) -> Self {
        self.config.subject.country = Some(country.into());
        self
    }

    /// Adds a Subject Alternative Name.
    pub fn add_san(mut self, san: SubjectAltName) -> Self {
        self.config.subject_alt_names.push(san);
        self
    }

    /// Adds a DNS name to Subject Alternative Names.
    pub fn add_dns(mut self, dns: impl Into<String>) -> Self {
        self.config.subject_alt_names.push(SubjectAltName::dns(dns));
        self
    }

    /// Adds an IP address to Subject Alternative Names.
    pub fn add_ip(mut self, ip: impl Into<String>) -> Self {
        self.config.subject_alt_names.push(SubjectAltName::ip(ip));
        self
    }

    /// Adds a URI to Subject Alternative Names.
    pub fn add_uri(mut self, uri: impl Into<String>) -> Self {
        self.config.subject_alt_names.push(SubjectAltName::uri(uri));
        self
    }

    /// Sets the application URI.
    pub fn application_uri(mut self, uri: impl Into<String>) -> Self {
        self.config.application_uri = uri.into();
        self
    }

    /// Sets the key algorithm.
    pub fn key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.config.key_algorithm = algorithm;
        self
    }

    /// Sets the signature algorithm.
    pub fn signature_algorithm(mut self, algorithm: SignatureAlgorithm) -> Self {
        self.config.signature_algorithm = algorithm;
        self
    }

    /// Sets the key usage.
    pub fn key_usage(mut self, usage: KeyUsage) -> Self {
        self.config.key_usage = usage;
        self
    }

    /// Sets the extended key usage.
    pub fn extended_key_usage(mut self, usage: ExtendedKeyUsage) -> Self {
        self.config.extended_key_usage = usage;
        self
    }

    /// Sets the validity period in days.
    pub fn validity_days(mut self, days: u32) -> Self {
        self.config.validity_days = days;
        self
    }

    /// Sets the certificate format.
    pub fn format(mut self, format: CertificateFormat) -> Self {
        self.config.format = format;
        self
    }

    /// Sets the certificate path.
    pub fn certificate_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.certificate_path = Some(path.into());
        self
    }

    /// Sets the private key path.
    pub fn private_key_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.private_key_path = Some(path.into());
        self
    }

    /// Sets whether this is a CA certificate.
    pub fn is_ca(mut self, is_ca: bool) -> Self {
        self.config.is_ca = is_ca;
        if is_ca {
            self.config.key_usage = KeyUsage::ca();
        }
        self
    }

    /// Sets the CA path length.
    pub fn path_length(mut self, length: u32) -> Self {
        self.config.path_length = Some(length);
        self
    }

    /// Sets the PKCS#12 password.
    pub fn pkcs12_password(mut self, password: impl Into<String>) -> Self {
        self.config.pkcs12_password = Some(password.into());
        self
    }

    /// Sets whether to overwrite existing certificate.
    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.config.overwrite = overwrite;
        self
    }

    /// Builds the configuration with validation.
    pub fn build(self) -> CertificateResult<CertificateConfig> {
        self.config.validate()?;
        Ok(self.config)
    }

    /// Builds the configuration without validation.
    pub fn build_unchecked(self) -> CertificateConfig {
        self.config
    }
}

// =============================================================================
// StoreConfig
// =============================================================================

/// Configuration for certificate storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Base directory for certificates.
    pub base_dir: PathBuf,
    /// Directory for own certificates.
    pub own_dir: PathBuf,
    /// Directory for trusted certificates.
    pub trusted_dir: PathBuf,
    /// Directory for rejected certificates.
    pub rejected_dir: PathBuf,
    /// Directory for issuer certificates.
    pub issuers_dir: PathBuf,
    /// Whether to create directories if they don't exist.
    pub create_dirs: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        let base_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("trap")
            .join("pki");

        Self {
            own_dir: base_dir.join("own"),
            trusted_dir: base_dir.join("trusted"),
            rejected_dir: base_dir.join("rejected"),
            issuers_dir: base_dir.join("issuers"),
            base_dir,
            create_dirs: true,
        }
    }
}

impl StoreConfig {
    /// Creates a new store config with custom base directory.
    pub fn with_base_dir(base_dir: impl Into<PathBuf>) -> Self {
        let base = base_dir.into();
        Self {
            own_dir: base.join("own"),
            trusted_dir: base.join("trusted"),
            rejected_dir: base.join("rejected"),
            issuers_dir: base.join("issuers"),
            base_dir: base,
            create_dirs: true,
        }
    }

    /// Returns all directory paths.
    pub fn all_dirs(&self) -> Vec<&PathBuf> {
        vec![
            &self.base_dir,
            &self.own_dir,
            &self.trusted_dir,
            &self.rejected_dir,
            &self.issuers_dir,
        ]
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_algorithm() {
        assert_eq!(KeyAlgorithm::Rsa2048.key_size(), 2048);
        assert!(KeyAlgorithm::Rsa2048.is_rsa());
        assert!(!KeyAlgorithm::Rsa2048.is_ecdsa());
        assert!(KeyAlgorithm::EcdsaP256.is_ecdsa());
    }

    #[test]
    fn test_signature_algorithm_compatibility() {
        assert!(SignatureAlgorithm::Sha256WithRsa.is_compatible_with(KeyAlgorithm::Rsa2048));
        assert!(!SignatureAlgorithm::Sha256WithRsa.is_compatible_with(KeyAlgorithm::EcdsaP256));
        assert!(SignatureAlgorithm::Sha256WithEcdsa.is_compatible_with(KeyAlgorithm::EcdsaP256));
    }

    #[test]
    fn test_subject_name() {
        let subject = SubjectName::new("Test CN")
            .with_organization("Test Org")
            .with_country("US");

        assert!(subject.validate().is_ok());
        assert!(subject.to_dn_string().contains("CN=Test CN"));
        assert!(subject.to_dn_string().contains("O=Test Org"));
    }

    #[test]
    fn test_subject_name_validation() {
        let empty = SubjectName::new("");
        assert!(empty.validate().is_err());

        let long = SubjectName::new("A".repeat(65));
        assert!(long.validate().is_err());

        let bad_country = SubjectName::new("Test").with_country("USA");
        assert!(bad_country.validate().is_err());
    }

    #[test]
    fn test_config_builder() {
        let config = CertificateConfig::builder()
            .common_name("Test")
            .organization("Test Org")
            .application_uri("urn:test:app")
            .validity_days(365)
            .build()
            .unwrap();

        assert_eq!(config.subject.common_name, "Test");
        assert_eq!(config.validity_days, 365);
    }

    #[test]
    fn test_config_validation_invalid_algorithm() {
        let result = CertificateConfig::builder()
            .common_name("Test")
            .application_uri("urn:test:app")
            .key_algorithm(KeyAlgorithm::Rsa2048)
            .signature_algorithm(SignatureAlgorithm::Sha256WithEcdsa)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_key_usage_bits() {
        let usage = KeyUsage::opcua_client();
        assert!(usage.digital_signature);
        assert!(usage.key_encipherment);
        assert!(!usage.key_cert_sign);
        assert!(usage.as_bits() > 0);
    }

    #[test]
    fn test_extended_key_usage_oids() {
        let eku = ExtendedKeyUsage::opcua();
        let oids = eku.oids();
        assert!(oids.contains(&"1.3.6.1.5.5.7.3.1")); // serverAuth
        assert!(oids.contains(&"1.3.6.1.5.5.7.3.2")); // clientAuth
    }

    #[test]
    fn test_san() {
        let san = SubjectAltName::dns("example.com");
        assert_eq!(san.type_name(), "DNS");
        assert_eq!(san.value(), "example.com");
    }

    #[test]
    fn test_store_config() {
        let config = StoreConfig::default();
        assert!(config.base_dir.to_string_lossy().contains("trap"));
        assert_eq!(config.all_dirs().len(), 5);
    }
}
