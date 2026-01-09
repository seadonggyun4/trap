// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Encryption utilities for sensitive configuration data.
//!
//! This module provides AES-256-GCM encryption for sensitive configuration
//! values such as passwords, API keys, and JWT secrets.
//!
//! # Encryption Format
//!
//! Encrypted values use the following format in configuration files:
//!
//! ```text
//! ENC:<base64-encoded-ciphertext>
//! ```
//!
//! Where the ciphertext includes:
//! - 12-byte nonce (IV)
//! - Encrypted data
//! - 16-byte authentication tag
//!
//! # Key Management
//!
//! The master encryption key should be:
//! - 32 bytes (256 bits) for AES-256
//! - Stored securely (e.g., environment variable, secrets vault)
//! - Never committed to source control
//!
//! # Examples
//!
//! ```ignore
//! use trap_config::encryption::{Encryptor, generate_key};
//!
//! // Generate a new random key
//! let key = generate_key();
//!
//! // Create encryptor
//! let encryptor = Encryptor::new(key);
//!
//! // Encrypt a secret
//! let encrypted = encryptor.encrypt("my-secret-password").unwrap();
//! println!("Encrypted: ENC:{}", encrypted);
//!
//! // Decrypt the secret
//! let decrypted = encryptor.decrypt(&encrypted).unwrap();
//! assert_eq!(decrypted, "my-secret-password");
//! ```

#[cfg(feature = "encryption")]
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

#[cfg(feature = "encryption")]
use crate::error::{ConfigError, ConfigResult};

// =============================================================================
// Constants
// =============================================================================

/// The prefix for encrypted values in configuration files.
pub const ENCRYPTED_PREFIX: &str = "ENC:";

/// The length of the encryption key in bytes (256 bits).
pub const KEY_LENGTH: usize = 32;

/// The length of the nonce/IV in bytes (96 bits).
pub const NONCE_LENGTH: usize = 12;

/// The length of the authentication tag in bytes (128 bits).
pub const TAG_LENGTH: usize = 16;

// =============================================================================
// Encryptor
// =============================================================================

/// AES-256-GCM encryptor for sensitive configuration values.
///
/// This encryptor uses AES-256-GCM (Galois/Counter Mode) which provides
/// both confidentiality and authenticity.
#[cfg(feature = "encryption")]
#[derive(Clone)]
pub struct Encryptor {
    cipher: Aes256Gcm,
}

#[cfg(feature = "encryption")]
impl Encryptor {
    /// Creates a new encryptor with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte (256-bit) encryption key
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use trap_config::encryption::Encryptor;
    ///
    /// let key = [0u8; 32]; // Use a proper key in production
    /// let encryptor = Encryptor::new(key);
    /// ```
    pub fn new(key: [u8; KEY_LENGTH]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    /// Creates an encryptor from a base64-encoded key.
    ///
    /// # Arguments
    ///
    /// * `key_base64` - Base64-encoded 32-byte key
    ///
    /// # Returns
    ///
    /// * `Ok(Encryptor)` - Successfully created encryptor
    /// * `Err(ConfigError)` - If the key is invalid
    pub fn from_base64(key_base64: &str) -> ConfigResult<Self> {
        let key_bytes = decode_base64(key_base64).map_err(|e| {
            ConfigError::invalid_encryption_key(format!("invalid base64: {}", e))
        })?;

        if key_bytes.len() != KEY_LENGTH {
            return Err(ConfigError::invalid_encryption_key(format!(
                "expected {} bytes, got {}",
                KEY_LENGTH,
                key_bytes.len()
            )));
        }

        let mut key = [0u8; KEY_LENGTH];
        key.copy_from_slice(&key_bytes);
        Ok(Self::new(key))
    }

    /// Creates an encryptor from an environment variable.
    ///
    /// # Arguments
    ///
    /// * `env_var` - Name of the environment variable containing the base64 key
    ///
    /// # Returns
    ///
    /// * `Ok(Encryptor)` - Successfully created encryptor
    /// * `Err(ConfigError)` - If the environment variable is not set or invalid
    pub fn from_env(env_var: &str) -> ConfigResult<Self> {
        let key_base64 = std::env::var(env_var).map_err(|_| {
            ConfigError::env_var_not_found(env_var)
        })?;
        Self::from_base64(&key_base64)
    }

    /// Encrypts a plaintext string.
    ///
    /// The output is a base64-encoded string containing:
    /// - 12-byte nonce
    /// - Encrypted data
    /// - 16-byte authentication tag (included by GCM)
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The string to encrypt
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Base64-encoded ciphertext
    /// * `Err(ConfigError)` - If encryption fails
    pub fn encrypt(&self, plaintext: &str) -> ConfigResult<String> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| ConfigError::encryption_failed(e.to_string()))?;

        // Combine nonce and ciphertext
        let mut combined = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);

        Ok(encode_base64(&combined))
    }

    /// Decrypts a base64-encoded ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext_base64` - Base64-encoded ciphertext (without ENC: prefix)
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Decrypted plaintext
    /// * `Err(ConfigError)` - If decryption fails
    pub fn decrypt(&self, ciphertext_base64: &str) -> ConfigResult<String> {
        let combined = decode_base64(ciphertext_base64).map_err(|e| {
            ConfigError::decryption_failed(format!("invalid base64: {}", e))
        })?;

        if combined.len() < NONCE_LENGTH + TAG_LENGTH {
            return Err(ConfigError::decryption_failed(
                "ciphertext too short",
            ));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LENGTH);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| ConfigError::decryption_failed("authentication failed"))?;

        String::from_utf8(plaintext).map_err(|e| {
            ConfigError::decryption_failed(format!("invalid UTF-8: {}", e))
        })
    }

    /// Encrypts a value and returns it with the ENC: prefix.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The string to encrypt
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Encrypted value with ENC: prefix
    /// * `Err(ConfigError)` - If encryption fails
    pub fn encrypt_with_prefix(&self, plaintext: &str) -> ConfigResult<String> {
        let encrypted = self.encrypt(plaintext)?;
        Ok(format!("{}{}", ENCRYPTED_PREFIX, encrypted))
    }

    /// Decrypts a value that may or may not have the ENC: prefix.
    ///
    /// If the value doesn't have the ENC: prefix, it's returned as-is
    /// (assumed to be plaintext).
    ///
    /// # Arguments
    ///
    /// * `value` - The value to decrypt
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Decrypted or original value
    /// * `Err(ConfigError)` - If decryption fails
    pub fn decrypt_if_encrypted(&self, value: &str) -> ConfigResult<String> {
        if let Some(ciphertext) = value.strip_prefix(ENCRYPTED_PREFIX) {
            self.decrypt(ciphertext)
        } else {
            Ok(value.to_string())
        }
    }
}

#[cfg(feature = "encryption")]
impl std::fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encryptor")
            .field("cipher", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// Key Generation
// =============================================================================

/// Generates a random 256-bit encryption key.
///
/// Uses a cryptographically secure random number generator.
///
/// # Returns
///
/// A 32-byte random key suitable for AES-256.
#[cfg(feature = "encryption")]
pub fn generate_key() -> [u8; KEY_LENGTH] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut key = [0u8; KEY_LENGTH];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generates a random key and returns it as base64.
///
/// # Returns
///
/// Base64-encoded 32-byte key.
#[cfg(feature = "encryption")]
pub fn generate_key_base64() -> String {
    encode_base64(&generate_key())
}

// =============================================================================
// Base64 Encoding/Decoding
// =============================================================================

/// Encodes bytes to base64.
#[cfg(feature = "encryption")]
pub fn encode_base64(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

/// Decodes base64 to bytes.
#[cfg(feature = "encryption")]
pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD
        .decode(input.trim())
        .map_err(|e| e.to_string())
}

// =============================================================================
// Non-encryption feature stubs
// =============================================================================

/// Encodes bytes to base64 (stub for non-encryption feature).
#[cfg(not(feature = "encryption"))]
pub fn encode_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Decodes base64 to bytes (stub for non-encryption feature).
#[cfg(not(feature = "encryption"))]
pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim().trim_end_matches('=');
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for c in input.bytes() {
        let value = ALPHABET
            .iter()
            .position(|&b| b == c)
            .ok_or_else(|| format!("invalid base64 character: {}", c as char))?;

        buffer = (buffer << 6) | (value as u32);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(result)
}

// =============================================================================
// SecretValue Helper
// =============================================================================

/// Checks if a value is encrypted.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENCRYPTED_PREFIX)
}

/// Gets the encrypted payload (without the ENC: prefix).
pub fn get_encrypted_payload(value: &str) -> Option<&str> {
    value.strip_prefix(ENCRYPTED_PREFIX)
}

// =============================================================================
// Key Derivation (from password)
// =============================================================================

/// Derives an encryption key from a password using Argon2.
///
/// Note: This requires the `argon2` feature to be enabled in trap-core.
#[cfg(feature = "encryption")]
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> ConfigResult<[u8; KEY_LENGTH]> {
    use argon2::{
        password_hash::{PasswordHasher, SaltString},
        Argon2,
    };

    if salt.len() < 8 {
        return Err(ConfigError::invalid_encryption_key(
            "salt must be at least 8 bytes",
        ));
    }

    // Use the salt to create a SaltString
    let salt_b64 = encode_base64(salt);
    let salt_string = SaltString::from_b64(&salt_b64).map_err(|e| {
        ConfigError::invalid_encryption_key(format!("invalid salt: {}", e))
    })?;

    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| ConfigError::encryption_failed(e.to_string()))?;

    let hash_bytes = hash.hash.ok_or_else(|| {
        ConfigError::encryption_failed("failed to get hash output")
    })?;

    let hash_slice = hash_bytes.as_bytes();
    if hash_slice.len() < KEY_LENGTH {
        return Err(ConfigError::encryption_failed(
            "hash output too short",
        ));
    }

    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&hash_slice[..KEY_LENGTH]);
    Ok(key)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_encrypted() {
        assert!(is_encrypted("ENC:abc123"));
        assert!(!is_encrypted("plain-text"));
        assert!(!is_encrypted(""));
    }

    #[test]
    fn test_get_encrypted_payload() {
        assert_eq!(get_encrypted_payload("ENC:abc123"), Some("abc123"));
        assert_eq!(get_encrypted_payload("plain-text"), None);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = encode_base64(data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_empty() {
        let data = b"";
        let encoded = encode_base64(data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[cfg(feature = "encryption")]
    mod encryption_tests {
        use super::*;

        #[test]
        fn test_generate_key() {
            let key1 = generate_key();
            let key2 = generate_key();

            // Keys should be different (extremely high probability)
            assert_ne!(key1, key2);
            assert_eq!(key1.len(), KEY_LENGTH);
        }

        #[test]
        fn test_encrypt_decrypt_roundtrip() {
            let key = generate_key();
            let encryptor = Encryptor::new(key);

            let plaintext = "my-secret-password";
            let encrypted = encryptor.encrypt(plaintext).unwrap();
            let decrypted = encryptor.decrypt(&encrypted).unwrap();

            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_encrypt_with_prefix() {
            let key = generate_key();
            let encryptor = Encryptor::new(key);

            let plaintext = "secret123";
            let encrypted = encryptor.encrypt_with_prefix(plaintext).unwrap();

            assert!(encrypted.starts_with(ENCRYPTED_PREFIX));
        }

        #[test]
        fn test_decrypt_if_encrypted() {
            let key = generate_key();
            let encryptor = Encryptor::new(key);

            // Test with encrypted value
            let encrypted = encryptor.encrypt_with_prefix("secret").unwrap();
            let decrypted = encryptor.decrypt_if_encrypted(&encrypted).unwrap();
            assert_eq!(decrypted, "secret");

            // Test with plain value
            let plain = "not-encrypted";
            let result = encryptor.decrypt_if_encrypted(plain).unwrap();
            assert_eq!(result, plain);
        }

        #[test]
        fn test_from_base64() {
            let key = generate_key();
            let key_b64 = encode_base64(&key);

            let encryptor = Encryptor::from_base64(&key_b64).unwrap();

            // Test that it works
            let encrypted = encryptor.encrypt("test").unwrap();
            let decrypted = encryptor.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, "test");
        }

        #[test]
        fn test_invalid_key_length() {
            let short_key = encode_base64(&[0u8; 16]); // 16 bytes instead of 32
            let result = Encryptor::from_base64(&short_key);
            assert!(result.is_err());
        }

        #[test]
        fn test_tampered_ciphertext() {
            let key = generate_key();
            let encryptor = Encryptor::new(key);

            let encrypted = encryptor.encrypt("secret").unwrap();
            let mut tampered_bytes = decode_base64(&encrypted).unwrap();

            // Tamper with the ciphertext
            if let Some(byte) = tampered_bytes.last_mut() {
                *byte ^= 0xFF;
            }

            let tampered = encode_base64(&tampered_bytes);
            let result = encryptor.decrypt(&tampered);

            assert!(result.is_err());
        }

        #[test]
        fn test_different_keys() {
            let key1 = generate_key();
            let key2 = generate_key();

            let encryptor1 = Encryptor::new(key1);
            let encryptor2 = Encryptor::new(key2);

            let encrypted = encryptor1.encrypt("secret").unwrap();
            let result = encryptor2.decrypt(&encrypted);

            // Should fail because of wrong key
            assert!(result.is_err());
        }

        #[test]
        fn test_unicode() {
            let key = generate_key();
            let encryptor = Encryptor::new(key);

            let plaintext = "비밀번호123 🔐";
            let encrypted = encryptor.encrypt(plaintext).unwrap();
            let decrypted = encryptor.decrypt(&encrypted).unwrap();

            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_empty_string() {
            let key = generate_key();
            let encryptor = Encryptor::new(key);

            let plaintext = "";
            let encrypted = encryptor.encrypt(plaintext).unwrap();
            let decrypted = encryptor.decrypt(&encrypted).unwrap();

            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_long_string() {
            let key = generate_key();
            let encryptor = Encryptor::new(key);

            let plaintext = "a".repeat(10000);
            let encrypted = encryptor.encrypt(&plaintext).unwrap();
            let decrypted = encryptor.decrypt(&encrypted).unwrap();

            assert_eq!(decrypted, plaintext);
        }
    }
}
