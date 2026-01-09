// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Implementation of encryption-related commands.

use crate::cli::{Cli, DecryptArgs, EncryptArgs, GenKeyArgs};
use crate::error::{BinError, BinResult};

/// Executes the `gen-key` command to generate an encryption key.
pub fn gen_key(_cli: &Cli, _args: GenKeyArgs) -> BinResult<()> {
    #[cfg(feature = "encryption")]
    {
        use crate::cli::KeyFormat;
        use std::fs;

        let key = trap_config::generate_key();

        let output = match _args.format {
            KeyFormat::Base64 => trap_config::encode_base64(&key),
            KeyFormat::Hex => hex::encode(&key),
            KeyFormat::Raw => {
                // For raw format, we need to handle differently
                if let Some(path) = &_args.output {
                    fs::write(path, key).map_err(|e| {
                        BinError::Io(format!("Failed to write key file: {}", e))
                    })?;
                    eprintln!("Key written to: {}", path.display());
                    return Ok(());
                } else {
                    return Err(BinError::Configuration(
                        "Raw format requires --output file".to_string(),
                    ));
                }
            }
        };

        if let Some(path) = &_args.output {
            fs::write(path, &output).map_err(|e| {
                BinError::Io(format!("Failed to write key file: {}", e))
            })?;
            eprintln!("Key written to: {}", path.display());
        } else {
            println!("{}", output);
        }

        eprintln!();
        eprintln!("Store this key securely! You will need it to:");
        eprintln!("  - Encrypt secrets: trap encrypt <value> -k <key>");
        eprintln!("  - Set environment variable: export TRAP_ENCRYPTION_KEY=<key>");

        Ok(())
    }

    #[cfg(not(feature = "encryption"))]
    {
        let _ = _args;
        Err(BinError::Configuration(
            "Encryption feature is not enabled. Rebuild with --features encryption".to_string(),
        ))
    }
}

/// Executes the `encrypt` command to encrypt a value.
pub fn encrypt(_cli: &Cli, _args: EncryptArgs) -> BinResult<()> {
    #[cfg(feature = "encryption")]
    {
        use std::io::{self, Read};

        // Get the value to encrypt
        let value = if _args.stdin {
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .map_err(|e| BinError::Io(format!("Failed to read from stdin: {}", e)))?;
            input.trim().to_string()
        } else {
            _args.value.clone().ok_or_else(|| {
                BinError::Configuration("No value provided. Use --stdin or provide a value".to_string())
            })?
        };

        // Get the encryption key
        let key_bytes = get_encryption_key(&_args.key, &_args.key_file)?;

        // Create encryptor and encrypt
        let encryptor = trap_config::Encryptor::new(key_bytes);
        let encrypted = encryptor.encrypt_with_prefix(&value).map_err(|e| {
            BinError::Configuration(format!("Encryption failed: {}", e))
        })?;

        println!("{}", encrypted);

        eprintln!();
        eprintln!("Use this value in your configuration file:");
        eprintln!("  secret: \"{}\"", encrypted);

        Ok(())
    }

    #[cfg(not(feature = "encryption"))]
    {
        let _ = _args;
        Err(BinError::Configuration(
            "Encryption feature is not enabled. Rebuild with --features encryption".to_string(),
        ))
    }
}

/// Executes the `decrypt` command to decrypt a value.
pub fn decrypt(_cli: &Cli, _args: DecryptArgs) -> BinResult<()> {
    #[cfg(feature = "encryption")]
    {
        use std::io::{self, Read};

        // Get the value to decrypt
        let value = if _args.stdin {
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .map_err(|e| BinError::Io(format!("Failed to read from stdin: {}", e)))?;
            input.trim().to_string()
        } else {
            _args.value.clone().ok_or_else(|| {
                BinError::Configuration("No value provided. Use --stdin or provide a value".to_string())
            })?
        };

        // Get the encrypted payload (strip ENC: prefix if present)
        let encrypted_payload = if trap_config::is_encrypted(&value) {
            trap_config::get_encrypted_payload(&value).ok_or_else(|| {
                BinError::Configuration("Invalid encrypted value format".to_string())
            })?.to_string()
        } else {
            value
        };

        // Get the encryption key
        let key_bytes = get_encryption_key(&_args.key, &_args.key_file)?;

        // Create encryptor and decrypt
        let encryptor = trap_config::Encryptor::new(key_bytes);
        let decrypted = encryptor.decrypt(&encrypted_payload).map_err(|e| {
            BinError::Configuration(format!("Decryption failed: {}", e))
        })?;

        println!("{}", decrypted);

        Ok(())
    }

    #[cfg(not(feature = "encryption"))]
    {
        let _ = _args;
        Err(BinError::Configuration(
            "Encryption feature is not enabled. Rebuild with --features encryption".to_string(),
        ))
    }
}

/// Gets the encryption key from the provided source.
#[cfg(feature = "encryption")]
fn get_encryption_key(
    key: &Option<String>,
    key_file: &Option<std::path::PathBuf>,
) -> BinResult<[u8; trap_config::KEY_LENGTH]> {
    use std::fs;
    use trap_config::KEY_LENGTH;

    let key_string = if let Some(k) = key {
        k.clone()
    } else if let Some(path) = key_file {
        fs::read_to_string(path)
            .map_err(|e| BinError::Io(format!("Failed to read key file: {}", e)))?
            .trim()
            .to_string()
    } else {
        return Err(BinError::Configuration(
            "No encryption key provided. Use -k or --key-file, or set TRAP_ENCRYPTION_KEY".to_string(),
        ));
    };

    // Decode the key
    let key_bytes = trap_config::decode_base64(&key_string).map_err(|e| {
        BinError::Configuration(format!("Invalid key format (expected base64): {}", e))
    })?;

    // Verify key length
    if key_bytes.len() != KEY_LENGTH {
        return Err(BinError::Configuration(format!(
            "Invalid key length: expected {} bytes, got {}",
            KEY_LENGTH,
            key_bytes.len()
        )));
    }

    let mut key_array = [0u8; KEY_LENGTH];
    key_array.copy_from_slice(&key_bytes);

    Ok(key_array)
}

// hex encoding helper (simple implementation)
#[cfg(feature = "encryption")]
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
