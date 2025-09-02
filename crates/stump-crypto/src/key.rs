//! Key derivation module for generating master encryption keys from passwords

use argon2::{Argon2, Algorithm, Version, ParamsBuilder};
use argon2::password_hash::{PasswordHasher, PasswordVerifier, PasswordHash, SaltString};
use rand::RngCore;
use secrecy::SecretBox;
use tracing::{debug, error, trace};

use crate::{error::CryptoResult, CryptoError, KEY_SIZE, SALT_SIZE};

/// Master encryption key wrapper
pub type MasterKey = SecretBox<Vec<u8>>;

/// Parameters for key derivation
#[derive(Debug, Clone)]
pub struct KeyDerivationParams {
    /// Memory cost in KiB (default: 19456 = 19 MiB)
    pub memory_cost: u32,
    /// Time cost (iterations, default: 2)
    pub time_cost: u32,
    /// Parallelism (default: 1)
    pub parallelism: u32,
    /// Salt (must be 32 bytes)
    pub salt: [u8; SALT_SIZE],
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            memory_cost: 19456, // 19 MiB
            time_cost: 2,
            parallelism: 1,
            salt: [0u8; SALT_SIZE],
        }
    }
}

impl KeyDerivationParams {
    /// Create new params with a random salt
    pub fn new() -> Self {
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        
        Self {
            memory_cost: 19456, // 19 MiB
            time_cost: 2,
            parallelism: 1,
            salt,
        }
    }

    /// Create params with a specific salt (for verification)
    pub fn with_salt(salt: [u8; SALT_SIZE]) -> Self {
        Self {
            memory_cost: 19456,
            time_cost: 2,
            parallelism: 1,
            salt,
        }
    }
}

/// Derive master encryption key from password using Argon2id
pub fn derive_master_key(
    password: &str,
    params: &KeyDerivationParams,
) -> CryptoResult<MasterKey> {
    trace!("Starting key derivation with Argon2id");
    
    let argon2_params = ParamsBuilder::new()
        .m_cost(params.memory_cost)
        .t_cost(params.time_cost)
        .p_cost(params.parallelism)
        .output_len(KEY_SIZE)
        .build()
        .map_err(|e| {
            error!("Failed to build Argon2 params: {}", e);
            CryptoError::KeyDerivation(e.to_string())
        })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    debug!(
        memory_cost = params.memory_cost,
        time_cost = params.time_cost,
        "Deriving master key with Argon2id"
    );

    let mut output_key_material = vec![0u8; KEY_SIZE];
    argon2.hash_password_into(password.as_bytes(), &params.salt, &mut output_key_material)
        .map_err(|e| {
            error!("Argon2 key derivation failed: {}", e);
            CryptoError::KeyDerivation(e.to_string())
        })?;

    trace!("Key derivation completed successfully");
    Ok(SecretBox::from(Box::new(output_key_material)))
}

/// Generate a verification hash for password checking
/// This is separate from the encryption key derivation
pub fn generate_verification_hash(
    password: &str,
    salt: &[u8; SALT_SIZE],
) -> CryptoResult<String> {
    trace!("Generating password verification hash");
    
    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| {
            error!("Failed to encode salt: {}", e);
            CryptoError::KeyDerivation(e.to_string())
        })?;
    
    let hash_string = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| {
            error!("Password hash generation failed: {}", e);
            CryptoError::KeyDerivation(e.to_string())
        })?
        .to_string();

    trace!("Verification hash generated successfully");
    Ok(hash_string)
}

/// Verify a password against a stored hash
pub fn verify_password(password: &str, hash: &str) -> CryptoResult<bool> {
    trace!("Verifying password against stored hash");
    
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| {
            error!("Failed to parse password hash: {}", e);
            CryptoError::KeyDerivation(e.to_string())
        })?;
    
    let is_valid = Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok();

    if is_valid {
        debug!("Password verification successful");
    } else {
        debug!("Password verification failed");
    }

    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_key_derivation() {
        let params = KeyDerivationParams::new();
        let password = "test_password";
        
        let key1 = derive_master_key(password, &params).unwrap();
        let key2 = derive_master_key(password, &params).unwrap();
        
        // Same password and salt should produce same key
        assert_eq!(key1.expose_secret(), key2.expose_secret());
        assert_eq!(key1.expose_secret().len(), KEY_SIZE);
    }

    #[test]
    fn test_password_verification() {
        let salt = [1u8; SALT_SIZE];
        let password = "test_password";
        
        let hash = generate_verification_hash(password, &salt).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }
}
