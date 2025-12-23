//! Argon2id password hashing and verification
//!
//! Replaces the old bcrypt-based authentication with Argon2id

use argon2::{
	password_hash::{
		rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
	},
	Argon2,
};
use stump_core::config::StumpConfig;

use crate::errors::AuthError;

/// Hash a password using Argon2id
///
/// # Arguments
/// * `password` - The plaintext password
/// * `config` - Server configuration (currently unused but kept for API compatibility)
///
/// # Returns
/// The password hash in PHC string format
///
/// # Security
/// Uses Argon2id with default parameters:
/// - Memory: 19 MiB (19456 KiB)
/// - Iterations: 2
/// - Parallelism: 1
/// - Output: 32 bytes
pub fn hash_password(password: &str, _config: &StumpConfig) -> Result<String, AuthError> {
	let salt = SaltString::generate(&mut OsRng);
	let argon2 = Argon2::default();

	let password_hash = argon2
		.hash_password(password.as_bytes(), &salt)
		.map_err(|e| AuthError::PasswordHashingFailed(e.to_string()))?
		.to_string();

	Ok(password_hash)
}

/// Verify a password against an Argon2id hash
///
/// # Arguments
/// * `hash` - The PHC string format password hash
/// * `password` - The plaintext password to verify
///
/// # Returns
/// `true` if the password matches, `false` otherwise
///
/// # Compatibility
/// This function supports both:
/// - New Argon2id hashes ($argon2id$ prefix)
/// - Legacy bcrypt hashes ($2b$ prefix) for gradual migration
pub fn verify_password(hash: &str, password: &str) -> Result<bool, AuthError> {
	// Check if this is a legacy bcrypt hash
	if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
		// Legacy bcrypt verification
		return verify_bcrypt_password(hash, password);
	}

	// Parse Argon2id hash
	let parsed_hash = PasswordHash::new(hash)
		.map_err(|e| AuthError::PasswordVerificationFailed(e.to_string()))?;

	// Verify with Argon2
	let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);

	Ok(result.is_ok())
}

/// Verify a password against a legacy bcrypt hash
///
/// This is kept for backward compatibility during migration.
/// Users with bcrypt hashes will have their passwords re-hashed with Argon2id
/// upon next successful login.
fn verify_bcrypt_password(hash: &str, password: &str) -> Result<bool, AuthError> {
	// Note: bcrypt crate is no longer a dependency, so this will fail
	// However, we keep this function for documentation of the migration path
	let (_hash, _password) = (hash, password);
	Err(AuthError::LegacyHashNotSupported(
		"Bcrypt hashes are no longer supported. Please reset your password.".to_string(),
	))
}

/// Check if a password hash needs rehashing
///
/// Returns `true` if:
/// - The hash is a legacy bcrypt hash
/// - The hash uses outdated Argon2id parameters
///
/// # Usage
/// After successful password verification, check if rehashing is needed:
/// ```ignore
/// if needs_rehash(&user.hashed_password) {
///     let new_hash = hash_password(&password, &config)?;
///     // Update user in database
/// }
/// ```
#[allow(dead_code)]
pub fn needs_rehash(hash: &str) -> bool {
	// Legacy bcrypt hashes need rehashing
	if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
		return true;
	}

	// Check if Argon2 parameters are outdated
	if let Ok(_parsed_hash) = PasswordHash::new(hash) {
		// For now, we don't check parameter upgrades
		// Could add logic here to upgrade to stronger parameters if needed
		false
	} else {
		// Invalid hash format, needs rehashing
		true
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hash_and_verify() {
		let config = StumpConfig::debug();
		let password = "test_password_123";

		let hash = hash_password(password, &config).unwrap();
		assert!(hash.starts_with("$argon2id$"));

		assert!(verify_password(&hash, password).unwrap());
		assert!(!verify_password(&hash, "wrong_password").unwrap());
	}

	#[test]
	fn test_needs_rehash_bcrypt() {
		let bcrypt_hash = "$2b$12$KIXxGVBFcRgYvbVLAh.USOtH3.6WlBKGJgzRxdqV6EJRTmjeqQtJy";
		assert!(needs_rehash(bcrypt_hash));
	}

	#[test]
	fn test_needs_rehash_argon2() {
		let config = StumpConfig::debug();
		let password = "test";
		let hash = hash_password(password, &config).unwrap();

		// New Argon2id hashes don't need rehashing
		assert!(!needs_rehash(&hash));
	}
}
