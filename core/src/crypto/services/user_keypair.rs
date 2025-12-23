//! User Keypair Service - High-level API for user key management

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::crypto::{
	errors::{CryptoError, CryptoResult},
	user_keys::{
		decrypt_private_key, encrypt_private_key, generate_salt, EncryptedPrivateKey,
		UserKeypair,
	},
};

/// Service for managing user X25519 keypairs
pub struct UserKeypairService;

impl UserKeypairService {
	/// Generate a new X25519 keypair for a user
	///
	/// # Returns
	/// A new random X25519 keypair
	pub fn generate_keypair() -> UserKeypair {
		UserKeypair::generate()
	}

	/// Encrypt a user's private key with their password
	///
	/// # Arguments
	/// * `keypair` - The user's keypair
	/// * `password` - The user's password
	///
	/// # Returns
	/// Encrypted private key data suitable for database storage
	///
	/// # Security
	/// Uses Argon2id to derive a KEK from the password, then encrypts the
	/// private key with AES-256-GCM.
	pub fn encrypt_private_key_with_password(
		keypair: &UserKeypair,
		password: &str,
	) -> CryptoResult<EncryptedPrivateKey> {
		let salt = generate_salt();
		encrypt_private_key(&keypair.private_key, password, &salt)
	}

	/// Decrypt a user's private key with their password
	///
	/// # Arguments
	/// * `encrypted` - The encrypted private key data
	/// * `password` - The user's password
	///
	/// # Returns
	/// The decrypted X25519 private key
	pub fn decrypt_private_key_with_password(
		encrypted: &EncryptedPrivateKey,
		password: &str,
	) -> CryptoResult<x25519_dalek::StaticSecret> {
		decrypt_private_key(encrypted, password)
	}

	/// Convert public key to base64 for database storage
	pub fn public_key_to_base64(public_key: &[u8; 32]) -> String {
		STANDARD.encode(public_key)
	}

	/// Parse public key from base64
	pub fn public_key_from_base64(encoded: &str) -> CryptoResult<[u8; 32]> {
		let bytes = STANDARD
			.decode(encoded)
			.map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

		if bytes.len() != 32 {
			return Err(CryptoError::InvalidKeySize {
				expected: 32,
				actual: bytes.len(),
			});
		}

		let mut key = [0u8; 32];
		key.copy_from_slice(&bytes);
		Ok(key)
	}

	/// Convert encrypted private key to base64 strings for database storage
	pub fn encrypted_private_key_to_base64(
		encrypted: &EncryptedPrivateKey,
	) -> (String, String, String) {
		(
			STANDARD.encode(&encrypted.ciphertext),
			STANDARD.encode(&encrypted.nonce),
			STANDARD.encode(&encrypted.password_salt),
		)
	}

	/// Parse encrypted private key from base64 strings
	pub fn encrypted_private_key_from_base64(
		ciphertext: &str,
		nonce: &str,
		salt: &str,
	) -> CryptoResult<EncryptedPrivateKey> {
		let ciphertext = STANDARD.decode(ciphertext).map_err(|e| {
			CryptoError::InvalidKeyFormat(format!("Invalid ciphertext: {}", e))
		})?;

		let nonce = STANDARD.decode(nonce).map_err(|e| {
			CryptoError::InvalidKeyFormat(format!("Invalid nonce: {}", e))
		})?;

		let password_salt = STANDARD
			.decode(salt)
			.map_err(|e| CryptoError::InvalidKeyFormat(format!("Invalid salt: {}", e)))?;

		Ok(EncryptedPrivateKey {
			ciphertext,
			nonce,
			password_salt,
		})
	}

	/// Re-encrypt a user's private key with a new password
	///
	/// This is used when a user changes their password.
	///
	/// # Arguments
	/// * `encrypted` - The current encrypted private key
	/// * `old_password` - The user's old password
	/// * `new_password` - The user's new password
	///
	/// # Returns
	/// New encrypted private key data
	pub fn reencrypt_private_key(
		encrypted: &EncryptedPrivateKey,
		old_password: &str,
		new_password: &str,
	) -> CryptoResult<EncryptedPrivateKey> {
		// Decrypt with old password
		let private_key = decrypt_private_key(encrypted, old_password)?;

		// Re-encrypt with new password
		let new_salt = generate_salt();
		encrypt_private_key(&private_key, new_password, &new_salt)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_keypair_generation() {
		let keypair = UserKeypairService::generate_keypair();
		assert_eq!(keypair.public_key_bytes().len(), 32);
		assert_eq!(keypair.private_key_bytes().len(), 32);
	}

	#[test]
	fn test_private_key_encryption_roundtrip() {
		let keypair = UserKeypairService::generate_keypair();
		let password = "test_password_123";

		let encrypted =
			UserKeypairService::encrypt_private_key_with_password(&keypair, password)
				.unwrap();
		let decrypted =
			UserKeypairService::decrypt_private_key_with_password(&encrypted, password)
				.unwrap();

		assert_eq!(keypair.private_key_bytes(), decrypted.to_bytes());
	}

	#[test]
	fn test_base64_roundtrip() {
		let keypair = UserKeypairService::generate_keypair();
		let public_key = keypair.public_key_bytes();

		let encoded = UserKeypairService::public_key_to_base64(&public_key);
		let decoded = UserKeypairService::public_key_from_base64(&encoded).unwrap();

		assert_eq!(public_key, decoded);
	}

	#[test]
	fn test_encrypted_private_key_base64_roundtrip() {
		let keypair = UserKeypairService::generate_keypair();
		let encrypted =
			UserKeypairService::encrypt_private_key_with_password(&keypair, "password")
				.unwrap();

		let (ct, nonce, salt) =
			UserKeypairService::encrypted_private_key_to_base64(&encrypted);
		let decoded =
			UserKeypairService::encrypted_private_key_from_base64(&ct, &nonce, &salt)
				.unwrap();

		assert_eq!(encrypted.ciphertext, decoded.ciphertext);
		assert_eq!(encrypted.nonce, decoded.nonce);
		assert_eq!(encrypted.password_salt, decoded.password_salt);
	}

	#[test]
	fn test_reencrypt_private_key() {
		let keypair = UserKeypairService::generate_keypair();
		let old_password = "old_password";
		let new_password = "new_password";

		let encrypted1 =
			UserKeypairService::encrypt_private_key_with_password(&keypair, old_password)
				.unwrap();

		let encrypted2 = UserKeypairService::reencrypt_private_key(
			&encrypted1,
			old_password,
			new_password,
		)
		.unwrap();

		// Should not decrypt with old password
		let result = UserKeypairService::decrypt_private_key_with_password(
			&encrypted2,
			old_password,
		);
		assert!(result.is_err());

		// Should decrypt with new password
		let decrypted = UserKeypairService::decrypt_private_key_with_password(
			&encrypted2,
			new_password,
		)
		.unwrap();
		assert_eq!(keypair.private_key_bytes(), decrypted.to_bytes());
	}
}
