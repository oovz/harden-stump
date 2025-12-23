//! User key management - X25519 keypairs and password-based encryption
//!
//! Each user has an asymmetric X25519 keypair:
//! - Public key: Stored in database plaintext
//! - Private key: Encrypted with KEK derived from user password

use chacha20poly1305::{
	aead::{Aead, AeadCore, KeyInit, OsRng},
	ChaCha20Poly1305, Nonce,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{
	errors::{CryptoError, CryptoResult},
	keys::derive_key_encryption_key,
	sizes::*,
};

/// User keypair for X25519-ECDH
#[derive(Clone)]
pub struct UserKeypair {
	/// Public key (32 bytes)
	pub public_key: PublicKey,
	/// Private key (32 bytes)
	pub private_key: StaticSecret,
}

impl UserKeypair {
	/// Generate a new random keypair
	pub fn generate() -> Self {
		let private_key = StaticSecret::random_from_rng(OsRng);
		let public_key = PublicKey::from(&private_key);

		Self {
			public_key,
			private_key,
		}
	}

	/// Get the public key bytes
	pub fn public_key_bytes(&self) -> [u8; X25519_KEY_SIZE] {
		self.public_key.to_bytes()
	}

	/// Get the private key bytes (use with extreme caution)
	pub fn private_key_bytes(&self) -> [u8; X25519_KEY_SIZE] {
		self.private_key.to_bytes()
	}
}

/// Encrypted private key for database storage
#[derive(Debug, Clone)]
pub struct EncryptedPrivateKey {
	/// Encrypted private key bytes
	pub ciphertext: Vec<u8>,
	/// Nonce used for ChaCha20-Poly1305
	pub nonce: Vec<u8>,
	/// Salt used for KEK derivation
	pub password_salt: Vec<u8>,
}

/// Encrypt a user's private key with their password
///
/// The private key is encrypted using ChaCha20-Poly1305 with a KEK derived
/// from the user's password via Argon2id.
///
/// # Arguments
/// * `private_key` - The X25519 private key to encrypt
/// * `password` - The user's password
/// * `salt` - Unique salt for this user (16 bytes)
///
/// # Returns
/// An `EncryptedPrivateKey` containing the ciphertext, nonce, and salt
pub fn encrypt_private_key(
	private_key: &StaticSecret,
	password: &str,
	salt: &[u8],
) -> CryptoResult<EncryptedPrivateKey> {
	if salt.len() != ARGON2_SALT_SIZE {
		return Err(CryptoError::InvalidKeySize {
			expected: ARGON2_SALT_SIZE,
			actual: salt.len(),
		});
	}

	// Derive KEK from password
	let kek = derive_key_encryption_key(password, salt)?;

	// Encrypt private key with ChaCha20-Poly1305
	let cipher = ChaCha20Poly1305::new(kek.expose_secret().into());
	let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

	let private_key_bytes = private_key.to_bytes();
	let ciphertext = cipher
		.encrypt(&nonce, private_key_bytes.as_ref())
		.map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

	Ok(EncryptedPrivateKey {
		ciphertext,
		nonce: nonce.to_vec(),
		password_salt: salt.to_vec(),
	})
}

/// Decrypt a user's private key with their password
///
/// # Arguments
/// * `encrypted` - The encrypted private key data
/// * `password` - The user's password
///
/// # Returns
/// The decrypted X25519 private key
pub fn decrypt_private_key(
	encrypted: &EncryptedPrivateKey,
	password: &str,
) -> CryptoResult<StaticSecret> {
	// Derive KEK from password using stored salt
	let kek = derive_key_encryption_key(password, &encrypted.password_salt)?;

	// Decrypt private key
	let cipher = ChaCha20Poly1305::new(kek.expose_secret().into());

	if encrypted.nonce.len() != CHACHA20_NONCE_SIZE {
		return Err(CryptoError::InvalidNonceSize {
			expected: CHACHA20_NONCE_SIZE,
			actual: encrypted.nonce.len(),
		});
	}

	#[allow(deprecated)]
	let nonce = Nonce::from_slice(&encrypted.nonce);

	let plaintext = cipher
		.decrypt(nonce, encrypted.ciphertext.as_ref())
		.map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

	if plaintext.len() != X25519_KEY_SIZE {
		return Err(CryptoError::InvalidKeySize {
			expected: X25519_KEY_SIZE,
			actual: plaintext.len(),
		});
	}

	let mut key_bytes = Zeroizing::new([0u8; X25519_KEY_SIZE]);
	key_bytes.copy_from_slice(&plaintext);

	Ok(StaticSecret::from(*key_bytes))
}

/// Generate a new salt for Argon2id
pub fn generate_salt() -> [u8; ARGON2_SALT_SIZE] {
	use rand::RngCore;
	let mut rng = OsRng;
	let mut salt = [0u8; ARGON2_SALT_SIZE];
	rng.fill_bytes(&mut salt);
	salt
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_keypair_generation() {
		let keypair = UserKeypair::generate();
		assert_eq!(keypair.public_key_bytes().len(), X25519_KEY_SIZE);
		assert_eq!(keypair.private_key_bytes().len(), X25519_KEY_SIZE);
	}

	#[test]
	fn test_private_key_encryption_roundtrip() {
		let keypair = UserKeypair::generate();
		let password = "test_password_123";
		let salt = generate_salt();

		// Encrypt
		let encrypted =
			encrypt_private_key(&keypair.private_key, password, &salt).unwrap();

		// Decrypt
		let decrypted = decrypt_private_key(&encrypted, password).unwrap();

		// Verify
		assert_eq!(keypair.private_key_bytes(), decrypted.to_bytes());
	}

	#[test]
	fn test_wrong_password_fails() {
		let keypair = UserKeypair::generate();
		let password = "correct_password";
		let salt = generate_salt();

		let encrypted =
			encrypt_private_key(&keypair.private_key, password, &salt).unwrap();

		// Try with wrong password
		let result = decrypt_private_key(&encrypted, "wrong_password");
		assert!(result.is_err());
	}

	#[test]
	fn test_different_salts_produce_different_ciphertexts() {
		let keypair = UserKeypair::generate();
		let password = "password";

		let salt1 = generate_salt();
		let salt2 = generate_salt();

		let encrypted1 =
			encrypt_private_key(&keypair.private_key, password, &salt1).unwrap();
		let encrypted2 =
			encrypt_private_key(&keypair.private_key, password, &salt2).unwrap();

		// Different salts should produce different ciphertexts
		assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);

		// But both should decrypt correctly
		let decrypted1 = decrypt_private_key(&encrypted1, password).unwrap();
		let decrypted2 = decrypt_private_key(&encrypted2, password).unwrap();

		assert_eq!(decrypted1.to_bytes(), decrypted2.to_bytes());
		assert_eq!(keypair.private_key_bytes(), decrypted1.to_bytes());
	}
}
