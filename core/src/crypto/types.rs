//! Cryptographic type definitions with secure memory handling
//!
//! This module defines type-safe wrappers for cryptographic keys using the
//! `secrecy` and `zeroize` crates to ensure keys are properly protected in memory.

use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{
	errors::{CryptoError, CryptoResult},
	sizes::*,
};

/// Library Master Key (LMK) - Derived per-library from SMK
///
/// Used to derive file-specific keys (DEK, MEK, FEK) for a secure library.
#[derive(Clone)]
pub struct LibraryMasterKey(Secret<[u8; AES_256_KEY_SIZE]>);

impl LibraryMasterKey {
	pub fn from_bytes(mut bytes: [u8; AES_256_KEY_SIZE]) -> Self {
		let key = Self(Secret::new(bytes));
		bytes.zeroize();
		key
	}

	pub fn expose_secret(&self) -> &[u8; AES_256_KEY_SIZE] {
		self.0.expose_secret()
	}

	pub fn from_slice(bytes: &[u8]) -> CryptoResult<Self> {
		if bytes.len() != AES_256_KEY_SIZE {
			return Err(CryptoError::InvalidKeySize {
				expected: AES_256_KEY_SIZE,
				actual: bytes.len(),
			});
		}

		let mut key_bytes = [0u8; AES_256_KEY_SIZE];
		key_bytes.copy_from_slice(bytes);
		Ok(Self::from_bytes(key_bytes))
	}
}

/// Data Encryption Key (DEK) - Derived per-file from LMK
///
/// Used with AES-256-GCM to encrypt file contents
#[derive(Clone)]
pub struct DataEncryptionKey(Secret<[u8; AES_256_KEY_SIZE]>);

impl DataEncryptionKey {
	pub fn from_bytes(mut bytes: [u8; AES_256_KEY_SIZE]) -> Self {
		let key = Self(Secret::new(bytes));
		bytes.zeroize();
		key
	}

	pub fn expose_secret(&self) -> &[u8; AES_256_KEY_SIZE] {
		self.0.expose_secret()
	}
}

/// Key Encryption Key (KEK) - Derived from user password
///
/// Used to encrypt user's private X25519 key
#[derive(Clone)]
pub struct KeyEncryptionKey(Secret<[u8; AES_256_KEY_SIZE]>);

impl KeyEncryptionKey {
	pub fn from_bytes(mut bytes: [u8; AES_256_KEY_SIZE]) -> Self {
		let key = Self(Secret::new(bytes));
		bytes.zeroize();
		key
	}

	pub fn expose_secret(&self) -> &[u8; AES_256_KEY_SIZE] {
		self.0.expose_secret()
	}
}

/// Encrypted LMK wrapper for database storage
///
/// Contains the encrypted LMK and associated metadata needed for decryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedLibraryMasterKey {
	/// Encrypted LMK bytes
	pub ciphertext: Vec<u8>,
	/// Ephemeral public key used for ECDH
	pub ephemeral_public: Vec<u8>,
	/// Nonce used for AES-256-GCM
	pub nonce: Vec<u8>,
}

/// Nonce for AES-GCM encryption
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct AesGcmNonce([u8; AES_GCM_NONCE_SIZE]);

impl AesGcmNonce {
	pub fn generate() -> Self {
		use rand::RngCore;
		let mut rng = rand::rngs::OsRng;
		let mut bytes = [0u8; AES_GCM_NONCE_SIZE];
		rng.fill_bytes(&mut bytes);
		Self(bytes)
	}

	pub fn from_slice(bytes: &[u8]) -> CryptoResult<Self> {
		if bytes.len() != AES_GCM_NONCE_SIZE {
			return Err(CryptoError::InvalidNonceSize {
				expected: AES_GCM_NONCE_SIZE,
				actual: bytes.len(),
			});
		}

		let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
		nonce_bytes.copy_from_slice(bytes);
		Ok(Self(nonce_bytes))
	}

	pub fn as_slice(&self) -> &[u8] {
		&self.0
	}

	pub fn to_vec(&self) -> Vec<u8> {
		self.0.to_vec()
	}

	pub fn to_base64(&self) -> String {
		use base64::{engine::general_purpose::STANDARD, Engine};
		STANDARD.encode(self.0)
	}
}

/// Authentication tag from AES-GCM
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct AesGcmTag([u8; AES_GCM_TAG_SIZE]);

impl AesGcmTag {
	pub fn from_slice(bytes: &[u8]) -> CryptoResult<Self> {
		if bytes.len() != AES_GCM_TAG_SIZE {
			return Err(CryptoError::InvalidKeySize {
				expected: AES_GCM_TAG_SIZE,
				actual: bytes.len(),
			});
		}

		let mut tag_bytes = [0u8; AES_GCM_TAG_SIZE];
		tag_bytes.copy_from_slice(bytes);
		Ok(Self(tag_bytes))
	}

	pub fn as_slice(&self) -> &[u8] {
		&self.0
	}

	pub fn to_vec(&self) -> Vec<u8> {
		self.0.to_vec()
	}

	pub fn to_base64(&self) -> String {
		use base64::{engine::general_purpose::STANDARD, Engine};
		STANDARD.encode(self.0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// Note: SystemMasterKey tests moved to smk.rs

	#[test]
	fn test_nonce_generation() {
		let nonce = AesGcmNonce::generate();
		assert_eq!(nonce.as_slice().len(), AES_GCM_NONCE_SIZE);
	}
}
