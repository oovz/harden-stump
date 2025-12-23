//! Key derivation and management
//!
//! This module implements the cryptographic key hierarchy:
//! SMK → LMK → DEK
//!
//! All key derivations use HKDF-SHA256 with domain separation.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::{
	domains::*,
	errors::{CryptoError, CryptoResult},
	sizes::*,
	smk::SystemMasterKey,
	types::*,
};

/// Derive Library Master Key (LMK) from System Master Key (SMK)
///
/// Uses HKDF-SHA256 with domain separation to derive a unique LMK per library.
///
/// # Arguments
/// * `smk` - The system master key (owner-held)
/// * `library_id` - Unique identifier for the library
///
/// # Returns
/// The derived LibraryMasterKey
///
/// # Security
/// The SMK is never stored. This derivation happens ephemerally during admin
/// operations when the owner provides the SMK.
pub fn derive_library_master_key(
	smk: &SystemMasterKey,
	library_id: &str,
) -> CryptoResult<LibraryMasterKey> {
	let hkdf = Hkdf::<Sha256>::new(Some(LMK_DOMAIN), smk.expose_secret());

	let info = format!("library:{}", library_id);
	let mut okm = Zeroizing::new([0u8; AES_256_KEY_SIZE]);

	hkdf.expand(info.as_bytes(), okm.as_mut())
		.map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

	Ok(LibraryMasterKey::from_bytes(*okm))
}

/// Derive Data Encryption Key (DEK) from Library Master Key (LMK)
///
/// Used to encrypt individual file contents with AES-256-GCM.
///
/// # Arguments
/// * `lmk` - The library master key
/// * `file_id` - Unique identifier for the file
///
/// # Returns
/// The derived DataEncryptionKey
pub fn derive_data_encryption_key(
	lmk: &LibraryMasterKey,
	file_id: &str,
) -> CryptoResult<DataEncryptionKey> {
	let hkdf = Hkdf::<Sha256>::new(Some(lmk.expose_secret()), DEK_DOMAIN);

	let info = format!("file:{}", file_id);
	let mut okm = Zeroizing::new([0u8; AES_256_KEY_SIZE]);

	hkdf.expand(info.as_bytes(), okm.as_mut())
		.map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

	Ok(DataEncryptionKey::from_bytes(*okm))
}

/// Derive Thumbnail Encryption Key (TEK) from Library Master Key (LMK)
///
/// Used to encrypt thumbnails with AES-256-GCM. Uses a separate `thumb:` info
/// label for key separation from file content.
///
/// # Arguments
/// * `lmk` - The library master key
/// * `media_id` - Unique identifier for the media item
///
/// # Returns
/// The derived DataEncryptionKey for thumbnail encryption
pub fn derive_thumbnail_encryption_key(
	lmk: &LibraryMasterKey,
	media_id: &str,
) -> CryptoResult<DataEncryptionKey> {
	let hkdf = Hkdf::<Sha256>::new(Some(lmk.expose_secret()), DEK_DOMAIN);

	let info = format!("thumb:{}", media_id);
	let mut okm = Zeroizing::new([0u8; AES_256_KEY_SIZE]);

	hkdf.expand(info.as_bytes(), okm.as_mut())
		.map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

	Ok(DataEncryptionKey::from_bytes(*okm))
}

/// Derive Key Encryption Key (KEK) from user password
///
/// Uses Argon2id to derive a KEK from the user's password for encrypting
/// their private X25519 key.
///
/// # Arguments
/// * `password` - The user's password
/// * `salt` - Salt for Argon2id (must be unique per user)
///
/// # Returns
/// The derived KeyEncryptionKey
///
/// # Security
/// Uses Argon2id with parameters tuned for security:
/// - Memory: 256 MiB
/// - Iterations: 3
/// - Parallelism: 4
pub fn derive_key_encryption_key(
	password: &str,
	salt: &[u8],
) -> CryptoResult<KeyEncryptionKey> {
	use argon2::{Algorithm, Argon2, Params, Version};

	if salt.len() != ARGON2_SALT_SIZE {
		return Err(CryptoError::InvalidKeySize {
			expected: ARGON2_SALT_SIZE,
			actual: salt.len(),
		});
	}

	// Configure Argon2id with recommended parameters
	let params = Params::new(
		crate::crypto::versions::argon2::MEMORY_COST,
		crate::crypto::versions::argon2::TIME_COST,
		crate::crypto::versions::argon2::PARALLELISM,
		Some(crate::crypto::versions::argon2::OUTPUT_LEN),
	)
	.map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

	let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

	// Use HKDF after Argon2 for domain separation
	let mut output = Zeroizing::new([0u8; AES_256_KEY_SIZE]);
	argon2
		.hash_password_into(password.as_bytes(), salt, output.as_mut())
		.map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

	Ok(KeyEncryptionKey::from_bytes(*output))
}

/// Wrap LMK for a user using X25519-ECDH + AES-256-GCM
///
/// This creates an encrypted copy of the LMK that only the user can decrypt
/// using their private X25519 key.
///
/// # Arguments
/// * `lmk` - The library master key to wrap
/// * `user_public_key` - The user's X25519 public key (32 bytes)
///
/// # Returns
/// An `EncryptedLibraryMasterKey` containing the ciphertext, ephemeral public key, and nonce
pub fn wrap_lmk_for_user(
	lmk: &LibraryMasterKey,
	user_public_key: &[u8],
) -> CryptoResult<EncryptedLibraryMasterKey> {
	use aes_gcm::{
		aead::{Aead, AeadCore, KeyInit, OsRng},
		Aes256Gcm,
	};
	use x25519_dalek::{PublicKey, StaticSecret};

	if user_public_key.len() != X25519_KEY_SIZE {
		return Err(CryptoError::InvalidKeySize {
			expected: X25519_KEY_SIZE,
			actual: user_public_key.len(),
		});
	}

	// Parse user's public key
	let user_pub_array: [u8; 32] = user_public_key
		.try_into()
		.map_err(|_| CryptoError::InvalidKeyFormat("Invalid X25519 public key".into()))?;
	let user_public = PublicKey::from(user_pub_array);

	// Generate ephemeral keypair for ECDH
	let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
	let ephemeral_public = PublicKey::from(&ephemeral_secret);

	// Perform ECDH
	let shared_secret = ephemeral_secret.diffie_hellman(&user_public);

	// Derive wrapping key from shared secret using HKDF
	let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
	let mut wrapping_key = Zeroizing::new([0u8; AES_256_KEY_SIZE]);

	hkdf.expand(LMK_WRAP_DOMAIN, wrapping_key.as_mut())
		.map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

	// Encrypt LMK with AES-256-GCM
	let cipher = Aes256Gcm::new(wrapping_key.as_ref().into());
	let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

	let ciphertext = cipher
		.encrypt(&nonce, lmk.expose_secret().as_ref())
		.map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

	Ok(EncryptedLibraryMasterKey {
		ciphertext,
		ephemeral_public: ephemeral_public.to_bytes().to_vec(),
		nonce: nonce.to_vec(),
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_lmk_derivation() {
		let smk = SystemMasterKey::generate();
		let lmk1 = derive_library_master_key(&smk, "lib123").unwrap();
		let lmk2 = derive_library_master_key(&smk, "lib123").unwrap();

		// Same library ID should produce same LMK
		assert_eq!(lmk1.expose_secret(), lmk2.expose_secret());

		// Different library ID should produce different LMK
		let lmk3 = derive_library_master_key(&smk, "lib456").unwrap();
		assert_ne!(lmk1.expose_secret(), lmk3.expose_secret());
	}

	#[test]
	fn test_dek_derivation() {
		let smk = SystemMasterKey::generate();
		let lmk = derive_library_master_key(&smk, "lib123").unwrap();

		let dek1 = derive_data_encryption_key(&lmk, "file1").unwrap();
		let dek2 = derive_data_encryption_key(&lmk, "file1").unwrap();

		// Same file ID should produce same DEK
		assert_eq!(dek1.expose_secret(), dek2.expose_secret());

		// Different file ID should produce different DEK
		let dek3 = derive_data_encryption_key(&lmk, "file2").unwrap();
		assert_ne!(dek1.expose_secret(), dek3.expose_secret());
	}

	#[test]
	fn test_kek_derivation() {
		let salt = [0u8; ARGON2_SALT_SIZE];
		let kek1 = derive_key_encryption_key("password123", &salt).unwrap();
		let kek2 = derive_key_encryption_key("password123", &salt).unwrap();

		// Same password and salt should produce same KEK
		assert_eq!(kek1.expose_secret(), kek2.expose_secret());

		// Different password should produce different KEK
		let kek3 = derive_key_encryption_key("different", &salt).unwrap();
		assert_ne!(kek1.expose_secret(), kek3.expose_secret());
	}
}
