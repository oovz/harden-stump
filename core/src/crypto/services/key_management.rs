//! Key Management Service - SMK and LMK operations

use crate::crypto::{
	errors::{CryptoError, CryptoResult},
	keys::{derive_library_master_key, wrap_lmk_for_user},
	smk::SystemMasterKey,
	types::{EncryptedLibraryMasterKey, LibraryMasterKey},
};

/// Service for managing System Master Key and Library Master Key operations
pub struct KeyManagementService;

impl KeyManagementService {
	/// Derive a Library Master Key (LMK) from the System Master Key (SMK)
	///
	/// # Arguments
	/// * `smk` - The system master key (owner-provided, never stored)
	/// * `library_id` - Unique identifier for the library
	///
	/// # Returns
	/// The derived LMK for this library
	///
	/// # Security
	/// The SMK is ephemeral and must be provided by the server owner for this operation.
	/// The LMK is not stored directly but wrapped for each user with access.
	pub fn derive_lmk(
		smk: &SystemMasterKey,
		library_id: &str,
	) -> CryptoResult<LibraryMasterKey> {
		derive_library_master_key(smk, library_id)
	}

	/// Wrap an LMK for a specific user
	///
	/// # Arguments
	/// * `lmk` - The library master key to wrap
	/// * `user_public_key` - The user's X25519 public key (32 bytes)
	///
	/// # Returns
	/// An encrypted LMK that can only be decrypted by the user's private key
	///
	/// # Security
	/// Uses X25519-ECDH for key agreement, then AES-256-GCM for encryption.
	/// Each wrap creates a new ephemeral keypair for forward secrecy.
	pub fn wrap_lmk_for_user(
		lmk: &LibraryMasterKey,
		user_public_key: &[u8],
	) -> CryptoResult<EncryptedLibraryMasterKey> {
		wrap_lmk_for_user(lmk, user_public_key)
	}

	/// Generate HMAC verification tag for SMK validation
	///
	/// # Arguments
	/// * `lmk` - The library master key
	/// * `library_id` - The library ID
	///
	/// # Returns
	/// HMAC-SHA256 tag bytes
	pub fn generate_verification_tag(
		lmk: &LibraryMasterKey,
		library_id: &str,
	) -> CryptoResult<Vec<u8>> {
		use hmac::{Hmac, Mac};
		use sha2::Sha256;

		type HmacSha256 = Hmac<Sha256>;

		let mut mac = HmacSha256::new_from_slice(lmk.expose_secret()).map_err(|_| {
			CryptoError::InvalidKeySize {
				expected: 32,
				actual: lmk.expose_secret().len(),
			}
		})?;
		mac.update(library_id.as_bytes());
		Ok(mac.finalize().into_bytes().to_vec())
	}

	/// Unwrap an LMK using a user's private key
	///
	/// # Arguments
	/// * `encrypted_lmk` - The encrypted LMK data
	/// * `user_private_key` - The user's X25519 private key (32 bytes)
	///
	/// # Returns
	/// The decrypted LMK
	///
	/// # Security
	/// Performs ECDH with the ephemeral public key to derive the decryption key.
	pub fn unwrap_lmk(
		encrypted_lmk: &EncryptedLibraryMasterKey,
		user_private_key: &[u8],
	) -> CryptoResult<LibraryMasterKey> {
		use aes_gcm::{
			aead::{Aead, KeyInit},
			Aes256Gcm, Nonce,
		};
		use hkdf::Hkdf;
		use sha2::Sha256;
		use x25519_dalek::{PublicKey, StaticSecret};
		use zeroize::Zeroizing;

		use crate::crypto::{domains::LMK_WRAP_DOMAIN, sizes::*};

		// Parse user's private key
		if user_private_key.len() != X25519_KEY_SIZE {
			return Err(CryptoError::InvalidKeySize {
				expected: X25519_KEY_SIZE,
				actual: user_private_key.len(),
			});
		}

		let mut private_key_bytes = Zeroizing::new([0u8; X25519_KEY_SIZE]);
		private_key_bytes.copy_from_slice(user_private_key);
		let user_private = StaticSecret::from(*private_key_bytes);

		// Parse ephemeral public key
		if encrypted_lmk.ephemeral_public.len() != X25519_KEY_SIZE {
			return Err(CryptoError::InvalidKeySize {
				expected: X25519_KEY_SIZE,
				actual: encrypted_lmk.ephemeral_public.len(),
			});
		}

		let ephemeral_pub_array: [u8; 32] = encrypted_lmk
			.ephemeral_public
			.as_slice()
			.try_into()
			.map_err(|_| {
				CryptoError::InvalidKeyFormat("Invalid ephemeral public key".into())
			})?;
		let ephemeral_public = PublicKey::from(ephemeral_pub_array);

		// Perform ECDH
		let shared_secret = user_private.diffie_hellman(&ephemeral_public);

		// Derive wrapping key from shared secret
		let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
		let mut wrapping_key = Zeroizing::new([0u8; AES_256_KEY_SIZE]);

		hkdf.expand(LMK_WRAP_DOMAIN, wrapping_key.as_mut())
			.map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

		// Decrypt LMK
		let cipher = Aes256Gcm::new(wrapping_key.as_ref().into());

		if encrypted_lmk.nonce.len() != AES_GCM_NONCE_SIZE {
			return Err(CryptoError::InvalidNonceSize {
				expected: AES_GCM_NONCE_SIZE,
				actual: encrypted_lmk.nonce.len(),
			});
		}

		#[allow(deprecated)]
		let nonce = Nonce::from_slice(&encrypted_lmk.nonce);

		let plaintext = cipher
			.decrypt(nonce, encrypted_lmk.ciphertext.as_ref())
			.map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

		if plaintext.len() != AES_256_KEY_SIZE {
			return Err(CryptoError::InvalidKeySize {
				expected: AES_256_KEY_SIZE,
				actual: plaintext.len(),
			});
		}

		let mut lmk_bytes = Zeroizing::new([0u8; AES_256_KEY_SIZE]);
		lmk_bytes.copy_from_slice(&plaintext);

		Ok(LibraryMasterKey::from_bytes(*lmk_bytes))
	}

	/// Validate that an SMK is correct for a specific library
	///
	/// This method derives the LMK from the provided SMK and validates it
	/// by comparing an HMAC-SHA256(LMK, `library_id`) verification tag
	/// against the stored `LibraryEncryptionMetadata.verification_tag` row
	/// for that library.
	///
	/// # Arguments
	/// * `db` - Database client
	/// * `smk` - The system master key to validate
	/// * `library_id` - The library ID to validate against
	///
	/// # Returns
	/// Ok(()) if the SMK is valid for this library
	/// Err if the SMK is invalid or library doesn't exist
	///
	/// # Security
	/// This validates the SMK without exposing any key material. It uses
	/// constant-time comparison where possible and implements the contract
	/// described in `specs/001-secure-libraries/spec.md` FR-012
	/// (`invalid_smk` error posture).
	pub async fn validate_smk_for_library(
		db: &crate::prisma::PrismaClient,
		smk: &SystemMasterKey,
		library_id: &str,
	) -> CryptoResult<()> {
		use crate::prisma::{library, library_encryption_metadata};

		// Derive LMK from SMK. This ensures the provided SMK has the correct
		// format/entropy for this library ID without persisting any secrets.
		let derived_lmk = Self::derive_lmk(smk, library_id)?;

		// Fetch library and ensure it exists and is marked secure.
		let library = db
			.library()
			.find_unique(library::id::equals(library_id.to_string()))
			.exec()
			.await
			.map_err(|e| CryptoError::DatabaseError(e.to_string()))?
			.ok_or_else(|| CryptoError::LibraryNotFound(library_id.to_string()))?;

		if !library.is_secure {
			return Err(CryptoError::InvalidOperation(
				"Cannot validate SMK for non-secure library".to_string(),
			));
		}

		let metadata = db
			.library_encryption_metadata()
			.find_unique(library_encryption_metadata::library_id::equals(
				library_id.to_string(),
			))
			.exec()
			.await
			.map_err(|e| CryptoError::DatabaseError(e.to_string()))?
			.ok_or_else(|| {
				CryptoError::InvalidKey("Missing SMK verification metadata".to_string())
			})?;

		let expected_tag = Self::generate_verification_tag(&derived_lmk, library_id)?;

		if metadata.verification_tag.len() != expected_tag.len() {
			return Err(CryptoError::InvalidKey(
				"SMK verification failed".to_string(),
			));
		}

		let mut diff = 0u8;
		for (a, b) in metadata.verification_tag.iter().zip(expected_tag.iter()) {
			diff |= a ^ b;
		}

		if diff != 0 {
			return Err(CryptoError::InvalidKey(
				"SMK verification failed".to_string(),
			));
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::user_keys::UserKeypair;

	#[test]
	fn test_lmk_wrap_unwrap_roundtrip() {
		let smk = SystemMasterKey::generate();
		let lmk = KeyManagementService::derive_lmk(&smk, "test-library").unwrap();

		let user_keypair = UserKeypair::generate();
		let user_public = user_keypair.public_key_bytes();

		// Wrap LMK for user
		let encrypted_lmk =
			KeyManagementService::wrap_lmk_for_user(&lmk, &user_public).unwrap();

		// Unwrap LMK with user's private key
		let user_private = user_keypair.private_key_bytes();
		let unwrapped_lmk =
			KeyManagementService::unwrap_lmk(&encrypted_lmk, &user_private).unwrap();

		// Verify LMKs match
		assert_eq!(lmk.expose_secret(), unwrapped_lmk.expose_secret());
	}

	#[test]
	fn test_wrong_private_key_fails() {
		let smk = SystemMasterKey::generate();
		let lmk = KeyManagementService::derive_lmk(&smk, "test-library").unwrap();

		let user1 = UserKeypair::generate();
		let user2 = UserKeypair::generate();

		// Wrap for user1
		let encrypted_lmk =
			KeyManagementService::wrap_lmk_for_user(&lmk, &user1.public_key_bytes())
				.unwrap();

		// Try to unwrap with user2's private key
		let result =
			KeyManagementService::unwrap_lmk(&encrypted_lmk, &user2.private_key_bytes());
		assert!(result.is_err());
	}

	#[test]
	fn test_verification_tag_deterministic_for_same_lmk_and_library() {
		let smk = SystemMasterKey::generate();
		let lmk = KeyManagementService::derive_lmk(&smk, "lib-deterministic").unwrap();

		let tag1 =
			KeyManagementService::generate_verification_tag(&lmk, "lib-deterministic")
				.unwrap();
		let tag2 =
			KeyManagementService::generate_verification_tag(&lmk, "lib-deterministic")
				.unwrap();

		assert_eq!(tag1, tag2);
	}

	#[test]
	fn test_verification_tag_differs_for_different_library_ids() {
		let smk = SystemMasterKey::generate();
		let lmk = KeyManagementService::derive_lmk(&smk, "lib-a").unwrap();

		let tag_a =
			KeyManagementService::generate_verification_tag(&lmk, "lib-a").unwrap();
		let tag_b =
			KeyManagementService::generate_verification_tag(&lmk, "lib-b").unwrap();

		assert_ne!(tag_a, tag_b);
	}

	#[test]
	fn test_verification_tag_differs_for_different_lmks_same_library() {
		let smk1 = SystemMasterKey::generate();
		let smk2 = SystemMasterKey::generate();

		let lmk1 = KeyManagementService::derive_lmk(&smk1, "lib-same").unwrap();
		let lmk2 = KeyManagementService::derive_lmk(&smk2, "lib-same").unwrap();

		let tag1 =
			KeyManagementService::generate_verification_tag(&lmk1, "lib-same").unwrap();
		let tag2 =
			KeyManagementService::generate_verification_tag(&lmk2, "lib-same").unwrap();

		assert_ne!(tag1, tag2);
	}
}
