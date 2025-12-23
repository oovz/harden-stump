//! File encryption and decryption operations
//!
//! Implements AES-256-GCM encryption for file contents with file size padding.

use aes_gcm::{
	aead::{
		Aead as AesGcmAead, AeadInPlace as AesGcmAeadInPlace, KeyInit as AesGcmKeyInit,
	},
	Aes256Gcm, Nonce as AesGcmNonceType,
};
use zeroize::Zeroizing;

use crate::crypto::{
	errors::{CryptoError, CryptoResult},
	sizes::*,
	types::*,
};

/// Result of file encryption
#[derive(Debug, Clone)]
pub struct EncryptedFile {
	/// Encrypted file content (with padding)
	pub ciphertext: Vec<u8>,
	/// Nonce used for AES-GCM
	pub nonce: AesGcmNonce,
	/// Authentication tag from AES-GCM
	pub tag: AesGcmTag,
	/// Original file size (before padding)
	pub original_size: usize,
	/// Padded file size
	pub padded_size: usize,
}

/// Core implementation for file encryption which operates in-place on a
/// `Vec<u8>`, to avoid allocating a separate ciphertext buffer for large
/// files. The resulting on-disk format remains `ciphertext || tag || padding`
/// and is described by `EncryptedFile`.
pub fn encrypt_file_inplace(
	dek: &DataEncryptionKey,
	mut plaintext: Vec<u8>,
) -> CryptoResult<EncryptedFile> {
	// Generate random nonce
	let nonce = AesGcmNonce::generate();

	// Create cipher
	let cipher = Aes256Gcm::new(dek.expose_secret().into());
	#[allow(deprecated)]
	let aes_nonce = AesGcmNonceType::from_slice(nonce.as_slice());

	// Encrypt in-place; the plaintext buffer is transformed into ciphertext and
	// we obtain the detached authentication tag separately.
	let raw_tag = AesGcmAeadInPlace::encrypt_in_place_detached(
		&cipher,
		aes_nonce,
		&[],
		plaintext.as_mut_slice(),
	)
	.map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
	let tag = AesGcmTag::from_slice(raw_tag.as_ref())?;

	// Append tag and then apply padding to the nearest FILE_PADDING_BOUNDARY.
	plaintext.extend_from_slice(tag.as_slice());
	let original_size = plaintext.len();
	let padded_size =
		((original_size / FILE_PADDING_BOUNDARY) + 1) * FILE_PADDING_BOUNDARY;
	let padding_length = padded_size - original_size;

	if padding_length > 0 {
		use rand::RngCore;
		let mut rng = rand::rngs::OsRng;
		let mut padding = vec![0u8; padding_length];
		rng.fill_bytes(&mut padding);
		plaintext.extend_from_slice(&padding);
	}

	Ok(EncryptedFile {
		ciphertext: plaintext,
		nonce,
		tag,
		original_size,
		padded_size,
	})
}

/// Encrypt file contents with AES-256-GCM and apply padding.
///
/// This convenience wrapper accepts a plaintext slice and internally moves it
/// into a `Vec<u8>` before delegating to `encrypt_file_inplace`. Use
/// `encrypt_file_inplace` directly when you already own a `Vec<u8>` to avoid a
/// redundant allocation for large files.
pub fn encrypt_file(
	dek: &DataEncryptionKey,
	plaintext: &[u8],
) -> CryptoResult<EncryptedFile> {
	let buffer = plaintext.to_vec();
	encrypt_file_inplace(dek, buffer)
}

/// Decrypt file contents
///
/// # Arguments
/// * `dek` - Data encryption key
/// * `encrypted` - Encrypted file data
///
/// # Returns
/// The decrypted plaintext (with padding removed)
///
/// # Security
/// Uses the stored `original_size` to trim padding after decryption.
pub fn decrypt_file(
	dek: &DataEncryptionKey,
	encrypted: &EncryptedFile,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
	// Create cipher
	let cipher = Aes256Gcm::new(dek.expose_secret().into());
	#[allow(deprecated)]
	let aes_nonce = AesGcmNonceType::from_slice(encrypted.nonce.as_slice());

	// Extract ciphertext and tag (before padding)
	if encrypted.ciphertext.len() < encrypted.original_size {
		return Err(CryptoError::DecryptionFailed(
			"Padded ciphertext too short".into(),
		));
	}

	let mut ciphertext_with_tag = Vec::with_capacity(encrypted.original_size);
	ciphertext_with_tag.extend_from_slice(
		&encrypted.ciphertext[..encrypted.original_size - AES_GCM_TAG_SIZE],
	);
	ciphertext_with_tag.extend_from_slice(encrypted.tag.as_slice());

	// Decrypt
	let plaintext = AesGcmAead::decrypt(&cipher, aes_nonce, ciphertext_with_tag.as_ref())
		.map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

	Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::keys::*;
	use crate::crypto::SystemMasterKey;

	#[test]
	fn test_file_encryption_roundtrip() {
		let smk = SystemMasterKey::generate();
		let lmk = derive_library_master_key(&smk, "test-lib").unwrap();
		let dek = derive_data_encryption_key(&lmk, "file-1").unwrap();

		let plaintext = b"Hello, this is a test file!";

		// Encrypt
		let encrypted = encrypt_file(&dek, plaintext).unwrap();

		// Verify padding was applied
		assert!(encrypted.padded_size >= encrypted.original_size);
		assert_eq!(encrypted.padded_size % FILE_PADDING_BOUNDARY, 0);

		// Decrypt
		let decrypted = decrypt_file(&dek, &encrypted).unwrap();

		// Verify
		assert_eq!(plaintext, decrypted.as_slice());
	}

	#[test]
	fn test_file_padding() {
		let smk = SystemMasterKey::generate();
		let lmk = derive_library_master_key(&smk, "test-lib").unwrap();
		let dek = derive_data_encryption_key(&lmk, "file-1").unwrap();

		// Small file should be padded to 1MB
		let small_plaintext = b"Small file";
		let encrypted_small = encrypt_file(&dek, small_plaintext).unwrap();
		assert_eq!(encrypted_small.padded_size, FILE_PADDING_BOUNDARY);

		// File just over 1MB should be padded to 2MB
		let large_plaintext = vec![0u8; FILE_PADDING_BOUNDARY + 100];
		let encrypted_large = encrypt_file(&dek, &large_plaintext).unwrap();
		assert_eq!(encrypted_large.padded_size, FILE_PADDING_BOUNDARY * 2);
	}

	#[test]
	fn test_wrong_key_fails_decryption() {
		let smk = SystemMasterKey::generate();
		let lmk = derive_library_master_key(&smk, "test-lib").unwrap();
		let dek1 = derive_data_encryption_key(&lmk, "file-1").unwrap();
		let dek2 = derive_data_encryption_key(&lmk, "file-2").unwrap();

		let plaintext = b"Secret data";
		let encrypted = encrypt_file(&dek1, plaintext).unwrap();

		// Try to decrypt with wrong key
		let result = decrypt_file(&dek2, &encrypted);
		assert!(result.is_err());
	}
}
