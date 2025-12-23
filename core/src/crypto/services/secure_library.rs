//! Secure Library Service - High-level operations for secure library management

use crate::crypto::{
	errors::CryptoResult,
	keys::derive_data_encryption_key,
	services::key_management::KeyManagementService,
	smk::SystemMasterKey,
	types::{DataEncryptionKey, LibraryMasterKey},
};

/// Service for managing secure library operations
pub struct SecureLibraryService;

impl SecureLibraryService {
	/// Create a new secure library by deriving its LMK from the SMK
	///
	/// # Arguments
	/// * `smk` - The system master key (owner-provided)
	/// * `library_id` - Unique identifier for the library
	///
	/// # Returns
	/// The derived LMK for this library
	///
	/// # Admin Operation
	/// This requires the server owner to provide the SMK.
	pub fn create_secure_library(
		smk: &SystemMasterKey,
		library_id: &str,
	) -> CryptoResult<LibraryMasterKey> {
		KeyManagementService::derive_lmk(smk, library_id)
	}

	/// Derive a Data Encryption Key (DEK) for encrypting a specific file
	///
	/// # Arguments
	/// * `lmk` - The library master key
	/// * `file_id` - Unique identifier for the file (e.g., media ID)
	///
	/// # Returns
	/// The derived DEK for this file
	pub fn derive_file_key(
		lmk: &LibraryMasterKey,
		file_id: &str,
	) -> CryptoResult<DataEncryptionKey> {
		derive_data_encryption_key(lmk, file_id)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_create_secure_library() {
		let smk = SystemMasterKey::generate();
		let lmk = SecureLibraryService::create_secure_library(&smk, "test-lib").unwrap();
		assert_eq!(lmk.expose_secret().len(), 32);
	}

	#[test]
	fn test_derive_file_key() {
		let smk = SystemMasterKey::generate();
		let lmk = SecureLibraryService::create_secure_library(&smk, "test-lib").unwrap();

		let dek1 = SecureLibraryService::derive_file_key(&lmk, "file-1").unwrap();
		let dek2 = SecureLibraryService::derive_file_key(&lmk, "file-2").unwrap();

		assert_eq!(dek1.expose_secret().len(), 32);
		assert_eq!(dek2.expose_secret().len(), 32);

		// Different file IDs should produce different keys
		assert_ne!(dek1.expose_secret(), dek2.expose_secret());
	}
}
