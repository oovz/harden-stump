use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;
use tokio::fs;
use tracing::{debug, info, warn};
use zip::result::ZipError;

use crate::{
	error::{CoreError, CoreResult},
	security::audit::AuditLogger,
};
use stump_crypto::{
	encrypt::{encrypt_comic_archive, EncryptionParams},
	decrypt::{decrypt_comic_page, DecryptionParams},
	key::MasterKey,
	error::CryptoError,
};

/// Errors that can occur during file encryption operations
#[derive(Error, Debug)]
pub enum FileEncryptionError {
	#[error("No master key available - server must be unlocked")]
	NoMasterKey,
	#[error("Cryptographic operation failed: {0}")]
	CryptoError(String),
	#[error("I/O error: {0}")]
	IoError(#[from] std::io::Error),
	#[error("ZIP archive error: {0}")]
	ZipError(#[from] ZipError),
}

/// File encryption service for managing encrypted comic archives and assets
pub struct FileEncryptionService {
	/// Base directory for storing encrypted files
	encrypted_storage_path: PathBuf,
	/// Current master encryption key (if server is unlocked)
	master_key: Option<SecretBox<Vec<u8>>>,
	/// Last time the encryption key was accessed/used
	last_key_activity: Arc<Mutex<Option<SystemTime>>>,
}

impl FileEncryptionService {
	/// Create a new file encryption service
	pub fn new(encrypted_storage_path: PathBuf) -> Self {
		Self {
			encrypted_storage_path,
			master_key: None,
			last_key_activity: Arc::new(Mutex::new(None)),
		}
	}

	/// Set the master encryption key when server is unlocked
	pub fn set_master_key(&mut self, key: SecretBox<Vec<u8>>) {
		self.master_key = Some(key);
		if let Ok(mut activity) = self.last_key_activity.lock() {
			*activity = Some(SystemTime::now());
		}
		
		// Log key set event for security audit
		AuditLogger::log_key_operation("loaded", true, Some("Master key loaded into memory"));
		
		debug!("Master encryption key set successfully");
	}

	/// Clear the master encryption key when server is locked
	pub fn clear_master_key(&mut self) {
		let was_present = self.master_key.is_some();
		self.master_key = None;
		if let Ok(mut activity) = self.last_key_activity.lock() {
			*activity = None;
		}
		
		if was_present {
			// Log key clear event for security audit
			AuditLogger::log_key_operation("cleared", true, Some("Manual key clearing"));
			
			info!("Master encryption key cleared from memory");
		} else {
			debug!("Clear master key called but no key was present");
		}
	}

	/// Check if encryption is available (server unlocked with key)
	pub fn is_encryption_available(&self) -> bool {
		self.master_key.is_some()
	}

	/// Get a copy of the master key for transferring to other components
	/// Used primarily for testing and context setup
    pub fn get_master_key_copy(&self) -> Option<SecretBox<Vec<u8>>> {
        self.master_key.as_ref().map(|key| {
            // Create a new SecretBox with the same data
            SecretBox::new(Box::new(key.expose_secret().clone()))
        })
    }	/// Get the last time the encryption key was accessed
	/// Returns None if no key is set or no activity has been recorded
	pub fn get_last_key_activity(&self) -> Option<SystemTime> {
		self.last_key_activity.lock().ok().and_then(|activity| *activity)
	}

	/// Update the last key activity timestamp (called when key is used)
	fn update_key_activity(&self) {
		if self.master_key.is_some() {
			if let Ok(mut activity) = self.last_key_activity.lock() {
				*activity = Some(SystemTime::now());
			}
		}
	}

	/// Encrypt a file and store it in the encrypted storage area
	/// Returns the path to the encrypted file
	pub async fn encrypt_file<P: AsRef<Path>>(
		&self,
		source_path: P,
		relative_path: P,
	) -> CoreResult<PathBuf> {
		let master_key = self.master_key.as_ref()
			.ok_or_else(|| CoreError::BadRequest("Server must be unlocked for file encryption".to_string()))?;

		// Update key activity since we're using the encryption key
		self.update_key_activity();

		let source_path = source_path.as_ref();
		let relative_path = relative_path.as_ref();

		// Determine target path in encrypted storage
		let target_path = self.encrypted_storage_path.join(relative_path).with_extension("stumpenc");

		// Ensure target directory exists
		if let Some(parent) = target_path.parent() {
			fs::create_dir_all(parent).await
				.map_err(|e| CoreError::IoError(e))?;
		}

		// Create master key for crypto API
		let crypto_key = MasterKey::new(Box::new(master_key.expose_secret().clone()));

		// Create encryption parameters
		let encryption_params = EncryptionParams::default();

		// Run encryption in blocking thread since crypto operations are CPU-bound
		let source_path_owned = source_path.to_owned();
		let target_path_owned = target_path.clone();
		let encryption_result = tokio::task::spawn_blocking(move || {
			encrypt_comic_archive(&source_path_owned, &target_path_owned, &crypto_key, &encryption_params)
		}).await
		.map_err(|e| CoreError::InitializationError(format!("Task join error: {}", e)))?;

		match encryption_result {
			Ok(_) => {
				// Log successful encryption
				AuditLogger::log_file_operation(
					"encrypt", 
					&source_path.to_string_lossy(), 
					true, 
					None
				);
				info!("Encrypted file: {} -> {}", source_path.display(), target_path.display());
				Ok(target_path)
			},
			Err(e) => {
				// Log failed encryption
				AuditLogger::log_file_operation(
					"encrypt", 
					&source_path.to_string_lossy(), 
					false, 
					Some(&e.to_string())
				);
				Err(CoreError::EncryptionFailed(e.to_string()))
			}
		}
	}

	/// Encrypt data from memory and store it in the encrypted storage area
	/// Returns the path to the encrypted file
	pub async fn encrypt_data<P: AsRef<Path>>(
		&self,
		data: &[u8],
		relative_path: P,
	) -> CoreResult<PathBuf> {
		let relative_path = relative_path.as_ref();

		// Write data to a temporary file first
		let temp_file = tempfile::NamedTempFile::new()
			.map_err(|e| CoreError::IoError(e))?;
		
		fs::write(temp_file.path(), data).await
			.map_err(|e| CoreError::IoError(e))?;

		// Encrypt the temporary file
		let result = self.encrypt_file(temp_file.path(), relative_path).await;

		// The temporary file is automatically cleaned up when dropped
		result
	}

	/// Decrypt a specific page from an encrypted archive
	pub async fn decrypt_page<P: AsRef<Path>>(
		&self,
		encrypted_archive_path: P,
		page_name: &str,
	) -> CoreResult<Vec<u8>> {
		let master_key = self.master_key.as_ref()
			.ok_or_else(|| CoreError::BadRequest("Server must be unlocked for file decryption".to_string()))?;

		// Update key activity since we're using the encryption key
		self.update_key_activity();

		let encrypted_archive_path = encrypted_archive_path.as_ref();

		// Create master key for crypto API
		let crypto_key = MasterKey::new(Box::new(master_key.expose_secret().clone()));

		// Create decryption parameters
		let decryption_params = DecryptionParams::default();

		// Run decryption in blocking thread since crypto operations are CPU-bound
		let archive_path_owned = encrypted_archive_path.to_owned();
		let page_name_owned = page_name.to_owned();
		let decryption_result = tokio::task::spawn_blocking(move || {
			// Read the encrypted archive file
			let archive_data = std::fs::read(&archive_path_owned)
				.map_err(|e| CryptoError::Io(e))?;
			
			// Decrypt the specific page
			decrypt_comic_page(&archive_data, &page_name_owned, &crypto_key, &decryption_params)
		}).await
		.map_err(|e| CoreError::InitializationError(format!("Task join error: {}", e)))?;

		match decryption_result {
			Ok(decrypted_data) => {
				// Log successful decryption
				AuditLogger::log_file_operation(
					"decrypt", 
					&format!("{}:{}", encrypted_archive_path.to_string_lossy(), page_name), 
					true, 
					None
				);
				debug!("Decrypted page '{}' from archive: {}", page_name, encrypted_archive_path.display());
				Ok(decrypted_data)
			},
			Err(e) => {
				// Log failed decryption
				AuditLogger::log_file_operation(
					"decrypt", 
					&format!("{}:{}", encrypted_archive_path.to_string_lossy(), page_name), 
					false, 
					Some(&e.to_string())
				);
				Err(CoreError::DecryptionFailed(e.to_string()))
			}
		}
	}

	/// Decrypt an entire archive (for migration purposes)
	pub async fn decrypt_archive<P: AsRef<Path>>(
		&self,
		encrypted_path: P,
		output_path: P,
	) -> CoreResult<()> {
		let master_key = self.master_key.as_ref()
			.ok_or_else(|| CoreError::BadRequest("Server must be unlocked for file decryption".to_string()))?;

		// Update key activity since we're using the encryption key
		self.update_key_activity();

		let encrypted_path = encrypted_path.as_ref();
		let output_path = output_path.as_ref();

		// Create master key for crypto API
		let _crypto_key = MasterKey::new(Box::new(master_key.expose_secret().clone()));

		// Create decryption parameters
		let _decryption_params = DecryptionParams::default();

		// Ensure output directory exists
		if let Some(parent) = output_path.parent() {
			fs::create_dir_all(parent).await
				.map_err(|e| CoreError::IoError(e))?;
		}

		// Run decryption in blocking thread since crypto operations are CPU-bound
		let _encrypted_path_owned = encrypted_path.to_owned();
		let _output_path_owned = output_path.to_owned();
		tokio::task::spawn_blocking(move || {
			// Note: decrypt_comic_archive doesn't exist yet, we might need to add it
			// For now, we'll use a placeholder
			Err(CoreError::DecryptionFailed("Full archive decryption not yet implemented".to_string()))
		}).await
		.map_err(|e| CoreError::InitializationError(format!("Task join error: {}", e)))?
		.map_err(|e| e)?;

		debug!("Decrypted archive: {} -> {}", encrypted_path.display(), output_path.display());
		Ok(())
	}

	/// Get the encrypted storage path for a relative path
	pub fn get_encrypted_path<P: AsRef<Path>>(&self, relative_path: P) -> PathBuf {
		self.encrypted_storage_path.join(relative_path).with_extension("stumpenc")
	}

	/// Decrypt a file from encrypted storage and return its contents
	pub async fn decrypt_file<P: AsRef<Path>>(&self, encrypted_file_path: P) -> CoreResult<Vec<u8>> {
		let master_key = self.master_key.as_ref()
			.ok_or_else(|| CoreError::BadRequest("Server must be unlocked for file decryption".to_string()))?;

		// Update key activity since we're using the encryption key
		self.update_key_activity();

		let encrypted_file_path = encrypted_file_path.as_ref();

		// Read the encrypted file
		let encrypted_data = fs::read(encrypted_file_path).await
			.map_err(|e| CoreError::IoError(e))?;

		// Create master key for crypto API
		let crypto_key = MasterKey::new(Box::new(master_key.expose_secret().clone()));

		// Run decryption in blocking thread since crypto operations are CPU-bound
		let decrypted_data = tokio::task::spawn_blocking(move || {
			stump_crypto::decrypt::decrypt_data(&encrypted_data, &crypto_key)
		}).await
		.map_err(|e| CoreError::InitializationError(format!("Task join error: {}", e)))?
		.map_err(|e| CoreError::DecryptionFailed(e.to_string()))?;

		debug!("Decrypted file: {}", encrypted_file_path.display());
		Ok(decrypted_data)
	}

	/// Check if an encrypted version of a file exists
	pub async fn encrypted_file_exists<P: AsRef<Path>>(&self, relative_path: P) -> bool {
		let encrypted_path = self.get_encrypted_path(relative_path);
		fs::metadata(encrypted_path).await.is_ok()
	}

	/// Move an existing unencrypted file to encrypted storage
	/// This removes the original file after successful encryption
	pub async fn migrate_file_to_encrypted<P: AsRef<Path>>(
		&self,
		source_path: P,
		relative_path: P,
	) -> CoreResult<PathBuf> {
		let source_path = source_path.as_ref();
		let relative_path = relative_path.as_ref();

		// Encrypt the file
		let encrypted_path = self.encrypt_file(source_path, relative_path).await?;

		// Remove the original file after successful encryption
		fs::remove_file(source_path).await
			.map_err(|e| {
				warn!("Failed to remove original file after encryption: {}", e);
				CoreError::IoError(e)
			})?;

		info!("Migrated file to encrypted storage: {} -> {}", 
			source_path.display(), encrypted_path.display());

		Ok(encrypted_path)
	}

	/// Get the encrypted storage root directory
	pub fn get_encrypted_storage_path(&self) -> &PathBuf {
		&self.encrypted_storage_path
	}

	/// Initialize the encrypted storage directory
	pub async fn initialize_storage(&self) -> CoreResult<()> {
		fs::create_dir_all(&self.encrypted_storage_path).await
			.map_err(|e| CoreError::IoError(e))?;
		
		info!("Initialized encrypted storage directory: {}", 
			self.encrypted_storage_path.display());
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tempfile::TempDir;
	use stump_crypto::key::{derive_master_key, KeyDerivationParams};

	#[tokio::test]
	async fn test_file_encryption_service() {
		let temp_dir = TempDir::new().unwrap();
		let storage_path = temp_dir.path().join("encrypted");
		let mut service = FileEncryptionService::new(storage_path.clone());

		// Test that encryption is not available without key
		assert!(!service.is_encryption_available());

		// Set up master key
		let password = "test_password";
		let params = KeyDerivationParams::default();
		let master_key = derive_master_key(password, &params).unwrap();
		service.set_master_key(master_key);

		assert!(service.is_encryption_available());

		// Initialize storage
		service.initialize_storage().await.unwrap();
		assert!(storage_path.exists());

		// Create a test ZIP file with image content (as expected by encrypt_comic_archive)
		let test_comic_dir = temp_dir.path().join("test_comic");
		std::fs::create_dir_all(&test_comic_dir).unwrap();
		
		// Create a simple test image file (minimal PNG)
		let test_image_data = vec![
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
			0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
			0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, // IHDR data
			0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
			0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, // IDAT data
			0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 // IEND chunk
		];
		
		let test_image_path = test_comic_dir.join("page01.png");
		std::fs::write(&test_image_path, &test_image_data).unwrap();
		
		// Create ZIP archive using the utility function
		use crate::filesystem::archive::create_zip_archive;
		let zip_path = create_zip_archive(&test_comic_dir, "test_comic", "cbr", temp_dir.path()).unwrap();
		
		// Test file encryption with the proper ZIP comic file
		let relative_path = std::path::PathBuf::from("test/comic.cbz");
		let encrypted_path = service.encrypt_file(&zip_path, &relative_path).await.unwrap();
		assert!(encrypted_path.exists());
		assert!(encrypted_path.extension().unwrap() == "stumpenc");

		// Test decryption
		let decrypted_data = service.decrypt_file(&encrypted_path).await.unwrap();
		// Verify the decrypted data matches the original ZIP file
		let original_data = std::fs::read(&zip_path).unwrap();
		assert_eq!(decrypted_data, original_data);

		// Test encrypted file existence check
		assert!(service.encrypted_file_exists(&relative_path).await);
		assert!(!service.encrypted_file_exists("nonexistent/file.cbz").await);

		// Test key clearing
		service.clear_master_key();
		assert!(!service.is_encryption_available());
	}
}
