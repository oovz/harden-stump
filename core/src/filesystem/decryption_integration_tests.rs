//! Integration tests for the complete encryption workflow
//!
//! These tests validate the end-to-end flow:
//! 1. Create comic files with multiple pages
//! 2. Encrypt using FileEncryptionService
//! 3. Decrypt using DecryptionMiddleware  
//! 4. Validate content matches original

use std::path::PathBuf;
use tempfile::TempDir;
use tokio;

use crate::{
	config::StumpConfig,
	context::Ctx,
	filesystem::{
		archive::create_zip_archive, decryption_middleware::DecryptionMiddleware,
		encrypted_file::FileEncryptionService, ContentType,
	},
};
use stump_crypto::{derive_master_key, KeyDerivationParams};

/// Helper to create a test comic with multiple image pages
async fn create_test_comic(temp_dir: &TempDir, name: &str) -> PathBuf {
	let comic_dir = temp_dir.path().join(format!("{}_pages", name));
	std::fs::create_dir_all(&comic_dir).unwrap();

	// Create multiple test image files (minimal PNG format)
	let test_image_data = vec![
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, // IHDR data
		0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
		0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, // IDAT data
		0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60,
		0x82, // IEND chunk
	];

	// Create 5 pages for testing pagination
	for i in 1..=5 {
		let page_path = comic_dir.join(format!("page{:02}.png", i));
		std::fs::write(&page_path, &test_image_data).unwrap();
	}

	// Create ZIP archive
	let zip_path = create_zip_archive(&comic_dir, name, "cbr", temp_dir.path()).unwrap();
	zip_path
}

/// Helper to setup encryption service with test key
async fn setup_encryption_service(storage_path: PathBuf) -> FileEncryptionService {
	let mut service = FileEncryptionService::new(storage_path);

	// Set up master key
	let password = "test_integration_password";
	let params = KeyDerivationParams::default();
	let master_key = derive_master_key(password, &params).unwrap();
	service.set_master_key(master_key);

	// Initialize storage
	service.initialize_storage().await.unwrap();

	service
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn test_complete_encryption_decryption_workflow() {
		// Setup temporary directories
		let temp_dir = TempDir::new().unwrap();
		let storage_path = temp_dir.path().join("encrypted_storage");

		// Create test comic with multiple pages
		let comic_path = create_test_comic(&temp_dir, "test_comic").await;
		let original_comic_data = std::fs::read(&comic_path).unwrap();

		// Setup encryption service
		let mut encryption_service = setup_encryption_service(storage_path.clone()).await;

		// Encrypt the comic file
		let relative_path = PathBuf::from("comics/test_comic.cbz");
		let encrypted_path = encryption_service
			.encrypt_file(&comic_path, &relative_path)
			.await
			.unwrap();

		// Verify encrypted file exists and has correct extension
		assert!(encrypted_path.exists());
		assert_eq!(encrypted_path.extension().unwrap(), "stumpenc");

		// Setup decryption middleware
		let ctx = Ctx::mock().0;

		// Transfer encryption key to context for middleware access
		ctx.set_master_encryption_key(encryption_service.get_master_key_copy().unwrap());

		let middleware = DecryptionMiddleware::new(ctx.clone());
		let config = StumpConfig::debug();

		// Test 1: Decrypt individual pages
		for page_num in 1..=5 {
			let (content_type, page_data) = middleware
				.decrypt_page_from_archive(&encrypted_path, page_num, &config)
				.await
				.unwrap();

			// Verify content type is correct
			assert_eq!(content_type, ContentType::PNG);

			// Verify page data is not empty and starts with PNG signature
			assert!(!page_data.is_empty());
			assert_eq!(
				&page_data[0..8],
				&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
			);
		}

		// Test 2: Decrypt entire file
		let (_temp_dir, decrypted_path) = middleware
			.decrypt_file_to_temp(&encrypted_path)
			.await
			.unwrap();

		// Verify decrypted file matches original
		let decrypted_data = std::fs::read(&decrypted_path).unwrap();
		assert_eq!(decrypted_data, original_comic_data);

		// Test 3: Test error cases

		// Test with invalid page number
		let result = middleware
			.decrypt_page_from_archive(&encrypted_path, 10, &config)
			.await;
		assert!(result.is_err());

		// Test with non-encrypted file
		let result = middleware
			.decrypt_page_from_archive(&comic_path, 1, &config)
			.await;
		// Should succeed because it falls back to regular get_page
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_encrypted_aware_named_file() {
		use crate::filesystem::decryption_middleware::file_serving::EncryptedAwareNamedFile;

		// Setup
		let temp_dir = TempDir::new().unwrap();
		let storage_path = temp_dir.path().join("encrypted_storage");

		// Create and encrypt test comic
		let comic_path = create_test_comic(&temp_dir, "test_file_serving").await;
		let encryption_service = setup_encryption_service(storage_path).await;
		let relative_path = PathBuf::from("comics/test_file_serving.cbz");
		let encrypted_path = encryption_service
			.encrypt_file(&comic_path, &relative_path)
			.await
			.unwrap();

		// Setup middleware
		let ctx = Ctx::mock().0;
		ctx.set_master_encryption_key(encryption_service.get_master_key_copy().unwrap());
		let middleware = DecryptionMiddleware::new(ctx);

		// Test EncryptedAwareNamedFile with encrypted file
		let named_file = EncryptedAwareNamedFile::open(&encrypted_path, &middleware)
			.await
			.unwrap();

		// Verify the file was opened successfully
		// The path should point to a temporary decrypted file
		assert!(named_file.path().exists());

		// Test with non-encrypted file
		let named_file_normal = EncryptedAwareNamedFile::open(&comic_path, &middleware)
			.await
			.unwrap();

		// Should open the original file directly
		assert_eq!(named_file_normal.path(), comic_path);
	}

	#[tokio::test]
	async fn test_multiple_comics_workflow() {
		// Test handling multiple encrypted comics simultaneously
		let temp_dir = TempDir::new().unwrap();
		let storage_path = temp_dir.path().join("encrypted_storage");

		// Create multiple test comics
		let comic1_path = create_test_comic(&temp_dir, "comic_series_1").await;
		let comic2_path = create_test_comic(&temp_dir, "comic_series_2").await;

		// Setup encryption service
		let mut encryption_service = setup_encryption_service(storage_path).await;

		// Encrypt both comics
		let encrypted1_path = encryption_service
			.encrypt_file(&comic1_path, &PathBuf::from("series1/comic1.cbz"))
			.await
			.unwrap();

		let encrypted2_path = encryption_service
			.encrypt_file(&comic2_path, &PathBuf::from("series2/comic2.cbz"))
			.await
			.unwrap();

		// Setup middleware
		let ctx = Ctx::mock().0;
		ctx.set_master_encryption_key(encryption_service.get_master_key_copy().unwrap());
		let middleware = DecryptionMiddleware::new(ctx);
		let config = StumpConfig::debug();

		// Test accessing pages from both comics
		let (content_type1, _) = middleware
			.decrypt_page_from_archive(&encrypted1_path, 1, &config)
			.await
			.unwrap();

		let (content_type2, _) = middleware
			.decrypt_page_from_archive(&encrypted2_path, 3, &config)
			.await
			.unwrap();

		assert_eq!(content_type1, ContentType::PNG);
		assert_eq!(content_type2, ContentType::PNG); // Test full file decryption for both
		let (_temp1, decrypted1) = middleware
			.decrypt_file_to_temp(&encrypted1_path)
			.await
			.unwrap();

		let (_temp2, decrypted2) = middleware
			.decrypt_file_to_temp(&encrypted2_path)
			.await
			.unwrap();

		// Verify both files were decrypted correctly
		assert!(decrypted1.exists());
		assert!(decrypted2.exists());

		// Verify they are different files
		assert_ne!(decrypted1, decrypted2);
	}

	#[tokio::test]
	async fn test_error_scenarios() {
		let temp_dir = TempDir::new().unwrap();
		let _storage_path = temp_dir.path().join("encrypted_storage");

		// Setup middleware without encryption key
		let ctx = Ctx::mock().0;
		let middleware = DecryptionMiddleware::new(ctx);
		let config = StumpConfig::debug();

		// Create a fake encrypted file
		let fake_encrypted = temp_dir.path().join("fake.cbz.stumpenc");
		std::fs::write(&fake_encrypted, b"not really encrypted data").unwrap();

		// Test decryption without server being unlocked
		let result = middleware
			.decrypt_page_from_archive(&fake_encrypted, 1, &config)
			.await;

		assert!(result.is_err());
		if let Err(error) = result {
			assert!(error.to_string().contains("Server must be unlocked"));
		}

		// Test decrypt_file_to_temp on non-encrypted file
		let normal_file = temp_dir.path().join("normal.txt");
		std::fs::write(&normal_file, b"normal content").unwrap();

		let result = middleware.decrypt_file_to_temp(&normal_file).await;
		assert!(result.is_err());
		if let Err(error) = result {
			assert!(error.to_string().contains("File is not encrypted"));
		}
	}
}
