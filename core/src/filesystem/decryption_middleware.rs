use secrecy::ExposeSecret;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tracing::{debug, trace, warn};

use crate::{
	context::Ctx,
	error::CoreResult,
	filesystem::{
		get_file_mtime, CacheKey, ContentType, DecryptionCache, DecryptionCacheConfig,
		FileError, PathUtils,
	},
	StumpConfig,
};

/// Decryption middleware for on-the-fly file decryption
pub struct DecryptionMiddleware {
	/// Server context for accessing file encryption service
	ctx: Ctx,
	/// Decryption cache for performance optimization
	cache: Option<DecryptionCache>,
}

impl DecryptionMiddleware {
	/// Create new decryption middleware
	pub fn new(ctx: Ctx) -> Self {
		Self { ctx, cache: None }
	}

	/// Create new decryption middleware with caching enabled
	pub fn with_cache(ctx: Ctx, cache_config: DecryptionCacheConfig) -> CoreResult<Self> {
		let cache = DecryptionCache::new(&ctx.config, cache_config)?;
		Ok(Self {
			ctx,
			cache: Some(cache),
		})
	}

	/// Check if a file path points to an encrypted file
	pub fn is_encrypted_file<P: AsRef<Path>>(&self, path: P) -> bool {
		let path = path.as_ref();
		path.extension()
			.and_then(|ext| ext.to_str())
			.map(|ext| ext == "stumpenc")
			.unwrap_or(false)
	}

	/// Get the original file path from an encrypted file path
	pub fn get_original_path<P: AsRef<Path>>(
		&self,
		encrypted_path: P,
	) -> Option<PathBuf> {
		let path = encrypted_path.as_ref();
		if self.is_encrypted_file(path) {
			Some(path.with_extension(""))
		} else {
			Some(path.to_path_buf())
		}
	}

	/// Decrypt a page from an encrypted comic archive
	#[tracing::instrument(skip(self), fields(path = %path.as_ref().display()))]
	pub async fn decrypt_page_from_archive<P: AsRef<Path>>(
		&self,
		path: P,
		page: i32,
		config: &StumpConfig,
	) -> Result<(ContentType, Vec<u8>), FileError> {
		let path = path.as_ref();

		trace!(?page, "Attempting to decrypt page from encrypted archive");

		// Check if file is encrypted
		if !self.is_encrypted_file(path) {
			// File is not encrypted, use regular get_page
			debug!("File is not encrypted, using regular get_page");
			return crate::filesystem::media::get_page_async(path, page, config).await;
		}

		// File is encrypted - decrypt the specific page
		debug!("File is encrypted, decrypting page {}", page);

		// First, we need to get the sorted list of files in the archive to map page number to file name
		let page_name = self
			.get_page_name_from_encrypted_archive(path, page)
			.await
			.map_err(|e| {
				FileError::DecryptionFailed(format!("Failed to find page name: {}", e))
			})?;

		// Extract the master key without holding the guard across await points
		let master_key = {
			let file_encryption = self.ctx.get_file_encryption_service();
			let file_encryption_guard = file_encryption.read().unwrap();

			if !file_encryption_guard.is_encryption_available() {
				return Err(FileError::DecryptionFailed(
					"Server must be unlocked for page decryption".to_string(),
				));
			}

			// Clone the master key to use outside the guard
			file_encryption_guard.get_master_key_copy().ok_or_else(|| {
				FileError::DecryptionFailed("Master key not available".to_string())
			})?
		};

		// Now decrypt the page using the extracted key, without holding any guards
		let page_data = self
			.decrypt_page_with_key(path, &page_name, &master_key)
			.await
			.map_err(|e| {
				FileError::DecryptionFailed(format!("Page decryption failed: {}", e))
			})?;

		// Determine content type from file extension
		let content_type = ContentType::from_file(&page_name);

		debug!(
			"Successfully decrypted page {} ({} bytes)",
			page,
			page_data.len()
		);
		Ok((content_type, page_data))
	}

	/// Decrypt a page using a pre-extracted master key (avoids holding guards across await)
	async fn decrypt_page_with_key<P: AsRef<Path>>(
		&self,
		archive_path: P,
		page_name: &str,
		master_key: &secrecy::SecretBox<Vec<u8>>,
	) -> CoreResult<Vec<u8>> {
		let archive_path = archive_path.as_ref();

		// Create master key for crypto API
		let crypto_key = stump_crypto::key::MasterKey::new(Box::new(
			master_key.expose_secret().clone(),
		));

		// Run decryption in blocking thread since crypto operations are CPU-bound
		let archive_path_owned = archive_path.to_owned();
		let page_name_owned = page_name.to_owned();
		let decryption_result = tokio::task::spawn_blocking(move || {
			// Read the encrypted archive file
			let archive_data = std::fs::read(&archive_path_owned)
				.map_err(|e| crate::error::CoreError::IoError(e))?;

			// Decrypt the specific page from the archive
			let params = stump_crypto::decrypt::DecryptionParams::default();
			stump_crypto::decrypt::decrypt_comic_page(
				&archive_data,
				&page_name_owned,
				&crypto_key,
				&params,
			)
			.map_err(|e| crate::error::CoreError::DecryptionFailed(e.to_string()))
		})
		.await
		.map_err(|e| {
			crate::error::CoreError::InitializationError(format!(
				"Task join error: {}",
				e
			))
		})??;

		Ok(decryption_result)
	}

	/// Decrypt an entire file using a pre-extracted master key (avoids holding guards across await)
	async fn decrypt_file_with_key<P: AsRef<Path>>(
		&self,
		path: P,
		master_key: &secrecy::SecretBox<Vec<u8>>,
	) -> CoreResult<Vec<u8>> {
		let path = path.as_ref();

		// Create master key for crypto API
		let crypto_key = stump_crypto::key::MasterKey::new(Box::new(
			master_key.expose_secret().clone(),
		));

		// Run decryption in blocking thread since crypto operations are CPU-bound
		let path_owned = path.to_owned();
		let decryption_result = tokio::task::spawn_blocking(move || {
			// Read the encrypted file
			let file_data = std::fs::read(&path_owned)
				.map_err(|e| crate::error::CoreError::IoError(e))?;

			// Decrypt the entire file
			stump_crypto::decrypt::decrypt_data(&file_data, &crypto_key)
				.map_err(|e| crate::error::CoreError::DecryptionFailed(e.to_string()))
		})
		.await
		.map_err(|e| {
			crate::error::CoreError::InitializationError(format!(
				"Task join error: {}",
				e
			))
		})??;

		Ok(decryption_result)
	}

	/// Decrypt an entire file and return a temporary file path
	#[tracing::instrument(skip(self), fields(path = %path.as_ref().display()))]
	pub async fn decrypt_file_to_temp<P: AsRef<Path>>(
		&self,
		path: P,
	) -> CoreResult<(TempDir, PathBuf)> {
		let path = path.as_ref();

		trace!("Attempting to decrypt entire file to temporary location");

		// Check if file is encrypted
		if !self.is_encrypted_file(path) {
			// File is not encrypted, return error since this method is for encrypted files only
			return Err(crate::error::CoreError::BadRequest(
				"File is not encrypted".to_string(),
			));
		}

		// Get the master key without holding the guard across await points
		let master_key = {
			let file_encryption = self.ctx.get_file_encryption_service();
			let file_encryption_guard = file_encryption.read().unwrap();

			if !file_encryption_guard.is_encryption_available() {
				return Err(crate::error::CoreError::BadRequest(
					"Server must be unlocked for file decryption".to_string(),
				));
			}

			// Clone the master key to use outside the guard
			file_encryption_guard.get_master_key_copy().ok_or_else(|| {
				crate::error::CoreError::BadRequest(
					"Master key not available".to_string(),
				)
			})?
		};

		// Decrypt the entire file using the extracted key
		let decrypted_data = self.decrypt_file_with_key(path, &master_key).await?;

		// Create a temporary directory and file
		let temp_dir = TempDir::new().map_err(|e| crate::error::CoreError::IoError(e))?;

		let original_name = path
			.file_stem()
			.and_then(|s| s.to_str())
			.unwrap_or("decrypted_file");
		let temp_file_path = temp_dir.path().join(original_name);

		// Write decrypted data to temporary file
		tokio::fs::write(&temp_file_path, decrypted_data)
			.await
			.map_err(|e| crate::error::CoreError::IoError(e))?;

		debug!(
			"Decrypted file to temporary location: {}",
			temp_file_path.display()
		);
		Ok((temp_dir, temp_file_path))
	}

	/// Get the file name for a specific page number in an encrypted archive
	/// This maps page numbers (1-based) to actual file names within the archive
	async fn get_page_name_from_encrypted_archive<P: AsRef<Path>>(
		&self,
		encrypted_path: P,
		page: i32,
	) -> CoreResult<String> {
		let encrypted_path = encrypted_path.as_ref();

		// Read the encrypted archive data
		let archive_data = tokio::fs::read(encrypted_path)
			.await
			.map_err(|e| crate::error::CoreError::IoError(e))?;

		// Extract master key without holding the guard across await points
		let crypto_key = {
			let file_encryption = self.ctx.get_file_encryption_service();
			let file_encryption_guard = file_encryption.read().unwrap();

			if !file_encryption_guard.is_encryption_available() {
				return Err(crate::error::CoreError::BadRequest(
					"Server must be unlocked for archive analysis".to_string(),
				));
			}

			// Get the master key for crypto operations
			let master_key = self.ctx.get_master_encryption_key().ok_or_else(|| {
				crate::error::CoreError::BadRequest(
					"No encryption key available".to_string(),
				)
			})?;

			// Create master key for stump-crypto API (clone to move outside guard scope)
			stump_crypto::key::MasterKey::new(Box::new(
				master_key.expose_secret().clone(),
			))
		}; // Guard is released here

		// Get list of files in the archive
		let file_names = tokio::task::spawn_blocking(move || {
			stump_crypto::decrypt::list_archive_files(&archive_data, &crypto_key)
		})
		.await
		.map_err(|e| {
			crate::error::CoreError::InitializationError(format!(
				"Task join error: {}",
				e
			))
		})?
		.map_err(|e| crate::error::CoreError::DecryptionFailed(e.to_string()))?;

		// Filter and sort image files (same logic as ZIP processor)
		let mut image_files: Vec<String> = file_names
			.into_iter()
			.filter(|name| {
				let path = std::path::Path::new(name);
				// Skip hidden files and directories
				!path.is_hidden_file() && ContentType::from_file(name).is_image()
			})
			.collect();

		// Sort files using alphanumeric sort (same logic as the ZIP processor)
		alphanumeric_sort::sort_str_slice(&mut image_files);

		// Get the page name (1-based indexing)
		if page < 1 || page as usize > image_files.len() {
			return Err(crate::error::CoreError::BadRequest(format!(
				"Page {} not found (archive has {} pages)",
				page,
				image_files.len()
			)));
		}

		let page_name = image_files[(page - 1) as usize].clone();
		debug!("Mapped page {} to file name: {}", page, page_name);

		Ok(page_name)
	}

	/// Wrapper around get_page_async that handles encryption transparently
	pub async fn get_page_async<P: AsRef<Path>>(
		&self,
		path: P,
		page: i32,
		config: &StumpConfig,
	) -> Result<(ContentType, Vec<u8>), FileError> {
		let path = path.as_ref();

		// Try cache first if available
		if let Some(ref cache) = self.cache {
			if let Ok(mtime) = get_file_mtime(path).await {
				let cache_key = CacheKey::for_page(path.to_path_buf(), page, mtime);

				if let Ok(Some((content_type, data))) = cache.get(&cache_key).await {
					trace!("Cache hit for page {} in {}", page, path.display());
					return Ok((content_type, data));
				}
			}
		}

		// Cache miss or no cache - decrypt the page
		let result = self.decrypt_page_from_archive(path, page, config).await;

		// Cache the result if successful and cache is available
		if let (Ok((content_type, ref data)), Some(ref cache)) = (&result, &self.cache) {
			if let Ok(mtime) = get_file_mtime(path).await {
				let cache_key = CacheKey::for_page(path.to_path_buf(), page, mtime);

				if let Err(e) = cache.put(cache_key, *content_type, data.clone()).await {
					warn!(
						"Failed to cache page {} from {}: {}",
						page,
						path.display(),
						e
					);
				} else {
					trace!(
						"Cached page {} from {} ({} bytes)",
						page,
						path.display(),
						data.len()
					);
				}
			}
		}

		result
	}
}

/// Enhanced file serving utilities that handle encryption transparently
pub mod file_serving {
	use super::*;
	use std::io;
	use tokio::fs::File;

	/// Encrypted-aware NamedFile replacement
	pub struct EncryptedAwareNamedFile {
		pub path_buf: PathBuf,
		pub file: File,
		pub _temp_dir: Option<TempDir>, // Keep temp dir alive
	}

	impl EncryptedAwareNamedFile {
		/// Open a file, decrypting if necessary
		pub async fn open<P: AsRef<Path>>(
			path: P,
			decryption_middleware: &DecryptionMiddleware,
		) -> io::Result<Self> {
			let path = path.as_ref();

			// Check if the file is encrypted
			if decryption_middleware.is_encrypted_file(path) {
				// File is encrypted - decrypt to temporary location
				match decryption_middleware.decrypt_file_to_temp(path).await {
					Ok((temp_dir, temp_file_path)) => {
						let file = File::open(&temp_file_path).await?;
						Ok(Self {
							path_buf: temp_file_path,
							file,
							_temp_dir: Some(temp_dir), // Keep temp dir alive
						})
					},
					Err(e) => {
						debug!("Failed to decrypt file {}: {}", path.display(), e);
						Err(io::Error::new(
							io::ErrorKind::PermissionDenied,
							format!("Decryption failed: {}", e),
						))
					},
				}
			} else {
				// File is not encrypted - open normally
				let file = File::open(path).await?;
				Ok(Self {
					path_buf: path.to_path_buf(),
					file,
					_temp_dir: None,
				})
			}
		}

		/// Get the path of the opened file (may be temporary for encrypted files)
		pub fn path(&self) -> &Path {
			&self.path_buf
		}

		/// Get a reference to the opened file
		pub fn file(&self) -> &File {
			&self.file
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{config::StumpConfig, Ctx};
	use std::path::PathBuf;

	#[tokio::test]
	async fn test_is_encrypted_file() {
		let ctx = Ctx::mock().0;
		let middleware = DecryptionMiddleware::new(ctx);

		// Test encrypted file extension
		assert!(middleware.is_encrypted_file("test.stumpenc"));
		assert!(middleware.is_encrypted_file(PathBuf::from("path/to/file.stumpenc")));

		// Test non-encrypted files
		assert!(!middleware.is_encrypted_file("test.cbz"));
		assert!(!middleware.is_encrypted_file("test.zip"));
		assert!(!middleware.is_encrypted_file("test.rar"));
		assert!(!middleware.is_encrypted_file("test.pdf"));
	}

	#[tokio::test]
	async fn test_get_original_path() {
		let ctx = Ctx::mock().0;
		let middleware = DecryptionMiddleware::new(ctx);

		// Test encrypted file path
		let encrypted_path = PathBuf::from("test.cbz.stumpenc");
		let original = middleware.get_original_path(&encrypted_path).unwrap();
		assert_eq!(original, PathBuf::from("test.cbz"));

		// Test non-encrypted file path
		let normal_path = PathBuf::from("test.cbz");
		let result = middleware.get_original_path(&normal_path).unwrap();
		assert_eq!(result, normal_path);
	}

	#[tokio::test]
	async fn test_decrypt_page_from_unencrypted_archive() {
		let ctx = Ctx::mock().0;
		let middleware = DecryptionMiddleware::new(ctx);
		let config = StumpConfig::debug();

		// Test with a non-encrypted file (should delegate to regular get_page)
		let test_path = PathBuf::from("non_existent.cbz");
		let result = middleware
			.decrypt_page_from_archive(&test_path, 1, &config)
			.await;

		// Should fail because file doesn't exist, but not because of encryption
		assert!(result.is_err());
		match result.unwrap_err() {
			FileError::FileIoError(_) => {
				// Expected - file doesn't exist
			},
			_ => panic!("Expected FileIoError for non-existent file"),
		}
	}

	#[tokio::test]
	async fn test_encrypted_aware_named_file_nonexistent() {
		use super::file_serving::EncryptedAwareNamedFile;

		let ctx = Ctx::mock().0;
		let middleware = DecryptionMiddleware::new(ctx);

		// Test with non-existent non-encrypted file
		let test_path = PathBuf::from("non_existent.cbz");
		let result = EncryptedAwareNamedFile::open(&test_path, &middleware).await;

		// Should fail because file doesn't exist
		assert!(result.is_err());
	}
}
