//! File decryption module for encrypted comic archives

use std::io::Read;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use secrecy::ExposeSecret;
use tracing::{debug, error, trace};
use zip::ZipArchive;

use crate::{
    error::{CryptoError, CryptoResult},
    key::MasterKey,
    NONCE_SIZE,
};

/// Parameters for file decryption
#[derive(Debug)]
pub struct DecryptionParams {
    /// Whether to verify file integrity (default: true)
    pub verify_integrity: bool,
}

impl Default for DecryptionParams {
    fn default() -> Self {
        Self {
            verify_integrity: true,
        }
    }
}

/// Decrypt a single page from an encrypted comic archive
///
/// # Arguments
/// * `archive_data` - The encrypted archive data
/// * `page_name` - Name of the page file to extract (e.g., "page001.jpg")
/// * `master_key` - The master encryption key
/// * `params` - Decryption parameters
///
/// # Returns
/// The decrypted page data as bytes
pub fn decrypt_comic_page(
    archive_data: &[u8],
    page_name: &str,
    master_key: &MasterKey,
    params: &DecryptionParams,
) -> CryptoResult<Vec<u8>> {
    trace!("Decrypting page '{}' from archive", page_name);

    // First decrypt the archive data
    let decrypted_archive = decrypt_data(archive_data, master_key)?;
    
    // Open as ZIP archive in memory
    let cursor = std::io::Cursor::new(decrypted_archive);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| {
            error!("Failed to open decrypted archive as ZIP: {}", e);
            CryptoError::Zip(e)
        })?;

    // Find and extract the requested page
    let mut file = archive.by_name(page_name)
        .map_err(|e| {
            error!("Page '{}' not found in archive: {}", page_name, e);
            CryptoError::PageNotFound(page_name.to_string())
        })?;

    let mut page_data = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut page_data)
        .map_err(|e| {
            error!("Failed to read page '{}': {}", page_name, e);
            CryptoError::Io(e)
        })?;

    // Verify integrity if requested
    if params.verify_integrity {
        // Basic verification - check if data looks like valid image
        if page_data.is_empty() {
            return Err(CryptoError::InvalidData("Page data is empty".to_string()));
        }
    }

    debug!("Successfully decrypted page '{}' ({} bytes)", page_name, page_data.len());
    Ok(page_data)
}

/// Decrypt and open an entire comic archive
///
/// # Arguments
/// * `archive_data` - The encrypted archive data
/// * `master_key` - The master encryption key
/// * `params` - Decryption parameters
///
/// # Returns
/// A ZipArchive reader for accessing archive contents
pub fn decrypt_comic_archive(
    archive_data: &[u8],
    master_key: &MasterKey,
    params: &DecryptionParams,
) -> CryptoResult<ZipArchive<std::io::Cursor<Vec<u8>>>> {
    trace!("Decrypting comic archive ({} bytes)", archive_data.len());

    // Decrypt the archive data
    let decrypted_archive = decrypt_data(archive_data, master_key)?;
    
    // Verify integrity if requested
    if params.verify_integrity {
        if decrypted_archive.is_empty() {
            return Err(CryptoError::InvalidData("Decrypted archive is empty".to_string()));
        }
    }

    // Open as ZIP archive in memory
    let cursor = std::io::Cursor::new(decrypted_archive);
    let archive = ZipArchive::new(cursor)
        .map_err(|e| {
            error!("Failed to open decrypted data as ZIP archive: {}", e);
            CryptoError::Zip(e)
        })?;

    debug!("Successfully decrypted comic archive with {} files", archive.len());
    Ok(archive)
}

/// Core data decryption function
///
/// Decrypts data that was encrypted with `encrypt_data` function.
/// Format: [12-byte nonce][encrypted_data]
///
/// # Arguments
/// * `encrypted_data` - Data to decrypt (nonce + ciphertext)
/// * `master_key` - The master encryption key
///
/// # Returns
/// The decrypted plaintext data
pub fn decrypt_data(encrypted_data: &[u8], master_key: &MasterKey) -> CryptoResult<Vec<u8>> {
    if encrypted_data.len() < NONCE_SIZE {
        return Err(CryptoError::InvalidData(
            format!("Data too short: {} bytes, need at least {}", encrypted_data.len(), NONCE_SIZE)
        ));
    }

    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(master_key.expose_secret())
        .map_err(|e| {
            error!("Failed to create AES cipher: {}", e);
            CryptoError::Encryption(e.to_string())
        })?;

    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| {
            error!("Decryption failed: {}", e);
            CryptoError::Decryption(e.to_string())
        })?;

    trace!("Successfully decrypted {} bytes of data", plaintext.len());
    Ok(plaintext)
}

/// Check if a file is encrypted by examining its header
///
/// This function reads the first few bytes of a file to determine
/// if it appears to be encrypted with our format.
///
/// # Arguments
/// * `file_data` - The file data to check
///
/// # Returns
/// `true` if the file appears to be encrypted, `false` otherwise
pub fn is_encrypted_file(file_data: &[u8]) -> bool {
    // Our encrypted files always start with a 12-byte nonce
    // followed by encrypted data. We can't definitively identify
    // them without trying to decrypt, but we can check basic
    // structural requirements.
    
    // Must be at least nonce size + some encrypted data
    if file_data.len() < NONCE_SIZE + 16 {
        return false;
    }

    // Check if it looks like a known unencrypted format
    if is_known_unencrypted_format(file_data) {
        return false;
    }

    // If it's not a known format and meets size requirements,
    // assume it might be encrypted
    true
}

/// Check if file data matches known unencrypted formats
fn is_known_unencrypted_format(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Check common archive/image signatures
    match &data[0..4] {
        // ZIP files (including CBZ)
        [0x50, 0x4B, 0x03, 0x04] | [0x50, 0x4B, 0x05, 0x06] | [0x50, 0x4B, 0x07, 0x08] => true,
        
        // RAR files (including CBR)
        [0x52, 0x61, 0x72, 0x21] => true,
        
        // 7z files
        [0x37, 0x7A, 0xBC, 0xAF] => true,
        
        // JPEG files
        [0xFF, 0xD8, 0xFF, _] => true,
        
        // PNG files
        [0x89, 0x50, 0x4E, 0x47] => true,
        
        // GIF files
        [0x47, 0x49, 0x46, 0x38] => true,
        
        // WebP files
        [0x52, 0x49, 0x46, 0x46] if data.len() >= 12 && &data[8..12] == b"WEBP" => true,
        
        _ => false,
    }
}

/// Extract the list of files from an encrypted comic archive
///
/// This function decrypts the archive and returns a list of all
/// file names contained within it, without fully extracting the files.
///
/// # Arguments
/// * `archive_data` - The encrypted archive data
/// * `master_key` - The master encryption key
///
/// # Returns
/// A vector of file names in the archive
pub fn list_archive_files(
    archive_data: &[u8],
    master_key: &MasterKey,
) -> CryptoResult<Vec<String>> {
    trace!("Listing files in encrypted archive");

    // Decrypt the archive data
    let decrypted_archive = decrypt_data(archive_data, master_key)?;
    
    // Open as ZIP archive in memory
    let cursor = std::io::Cursor::new(decrypted_archive);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| {
            error!("Failed to open decrypted archive as ZIP: {}", e);
            CryptoError::Zip(e)
        })?;

    let mut file_names = Vec::new();
    
    for i in 0..archive.len() {
        let file = archive.by_index(i)
            .map_err(|e| {
                error!("Failed to read file at index {}: {}", i, e);
                CryptoError::Zip(e)
            })?;

        if !file.is_dir() {
            file_names.push(file.name().to_string());
        }
    }

    debug!("Found {} files in encrypted archive", file_names.len());
    Ok(file_names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::encrypt_data;
    use secrecy::SecretBox;

    #[test]
    fn test_decrypt_data() {
        let master_key = SecretBox::new(Box::new(vec![1u8; 32]));
        let test_data = b"Hello, world!";
        
        // Encrypt first
        let encrypted = encrypt_data(test_data, &master_key).unwrap();
        
        // Then decrypt
        let decrypted = decrypt_data(&encrypted, &master_key).unwrap();
        
        assert_eq!(test_data, &decrypted[..]);
    }

    #[test]
    fn test_decrypt_invalid_data() {
        let master_key = SecretBox::new(Box::new(vec![1u8; 32]));
        let invalid_data = vec![0u8; 5]; // Too short
        
        assert!(decrypt_data(&invalid_data, &master_key).is_err());
    }

    #[test]
    fn test_is_encrypted_file() {
        // Test known unencrypted formats
        let zip_header = vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert!(!is_encrypted_file(&zip_header));
        
        let jpeg_header = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert!(!is_encrypted_file(&jpeg_header));
        
        // Test potential encrypted data (random bytes of sufficient length - needs NONCE_SIZE + 16 bytes minimum)
        let potential_encrypted = vec![
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, // 12 bytes (nonce)
            0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, // 12 bytes (encrypted data)
            0x01, 0x02, 0x03, 0x04  // 4 more bytes to ensure sufficient length
        ];
        assert!(is_encrypted_file(&potential_encrypted));
        
        // Test too short data
        let short_data = vec![0x12, 0x34];
        assert!(!is_encrypted_file(&short_data));
    }
}
