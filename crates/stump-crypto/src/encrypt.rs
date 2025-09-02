//! File encryption module for comic archives

use std::io::{Read, Write};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use secrecy::ExposeSecret;
use tracing::{debug, error, trace};
use zip::{write::FileOptions, ZipArchive, ZipWriter};

use crate::{
    error::{CryptoError, CryptoResult},
    key::MasterKey,
    NONCE_SIZE,
};

/// Parameters for file encryption
#[derive(Debug)]
pub struct EncryptionParams {
    /// Whether to compress the archive (default: true)
    pub compress: bool,
}

impl Default for EncryptionParams {
    fn default() -> Self {
        Self { compress: true }
    }
}

/// Encrypt a comic archive (.cbz, .cbr) into an encrypted format
/// 
/// This function:
/// 1. Reads the input archive
/// 2. Extracts each file
/// 3. Encrypts each file individually with AES-256-GCM
/// 4. Creates a new encrypted archive with .stumpenc extension
pub fn encrypt_comic_archive(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    master_key: &MasterKey,
    params: &EncryptionParams,
) -> CryptoResult<()> {
    debug!("Starting encryption of comic archive: {:?}", input_path);

    // Read input archive
    let input_file = std::fs::File::open(input_path)
        .map_err(|e| {
            error!("Failed to open input file {:?}: {}", input_path, e);
            CryptoError::Io(e)
        })?;

    let mut input_archive = ZipArchive::new(input_file)
        .map_err(|e| {
            error!("Failed to read zip archive {:?}: {}", input_path, e);
            CryptoError::Zip(e)
        })?;

    // Create output file
    let output_file = std::fs::File::create(output_path)
        .map_err(|e| {
            error!("Failed to create output file {:?}: {}", output_path, e);
            CryptoError::Io(e)
        })?;

    let mut output_archive = ZipWriter::new(output_file);

    // Setup encryption
    let cipher = Aes256Gcm::new_from_slice(master_key.expose_secret())
        .map_err(|e| {
            error!("Failed to create AES cipher: {}", e);
            CryptoError::Encryption(e.to_string())
        })?;

    let file_options: FileOptions<()> = if params.compress {
        FileOptions::default().compression_method(zip::CompressionMethod::Deflated)
    } else {
        FileOptions::default().compression_method(zip::CompressionMethod::Stored)
    };

    let total_files = input_archive.len();
    debug!("Encrypting {} files in archive", total_files);

    // Process each file in the archive
    for i in 0..total_files {
        let mut file = input_archive.by_index(i)
            .map_err(|e| {
                error!("Failed to read file at index {}: {}", i, e);
                CryptoError::Zip(e)
            })?;

        let file_name = file.name().to_string();
        trace!("Encrypting file: {}", file_name);

        // Skip directories
        if file.is_dir() {
            output_archive.add_directory(&file_name, file_options)
                .map_err(|e| {
                    error!("Failed to add directory {}: {}", file_name, e);
                    CryptoError::Zip(e)
                })?;
            continue;
        }

        // Read file content
        let mut file_content = Vec::new();
        file.read_to_end(&mut file_content)
            .map_err(|e| {
                error!("Failed to read content of file {}: {}", file_name, e);
                CryptoError::Io(e)
            })?;

        // Generate unique nonce for this file
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt file content
        let encrypted_content = cipher.encrypt(nonce, file_content.as_ref())
            .map_err(|e| {
                error!("Failed to encrypt file {}: {}", file_name, e);
                CryptoError::Encryption(e.to_string())
            })?;

        // Prepend nonce to encrypted content
        let mut final_content = Vec::with_capacity(NONCE_SIZE + encrypted_content.len());
        final_content.extend_from_slice(&nonce_bytes);
        final_content.extend_from_slice(&encrypted_content);

        // Add encrypted file to output archive
        output_archive.start_file(file_name.as_str(), file_options)
            .map_err(|e| {
                error!("Failed to start file {} in output archive: {}", file_name, e);
                CryptoError::Zip(e)
            })?;

        output_archive.write_all(&final_content)
            .map_err(|e| {
                error!("Failed to write encrypted content for file {}: {}", file_name, e);
                CryptoError::Io(e)
            })?;

        trace!("Successfully encrypted file: {}", file_name);
    }

    // Finalize the archive
    output_archive.finish()
        .map_err(|e| {
            error!("Failed to finalize output archive: {}", e);
            CryptoError::Zip(e)
        })?;

    debug!("Successfully encrypted comic archive to: {:?}", output_path);
    Ok(())
}

/// Encrypt data in memory (used for thumbnails and temporary files)
pub fn encrypt_data(
    data: &[u8],
    master_key: &MasterKey,
) -> CryptoResult<Vec<u8>> {
    trace!("Encrypting data in memory ({} bytes)", data.len());

    let cipher = Aes256Gcm::new_from_slice(master_key.expose_secret())
        .map_err(|e| {
            error!("Failed to create AES cipher: {}", e);
            CryptoError::Encryption(e.to_string())
        })?;

    // Generate unique nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt data
    let encrypted_data = cipher.encrypt(nonce, data)
        .map_err(|e| {
            error!("Failed to encrypt data: {}", e);
            CryptoError::Encryption(e.to_string())
        })?;

    // Prepend nonce to encrypted data
    let mut result = Vec::with_capacity(NONCE_SIZE + encrypted_data.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&encrypted_data);

    trace!("Successfully encrypted data ({} bytes output)", result.len());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use secrecy::SecretBox;

    #[test]
    fn test_encrypt_data() {
        let master_key = SecretBox::new(Box::new(vec![0u8; 32]));
        let test_data = b"Hello, world!";
        
        let encrypted = encrypt_data(test_data, &master_key).unwrap();
        
        // Should have nonce + encrypted data
        assert!(encrypted.len() > test_data.len());
        assert!(encrypted.len() >= NONCE_SIZE);
    }
}
