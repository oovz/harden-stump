use std::path::Path;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::security::audit::AuditLogger;
use stump_crypto::{
    key::{derive_master_key, MasterKey, KeyDerivationParams},
    error::CryptoError,
};

/// Errors that can occur during backup encryption operations
#[derive(Error, Debug)]
pub enum BackupEncryptionError {
    #[error("No backup master key available")]
    NoBackupKey,
    #[error("Invalid backup key derivation")]
    InvalidKeyDerivation,
    #[error("Backup encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Backup decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("I/O error during backup encryption: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

/// Configuration for backup encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEncryptionConfig {
    /// Whether backup encryption is enabled
    pub enabled: bool,
    /// Salt for backup key derivation (separate from primary encryption)
    pub backup_salt: Vec<u8>,
}

impl Default for BackupEncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backup_salt: b"stump_backup_salt_v1".to_vec(), // TODO: Generate random salt
        }
    }
}

/// Service for managing backup encryption keys and operations
pub struct BackupEncryption {
    /// Configuration for backup encryption
    config: BackupEncryptionConfig,
    /// Current backup master key (if set)
    backup_master_key: Option<SecretBox<Vec<u8>>>,
}

impl BackupEncryption {
    /// Create a new backup encryption service
    pub fn new(config: BackupEncryptionConfig) -> Self {
        Self {
            config,
            backup_master_key: None,
        }
    }

    /// Derive and set the backup master key from a password
    pub fn derive_backup_key(&mut self, password: &str) -> Result<(), BackupEncryptionError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Derive backup master key using default parameters
        let default_params = KeyDerivationParams::default();
        let backup_key = derive_master_key(password, &default_params)
            .map_err(|e| BackupEncryptionError::InvalidKeyDerivation)?;

        // Store the derived key
        self.backup_master_key = Some(SecretBox::new(Box::new(backup_key.expose_secret().clone())));

        // Log backup key derivation for audit purposes
        AuditLogger::log_key_operation("backup_key_derived", true, Some("Backup master key derived from password"));

        Ok(())
    }

    /// Clear the backup master key from memory
    pub fn clear_backup_key(&mut self) {
        let was_present = self.backup_master_key.is_some();
        self.backup_master_key = None;

        if was_present {
            // Log backup key clear for audit purposes
            AuditLogger::log_key_operation("backup_key_cleared", true, Some("Backup master key cleared from memory"));
        }
    }

    /// Check if backup encryption is available
    pub fn is_encryption_available(&self) -> bool {
        self.config.enabled && self.backup_master_key.is_some()
    }

    /// Derive a backup-specific encryption key from backup ID and timestamp
    pub fn derive_backup_archive_key(&self, backup_id: &str, timestamp: u64) -> Result<MasterKey, BackupEncryptionError> {
        let backup_master_key = self.backup_master_key.as_ref()
            .ok_or(BackupEncryptionError::NoBackupKey)?;

        // Create backup-specific key material
        let key_material = format!("{}_{}_{}", backup_id, timestamp, "stump_backup_archive");
        
        // Derive archive-specific key using HKDF or similar
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(backup_master_key.expose_secret());
        hasher.update(key_material.as_bytes());
        let archive_key = hasher.finalize().to_vec();

        Ok(MasterKey::new(Box::new(archive_key)))
    }

    /// Encrypt backup data using backup-specific encryption
    pub async fn encrypt_backup_data(
        &self,
        data: Vec<u8>,
        backup_id: &str,
        timestamp: u64,
    ) -> Result<Vec<u8>, BackupEncryptionError> {
        if !self.config.enabled {
            return Ok(data);
        }

        // Derive backup-specific key
        let archive_key = self.derive_backup_archive_key(backup_id, timestamp)?;

        // Encrypt data using stump-crypto
        let encrypted_data = tokio::task::spawn_blocking(move || {
            stump_crypto::encrypt::encrypt_data(&data, &archive_key)
        }).await
        .map_err(|e| BackupEncryptionError::EncryptionFailed(format!("Task join error: {}", e)))?
        .map_err(|e| BackupEncryptionError::EncryptionFailed(e.to_string()))?;

        // Log encryption operation for audit purposes
        AuditLogger::log_file_operation(
            "backup_encrypt",
            &format!("backup_id: {}", backup_id),
            true,
            None
        );

        Ok(encrypted_data)
    }

    /// Decrypt backup data using backup-specific decryption
    pub async fn decrypt_backup_data(
        &self,
        encrypted_data: Vec<u8>,
        backup_id: &str,
        timestamp: u64,
    ) -> Result<Vec<u8>, BackupEncryptionError> {
        if !self.config.enabled {
            return Ok(encrypted_data);
        }

        // Derive backup-specific key
        let archive_key = self.derive_backup_archive_key(backup_id, timestamp)?;

        // Decrypt data using stump-crypto
        let decrypted_data = tokio::task::spawn_blocking(move || {
            stump_crypto::decrypt::decrypt_data(&encrypted_data, &archive_key)
        }).await
        .map_err(|e| BackupEncryptionError::DecryptionFailed(format!("Task join error: {}", e)))?
        .map_err(|e| BackupEncryptionError::DecryptionFailed(e.to_string()))?;

        // Log decryption operation for audit purposes
        AuditLogger::log_file_operation(
            "backup_decrypt",
            &format!("backup_id: {}", backup_id),
            true,
            None
        );

        Ok(decrypted_data)
    }

    /// Encrypt a file for backup storage
    pub async fn encrypt_backup_file<P: AsRef<Path>>(
        &self,
        source_path: P,
        output_path: P,
        backup_id: &str,
        timestamp: u64,
    ) -> Result<(), BackupEncryptionError> {
        if !self.config.enabled {
            // If encryption is disabled, just copy the file
            tokio::fs::copy(source_path, output_path).await?;
            return Ok(());
        }

        let source_path = source_path.as_ref();
        let output_path = output_path.as_ref();

        // Read source file
        let file_data = tokio::fs::read(source_path).await?;

        // Encrypt the data
        let encrypted_data = self.encrypt_backup_data(file_data, backup_id, timestamp).await?;

        // Write encrypted data to output
        tokio::fs::write(output_path, encrypted_data).await?;

        Ok(())
    }

    /// Decrypt a backup file
    pub async fn decrypt_backup_file<P: AsRef<Path>>(
        &self,
        encrypted_path: P,
        output_path: P,
        backup_id: &str,
        timestamp: u64,
    ) -> Result<(), BackupEncryptionError> {
        if !self.config.enabled {
            // If encryption is disabled, just copy the file
            tokio::fs::copy(encrypted_path, output_path).await?;
            return Ok(());
        }

        let encrypted_path = encrypted_path.as_ref();
        let output_path = output_path.as_ref();

        // Read encrypted file
        let encrypted_data = tokio::fs::read(encrypted_path).await?;

        // Decrypt the data
        let decrypted_data = self.decrypt_backup_data(encrypted_data, backup_id, timestamp).await?;

        // Write decrypted data to output
        tokio::fs::write(output_path, decrypted_data).await?;

        Ok(())
    }

    /// Get backup encryption configuration
    pub fn get_config(&self) -> &BackupEncryptionConfig {
        &self.config
    }

    /// Update backup encryption configuration
    pub fn update_config(&mut self, config: BackupEncryptionConfig) {
        self.config = config;
        
        // Clear existing key if encryption is disabled
        if !self.config.enabled {
            self.clear_backup_key();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_backup_encryption_disabled() {
        let config = BackupEncryptionConfig {
            enabled: false,
            ..Default::default()
        };
        
        let encryption = BackupEncryption::new(config);
        assert!(!encryption.is_encryption_available());

        // Test that data passes through unchanged when encryption is disabled
        let test_data = b"test data";
        let result = encryption.encrypt_backup_data(test_data.to_vec(), "test_backup", 123456).await.unwrap();
        assert_eq!(result, test_data);
    }

    #[tokio::test]
    async fn test_backup_key_derivation() {
        let config = BackupEncryptionConfig {
            enabled: true,
            backup_salt: b"test_salt".to_vec(),
        };
        let mut encryption = BackupEncryption::new(config);

        // Test key derivation
        encryption.derive_backup_key("test_password").unwrap();
        assert!(encryption.is_encryption_available());

        // Test backup archive key derivation
        let archive_key = encryption.derive_backup_archive_key("backup_123", 123456).unwrap();
        assert!(!archive_key.expose_secret().is_empty());

        // Test key clearing
        encryption.clear_backup_key();
        assert!(!encryption.is_encryption_available());
    }

    #[tokio::test] 
    async fn test_backup_data_encryption() {
        let config = BackupEncryptionConfig {
            enabled: true,
            backup_salt: b"test_salt".to_vec(),
        };
        let mut encryption = BackupEncryption::new(config);
        encryption.derive_backup_key("test_password").unwrap();

        let test_data = b"This is test backup data";
        let backup_id = "test_backup_123";
        let timestamp = 123456789;

        // Encrypt the data
        let encrypted = encryption.encrypt_backup_data(test_data.to_vec(), backup_id, timestamp).await.unwrap();
        assert_ne!(encrypted, test_data);
        assert!(!encrypted.is_empty());

        // Decrypt the data
        let decrypted = encryption.decrypt_backup_data(encrypted, backup_id, timestamp).await.unwrap();
        assert_eq!(decrypted, test_data);
    }
}
