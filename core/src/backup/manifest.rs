use std::path::PathBuf;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use specta::Type;

/// Types of backups that can be created
#[derive(Debug, Clone, Serialize, Deserialize, Type, PartialEq)]
pub enum BackupType {
    /// Complete backup of all data
    Full,
    /// Only data changed since last backup
    Incremental { since: SystemTime },
    /// Only database content
    DatabaseOnly,
    /// Only comic files and media
    FilesOnly,
}

/// Entry in a backup manifest describing a backed up item
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct ManifestEntry {
    /// Relative path of the item within the backup
    pub path: String,
    /// Original path of the item
    pub original_path: PathBuf,
    /// Size of the item in bytes (compressed)
    pub compressed_size: u64,
    /// Size of the item in bytes (uncompressed)
    pub original_size: u64,
    /// SHA-256 hash of the original item
    pub checksum: String,
    /// When the item was last modified
    pub modified_time: SystemTime,
    /// Whether this item was compressed
    pub compressed: bool,
    /// Compression algorithm used (if any)
    pub compression_algorithm: Option<String>,
}

/// Backup manifest containing metadata about a backup
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct BackupManifest {
    /// Unique identifier for this backup
    pub backup_id: String,
    /// Type of backup
    pub backup_type: BackupType,
    /// When the backup was created
    pub created_at: SystemTime,
    /// When the backup was completed
    pub completed_at: Option<SystemTime>,
    /// Total size of the backup in bytes
    pub total_size: u64,
    /// Number of files in the backup
    pub file_count: usize,
    /// List of all items in the backup
    pub entries: Vec<ManifestEntry>,
    /// Version of the backup format
    pub format_version: String,
    /// Version of Stump that created this backup
    pub stump_version: String,
    /// SHA-256 hash of the entire manifest for integrity checking
    pub manifest_checksum: Option<String>,
    /// Optional backup description
    pub description: Option<String>,
    /// Storage backend used for this backup
    pub storage_backend: String,
    /// Encryption algorithm used
    pub encryption_algorithm: String,
    /// Whether the backup was verified after creation
    pub verified: bool,
}

impl BackupManifest {
    /// Create a new backup manifest
    pub fn new(backup_type: BackupType, storage_backend: String) -> Self {
        Self {
            backup_id: uuid::Uuid::new_v4().to_string(),
            backup_type,
            created_at: SystemTime::now(),
            completed_at: None,
            total_size: 0,
            file_count: 0,
            entries: Vec::new(),
            format_version: "1.0.0".to_string(),
            stump_version: env!("CARGO_PKG_VERSION").to_string(),
            manifest_checksum: None,
            description: None,
            storage_backend,
            encryption_algorithm: "AES-256-GCM".to_string(),
            verified: false,
        }
    }

    /// Add an entry to the backup manifest
    pub fn add_entry(&mut self, entry: ManifestEntry) {
        self.total_size += entry.compressed_size;
        self.file_count += 1;
        self.entries.push(entry);
    }

    /// Mark the backup as completed
    pub fn complete(&mut self) {
        self.completed_at = Some(SystemTime::now());
    }

    /// Calculate and set the manifest checksum
    pub fn finalize_checksum(&mut self) -> Result<(), serde_json::Error> {
        // Temporarily set checksum to None for hashing
        self.manifest_checksum = None;
        
        // Serialize the manifest
        let manifest_json = serde_json::to_string(self)?;
        
        // Calculate SHA-256 hash
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(manifest_json.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        
        // Set the checksum
        self.manifest_checksum = Some(hash);
        
        Ok(())
    }

    /// Verify the manifest checksum
    pub fn verify_checksum(&self) -> Result<bool, serde_json::Error> {
        let stored_checksum = match &self.manifest_checksum {
            Some(checksum) => checksum.clone(),
            None => return Ok(false), // No checksum to verify
        };

        // Create a copy without the checksum for verification
        let mut manifest_copy = self.clone();
        manifest_copy.manifest_checksum = None;

        // Serialize and hash
        let manifest_json = serde_json::to_string(&manifest_copy)?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(manifest_json.as_bytes());
        let calculated_hash = format!("{:x}", hasher.finalize());

        Ok(calculated_hash == stored_checksum)
    }

    /// Get a summary of the backup
    pub fn summary(&self) -> String {
        let status = if self.completed_at.is_some() {
            "Completed"
        } else {
            "In Progress"
        };

        format!(
            "Backup {} ({:?}) - {} - {} files, {} bytes",
            self.backup_id,
            self.backup_type,
            status,
            self.file_count,
            self.total_size
        )
    }

    /// Check if this backup is complete
    pub fn is_complete(&self) -> bool {
        self.completed_at.is_some()
    }

    /// Get the backup age
    pub fn age(&self) -> Result<std::time::Duration, std::time::SystemTimeError> {
        SystemTime::now().duration_since(self.created_at)
    }
}

impl ManifestEntry {
    /// Create a new manifest entry
    pub fn new(
        path: String,
        original_path: PathBuf,
        original_size: u64,
        checksum: String,
        modified_time: SystemTime,
    ) -> Self {
        Self {
            path,
            original_path,
            compressed_size: original_size, // Will be updated after compression
            original_size,
            checksum,
            modified_time,
            compressed: false,
            compression_algorithm: None,
        }
    }

    /// Mark this entry as compressed
    pub fn set_compressed(&mut self, compressed_size: u64, algorithm: String) {
        self.compressed_size = compressed_size;
        self.compressed = true;
        self.compression_algorithm = Some(algorithm);
    }

    /// Calculate compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 1.0;
        }
        self.compressed_size as f64 / self.original_size as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_backup_manifest_creation() {
        let manifest = BackupManifest::new(
            BackupType::Full,
            "local_filesystem".to_string(),
        );

        assert!(!manifest.backup_id.is_empty());
        assert!(matches!(manifest.backup_type, BackupType::Full));
        assert_eq!(manifest.total_size, 0);
        assert_eq!(manifest.file_count, 0);
        assert!(!manifest.is_complete());
    }

    #[test]
    fn test_manifest_entry_compression() {
        let mut entry = ManifestEntry::new(
            "test/file.txt".to_string(),
            PathBuf::from("/original/test/file.txt"),
            1000,
            "abcd1234".to_string(),
            SystemTime::now(),
        );

        assert!(!entry.compressed);
        assert_eq!(entry.compression_ratio(), 1.0);

        entry.set_compressed(500, "gzip".to_string());
        assert!(entry.compressed);
        assert_eq!(entry.compression_ratio(), 0.5);
        assert_eq!(entry.compression_algorithm, Some("gzip".to_string()));
    }

    #[test]
    fn test_manifest_checksum() {
        let mut manifest = BackupManifest::new(
            BackupType::Full,
            "local_filesystem".to_string(),
        );

        // Add some entries
        let entry = ManifestEntry::new(
            "test.txt".to_string(),
            PathBuf::from("/test.txt"),
            100,
            "hash123".to_string(),
            SystemTime::now(),
        );
        manifest.add_entry(entry);

        // Finalize checksum
        manifest.finalize_checksum().unwrap();
        assert!(manifest.manifest_checksum.is_some());

        // Verify checksum
        assert!(manifest.verify_checksum().unwrap());

        // Modify manifest and verify checksum fails
        manifest.file_count += 1;
        assert!(!manifest.verify_checksum().unwrap());
    }
}
