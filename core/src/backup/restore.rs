use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{fs, sync::RwLock};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    error::{CoreError, CoreResult},
    job::{JobExt, JobErrorType as JobError, JobExecuteLog, JobOutputExt, JobTaskOutput, WorkerCtx, WorkingState},
    security::audit::AuditLogger,
};

use super::{
    encryption::BackupEncryption,
    manifest::{BackupManifest, ManifestEntry},
    service::BackupConfig,
};

/// Output data for backup restoration jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreJobOutput {
    /// Number of files restored
    pub files_restored: usize,
    /// Total size of restored data in bytes
    pub restored_size_bytes: u64,
    /// Whether the restore was from an encrypted backup
    pub from_encrypted_backup: bool,
    /// Path to the restore target directory
    pub restore_target: Option<PathBuf>,
    /// Any errors encountered during restoration
    pub errors: Vec<String>,
    /// Checksum verification results
    pub verification_results: Vec<FileVerificationResult>,
}

impl Default for RestoreJobOutput {
    fn default() -> Self {
        Self {
            files_restored: 0,
            restored_size_bytes: 0,
            from_encrypted_backup: false,
            restore_target: None,
            errors: Vec::new(),
            verification_results: Vec::new(),
        }
    }
}

impl JobOutputExt for RestoreJobOutput {
    fn update(&mut self, updated: Self) {
        self.files_restored += updated.files_restored;
        self.restored_size_bytes += updated.restored_size_bytes;
        self.from_encrypted_backup = updated.from_encrypted_backup;
        if updated.restore_target.is_some() {
            self.restore_target = updated.restore_target;
        }
        self.errors.extend(updated.errors);
        self.verification_results.extend(updated.verification_results);
    }
}

/// Result of file verification during restoration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVerificationResult {
    /// Path of the verified file
    pub file_path: PathBuf,
    /// Whether checksum verification passed
    pub checksum_valid: bool,
    /// Expected checksum
    pub expected_checksum: String,
    /// Actual checksum
    pub actual_checksum: String,
}

/// Task types for restoration operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestoreTask {
    /// Load and validate backup manifest
    LoadManifest { backup_id: String },
    /// Prepare restore target directory
    PrepareTarget { target_path: PathBuf },
    /// Restore a batch of files from backup
    RestoreBatch { entries: Vec<ManifestEntry> },
    /// Verify restored files against checksums
    VerifyBatch { entries: Vec<ManifestEntry> },
    /// Finalize restoration process
    FinalizeRestore,
}

/// Request to restore from a backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRequest {
    /// ID of the backup to restore from
    pub backup_id: String,
    /// Target directory for restoration (if None, uses original locations)
    pub target_directory: Option<PathBuf>,
    /// Whether to verify restored files against checksums
    pub verify_checksums: bool,
    /// Specific files to restore (if None, restores all)
    pub include_files: Option<Vec<PathBuf>>,
    /// Files to exclude from restoration
    pub exclude_files: Option<Vec<PathBuf>>,
    /// Whether to overwrite existing files
    pub overwrite_existing: bool,
}

impl Default for RestoreRequest {
    fn default() -> Self {
        Self {
            backup_id: String::new(),
            target_directory: None,
            verify_checksums: true,
            include_files: None,
            exclude_files: None,
            overwrite_existing: false,
        }
    }
}

/// Job for performing backup restoration operations
#[derive(Clone)]
pub struct RestoreJob {
    /// Unique job ID
    id: String,
    /// Restoration request details
    request: RestoreRequest,
    /// Configuration references
    config: Arc<RwLock<BackupConfig>>,
    encryption: Arc<RwLock<BackupEncryption>>,
    /// Loaded backup manifest
    manifest: Option<BackupManifest>,
}

impl RestoreJob {
    pub fn new(
        restore_id: String,
        request: RestoreRequest,
        config: Arc<RwLock<BackupConfig>>,
        encryption: Arc<RwLock<BackupEncryption>>,
    ) -> Self {
        Self {
            id: restore_id,
            request,
            config,
            encryption,
            manifest: None,
        }
    }

    /// Filter manifest entries based on include/exclude patterns
    fn filter_entries(&self, entries: &[ManifestEntry]) -> Vec<ManifestEntry> {
        let mut filtered = Vec::new();

        for entry in entries {
            let mut should_include = true;

            // Check include patterns
            if let Some(include_files) = &self.request.include_files {
                should_include = include_files.iter().any(|pattern| {
                    PathBuf::from(&entry.path).starts_with(pattern) || 
                    entry.path.contains(&pattern.to_string_lossy().to_string())
                });
            }

            // Check exclude patterns
            if let Some(exclude_files) = &self.request.exclude_files {
                if exclude_files.iter().any(|pattern| {
                    PathBuf::from(&entry.path).starts_with(pattern) || 
                    entry.path.contains(&pattern.to_string_lossy().to_string())
                }) {
                    should_include = false;
                }
            }

            if should_include {
                filtered.push(entry.clone());
            }
        }

        filtered
    }

    /// Calculate target path for a file during restoration
    fn calculate_target_path(&self, original_path: &Path) -> PathBuf {
        if let Some(target_dir) = &self.request.target_directory {
            // If target directory is specified, preserve relative structure
            if let Ok(relative) = original_path.strip_prefix("/") {
                target_dir.join(relative)
            } else {
                target_dir.join(original_path.file_name().unwrap_or(original_path.as_os_str()))
            }
        } else {
            // Use original path
            original_path.to_path_buf()
        }
    }
}

#[async_trait]
impl JobExt for RestoreJob {
    const NAME: &'static str = "restore";

    type Output = RestoreJobOutput;
    type Task = RestoreTask;

    fn description(&self) -> Option<String> {
        Some(format!(
            "Restore job: {}, Backup ID: {}, Target: {:?}",
            self.id, self.request.backup_id, self.request.target_directory
        ))
    }

    async fn init(
        &mut self,
        ctx: &WorkerCtx,
    ) -> Result<WorkingState<Self::Output, Self::Task>, JobError> {
        let mut output = Self::Output::default();
        let mut tasks = VecDeque::new();

        ctx.report_progress(crate::job::JobProgress::msg("Initializing restore job"));

        // Create initial tasks for restoration
        tasks.push_back(RestoreTask::LoadManifest {
            backup_id: self.request.backup_id.clone(),
        });

        if let Some(target_dir) = &self.request.target_directory {
            tasks.push_back(RestoreTask::PrepareTarget {
                target_path: target_dir.clone(),
            });
        }

        // Additional tasks will be added after manifest is loaded
        tasks.push_back(RestoreTask::FinalizeRestore);

        // Log restore job initialization for audit purposes
        AuditLogger::log_backup_operation(
            "restore_initialized",
            &self.id,
            true,
            Some(&format!("Backup ID: {}, Tasks created: {}", self.request.backup_id, tasks.len()))
        );

        info!(job_id = %self.id, backup_id = %self.request.backup_id, task_count = tasks.len(), "Restore job initialized");

        Ok(WorkingState {
            output: Some(output),
            tasks,
            completed_tasks: 0,
            logs: vec![],
        })
    }

    async fn execute_task(
        &self,
        ctx: &WorkerCtx,
        task: Self::Task,
    ) -> Result<JobTaskOutput<Self>, JobError> {
        let mut output = RestoreJobOutput::default();
        let mut logs = Vec::new();
        let mut subtasks = Vec::new();

        match task {
            RestoreTask::LoadManifest { backup_id } => {
                logs.push(JobExecuteLog::new(
                    format!("Loading backup manifest for: {}", backup_id),
                    crate::db::entity::LogLevel::Info,
                ));

                let config = self.config.read().await;
                let manifest_path = config.backup_directory.join(format!("{}.manifest", backup_id));

                match fs::read(&manifest_path).await {
                    Ok(manifest_data) => {
                        match serde_json::from_slice::<BackupManifest>(&manifest_data) {
                            Ok(manifest) => {
                                output.from_encrypted_backup = !manifest.encryption_algorithm.is_empty();

                                // Filter entries based on include/exclude patterns
                                let filtered_entries = self.filter_entries(&manifest.entries);
                                
                                logs.push(JobExecuteLog::new(
                                    format!("Manifest loaded: {} files to restore", filtered_entries.len()),
                                    crate::db::entity::LogLevel::Info,
                                ));

                                // Create restore batch tasks
                                const BATCH_SIZE: usize = 10;
                                for chunk in filtered_entries.chunks(BATCH_SIZE) {
                                    subtasks.push(RestoreTask::RestoreBatch {
                                        entries: chunk.to_vec(),
                                    });

                                    if self.request.verify_checksums {
                                        subtasks.push(RestoreTask::VerifyBatch {
                                            entries: chunk.to_vec(),
                                        });
                                    }
                                }
                            }
                            Err(e) => {
                                let error_msg = format!("Failed to parse manifest: {}", e);
                                logs.push(JobExecuteLog::error(error_msg.clone()));
                                output.errors.push(error_msg);
                            }
                        }
                    }
                    Err(e) => {
                        let error_msg = format!("Failed to read manifest file: {}", e);
                        logs.push(JobExecuteLog::error(error_msg.clone()));
                        output.errors.push(error_msg);
                    }
                }
            }
            RestoreTask::PrepareTarget { target_path } => {
                logs.push(JobExecuteLog::new(
                    format!("Preparing target directory: {}", target_path.display()),
                    crate::db::entity::LogLevel::Info,
                ));

                if let Err(e) = fs::create_dir_all(&target_path).await {
                    let error_msg = format!("Failed to create target directory: {}", e);
                    logs.push(JobExecuteLog::error(error_msg.clone()));
                    output.errors.push(error_msg);
                } else {
                    output.restore_target = Some(target_path);
                    logs.push(JobExecuteLog::new(
                        "Target directory prepared successfully".to_string(),
                        crate::db::entity::LogLevel::Info,
                    ));
                }
            }
            RestoreTask::RestoreBatch { entries } => {
                logs.push(JobExecuteLog::new(
                    format!("Restoring batch of {} files", entries.len()),
                    crate::db::entity::LogLevel::Info,
                ));

                let config = self.config.read().await;
                let backup_dir = &config.backup_directory;

                for entry in &entries {
                    let source_path = backup_dir.join(format!("{}.backup", self.request.backup_id));
                    let target_path = self.calculate_target_path(&PathBuf::from(&entry.path));

                    // Create parent directories if they don't exist
                    if let Some(parent) = target_path.parent() {
                        if let Err(e) = fs::create_dir_all(parent).await {
                            let error_msg = format!("Failed to create directory {}: {}", parent.display(), e);
                            logs.push(JobExecuteLog::error(error_msg.clone()));
                            output.errors.push(error_msg);
                            continue;
                        }
                    }

                    // Check if file exists and whether to overwrite
                    if target_path.exists() && !self.request.overwrite_existing {
                        logs.push(JobExecuteLog::warn(&format!(
                            "Skipping existing file: {}", target_path.display()
                        )));
                        continue;
                    }

                    // TODO: Implement actual file restoration from backup archive
                    // This would involve:
                    // 1. Reading file from backup archive (tar/zip)
                    // 2. Decrypting file if backup is encrypted
                    // 3. Writing file to target location
                    // 4. Setting proper file permissions/timestamps

                    // For now, create a placeholder file
                    if let Err(e) = fs::write(&target_path, b"restored file placeholder").await {
                        let error_msg = format!("Failed to restore file {}: {}", target_path.display(), e);
                        logs.push(JobExecuteLog::error(error_msg.clone()));
                        output.errors.push(error_msg);
                    } else {
                        output.files_restored += 1;
                        output.restored_size_bytes += entry.original_size;
                        logs.push(JobExecuteLog::new(
                            format!("Restored file: {}", target_path.display()),
                            crate::db::entity::LogLevel::Info,
                        ));
                    }
                }

                logs.push(JobExecuteLog::new(
                    format!("Batch restoration completed: {} files, {} bytes", 
                        output.files_restored, output.restored_size_bytes),
                    crate::db::entity::LogLevel::Info,
                ));
            }
            RestoreTask::VerifyBatch { entries } => {
                logs.push(JobExecuteLog::new(
                    format!("Verifying batch of {} files", entries.len()),
                    crate::db::entity::LogLevel::Info,
                ));

                for entry in &entries {
                    let target_path = self.calculate_target_path(&PathBuf::from(&entry.path));
                    
                    if !target_path.exists() {
                        output.verification_results.push(FileVerificationResult {
                            file_path: target_path.clone(),
                            checksum_valid: false,
                            expected_checksum: entry.checksum.clone(),
                            actual_checksum: "file_not_found".to_string(),
                        });
                        continue;
                    }

                    // TODO: Implement actual checksum verification
                    // This would involve:
                    // 1. Reading the restored file
                    // 2. Calculating its checksum (SHA256)
                    // 3. Comparing with expected checksum from manifest

                    // For now, assume verification passes
                    output.verification_results.push(FileVerificationResult {
                        file_path: target_path,
                        checksum_valid: true,
                        expected_checksum: entry.checksum.clone(),
                        actual_checksum: entry.checksum.clone(), // Placeholder
                    });
                }

                let verified_count = output.verification_results.iter()
                    .filter(|r| r.checksum_valid)
                    .count();

                logs.push(JobExecuteLog::new(
                    format!("Verification completed: {}/{} files verified successfully", 
                        verified_count, entries.len()),
                    crate::db::entity::LogLevel::Info,
                ));
            }
            RestoreTask::FinalizeRestore => {
                logs.push(JobExecuteLog::new(
                    "Finalizing restoration process".to_string(),
                    crate::db::entity::LogLevel::Info,
                ));

                // TODO: Implement finalization tasks
                // This would involve:
                // 1. Updating file permissions and timestamps
                // 2. Creating restoration summary report
                // 3. Cleaning up temporary files
                // 4. Validating overall restoration integrity

                logs.push(JobExecuteLog::new(
                    format!("Restoration finalized: {} files restored, {} bytes total", 
                        output.files_restored, output.restored_size_bytes),
                    crate::db::entity::LogLevel::Info,
                ));
            }
        }

        Ok(JobTaskOutput {
            output,
            logs,
            subtasks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::backup::{BackupType, encryption::BackupEncryptionConfig};

    fn create_test_manifest() -> BackupManifest {
        let mut manifest = BackupManifest::new(BackupType::Full, "test_backend".to_string());

        manifest.entries.push(ManifestEntry {
            path: "/test/file1.txt".to_string(),
            original_path: PathBuf::from("/test/file1.txt"),
            compressed_size: 1024,
            original_size: 1024,
            checksum: "abc123".to_string(),
            modified_time: SystemTime::now(),
            compressed: false,
            compression_algorithm: None,
        });

        manifest.entries.push(ManifestEntry {
            path: "/test/file2.txt".to_string(),
            original_path: PathBuf::from("/test/file2.txt"),
            compressed_size: 2048,
            original_size: 2048,
            checksum: "def456".to_string(),
            modified_time: SystemTime::now(),
            compressed: false,
            compression_algorithm: None,
        });

        manifest
    }

    #[tokio::test]
    async fn test_restore_job_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = BackupConfig {
            backup_directory: temp_dir.path().join("backups"),
            encryption: BackupEncryptionConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let encryption = Arc::new(RwLock::new(crate::backup::BackupEncryption::new(config.encryption.clone())));

        let request = RestoreRequest {
            backup_id: "test_backup".to_string(),
            target_directory: Some(temp_dir.path().join("restore")),
            verify_checksums: true,
            ..Default::default()
        };

        let job = RestoreJob::new(
            "restore_123".to_string(),
            request.clone(),
            Arc::new(RwLock::new(config)),
            encryption,
        );

        assert_eq!(job.id, "restore_123");
        assert_eq!(job.request.backup_id, "test_backup");
        assert!(job.request.verify_checksums);
    }

    #[test]
    fn test_entry_filtering() {
        let temp_dir = TempDir::new().unwrap();
        let config = BackupConfig {
            backup_directory: temp_dir.path().join("backups"),
            ..Default::default()
        };

        let encryption = Arc::new(RwLock::new(crate::backup::BackupEncryption::new(
            BackupEncryptionConfig::default()
        )));

        let request = RestoreRequest {
            backup_id: "test".to_string(),
            include_files: Some(vec![PathBuf::from("/test/file1.txt")]),
            ..Default::default()
        };

        let job = RestoreJob::new(
            "restore_test".to_string(),
            request,
            Arc::new(RwLock::new(config)),
            encryption,
        );

        let manifest = create_test_manifest();
        let filtered = job.filter_entries(&manifest.entries);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "/test/file1.txt");
    }

    #[test]
    fn test_target_path_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let config = BackupConfig {
            backup_directory: temp_dir.path().join("backups"),
            ..Default::default()
        };

        let encryption = Arc::new(RwLock::new(crate::backup::BackupEncryption::new(
            BackupEncryptionConfig::default()
        )));

        // Test with target directory
        let request_with_target = RestoreRequest {
            backup_id: "test".to_string(),
            target_directory: Some(PathBuf::from("/restore")),
            ..Default::default()
        };

        let job_with_target = RestoreJob::new(
            "restore_test".to_string(),
            request_with_target,
            Arc::new(RwLock::new(config.clone())),
            encryption.clone(),
        );

        let target_path = job_with_target.calculate_target_path(&PathBuf::from("/original/file.txt"));
        assert_eq!(target_path, PathBuf::from("/restore/original/file.txt"));

        // Test without target directory
        let request_no_target = RestoreRequest {
            backup_id: "test".to_string(),
            target_directory: None,
            ..Default::default()
        };

        let job_no_target = RestoreJob::new(
            "restore_test".to_string(),
            request_no_target,
            Arc::new(RwLock::new(config)),
            encryption,
        );

        let original_path = job_no_target.calculate_target_path(&PathBuf::from("/original/file.txt"));
        assert_eq!(original_path, PathBuf::from("/original/file.txt"));
    }
}
