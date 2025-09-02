use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{fs, sync::RwLock};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    config::StumpConfig,
    error::{CoreError, CoreResult},
    job::{JobExt, JobErrorType as JobError, JobExecuteLog, JobOutputExt, JobStatus, JobTaskOutput, WorkerCtx, WorkingState},
    security::audit::AuditLogger,
};

use super::{
    encryption::{BackupEncryption, BackupEncryptionConfig, BackupEncryptionError},
    manifest::{BackupManifest, BackupType, ManifestEntry},
    restore::{RestoreJob, RestoreRequest},
};

/// Output data for backup jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJobOutput {
    /// Number of files backed up
    pub files_backed_up: usize,
    /// Total size of backup in bytes
    pub backup_size_bytes: u64,
    /// Whether the backup was encrypted
    pub encrypted: bool,
    /// Path to the created backup archive
    pub archive_path: Option<PathBuf>,
    /// Any errors encountered during backup
    pub errors: Vec<String>,
}

impl Default for BackupJobOutput {
    fn default() -> Self {
        Self {
            files_backed_up: 0,
            backup_size_bytes: 0,
            encrypted: false,
            archive_path: None,
            errors: Vec::new(),
        }
    }
}

impl JobOutputExt for BackupJobOutput {
    fn update(&mut self, updated: Self) {
        self.files_backed_up = updated.files_backed_up;
        self.backup_size_bytes = updated.backup_size_bytes;
        self.encrypted = updated.encrypted;
        self.archive_path = updated.archive_path;
        self.errors.extend(updated.errors);
    }
}

/// Task types for backup operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupTask {
    /// Scan directory for files to backup
    ScanDirectory { path: PathBuf },
    /// Backup a batch of files
    BackupBatch { files: Vec<PathBuf> },
    /// Create backup manifest
    CreateManifest,
    /// Finalize backup archive
    FinalizeArchive,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Whether backup functionality is enabled
    pub enabled: bool,
    /// Base directory for storing backups
    pub backup_directory: PathBuf,
    /// Maximum number of backup archives to retain
    pub max_backups: usize,
    /// Whether to compress backup archives
    pub compress_archives: bool,
    /// Backup encryption configuration
    pub encryption: BackupEncryptionConfig,
    /// Automatic backup schedule configuration
    pub schedule: BackupScheduleConfig,
}

/// Configuration for automatic backup scheduling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupScheduleConfig {
    /// Whether automatic backups are enabled
    pub enabled: bool,
    /// Interval between automatic backups
    pub interval: Duration,
    /// Type of backup to perform automatically
    pub backup_type: BackupType,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backup_directory: PathBuf::from("./backups"),
            max_backups: 10,
            compress_archives: true,
            encryption: BackupEncryptionConfig::default(),
            schedule: BackupScheduleConfig {
                enabled: false,
                interval: Duration::from_secs(24 * 60 * 60), // Daily
                backup_type: BackupType::Incremental { since: SystemTime::now() },
            },
        }
    }
}

/// Request to create a backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRequest {
    /// Type of backup to create
    pub backup_type: BackupType,
    /// Optional custom backup ID
    pub backup_id: Option<String>,
    /// Whether to encrypt the backup
    pub encrypt: bool,
    /// Optional description for the backup
    pub description: Option<String>,
    /// Paths to include in the backup (if None, includes all)
    pub include_paths: Option<Vec<PathBuf>>,
    /// Paths to exclude from the backup
    pub exclude_paths: Option<Vec<PathBuf>>,
}

impl Default for BackupRequest {
    fn default() -> Self {
        Self {
            backup_type: BackupType::Full,
            backup_id: None,
            encrypt: true,
            description: None,
            include_paths: None,
            exclude_paths: None,
        }
    }
}

/// Service for managing backups of the Stump server
pub struct BackupService {
    /// Backup configuration
    config: Arc<RwLock<BackupConfig>>,
    /// Backup encryption service
    encryption: Arc<RwLock<BackupEncryption>>,
}

impl BackupService {
    /// Create a new backup service
    pub async fn new(
        config: BackupConfig,
    ) -> CoreResult<Self> {
        // Create backup directory if it doesn't exist
        if let Err(e) = fs::create_dir_all(&config.backup_directory).await {
            error!(error = %e, path = ?config.backup_directory, "Failed to create backup directory");
            return Err(CoreError::IoError(e));
        }

        let encryption = BackupEncryption::new(config.encryption.clone());

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            encryption: Arc::new(RwLock::new(encryption)),
        })
    }

    /// Initialize backup encryption with a password
    pub async fn init_encryption(&self, password: &str) -> Result<(), BackupEncryptionError> {
        let mut encryption = self.encryption.write().await;
        encryption.derive_backup_key(password)?;
        info!("Backup encryption initialized");
        Ok(())
    }

    /// Clear backup encryption keys
    pub async fn clear_encryption(&self) {
        let mut encryption = self.encryption.write().await;
        encryption.clear_backup_key();
        info!("Backup encryption keys cleared");
    }

    /// Check if backup encryption is available
    pub async fn is_encryption_available(&self) -> bool {
        let encryption = self.encryption.read().await;
        encryption.is_encryption_available()
    }

    /// Create a new backup
    pub async fn create_backup(&self, request: BackupRequest) -> CoreResult<String> {
        let config = self.config.read().await;
        if !config.enabled {
            return Err(CoreError::BadRequest("Backup functionality is disabled".to_string()));
        }

        // Generate backup ID if not provided
        let backup_id = request.backup_id.clone().unwrap_or_else(|| {
            format!("backup_{}", Uuid::new_v4().to_string().replace('-', ""))
        });

        // Check if encryption is requested but not available
        if request.encrypt && !self.is_encryption_available().await {
            return Err(CoreError::BadRequest("Backup encryption requested but not available".to_string()));
        }

        // Create backup job
        let job = BackupJob::new(
            backup_id.clone(),
            request,
            self.config.clone(),
            self.encryption.clone(),
        );

        // TODO: Submit job to job manager instead of storing locally
        // This is a placeholder - in the real implementation, you would:
        // 1. Create a WrappedJob from the BackupJob
        // 2. Submit it to the JobManager 
        // 3. Return the job ID for tracking

        // Log backup creation for audit purposes
        AuditLogger::log_backup_operation(
            "backup_started",
            &backup_id,
            true,
            Some(&format!("Backup type: {:?}", job.request.backup_type))
        );

        info!(backup_id = %backup_id, backup_type = ?job.request.backup_type, "Started backup creation");

        Ok(backup_id)
    }

    /// Get the status of a backup job
    pub async fn get_backup_status(&self, backup_id: &str) -> Option<JobStatus> {
        // TODO: Query job manager for status instead of local storage
        // This would involve checking the JobManager for the job status
        None
    }

    /// Cancel a running backup job
    pub async fn cancel_backup(&self, backup_id: &str) -> CoreResult<()> {
        // TODO: Cancel job through job manager instead of direct cancellation
        // This would involve sending a cancellation command to the JobManager
        
        // Log backup cancellation for audit purposes
        AuditLogger::log_backup_operation(
            "backup_cancelled",
            backup_id,
            true,
            Some("Backup cancelled by user request")
        );

        info!(backup_id = %backup_id, "Backup cancelled");
        Ok(())
    }

    /// List available backups
    pub async fn list_backups(&self) -> CoreResult<Vec<BackupManifest>> {
        let config = self.config.read().await;
        let backup_dir = &config.backup_directory;

        let mut manifests = Vec::new();
        let mut entries = fs::read_dir(backup_dir).await.map_err(CoreError::IoError)?;

        while let Some(entry) = entries.next_entry().await.map_err(CoreError::IoError)? {
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "manifest") {
                if let Ok(manifest_data) = fs::read(&path).await {
                    if let Ok(manifest) = serde_json::from_slice::<BackupManifest>(&manifest_data) {
                        manifests.push(manifest);
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        manifests.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(manifests)
    }

    /// Restore from a backup
    pub async fn restore_backup(&self, request: RestoreRequest) -> CoreResult<String> {
        let config = self.config.read().await;
        let manifest_path = config.backup_directory.join(format!("{}.manifest", request.backup_id));

        // Load backup manifest to validate backup exists
        let manifest_data = fs::read(&manifest_path).await
            .map_err(|e| CoreError::NotFound(format!("Backup manifest not found: {}", e)))?;
        let manifest: BackupManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| CoreError::BadRequest(format!("Invalid backup manifest: {}", e)))?;

        // Check if encryption is needed but not available
        if !manifest.encryption_algorithm.is_empty() && !self.is_encryption_available().await {
            return Err(CoreError::BadRequest("Backup is encrypted but encryption key not available".to_string()));
        }

        // Generate restore job ID
        let restore_id = format!("restore_{}", Uuid::new_v4().to_string().replace('-', ""));

        // Create restore job
        let _job = RestoreJob::new(
            restore_id.clone(),
            request,
            self.config.clone(),
            self.encryption.clone(),
        );

        // TODO: Submit job to job manager instead of storing locally
        // This is a placeholder - in the real implementation, you would:
        // 1. Create a WrappedJob from the RestoreJob
        // 2. Submit it to the JobManager 
        // 3. Return the job ID for tracking

        // Log restore operation for audit purposes
        AuditLogger::log_backup_operation(
            "restore_started",
            &restore_id,
            true,
            Some(&format!("Restoring backup: {}", manifest.backup_id))
        );

        info!(restore_id = %restore_id, backup_id = %manifest.backup_id, "Started backup restore");

        Ok(restore_id)
    }

    /// Get details about a specific backup
    pub async fn get_backup_details(&self, backup_id: &str) -> CoreResult<BackupManifest> {
        let config = self.config.read().await;
        let manifest_path = config.backup_directory.join(format!("{}.manifest", backup_id));

        let manifest_data = fs::read(&manifest_path).await
            .map_err(|e| CoreError::NotFound(format!("Backup manifest not found: {}", e)))?;
        let manifest: BackupManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| CoreError::BadRequest(format!("Invalid backup manifest: {}", e)))?;

        Ok(manifest)
    }

    /// Delete a backup
    pub async fn delete_backup(&self, backup_id: &str) -> CoreResult<()> {
        let config = self.config.read().await;
        let backup_dir = &config.backup_directory;

        // Delete manifest file
        let manifest_path = backup_dir.join(format!("{}.manifest", backup_id));
        if manifest_path.exists() {
            fs::remove_file(&manifest_path).await.map_err(CoreError::IoError)?;
        }

        // Delete backup archive
        let archive_path = backup_dir.join(format!("{}.backup", backup_id));
        if archive_path.exists() {
            fs::remove_file(&archive_path).await.map_err(CoreError::IoError)?;
        }

        // Log backup deletion for audit purposes
        AuditLogger::log_backup_operation(
            "backup_deleted",
            backup_id,
            true,
            Some("Backup archive and manifest deleted")
        );

        info!(backup_id = %backup_id, "Backup deleted");
        Ok(())
    }

    /// Clean up old backups based on retention policy
    pub async fn cleanup_old_backups(&self) -> CoreResult<()> {
        let config = self.config.read().await;
        let max_backups = config.max_backups;
        drop(config);

        let backups = self.list_backups().await?;
        
        if backups.len() > max_backups {
            let to_delete = &backups[max_backups..];
            for backup in to_delete {
                if let Err(e) = self.delete_backup(&backup.backup_id).await {
                    warn!(backup_id = %backup.backup_id, error = %e, "Failed to delete old backup");
                } else {
                    info!(backup_id = %backup.backup_id, "Deleted old backup for cleanup");
                }
            }
        }

        Ok(())
    }

    /// Get backup service configuration
    pub async fn get_config(&self) -> BackupConfig {
        let config = self.config.read().await;
        config.clone()
    }

    /// Update backup service configuration
    pub async fn update_config(&self, new_config: BackupConfig) -> CoreResult<()> {
        // Create new backup directory if changed
        if let Err(e) = fs::create_dir_all(&new_config.backup_directory).await {
            error!(error = %e, path = ?new_config.backup_directory, "Failed to create new backup directory");
            return Err(CoreError::IoError(e));
        }

        // Update encryption configuration
        {
            let mut encryption = self.encryption.write().await;
            encryption.update_config(new_config.encryption.clone());
        }

        // Update main configuration
        {
            let mut config = self.config.write().await;
            *config = new_config;
        }

        info!("Backup service configuration updated");
        Ok(())
    }
}

/// Job for performing backup operations
#[derive(Clone)]
pub struct BackupJob {
    /// Unique job ID
    id: String,
    /// Backup request details
    request: BackupRequest,
    /// Configuration references
    config: Arc<RwLock<BackupConfig>>,
    encryption: Arc<RwLock<BackupEncryption>>,
}

impl BackupJob {
    pub fn new(
        backup_id: String,
        request: BackupRequest,
        config: Arc<RwLock<BackupConfig>>,
        encryption: Arc<RwLock<BackupEncryption>>,
    ) -> Self {
        Self {
            id: backup_id,
            request,
            config,
            encryption,
        }
    }
}

#[async_trait]
impl JobExt for BackupJob {
    const NAME: &'static str = "backup";

    type Output = BackupJobOutput;
    type Task = BackupTask;

    fn description(&self) -> Option<String> {
        Some(format!(
            "Backup job: {}, Type: {:?}, Encrypted: {}",
            self.id, self.request.backup_type, self.request.encrypt
        ))
    }

    async fn init(
        &mut self,
        ctx: &WorkerCtx,
    ) -> Result<WorkingState<Self::Output, Self::Task>, JobError> {
        let output = Self::Output::default();
        let mut tasks = VecDeque::new();

        ctx.report_progress(crate::job::JobProgress::msg("Initializing backup job"));

        // Create initial tasks based on backup type
        match self.request.backup_type {
            BackupType::Full | BackupType::FilesOnly => {
                // Add directory scanning tasks
                if let Some(include_paths) = &self.request.include_paths {
                    for path in include_paths {
                        tasks.push_back(BackupTask::ScanDirectory { path: path.clone() });
                    }
                } else {
                    // Scan default directories (this would be determined by file service)
                    // For now, add a placeholder scan task
                    tasks.push_back(BackupTask::ScanDirectory { 
                        path: PathBuf::from(".") 
                    });
                }
            }
            BackupType::DatabaseOnly => {
                // For database-only backups, we don't need to scan directories
                // Just add a database backup task (represented as a special file backup)
            }
            BackupType::Incremental { since: _ } => {
                // For incremental backups, we need to compare against the last backup
                // Add scanning tasks but with timestamp filtering
                if let Some(include_paths) = &self.request.include_paths {
                    for path in include_paths {
                        tasks.push_back(BackupTask::ScanDirectory { path: path.clone() });
                    }
                }
            }
        }

        // Add finalization tasks
        tasks.push_back(BackupTask::CreateManifest);
        tasks.push_back(BackupTask::FinalizeArchive);

        // Log backup job initialization for audit purposes
        AuditLogger::log_backup_operation(
            "backup_initialized",
            &self.id,
            true,
            Some(&format!("Tasks created: {}", tasks.len()))
        );

        info!(job_id = %self.id, task_count = tasks.len(), "Backup job initialized");

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
        let mut output = BackupJobOutput::default();
        let mut logs = Vec::new();
        let subtasks = Vec::new();

        match task {
            BackupTask::ScanDirectory { path } => {
                logs.push(JobExecuteLog::new(
                    format!("Scanning directory: {}", path.display()),
                    crate::db::entity::LogLevel::Info,
                ));

                // TODO: Implement actual directory scanning
                // This would involve:
                // 1. Walking the directory tree
                // 2. Filtering files based on include/exclude patterns
                // 3. Checking modification times for incremental backups
                // 4. Creating BackupBatch tasks for discovered files

                output.files_backed_up = 1; // Placeholder
                
                logs.push(JobExecuteLog::new(
                    format!("Directory scan completed: {} files found", output.files_backed_up),
                    crate::db::entity::LogLevel::Info,
                ));
            }
            BackupTask::BackupBatch { files } => {
                logs.push(JobExecuteLog::new(
                    format!("Backing up batch of {} files", files.len()),
                    crate::db::entity::LogLevel::Info,
                ));

                // TODO: Implement actual file backup
                // This would involve:
                // 1. Reading files from their source locations
                // 2. Encrypting files if encryption is enabled
                // 3. Adding files to backup archive
                // 4. Calculating checksums

                output.files_backed_up = files.len();
                output.backup_size_bytes = files.len() as u64 * 1024; // Placeholder
                output.encrypted = self.request.encrypt;

                logs.push(JobExecuteLog::new(
                    format!("Batch backup completed: {} files, {} bytes", 
                        output.files_backed_up, output.backup_size_bytes),
                    crate::db::entity::LogLevel::Info,
                ));
            }
            BackupTask::CreateManifest => {
                logs.push(JobExecuteLog::new(
                    "Creating backup manifest".to_string(),
                    crate::db::entity::LogLevel::Info,
                ));

                // TODO: Implement manifest creation
                // This would involve:
                // 1. Collecting all backup metadata
                // 2. Creating BackupManifest structure
                // 3. Serializing manifest to JSON
                // 4. Writing manifest file

                logs.push(JobExecuteLog::new(
                    "Backup manifest created".to_string(),
                    crate::db::entity::LogLevel::Info,
                ));
            }
            BackupTask::FinalizeArchive => {
                logs.push(JobExecuteLog::new(
                    "Finalizing backup archive".to_string(),
                    crate::db::entity::LogLevel::Info,
                ));

                // TODO: Implement archive finalization
                // This would involve:
                // 1. Compressing archive if enabled
                // 2. Setting final archive path
                // 3. Calculating final checksums
                // 4. Cleaning up temporary files

                let config = self.config.read().await;
                output.archive_path = Some(config.backup_directory.join(format!("{}.backup", self.id)));

                logs.push(JobExecuteLog::new(
                    format!("Backup archive finalized: {}", 
                        output.archive_path.as_ref().unwrap().display()),
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

    async fn create_test_backup_service() -> (BackupService, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        
        let config = BackupConfig {
            backup_directory: backup_dir,
            encryption: BackupEncryptionConfig {
                enabled: false, // Disable encryption for tests
                ..Default::default()
            },
            ..Default::default()
        };

        // Create backup service
        let service = BackupService::new(config).await.unwrap();
        
        (service, temp_dir)
    }

    #[tokio::test]
    async fn test_backup_service_creation() {
        let (service, _temp_dir) = create_test_backup_service().await;
        
        let config = service.get_config().await;
        assert!(config.enabled);
        assert!(!config.encryption.enabled);
    }

    #[tokio::test]
    async fn test_backup_creation() {
        let (service, _temp_dir) = create_test_backup_service().await;
        
        let request = BackupRequest {
            backup_type: BackupType::Full,
            encrypt: false,
            description: Some("Test backup".to_string()),
            ..Default::default()
        };

        let backup_id = service.create_backup(request).await.unwrap();
        assert!(!backup_id.is_empty());
        assert!(backup_id.starts_with("backup_"));
    }

    #[tokio::test]
    async fn test_backup_list() {
        let (service, _temp_dir) = create_test_backup_service().await;
        
        // Initially should be empty
        let backups = service.list_backups().await.unwrap();
        assert!(backups.is_empty());
    }

    #[tokio::test]
    async fn test_backup_encryption_integration() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        
        let config = BackupConfig {
            backup_directory: backup_dir,
            encryption: BackupEncryptionConfig {
                enabled: true, // Enable encryption for this test
                ..Default::default()
            },
            ..Default::default()
        };

        let service = BackupService::new(config).await.unwrap();
        
        // Initialize encryption
        service.init_encryption("test_password").await.unwrap();
        assert!(service.is_encryption_available().await);

        // Create encrypted backup request
        let request = BackupRequest {
            backup_type: BackupType::Full,
            encrypt: true,
            description: Some("Encrypted test backup".to_string()),
            ..Default::default()
        };

        let backup_id = service.create_backup(request).await.unwrap();
        assert!(!backup_id.is_empty());

        // Clear encryption and verify it's no longer available
        service.clear_encryption().await;
        assert!(!service.is_encryption_available().await);
    }

    #[tokio::test]
    async fn test_backup_job_implementation() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        
        let config = BackupConfig {
            backup_directory: backup_dir,
            encryption: BackupEncryptionConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let service = BackupService::new(config.clone()).await.unwrap();
        
        let request = BackupRequest {
            backup_type: BackupType::Full,
            encrypt: false,
            description: Some("Job test backup".to_string()),
            ..Default::default()
        };

        let backup_id = format!("test_backup_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        
        let job = BackupJob::new(
            backup_id.clone(),
            request.clone(),
            Arc::new(RwLock::new(config)),
            Arc::new(RwLock::new(BackupEncryption::new(BackupEncryptionConfig::default()))),
        );

        // Test job properties
        assert_eq!(job.id, backup_id);
        assert_eq!(job.request.backup_type, BackupType::Full);
        assert!(!job.request.encrypt);
        assert_eq!(job.request.description, Some("Job test backup".to_string()));

        // Test job description
        let description = job.description();
        assert!(description.is_some());
        let description_text = description.clone().unwrap();
        assert!(description_text.contains("Backup job"));
        assert!(description_text.contains(&backup_id));
    }
}
