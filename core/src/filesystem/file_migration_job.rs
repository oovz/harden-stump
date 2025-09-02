use std::{
	collections::VecDeque,
	path::{Path, PathBuf},
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
};

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use specta::Type;
use tokio::sync::Semaphore;
use utoipa::ToSchema;

use crate::{
	error::CoreError,
	filesystem::encrypted_file::FileEncryptionService,
	job::{
		error::JobError, Executor, JobExecuteLog, JobExt, JobOutputExt, JobProgress,
		JobTaskOutput, WorkerCtx, WorkingState, WrappedJob,
	},
	prisma::{library, media, series},
	security::audit::AuditLogger,
	CoreEvent,
};

/// The task variants that are used to migrate files to encrypted format
#[derive(Serialize, Deserialize)]
pub enum FileMigrationTask {
	/// Discover all unencrypted files in a library
	DiscoverFiles { library_id: String },
	/// Encrypt a batch of files
	EncryptBatch { files: Vec<PathBuf> },
}

/// A job that migrates unencrypted comic files to encrypted format
pub struct FileMigrationJob {
	/// Optional library ID to migrate specific library, None for all libraries
	pub library_id: Option<String>,
	/// Whether to force re-encryption of already encrypted files
	pub force_re_encrypt: bool,
	/// Maximum number of files to process in a single batch
	pub batch_size: usize,
	/// Master encryption key for encrypting files  
	pub master_key: Option<Vec<u8>>,
	/// Base path for encrypted storage
	pub encrypted_storage_path: PathBuf,
}

impl Clone for FileMigrationJob {
	fn clone(&self) -> Self {
		Self {
			library_id: self.library_id.clone(),
			force_re_encrypt: self.force_re_encrypt,
			batch_size: self.batch_size,
			master_key: self.master_key.clone(),
			encrypted_storage_path: self.encrypted_storage_path.clone(),
		}
	}
}

impl FileMigrationJob {
	pub fn new(
		library_id: Option<String>,
		force_re_encrypt: bool,
		master_key: SecretBox<Vec<u8>>,
		encrypted_storage_path: PathBuf,
	) -> Box<WrappedJob<FileMigrationJob>> {
		WrappedJob::new(Self {
			library_id,
			force_re_encrypt,
			batch_size: 50, // Process 50 files per batch
			master_key: Some(master_key.expose_secret().clone()),
			encrypted_storage_path,
		})
	}

	pub fn for_library(
		library_id: String,
		master_key: SecretBox<Vec<u8>>,
		encrypted_storage_path: PathBuf,
	) -> Box<WrappedJob<FileMigrationJob>> {
		Self::new(Some(library_id), false, master_key, encrypted_storage_path)
	}

	pub fn for_all_libraries(
		master_key: SecretBox<Vec<u8>>,
		encrypted_storage_path: PathBuf,
	) -> Box<WrappedJob<FileMigrationJob>> {
		Self::new(None, false, master_key, encrypted_storage_path)
	}
}

/// The data that is collected and updated during the execution of a file migration job
#[derive(Clone, Serialize, Deserialize, Default, Debug, Type, ToSchema)]
#[serde(default)]
pub struct FileMigrationOutput {
	/// The number of files that were visited during migration
	total_files: u64,
	/// The number of files that were skipped (already encrypted and not force re-encrypt)
	skipped_files: u64,
	/// The number of files that were successfully encrypted
	encrypted_files: u64,
	/// The number of files that failed to encrypt
	failed_files: u64,
	/// The number of libraries processed
	processed_libraries: u64,
}

impl JobOutputExt for FileMigrationOutput {
	fn update(&mut self, updated: Self) {
		self.total_files += updated.total_files;
		self.skipped_files += updated.skipped_files;
		self.encrypted_files += updated.encrypted_files;
		self.failed_files += updated.failed_files;
		self.processed_libraries += updated.processed_libraries;
	}
}

#[async_trait::async_trait]
impl JobExt for FileMigrationJob {
	const NAME: &'static str = "file_migration";

	type Output = FileMigrationOutput;
	type Task = FileMigrationTask;

	fn description(&self) -> Option<String> {
		match &self.library_id {
			Some(id) => Some(format!(
				"File migration job for library: {}, force_re_encrypt: {}",
				id, self.force_re_encrypt
			)),
			None => Some(format!(
				"File migration job for all libraries, force_re_encrypt: {}",
				self.force_re_encrypt
			)),
		}
	}

	async fn init(
		&mut self,
		ctx: &WorkerCtx,
	) -> Result<WorkingState<Self::Output, Self::Task>, JobError> {
		let output = Self::Output::default();

		ctx.report_progress(JobProgress::msg("Initializing file migration"));

		// Log file migration job start for audit purposes
		AuditLogger::log_file_operation(
			"migration_started",
			&format!("library: {:?}", self.library_id),
			true,
			None,
		);

		// Get libraries to process
		let libraries = match &self.library_id {
			Some(id) => {
				let library = ctx
					.db
					.library()
					.find_unique(library::id::equals(id.clone()))
					.exec()
					.await?
					.ok_or(JobError::InitFailed("Library not found".to_string()))?;
				vec![library]
			},
			None => ctx
				.db
				.library()
				.find_many(vec![])
				.exec()
				.await
				.map_err(|e| JobError::InitFailed(e.to_string()))?,
		};

		if libraries.is_empty() {
			// Log failed migration start
			AuditLogger::log_file_operation(
				"migration_failed",
				"no libraries found",
				false,
				Some("No libraries found to migrate"),
			);
			return Err(JobError::InitFailed("No libraries found".to_string()));
		}

		// Create discovery tasks for each library
		let tasks = libraries
			.into_iter()
			.map(|library| FileMigrationTask::DiscoverFiles {
				library_id: library.id,
			})
			.collect::<Vec<_>>();

		ctx.report_progress(JobProgress::msg(&format!(
			"Created {} library discovery tasks",
			tasks.len()
		)));

		Ok(WorkingState {
			output: Some(output),
			tasks: VecDeque::from(tasks),
			completed_tasks: 0,
			logs: vec![],
		})
	}

	async fn cleanup(
		&self,
		ctx: &WorkerCtx,
		output: &Self::Output,
	) -> Result<Option<Box<dyn Executor>>, JobError> {
		// Send completion event
		ctx.send_core_event(CoreEvent::JobOutput {
			id: ctx.job_id.clone(),
			output: crate::db::entity::CoreJobOutput::FileMigration(output.clone()),
		});

		// Log file migration completion for audit purposes
		if output.failed_files > 0 {
			AuditLogger::log_file_operation(
				"migration_completed_with_errors",
				&format!(
					"total: {}, encrypted: {}, failed: {}",
					output.total_files, output.encrypted_files, output.failed_files
				),
				false,
				Some(&format!("{} files failed to encrypt", output.failed_files)),
			);
		} else {
			AuditLogger::log_file_operation(
				"migration_completed",
				&format!(
					"total: {}, encrypted: {}",
					output.total_files, output.encrypted_files
				),
				true,
				None,
			);
		}

		tracing::info!(
			total_files = output.total_files,
			encrypted_files = output.encrypted_files,
			skipped_files = output.skipped_files,
			failed_files = output.failed_files,
			processed_libraries = output.processed_libraries,
			"File migration job completed"
		);

		Ok(None)
	}

	async fn execute_task(
		&self,
		ctx: &WorkerCtx,
		task: Self::Task,
	) -> Result<JobTaskOutput<Self>, JobError> {
		let mut output = Self::Output::default();
		let mut logs = vec![];
		let mut subtasks = vec![];

		match task {
			FileMigrationTask::DiscoverFiles { library_id } => {
				ctx.report_progress(JobProgress::msg(&format!(
					"Discovering files in library: {}",
					library_id
				)));

				// Get library details
				let library = ctx
					.db
					.library()
					.find_unique(library::id::equals(library_id.clone()))
					.exec()
					.await
					.map_err(|e| JobError::TaskFailed(e.to_string()))?
					.ok_or(JobError::TaskFailed("Library not found".to_string()))?;

				let library_path = PathBuf::from(&library.path);
				if !library_path.exists() {
					logs.push(JobExecuteLog::warn(&format!(
						"Library path does not exist: {}",
						library.path
					)));
					return Ok(JobTaskOutput {
						output,
						logs,
						subtasks,
					});
				}

				// Get all media files in this library that need to be processed
				let media_files = ctx
					.db
					.media()
					.find_many(vec![media::series::is(vec![series::library_id::equals(
						Some(library_id.clone()),
					)])])
					.exec()
					.await
					.map_err(|e| JobError::TaskFailed(e.to_string()))?;

				// Get supported content types for this library
				// For now, we'll focus on comic archive files (ZIP/CBZ/RAR/CBR)
				let supported_extensions = ["zip", "cbz", "rar", "cbr"];
				let mut files_to_encrypt = Vec::new();

				for media in media_files {
					let media_path = PathBuf::from(&media.path);

					if !media_path.exists() {
						logs.push(JobExecuteLog::warn(&format!(
							"Media file does not exist: {}",
							media.path
						)));
						continue;
					}

					// Check if file has supported extension for encryption
					if let Some(extension) = media_path.extension() {
						let ext_str = extension.to_string_lossy().to_lowercase();
						if !supported_extensions.contains(&ext_str.as_str()) {
							continue; // Only process comic archive files for encryption
						}

						// Check if file is already encrypted (unless force re-encrypt)
						if !self.force_re_encrypt {
							// Read first few bytes to check for encryption header
							if let Ok(mut file) = tokio::fs::File::open(&media_path).await
							{
								use tokio::io::AsyncReadExt;
								let mut header = [0u8; 16];
								if file.read_exact(&mut header).await.is_ok() {
									// Check for our encryption header pattern
									if header.starts_with(b"STUMP_ENC_V1") {
										output.skipped_files += 1;
										continue;
									}
								}
							}
						}

						files_to_encrypt.push(media_path);
						output.total_files += 1;
					}
				}

				// Create batch tasks for encryption
				if !files_to_encrypt.is_empty() {
					let chunks = files_to_encrypt.chunks(self.batch_size);
					for chunk in chunks {
						subtasks.push(FileMigrationTask::EncryptBatch {
							files: chunk.to_vec(),
						});
					}

					ctx.report_progress(JobProgress::msg(&format!(
						"Created {} encryption batches for {} files",
						subtasks.len(),
						files_to_encrypt.len()
					)));
				}

				output.processed_libraries += 1;
			},

			FileMigrationTask::EncryptBatch { files } => {
				ctx.report_progress(JobProgress::msg(&format!(
					"Encrypting batch of {} files",
					files.len()
				)));

				let task_count = files.len() as i32;
				let batch_output = safely_encrypt_batch(
					&files,
					self,
					ctx,
					self.force_re_encrypt,
					|position| {
						ctx.report_progress(JobProgress::subtask_position(
							position as i32,
							task_count,
						));
					},
				)
				.await;

				output.update(batch_output.output);
				logs.extend(batch_output.logs);
			},
		}

		Ok(JobTaskOutput {
			output,
			logs,
			subtasks,
		})
	}
}

/// Safely encrypt a batch of files with concurrency control
#[tracing::instrument(skip_all)]
pub async fn safely_encrypt_batch(
	files: &[PathBuf],
	job: &FileMigrationJob,
	ctx: &WorkerCtx,
	force_re_encrypt: bool,
	reporter: impl Fn(usize),
) -> JobTaskOutput<FileMigrationJob> {
	let mut output = FileMigrationOutput::default();
	let mut logs = vec![];

	// Get encryption key from job
	let master_key = match &job.master_key {
		Some(key) => key,
		None => {
			logs.push(JobExecuteLog::error(
				"No master encryption key available - server may be locked".to_string(),
			));
			return JobTaskOutput {
				output,
				logs,
				subtasks: vec![],
			};
		},
	};

	// Create encryption service for this batch
	let mut encryption_service =
		FileEncryptionService::new(job.encrypted_storage_path.clone());
	encryption_service.set_master_key(SecretBox::new(Box::new(master_key.clone())));

	let max_concurrency = ctx.config.max_scanner_concurrency.min(10); // Limit to 10 for file operations
	let semaphore = Arc::new(Semaphore::new(max_concurrency));

	tracing::debug!(
		max_concurrency,
		file_count = files.len(),
		"Starting batch file encryption"
	);

	let futures = files
		.iter()
		.map(|file_path| {
			let semaphore = semaphore.clone();
			let mut encryption_service =
				FileEncryptionService::new(job.encrypted_storage_path.clone());
			encryption_service
				.set_master_key(SecretBox::new(Box::new(master_key.clone())));
			let file_path = file_path.clone();

			async move {
				if semaphore.available_permits() == 0 {
					tracing::trace!(?file_path, "Waiting for permit for file encryption");
				}
				let _permit = semaphore.acquire().await.map_err(|e| {
					(
						CoreError::InternalError(format!("Semaphore error: {}", e)),
						file_path.clone(),
					)
				})?;

				tracing::trace!(?file_path, "Acquired permit for file encryption");

				encrypt_single_file(&encryption_service, &file_path, force_re_encrypt)
					.await
			}
		})
		.collect::<FuturesUnordered<_>>();

	let atomic_cursor = Arc::new(AtomicUsize::new(1));
	let mut futures = std::pin::pin!(futures);

	while let Some(encrypt_result) = futures.next().await {
		match encrypt_result {
			Ok(EncryptionResult::Encrypted) => {
				output.encrypted_files += 1;
			},
			Ok(EncryptionResult::Skipped) => {
				output.skipped_files += 1;
			},
			Err((error, path)) => {
				output.failed_files += 1;
				logs.push(
					JobExecuteLog::error(format!(
						"Failed to encrypt file: {:?}",
						error.to_string()
					))
					.with_ctx(format!("File path: {}", path.display())),
				);
			},
		}

		output.total_files += 1;
		reporter(atomic_cursor.fetch_add(1, Ordering::SeqCst));
	}

	JobTaskOutput {
		output,
		logs,
		subtasks: vec![],
	}
}

#[derive(Debug)]
enum EncryptionResult {
	Encrypted,
	Skipped,
}

/// Encrypt a single file
async fn encrypt_single_file(
	encryption_service: &FileEncryptionService,
	file_path: &Path,
	force_re_encrypt: bool,
) -> Result<EncryptionResult, (CoreError, PathBuf)> {
	let file_path_buf = file_path.to_path_buf();

	// Check if file is already encrypted (unless force re-encrypt)
	if !force_re_encrypt {
		if let Ok(mut file) = tokio::fs::File::open(file_path).await {
			use tokio::io::AsyncReadExt;
			let mut header = [0u8; 16];
			if file.read_exact(&mut header).await.is_ok() {
				// Check for our encryption header pattern
				if header.starts_with(b"STUMP_ENC_V1") {
					return Ok(EncryptionResult::Skipped);
				}
			}
		}
	}

	// Encrypt the file (in-place with ".enc" extension for now)
	let encrypted_path = file_path.with_extension(format!(
		"{}.enc",
		file_path
			.extension()
			.and_then(|s| s.to_str())
			.unwrap_or("bin")
	));

	encryption_service
		.encrypt_file(file_path, &encrypted_path)
		.await
		.map(|_| EncryptionResult::Encrypted)
		.map_err(|e| (e, file_path_buf))
}
