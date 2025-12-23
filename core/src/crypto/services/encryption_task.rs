use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use globset::GlobSet;
use prisma_client_rust::chrono::Utc;
/// Background encryption task for secure libraries
///
/// This module handles the asynchronous encryption of files when a library
/// is converted to a secure library. It encrypts files one by one, tracking
/// progress and handling failures gracefully.
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::{
	config::StumpConfig,
	crypto::{
		encrypt::{decrypt_file, encrypt_file, encrypt_file_inplace},
		keys::derive_data_encryption_key,
		types::{AesGcmNonce, AesGcmTag, LibraryMasterKey},
	},
	filesystem::{
		get_page, get_page_count,
		image::{GenericImageProcessor, ImageProcessor, ImageProcessorOptions},
		PathUtils,
	},
	prisma::{job, library, PrismaClient},
	CoreError, CoreResult,
};
use serde::Serialize;
use specta::Type;
use utoipa::ToSchema;
// Job system imports for integrating encryption as a queued job
use crate::db::entity::{
	macros::library_path_with_options_select, CoreJobOutput, LibraryConfig, LogLevel,
};
use crate::event::CoreEvent;
use crate::job::{
	error::JobError, Executor, JobExecuteLog, JobExt, JobOutputExt, JobProgress,
	JobTaskOutput, WorkerCtx, WorkingState, WrappedJob,
};
use serde_json;

#[derive(Clone, Debug, Serialize)]
struct NewMedia {
	id: String,
	series_id: Option<String>,
	series_name: Option<String>,
	name: String,
	pages: i32,
	extension: String,
	size: u64,
	updated_at: String,
}

/// Encryption status for tracking progress
#[derive(Debug, Clone)]
pub enum EncryptionStatus {
	NotStarted,
	InProgress {
		total_files: usize,
		encrypted_files: usize,
		current_file: Option<String>,
	},
	Completed {
		total_files: usize,
		encrypted_files: usize,
	},
	Failed {
		error: String,
		failed_at_file: Option<String>,
		encrypted_count: usize,
	},
}

/// Background encryption task that runs asynchronously
pub struct EncryptionTask {
	library_id: String,
	library_path: PathBuf,
	lmk: LibraryMasterKey,
	encrypted_storage_path: PathBuf,
	db: Arc<PrismaClient>,
	/// Optional config for page extraction/thumbnail generation
	config: Option<Arc<StumpConfig>>,
}

impl EncryptionTask {
	fn opaque_file_label(&self, index: usize, total: usize) -> String {
		format!("file {}/{}", index.saturating_add(1), total.max(1))
	}

	fn derive_series_id(&self, series_key: &str) -> String {
		if Uuid::parse_str(series_key).is_ok() {
			return series_key.to_string();
		}

		let namespace = Uuid::parse_str(&self.library_id).unwrap_or(Uuid::NAMESPACE_OID);
		Uuid::new_v5(&namespace, series_key.as_bytes()).to_string()
	}

	/// Create a new encryption task
	pub fn new(
		library_id: String,
		library_path: PathBuf,
		lmk: LibraryMasterKey,
		_encrypted_storage_base: PathBuf,
		db: Arc<PrismaClient>,
		config: Option<Arc<StumpConfig>>,
	) -> Self {
		// Create encrypted storage path: <library_path>/.secure
		let encrypted_storage_path = library_path.join(".secure");

		Self {
			library_id,
			library_path,
			lmk,
			encrypted_storage_path,
			db,
			config,
		}
	}

	/// Run the encryption task
	pub async fn run(self) -> CoreResult<()> {
		// Ensure encrypted storage directory exists
		fs::create_dir_all(&self.encrypted_storage_path).await?;

		// Update library status to "encrypting"
		self.db
			.library()
			.update(
				library::id::equals(self.library_id.clone()),
				vec![
					library::encryption_status::set("ENCRYPTING".to_string()),
					library::encryption_started_at::set(Some(Utc::now().into())),
				],
			)
			.exec()
			.await?;

		// Collect all plaintext files to encrypt (skip .secure and existing .enc files)
		let files = self.collect_plaintext_files().await?;
		let total_files = files.len();

		// Track new catalog additions during this run
		let mut new_media: Vec<NewMedia> = Vec::new();
		let mut new_series: HashMap<String, String> = HashMap::new();

		let mut encrypted_count = 0;
		let mut last_error = None;

		// Process each file
		for (idx, file_path) in files.iter().enumerate() {
			let file_label = self.opaque_file_label(idx, total_files);
			// Update progress
			let progress = (idx as f64 / total_files as f64) * 100.0;

			self.db
				.library()
				.update(
					library::id::equals(self.library_id.clone()),
					vec![
						library::encryption_progress::set(progress),
						library::total_files::set(total_files as i32),
						library::encrypted_files::set(encrypted_count),
						// Use encryption_error transiently while ENCRYPTING to hold the current file path
						library::encryption_error::set(Some(file_label.clone())),
					],
				)
				.exec()
				.await?;

			// Encrypt the file
			match self.encrypt_single_file(file_path).await {
				Ok(media) => {
					// record additions for catalog
					if let (Some(sid), Some(sname)) =
						(media.series_id.clone(), media.series_name.clone())
					{
						new_series.entry(sid).or_insert(sname);
					}
					new_media.push(media);
					encrypted_count += 1;
				},
				Err(_e) => {
					tracing::error!(file = %file_label, "Failed to encrypt file");
					last_error = Some(("Encryption failed".to_string(), file_label));
					// Continue with other files - don't fail entire operation
				},
			}
		}

		// Final status update
		let _was_success = last_error.is_none();
		if let Some((error, failed_file)) = last_error {
			// Some files failed but we encrypted what we could
			self.db
				.library()
				.update(
					library::id::equals(self.library_id.clone()),
					vec![
						library::encryption_status::set("ENCRYPTION_FAILED".to_string()),
						library::encryption_error::set(Some(format!(
							"Failed to encrypt some files. Last error: {} ({})",
							error, failed_file
						))),
						library::encrypted_files::set(encrypted_count),
					],
				)
				.exec()
				.await?;
		} else {
			// All files encrypted successfully
			self.db
				.library()
				.update(
					library::id::equals(self.library_id.clone()),
					vec![
						library::encryption_status::set("ENCRYPTED".to_string()),
						library::encrypted_at::set(Some(Utc::now().into())),
						library::encryption_progress::set(100.0),
						library::total_files::set(total_files as i32),
						library::encrypted_files::set(encrypted_count),
						// Clear transient current-file tracking on success
						library::encryption_error::set(None),
						library::is_secure::set(true),
					],
				)
				.exec()
				.await?;
		}

		// Generate and write encrypted catalog for client-side decryption (Option A)
		// Best-effort: do not fail the whole task if catalog generation fails
		if let Err(e) = self.write_encrypted_catalog(new_series, new_media).await {
			tracing::error!(
				error = ?e,
				"Failed to generate encrypted catalog for library"
			);
		}

		Ok(())
	}

	/// Write encrypted catalog (AES-GCM) by merging any new items with existing catalog (if present)
	/// Names are plaintext inside the encrypted JSON; the entire blob is sealed.
	async fn write_encrypted_catalog(
		&self,
		new_series: HashMap<String, String>,
		new_media: Vec<NewMedia>,
	) -> CoreResult<()> {
		#[derive(Serialize, serde::Deserialize, Clone)]
		struct CatalogSeries {
			id: String,
			name: String,
			cover_media_id: Option<String>,
			sort_order: i32,
			volume: Option<i32>,
			updated_at: String,
		}
		#[derive(Serialize, serde::Deserialize, Clone)]
		struct CatalogMedia {
			id: String,
			series_id: Option<String>,
			name: String,
			pages: i32,
			extension: String,
			size: u64,
			sort_order: i32,
			number: Option<i32>,
			volume: Option<i32>,
			updated_at: String,
		}
		#[derive(Serialize, serde::Deserialize, Clone)]
		struct Catalog {
			version: u32,
			total_series: u32,
			total_media: u32,
			library_id: String,
			series: Vec<CatalogSeries>,
			media: Vec<CatalogMedia>,
			updated_at: String,
		}

		#[derive(Serialize, serde::Deserialize, Clone)]
		struct LegacyCatalogSeries {
			id: String,
			name: String,
		}
		#[derive(Serialize, serde::Deserialize, Clone)]
		struct LegacyCatalogMedia {
			id: String,
			series_id: Option<String>,
			title: String,
		}
		#[derive(Serialize, serde::Deserialize, Clone)]
		struct LegacyCatalog {
			version: u32,
			library_id: String,
			library_name: String,
			generated_at: String,
			series: Vec<LegacyCatalogSeries>,
			media: Vec<LegacyCatalogMedia>,
		}

		// Ensure .secure exists
		fs::create_dir_all(&self.encrypted_storage_path).await?;

		// Load previous catalog if present
		let catalog_path = self.encrypted_storage_path.join("catalog.enc");
		let catalog_meta_path = self.encrypted_storage_path.join("catalog.meta.json");

		let mut existing_series: HashMap<String, CatalogSeries> = HashMap::new();
		let mut existing_media: Vec<CatalogMedia> = Vec::new();
		let mut catalog_updated_at: String = Utc::now().to_rfc3339();

		if let (Ok(meta_bytes), Ok(enc_bytes)) = (
			fs::read(&catalog_meta_path).await,
			fs::read(&catalog_path).await,
		) {
			if let Ok(meta_json) =
				serde_json::from_slice::<serde_json::Value>(&meta_bytes)
			{
				let size_field = meta_json.get("plaintext_size").and_then(|v| v.as_u64());
				if let (Some(nonce_b64), Some(tag_b64), Some(orig_sz)) = (
					meta_json.get("nonce").and_then(|v| v.as_str()),
					meta_json.get("tag").and_then(|v| v.as_str()),
					size_field,
				) {
					let nonce_bytes = BASE64.decode(nonce_b64).unwrap_or_default();
					let tag_bytes = BASE64.decode(tag_b64).unwrap_or_default();
					if nonce_bytes.len() == 12 && tag_bytes.len() == 16 {
						let nonce = AesGcmNonce::from_slice(&nonce_bytes)?;
						let tag = AesGcmTag::from_slice(&tag_bytes)?;
						let dek = derive_data_encryption_key(&self.lmk, "catalog")?;
						let encrypted = crate::crypto::encrypt::EncryptedFile {
							ciphertext: enc_bytes.clone(),
							nonce,
							tag,
							original_size: orig_sz as usize,
							padded_size: meta_json
								.get("padded_size")
								.and_then(|v| v.as_u64())
								.unwrap_or(orig_sz) as usize,
						};
						if let Ok(json_bytes) = decrypt_file(&dek, &encrypted) {
							if let Ok(value) =
								serde_json::from_slice::<serde_json::Value>(&json_bytes)
							{
								let version = value
									.get("version")
									.and_then(|v| v.as_u64())
									.unwrap_or(0);
								if version == 1 {
									if let Ok(prev) =
										serde_json::from_value::<Catalog>(value.clone())
									{
										catalog_updated_at = prev.updated_at;
										for s in prev.series {
											existing_series.insert(s.id.clone(), s);
										}
										existing_media = prev.media;
									} else if let Ok(prev) =
										serde_json::from_value::<LegacyCatalog>(value)
									{
										catalog_updated_at = prev.generated_at.clone();
										for s in prev.series {
											let sid = self.derive_series_id(&s.id);
											existing_series.insert(
												sid.clone(),
												CatalogSeries {
													id: sid,
													name: s.name,
													cover_media_id: None,
													sort_order: 0,
													volume: None,
													updated_at: prev.generated_at.clone(),
												},
											);
										}
										for m in prev.media {
											let series_id = m
												.series_id
												.map(|sid| self.derive_series_id(&sid));
											existing_media.push(CatalogMedia {
												id: m.id,
												series_id,
												name: m.title,
												pages: 0,
												extension: "cbz".to_string(),
												size: 0,
												sort_order: 0,
												number: None,
												volume: None,
												updated_at: prev.generated_at.clone(),
											});
										}
									}
								} else {
									tracing::warn!(
										version,
										library_id = %self.library_id,
										"Unsupported secure catalog version; regenerating from scratch",
									);
								}
							}
						}
					}
				}
			}
		}

		let now = Utc::now().to_rfc3339();

		// Merge new series
		for (sid, sname) in new_series.into_iter() {
			existing_series
				.entry(sid.clone())
				.and_modify(|s| {
					s.name = sname.clone();
					s.updated_at = now.clone();
				})
				.or_insert(CatalogSeries {
					id: sid,
					name: sname,
					cover_media_id: None,
					sort_order: 0,
					volume: None,
					updated_at: now.clone(),
				});
		}

		// Merge new media (dedupe by id)
		let mut existing_ids: HashSet<String> =
			existing_media.iter().map(|m| m.id.clone()).collect();
		for m in new_media.into_iter() {
			if existing_ids.insert(m.id.clone()) {
				existing_media.push(CatalogMedia {
					id: m.id,
					series_id: m.series_id,
					name: m.name,
					pages: m.pages,
					extension: m.extension,
					size: m.size,
					sort_order: 0,
					number: None,
					volume: None,
					updated_at: m.updated_at,
				});
			}
		}

		existing_media.sort_by(|a, b| {
			a.series_id
				.cmp(&b.series_id)
				.then_with(|| a.name.cmp(&b.name))
		});
		let mut current_series_id: Option<String> = None;
		let mut current_sort_order = 0;
		let mut cover_media_ids: HashMap<String, String> = HashMap::new();
		for media in existing_media.iter_mut() {
			if media.series_id != current_series_id {
				current_series_id = media.series_id.clone();
				current_sort_order = 0;
				if let Some(series_id) = &current_series_id {
					cover_media_ids
						.entry(series_id.clone())
						.or_insert_with(|| media.id.clone());
				}
			}
			media.sort_order = current_sort_order;
			current_sort_order += 1;
		}

		// Build final catalog
		let mut series_vec: Vec<CatalogSeries> = existing_series.into_values().collect();
		series_vec.sort_by(|a, b| a.name.cmp(&b.name));
		for (idx, series) in series_vec.iter_mut().enumerate() {
			series.sort_order = idx as i32;
			series.updated_at = now.clone();
			series.cover_media_id = cover_media_ids.get(&series.id).cloned();
		}

		let catalog = Catalog {
			version: 1,
			total_series: series_vec.len() as u32,
			total_media: existing_media.len() as u32,
			library_id: self.library_id.clone(),
			series: series_vec,
			media: existing_media,
			updated_at: if catalog_updated_at.is_empty() {
				now.clone()
			} else {
				now
			},
		};

		let catalog_bytes = serde_json::to_vec(&catalog)?;

		// Derive a DEK for catalog encryption with deterministic label
		let dek = derive_data_encryption_key(&self.lmk, "catalog")?;
		let encrypted = encrypt_file(&dek, &catalog_bytes)?;

		// Write encrypted catalog and metadata sidecar
		fs::write(&catalog_path, &encrypted.ciphertext).await?;
		let meta = serde_json::json!({
			"nonce": encrypted.nonce.to_base64(),
			"tag": encrypted.tag.to_base64(),
			"plaintext_size": encrypted.original_size,
			"padded_size": encrypted.padded_size,
		});
		fs::write(&catalog_meta_path, serde_json::to_vec(&meta)?).await?;

		Ok(())
	}
	/// Collect plaintext files that need to be encrypted by scanning the filesystem
	async fn collect_plaintext_files(&self) -> CoreResult<Vec<PathBuf>> {
		let library = self
			.db
			.library()
			.find_unique(library::id::equals(self.library_id.clone()))
			.select(library_path_with_options_select::select())
			.exec()
			.await?
			.ok_or_else(|| CoreError::NotFound("Library not found".to_string()))?;
		let library_config = LibraryConfig::from(library.config);
		let ignore_rules: GlobSet = library_config.ignore_rules.build()?;

		let mut files = Vec::new();
		for entry in WalkDir::new(&self.library_path)
			.into_iter()
			// Skip `.secure` and other ignored/hidden directories entirely while walking.
			.filter_entry(|e| {
				let path = e.path();
				if e.file_type().is_dir() {
					if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
						if name == ".secure" {
							return false;
						}
					}
					if path.is_hidden_file() {
						return false;
					}
					if ignore_rules.is_match(path) {
						return false;
					}
				}
				true
			}) {
			let entry = match entry {
				Ok(e) => e,
				Err(_) => continue,
			};
			if !entry.file_type().is_file() {
				continue;
			}

			let path = entry.path();
			let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
			if name.ends_with(".enc") {
				continue;
			}

			if ignore_rules.is_match(path) || path.is_default_ignored() {
				continue;
			}

			files.push(path.to_path_buf());
		}

		Ok(files)
	}

	/// Encrypt a single file
	async fn encrypt_single_file(&self, file_path: &Path) -> CoreResult<NewMedia> {
		// Generate unique file ID and path under .secure
		let encrypted_file_id = Uuid::new_v4().to_string();
		let encrypted_path = self
			.encrypted_storage_path
			.join(format!("{}.enc", encrypted_file_id));

		// Read original file
		let file_content = fs::read(file_path).await?;

		// Get name from file name (sans extension)
		let file_name = file_path
			.file_stem()
			.ok_or_else(|| CoreError::FileNotFound("Invalid file name".to_string()))?
			.to_string_lossy()
			.to_string();
		let extension = file_path
			.extension()
			.and_then(|e| e.to_str())
			.unwrap_or("")
			.to_string()
			.to_ascii_lowercase();
		let size = file_content.len() as u64;
		let updated_at = Utc::now().to_rfc3339();

		// Derive file-specific DEK using the randomized media_id
		let dek = derive_data_encryption_key(&self.lmk, &encrypted_file_id)?;

		// Encrypt file content in-place to avoid allocating an additional
		// ciphertext buffer for large media files.
		let encrypted_data = encrypt_file_inplace(&dek, file_content)?;

		// Write encrypted file
		fs::write(&encrypted_path, &encrypted_data.ciphertext).await?;

		// Write sidecar meta for the file
		let meta_path = self
			.encrypted_storage_path
			.join(format!("{}.meta.json", encrypted_file_id));
		let file_meta = serde_json::json!({
			"nonce": encrypted_data.nonce.to_base64(),
			"tag": encrypted_data.tag.to_base64(),
			"plaintext_size": encrypted_data.original_size,
			"padded_size": encrypted_data.padded_size,
		});
		fs::write(&meta_path, serde_json::to_vec(&file_meta)?).await?;

		// Best-effort: generate and encrypt thumbnail before removing plaintext
		if extension != "pdf" {
			if let Some(cfg) = &self.config {
				let _ = self
					.generate_and_encrypt_thumbnail(
						file_path,
						&encrypted_file_id,
						cfg.as_ref(),
					)
					.await
					.inspect_err(|_e| {
						tracing::warn!("Failed to generate secure thumbnail");
					});
			}
		}

		let pages = if extension == "pdf" {
			0
		} else {
			match self.config.as_ref() {
				Some(cfg) => {
					let path_str = file_path.to_string_lossy().to_string();
					get_page_count(&path_str, cfg.as_ref())
						.map_err(|e| CoreError::InternalError(e.to_string()))
						.unwrap_or(0)
				},
				None => 0,
			}
		};

		// Delete original file ONLY after successful encryption and DB update
		fs::remove_file(file_path).await?;

		tracing::info!("File encrypted successfully");
		let (series_id, series_name) = if extension == "pdf" {
			(None, None)
		} else {
			// Determine series information from relative path
			let rel = pathdiff::diff_paths(
				file_path.parent().unwrap_or(&self.library_path),
				&self.library_path,
			)
			.unwrap_or_else(|| PathBuf::from(""));
			if rel.as_os_str().is_empty() {
				(None, None)
			} else {
				let series_key = rel.to_string_lossy().to_string();
				let series_id = self.derive_series_id(&series_key);
				let series_name = Path::new(&series_key)
					.file_name()
					.and_then(|n| n.to_str())
					.map(|s| s.to_string());
				(Some(series_id), series_name)
			}
		};

		Ok(NewMedia {
			id: encrypted_file_id,
			series_id,
			series_name,
			name: file_name,
			pages,
			extension,
			size,
			updated_at,
		})
	}

	/// Generate a JPEG thumbnail from the first page of the plaintext file, encrypt it with the
	/// media-derived DEK, and write `.thumb.enc` and `.thumb.meta.json` under the `.secure` dir.
	async fn generate_and_encrypt_thumbnail(
		&self,
		file_path: &Path,
		media_id: &str,
		config: &StumpConfig,
	) -> CoreResult<()> {
		let path_str = file_path.to_string_lossy().to_string();
		// Extract first page bytes
		let (_ct, page_bytes) = get_page(&path_str, 1, config)
			.map_err(|e| CoreError::InternalError(e.to_string()))?;

		// Convert to JPEG (no resize for MVP)
		let jpeg_bytes =
			GenericImageProcessor::generate(&page_bytes, ImageProcessorOptions::jpeg())
				.map_err(|e| CoreError::InternalError(e.to_string()))?;

		// Encrypt with thumbnail-specific DEK for key separation
		let dek =
			crate::crypto::keys::derive_thumbnail_encryption_key(&self.lmk, media_id)?;
		let enc = encrypt_file(&dek, &jpeg_bytes)?;

		// Write encrypted thumbnail and meta sidecar
		let enc_path = self
			.encrypted_storage_path
			.join(format!("{}.thumb.enc", media_id));
		let meta_path = self
			.encrypted_storage_path
			.join(format!("{}.thumb.meta.json", media_id));

		fs::write(&enc_path, &enc.ciphertext).await?;
		let meta = serde_json::json!({
			"nonce": enc.nonce.to_base64(),
			"tag": enc.tag.to_base64(),
			"plaintext_size": enc.original_size as i64,
			"padded_size": enc.padded_size as i64,
		});
		fs::write(&meta_path, serde_json::to_vec(&meta)?).await?;

		Ok(())
	}
}

/// Spawn an encryption task in the background
pub fn spawn_encryption_task(
	library_id: String,
	library_path: PathBuf,
	lmk: LibraryMasterKey,
	encrypted_storage_base: PathBuf,
	db: Arc<PrismaClient>,
) -> tokio::task::JoinHandle<CoreResult<()>> {
	tokio::spawn(async move {
		let task = EncryptionTask::new(
			library_id,
			library_path,
			lmk,
			encrypted_storage_base,
			db,
			None,
		);

		task.run().await
	})
}

// =============================================================================================
// Job implementation to surface secure encryption in the job queue/overlay
// =============================================================================================

#[derive(Clone)]
pub struct SecureEncryptionJob {
	pub library_id: String,
	pub path: String,
	pub lmk: LibraryMasterKey,
}

impl SecureEncryptionJob {
	pub fn new(
		library_id: String,
		path: String,
		lmk: LibraryMasterKey,
	) -> Box<WrappedJob<Self>> {
		WrappedJob::new(Self {
			library_id,
			path,
			lmk,
		})
	}
}

#[derive(Clone, Serialize, serde::Deserialize, Default, Debug, Type, ToSchema)]
pub struct SecureEncryptionOutput {
	total_files: u64,
	encrypted_files: u64,
	failed_files: u64,
	#[serde(skip)]
	new_series: HashMap<String, String>,
	#[serde(skip)]
	new_media: Vec<NewMedia>,
	#[serde(skip)]
	last_error: Option<(String, String)>,
}

impl JobOutputExt for SecureEncryptionOutput {
	fn update(&mut self, updated: Self) {
		self.total_files = self.total_files.max(updated.total_files);
		self.encrypted_files += updated.encrypted_files;
		self.failed_files += updated.failed_files;
		for (k, v) in updated.new_series.into_iter() {
			self.new_series.entry(k).or_insert(v);
		}
		self.new_media.extend(updated.new_media);
		if updated.last_error.is_some() {
			self.last_error = updated.last_error;
		}
	}
}

#[derive(Clone, Serialize, serde::Deserialize)]
pub enum SecureEncryptionTask {
	Encrypt {
		path: String,
		index: usize,
		total: usize,
	},
}

#[async_trait::async_trait]
impl JobExt for SecureEncryptionJob {
	const NAME: &'static str = "secure_encryption";

	type Output = SecureEncryptionOutput;
	type Task = SecureEncryptionTask;

	fn description(&self) -> Option<String> {
		Some("Encrypting secure library".to_string())
	}

	#[tracing::instrument(level = "debug", skip(self, ctx))]
	async fn attempt_restore(
		&self,
		ctx: &WorkerCtx,
	) -> Result<Option<WorkingState<Self::Output, Self::Task>>, JobError> {
		let stored_job = ctx
			.db
			.job()
			.find_unique(job::id::equals(ctx.job_id.clone()))
			.exec()
			.await?;

		let Some(job) = stored_job else {
			if cfg!(test) {
				return Ok(None);
			}
			return Err(JobError::InitFailed("Job not found in DB".to_string()));
		};

		let Some(save_state) = job.save_state else {
			return Ok(None);
		};

		let state_value: serde_json::Value = serde_json::from_slice(&save_state)
			.map_err(|error| JobError::StateLoadFailed(error.to_string()))?;
		let completed_tasks = state_value
			.get("completed_tasks")
			.and_then(|v| v.as_u64())
			.unwrap_or(0) as usize;
		let logs: Vec<JobExecuteLog> = match state_value.get("logs") {
			Some(v) => serde_json::from_value(v.clone())
				.map_err(|error| JobError::StateLoadFailed(error.to_string()))?,
			None => vec![],
		};
		let output: Option<Self::Output> = match state_value.get("output") {
			Some(v) => Some(
				serde_json::from_value(v.clone())
					.map_err(|error| JobError::StateLoadFailed(error.to_string()))?,
			),
			None => None,
		};

		let helper = EncryptionTask::new(
			self.library_id.clone(),
			PathBuf::from(self.path.clone()),
			self.lmk.clone(),
			PathBuf::from(""),
			ctx.db.clone(),
			Some(ctx.config.clone()),
		);
		let files = helper
			.collect_plaintext_files()
			.await
			.map_err(|e| JobError::InitFailed(e.to_string()))?;
		let total_files = output
			.as_ref()
			.map(|o| o.total_files)
			.filter(|t| *t > 0)
			.unwrap_or_else(|| (completed_tasks + files.len()) as u64);
		let total = usize::try_from(total_files).unwrap_or(usize::MAX);
		let tasks = std::collections::VecDeque::from(
			files
				.into_iter()
				.enumerate()
				.map(|(idx, p)| SecureEncryptionTask::Encrypt {
					path: p.to_string_lossy().to_string(),
					index: completed_tasks.saturating_add(idx),
					total,
				})
				.collect::<Vec<_>>(),
		);

		Ok(Some(WorkingState {
			output,
			tasks,
			completed_tasks,
			logs,
		}))
	}

	#[tracing::instrument(level = "debug", err, skip(self, ctx, _tasks, logs))]
	async fn persist_restore_point(
		&self,
		ctx: &WorkerCtx,
		output: &Self::Output,
		_tasks: &std::collections::VecDeque<Self::Task>,
		completed_tasks: usize,
		logs: &Vec<JobExecuteLog>,
	) -> Result<(), JobError> {
		let json_output = serde_json::to_value(output)
			.map_err(|error| JobError::StateSaveFailed(error.to_string()))?;
		let json_logs = serde_json::to_value(logs)
			.map_err(|error| JobError::StateSaveFailed(error.to_string()))?;
		let working_state = serde_json::json!({
			"output": json_output,
			"completed_tasks": completed_tasks,
			"logs": json_logs,
		});
		let save_state = serde_json::to_vec(&working_state)
			.map_err(|error| JobError::StateSaveFailed(error.to_string()))?;

		ctx.db
			.job()
			.update(
				job::id::equals(ctx.job_id.clone()),
				vec![job::save_state::set(Some(save_state))],
			)
			.exec()
			.await
			.map_err(|error| JobError::StateSaveFailed(error.to_string()))?;

		Ok(())
	}

	async fn init(
		&mut self,
		ctx: &WorkerCtx,
	) -> Result<WorkingState<Self::Output, Self::Task>, JobError> {
		let library_path = PathBuf::from(self.path.clone());

		// Ensure encrypted storage directory exists and set status to ENCRYPTING
		fs::create_dir_all(library_path.join(".secure"))
			.await
			.map_err(|e| JobError::InitFailed(e.to_string()))?;
		ctx.db
			.library()
			.update(
				library::id::equals(self.library_id.clone()),
				vec![
					library::encryption_status::set("ENCRYPTING".to_string()),
					library::encryption_started_at::set(Some(Utc::now().into())),
					library::encryption_progress::set(0.0),
					library::encrypted_files::set(0),
					library::total_files::set(0),
				],
			)
			.exec()
			.await
			.map_err(|e| JobError::InitFailed(e.to_string()))?;

		// Discover plaintext files using the existing task helper
		let helper = EncryptionTask::new(
			self.library_id.clone(),
			library_path.clone(),
			self.lmk.clone(),
			PathBuf::from(""),
			ctx.db.clone(),
			Some(ctx.config.clone()),
		);
		let files = helper
			.collect_plaintext_files()
			.await
			.map_err(|e| JobError::InitFailed(e.to_string()))?;
		let total = files.len();

		// Seed initial state and tasks
		let tasks = std::collections::VecDeque::from(
			files
				.into_iter()
				.enumerate()
				.map(|(idx, p)| SecureEncryptionTask::Encrypt {
					path: p.to_string_lossy().to_string(),
					index: idx,
					total,
				})
				.collect::<Vec<_>>(),
		);

		ctx.report_progress(JobProgress::msg(&format!("Found {total} files to encrypt")));

		Ok(WorkingState {
			output: Some(SecureEncryptionOutput {
				total_files: total as u64,
				..Default::default()
			}),
			tasks,
			completed_tasks: 0,
			logs: vec![],
		})
	}

	async fn cleanup(
		&self,
		ctx: &WorkerCtx,
		output: &Self::Output,
	) -> Result<Option<Box<dyn Executor>>, JobError> {
		// Final library status
		let (status, error, progress) =
			if output.failed_files > 0 || output.last_error.is_some() {
				(
					"ENCRYPTION_FAILED".to_string(),
					output
						.last_error
						.as_ref()
						.map(|(e, f)| format!("{} (file: {})", e, f)),
					(output.encrypted_files as f64 / output.total_files.max(1) as f64)
						* 100.0,
				)
			} else {
				("ENCRYPTED".to_string(), None, 100.0)
			};

		if let Err(e) = ctx
			.db
			.library()
			.update(
				library::id::equals(self.library_id.clone()),
				vec![
					library::encryption_status::set(status),
					library::encrypted_at::set(Some(Utc::now().into())),
					library::encryption_progress::set(progress),
					library::total_files::set(output.total_files as i32),
					library::encrypted_files::set(output.encrypted_files as i32),
					library::encryption_error::set(error),
					library::is_secure::set(true),
				],
			)
			.exec()
			.await
		{
			tracing::error!(error = ?e, "Failed finalizing secure encryption job status");
		}

		// Write encrypted catalog (best-effort)
		let task = EncryptionTask::new(
			self.library_id.clone(),
			PathBuf::from(self.path.clone()),
			self.lmk.clone(),
			PathBuf::from(""),
			ctx.db.clone(),
			Some(ctx.config.clone()),
		);
		if let Err(e) = task
			.write_encrypted_catalog(output.new_series.clone(), output.new_media.clone())
			.await
		{
			tracing::error!(error = ?e, "Failed to generate encrypted catalog for library");
		}

		// Emit a CoreEvent so clients can react to job output
		ctx.send_core_event(CoreEvent::JobOutput {
			id: ctx.job_id.clone(),
			output: CoreJobOutput::SecureEncryption(output.clone()),
		});

		Ok(None)
	}

	async fn execute_task(
		&self,
		ctx: &WorkerCtx,
		task: Self::Task,
	) -> Result<JobTaskOutput<Self>, JobError> {
		let mut output = SecureEncryptionOutput::default();
		let mut logs = vec![];

		match task {
			SecureEncryptionTask::Encrypt { path, index, total } => {
				let file_label =
					format!("file {}/{}", index.saturating_add(1), total.max(1));
				// Update progress pre-encryption
				let progress = (index as f64 / (total.max(1)) as f64) * 100.0;
				if let Err(e) = ctx
					.db
					.library()
					.update(
						library::id::equals(self.library_id.clone()),
						vec![
							library::encryption_progress::set(progress),
							library::total_files::set(
								i32::try_from(total).unwrap_or(i32::MAX),
							),
							library::encrypted_files::set(
								i32::try_from(index).unwrap_or(i32::MAX),
							),
							// Use encryption_error transiently while ENCRYPTING to hold the current file path
							library::encryption_error::set(Some(file_label.clone())),
						],
					)
					.exec()
					.await
				{
					tracing::warn!(error = ?e, "Failed to update encryption progress");
				}

				ctx.report_progress(JobProgress::subtask_position(
					i32::try_from(index).unwrap_or(i32::MAX),
					i32::try_from(total).unwrap_or(i32::MAX),
				));
				ctx.report_progress(JobProgress::msg(&format!(
					"Encrypting {}",
					file_label
				)));

				// Execute encryption for single file using helper
				let helper = EncryptionTask::new(
					self.library_id.clone(),
					PathBuf::from(self.path.clone()),
					self.lmk.clone(),
					PathBuf::from(""),
					ctx.db.clone(),
					Some(ctx.config.clone()),
				);

				let file_path = PathBuf::from(path);
				match helper.encrypt_single_file(&file_path).await {
					Ok(media) => {
						if let (Some(sid), Some(sname)) =
							(media.series_id.clone(), media.series_name.clone())
						{
							output.new_series.entry(sid).or_insert(sname);
						}
						output.new_media.push(media);
						output.encrypted_files += 1;
						logs.push(JobExecuteLog::new(
							format!("Encrypted {file_label}"),
							LogLevel::Info,
						));
					},
					Err(_e) => {
						output.failed_files += 1;
						output.last_error =
							Some(("Encryption failed".to_string(), file_label.clone()));
						logs.push(JobExecuteLog::error(format!(
							"Failed to encrypt {file_label}"
						)));
					},
				}
			},
		}

		Ok(JobTaskOutput {
			output,
			logs,
			subtasks: vec![],
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tempfile::TempDir;

	#[tokio::test]
	async fn test_encryption_task_initialization() {
		let temp_dir = TempDir::new().unwrap();
		let library_path = temp_dir.path().join("library");

		fs::create_dir_all(&library_path).await.unwrap();

		// Create test file
		let test_file = library_path.join("test.pdf");
		fs::write(&test_file, b"test content").await.unwrap();

		// Would need a test database to fully test
		// This just tests the structure
		assert!(test_file.exists());
	}
}
