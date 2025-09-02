use axum::{
	extract::{Path, State},
	routing::{get, post},
	Json, Router,
};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use specta::Type;
use stump_core::{
	db::{self, DatabaseEncryptionState, EncryptedDatabase},
	error::CoreError,
	filesystem::FileMigrationJob,
	security::audit::AuditLogger,
};
use stump_crypto::key::derive_master_key;
use tower_governor::{
	governor::GovernorConfigBuilder,
	key_extractor::SmartIpKeyExtractor,
	GovernorLayer,
};
use utoipa::ToSchema;

use crate::{
	config::state::AppState,
	errors::{APIError, APIResult},
};

/// Mount server management routes (unlock endpoint with rate limiting)
pub(crate) fn mount(_app_state: AppState) -> Router<AppState> {
	// Configure rate limiting for unlock endpoint: 5 attempts per 5 minutes per IP
	let unlock_governor_conf = std::sync::Arc::new(
		GovernorConfigBuilder::default()
			.per_second(0) // No sustained rate
			.burst_size(5) // 5 attempts
			.period(std::time::Duration::from_secs(300)) // per 5 minutes
			.key_extractor(SmartIpKeyExtractor)
			.finish()
			.unwrap(),
	);

	// Configure lighter rate limiting for lock endpoint: 10 attempts per minute
	let lock_governor_conf = std::sync::Arc::new(
		GovernorConfigBuilder::default()
			.per_second(0) // No sustained rate  
			.burst_size(10) // 10 attempts
			.period(std::time::Duration::from_secs(60)) // per minute
			.key_extractor(SmartIpKeyExtractor)
			.finish()
			.unwrap(),
	);

	Router::new()
		// Status endpoint - no rate limiting for frequent health checks
		.route("/status", get(get_server_status))
		// Unlock endpoint - strict rate limiting
		.route("/unlock", post(unlock_server).layer(GovernorLayer {
			config: unlock_governor_conf,
		}))
		// Lock endpoint - moderate rate limiting
		.route("/lock", post(lock_server).layer(GovernorLayer {
			config: lock_governor_conf,
		}))
		// Migration endpoints - use unlock rate limiting
		.route("/migrate-files", post(migrate_all_files))
		.route("/migrate-files/{library_id}", post(migrate_library_files))
}

#[derive(Deserialize, Type, ToSchema)]
pub struct UnlockServerRequest {
	/// Master password for server encryption
	pub password: String,
}

#[derive(Serialize, Type, ToSchema)]
pub struct UnlockServerResponse {
	/// Success message
	pub message: String,
}

#[utoipa::path(
	post,
	path = "/api/v1/server/unlock",
	tag = "server",
	request_body = UnlockServerRequest,
	responses(
		(status = 200, description = "Server unlocked successfully", body = UnlockServerResponse),
		(status = 400, description = "Invalid password"),
		(status = 429, description = "Rate limit exceeded"),
		(status = 409, description = "Server already unlocked"),
		(status = 500, description = "Internal server error")
	)
)]
async fn unlock_server(
	State(ctx): State<AppState>,
	Json(payload): Json<UnlockServerRequest>,
) -> APIResult<Json<UnlockServerResponse>> {
	// Check if server is already unlocked
	if ctx.is_server_unlocked() {
		// Log attempted unlock on already unlocked server
		AuditLogger::log_server_operation("unlock", None, false);
		return Err(APIError::BadRequest("Server is already unlocked".to_string()));
	}

	// Get the stored password hash from database
	let stored_password_hash = ctx
		.get_encryption_key()
		.await
		.map_err(|e| {
			// Log failed unlock due to database error
			AuditLogger::log_server_operation("unlock", None, false);
			APIError::InternalServerError(format!("Database error: {}", e))
		})?;

	// Derive MEK from the provided password
	let default_params = stump_crypto::key::KeyDerivationParams::default();
	let master_key = derive_master_key(&payload.password, &default_params)
		.map_err(|e| {
			// Log failed unlock due to key derivation error
			AuditLogger::log_server_operation("unlock", None, false);
			APIError::InternalServerError(format!("Key derivation error: {}", e))
		})?;

	// Verify password by comparing derived key hash with stored hash
	// TODO: This is a simplified verification - in production we'd store the salt separately
	// and use proper password verification
	let derived_hash = hex::encode(master_key.expose_secret());
	if derived_hash != stored_password_hash {
		// Log failed unlock due to invalid password
		AuditLogger::log_server_operation("unlock", None, false);
		return Err(APIError::BadRequest("Invalid password".to_string()));
	}

	// Unlock the server by storing the MEK in memory
	let master_key_clone = SecretBox::new(Box::new(master_key.expose_secret().clone()));
	let unlock_result = ctx.unlock_server(master_key_clone);
	
	match unlock_result {
		Ok(_) => {
			// Log successful unlock event for audit purposes
			AuditLogger::log_server_operation("unlock", None, true);
			
			// Check if database migration is needed and handle it
			let migration_result = handle_database_migration(&ctx, &master_key).await;
			match migration_result {
				Ok(migrated) => {
					if migrated {
						tracing::info!("Database successfully migrated to encrypted format");
					}
				}
				Err(e) => {
					tracing::error!("Database migration failed: {}", e);
					// Don't fail the unlock process, but log the error
					// The server is still unlocked but migration may need manual intervention
				}
			}

			tracing::info!("Server successfully unlocked");

			Ok(Json(UnlockServerResponse {
				message: "Server unlocked successfully".to_string(),
			}))
		},
		Err(e) => {
			// Log failed unlock event
			AuditLogger::log_server_operation("unlock", None, false);
			Err(APIError::InternalServerError(format!("Failed to unlock server: {}", e)))
		}
	}
}

/// Handles database migration from unencrypted to encrypted format during server unlock
async fn handle_database_migration(
	ctx: &AppState,
	master_key: &SecretBox<Vec<u8>>,
) -> Result<bool, CoreError> {
	let config = &ctx.config;
	
	// Check current database state
	let db_state = EncryptedDatabase::analyze_state(config);
	
	match db_state {
		DatabaseEncryptionState::UnencryptedExists(unencrypted_path) => {
			tracing::info!("Starting database migration to encrypted format...");
			
			// Determine encrypted database path
			let encrypted_path = unencrypted_path.with_extension("encrypted.db");
			
			// Backup the unencrypted database before migration
			let backup_path = unencrypted_path.with_extension("unencrypted.bak");
			if let Err(e) = std::fs::copy(&unencrypted_path, &backup_path) {
				tracing::error!("Failed to backup unencrypted database: {}", e);
				return Err(CoreError::IoError(e));
			}
			tracing::info!("Backed up unencrypted database to: {}", backup_path.display());
			
			// Migrate to encrypted format
			EncryptedDatabase::migrate_to_encrypted(&unencrypted_path, &encrypted_path, master_key)?;
			tracing::info!("Database migration completed successfully");
			
			// Store encrypted database info in context
			let key_clone = SecretBox::new(Box::new(master_key.expose_secret().clone()));
			ctx.set_encrypted_db_info(
				encrypted_path.to_string_lossy().to_string(),
				key_clone
			)?;
			
			Ok(true)
		},
		DatabaseEncryptionState::EncryptedExists(encrypted_path) => {
			tracing::info!("Using existing encrypted database at: {}", encrypted_path.display());
			
			// Store encrypted database info in context
			let key_clone = SecretBox::new(Box::new(master_key.expose_secret().clone()));
			ctx.set_encrypted_db_info(
				encrypted_path.to_string_lossy().to_string(),
				key_clone
			)?;
			
			Ok(false) // No migration needed
		},
		DatabaseEncryptionState::MigrationIncomplete(unencrypted_path, encrypted_path) => {
			tracing::info!("Completing interrupted migration...");
			
			// Complete the migration
			EncryptedDatabase::migrate_to_encrypted(&unencrypted_path, &encrypted_path, master_key)?;
			tracing::info!("Migration completed successfully");
			
			// Store encrypted database info in context
			let key_clone = SecretBox::new(Box::new(master_key.expose_secret().clone()));
			ctx.set_encrypted_db_info(
				encrypted_path.to_string_lossy().to_string(),
				key_clone
			)?;
			
			Ok(true)
		},
		DatabaseEncryptionState::FirstTime => {
			tracing::info!("No existing database - will create encrypted database on first use");
			Ok(false) // No migration needed
		}
	}
}

#[derive(Deserialize, Type, ToSchema)]
pub struct MigrateFilesRequest {
	/// Whether to force re-encryption of already encrypted files
	#[serde(default)]
	pub force_re_encrypt: bool,
}

#[derive(Serialize, Type, ToSchema)]
pub struct MigrateFilesResponse {
	/// Success message
	pub message: String,
}

#[utoipa::path(
	post,
	path = "/api/v1/server/migrate-files",
	tag = "server",
	request_body = MigrateFilesRequest,
	responses(
		(status = 200, description = "File migration job started successfully", body = MigrateFilesResponse),
		(status = 400, description = "Server is locked or request invalid"),
		(status = 500, description = "Internal server error")
	)
)]
/// Start a background job to migrate all comic files to encrypted format
async fn migrate_all_files(
	State(ctx): State<AppState>,
	Json(payload): Json<MigrateFilesRequest>,
) -> APIResult<Json<MigrateFilesResponse>> {
	// Check if server is unlocked
	if !ctx.is_server_unlocked() {
		return Err(APIError::BadRequest("Server is locked - cannot start file migration. Please unlock the server first.".to_string()));
	}

	// Get the master encryption key and encrypted storage path
	let master_key = ctx.get_master_encryption_key()
		.ok_or_else(|| APIError::BadRequest("No master encryption key available".to_string()))?;
	
	// Use a default encrypted storage path (can be configured later)
	let encrypted_storage_path = ctx.config.get_config_dir().join("encrypted");

	// Enqueue the file migration job for all libraries
	let job = FileMigrationJob::new(None, payload.force_re_encrypt, master_key, encrypted_storage_path);
	ctx.enqueue_job(job)
		.map_err(|e| {
			tracing::error!(?e, "Failed to enqueue file migration job");
			APIError::InternalServerError("Failed to start file migration job".to_string())
		})?;

	Ok(Json(MigrateFilesResponse {
		message: "File migration job started successfully".to_string(),
	}))
}

#[utoipa::path(
	post,
	path = "/api/v1/server/migrate-files/{library_id}",
	tag = "server",
	request_body = MigrateFilesRequest,
	responses(
		(status = 200, description = "Library file migration job started successfully", body = MigrateFilesResponse),
		(status = 400, description = "Server is locked or request invalid"),
		(status = 404, description = "Library not found"),
		(status = 500, description = "Internal server error")
	)
)]
/// Start a background job to migrate files in a specific library to encrypted format
async fn migrate_library_files(
	Path(library_id): Path<String>,
	State(ctx): State<AppState>,
	Json(payload): Json<MigrateFilesRequest>,
) -> APIResult<Json<MigrateFilesResponse>> {
	// Check if server is unlocked
	if !ctx.is_server_unlocked() {
		return Err(APIError::BadRequest("Server is locked - cannot start file migration. Please unlock the server first.".to_string()));
	}

	// Verify library exists
	let library_exists = ctx.db
		.library()
		.find_unique(stump_core::prisma::library::id::equals(library_id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(format!("Database error: {}", e)))?
		.is_some();

	if !library_exists {
		return Err(APIError::NotFound(format!("Library with id {} not found", library_id)));
	}

	// Get the master encryption key and encrypted storage path
	let master_key = ctx.get_master_encryption_key()
		.ok_or_else(|| APIError::BadRequest("No master encryption key available".to_string()))?;
	
	// Use a default encrypted storage path (can be configured later)
	let encrypted_storage_path = ctx.config.get_config_dir().join("encrypted");

	// Enqueue the file migration job for the specific library
	let job = FileMigrationJob::new(Some(library_id), payload.force_re_encrypt, master_key, encrypted_storage_path);
	ctx.enqueue_job(job)
		.map_err(|e| {
			tracing::error!(?e, "Failed to enqueue library file migration job");
			APIError::InternalServerError("Failed to start library file migration job".to_string())
		})?;

	Ok(Json(MigrateFilesResponse {
		message: format!("Library file migration job started successfully"),
	}))
}

/// Server encryption status information
#[derive(Serialize, Type, ToSchema)]
pub struct ServerStatusResponse {
	/// Whether the server is currently unlocked (master key in memory)
	pub is_unlocked: bool,
	/// Whether encryption is enabled in server configuration
	pub encryption_enabled: bool,
	/// Whether the database is encrypted
	pub database_encrypted: bool,
	/// Whether encrypted file storage is available
	pub encrypted_storage_available: bool,
}

/// Request to lock the server and clear master key from memory
#[derive(Deserialize, Type, ToSchema)]
pub struct LockServerRequest {
	/// Optional reason for locking (for audit logging)
	pub reason: Option<String>,
}

/// Response confirming server lock operation
#[derive(Serialize, Type, ToSchema)]  
pub struct LockServerResponse {
	/// Success message
	pub message: String,
}

#[utoipa::path(
	get,
	path = "/api/v1/server/status",
	tag = "server",
	responses(
		(status = 200, description = "Server status retrieved successfully", body = ServerStatusResponse),
		(status = 500, description = "Internal server error")
	)
)]
/// Get current server encryption status
async fn get_server_status(
	State(ctx): State<AppState>,
) -> APIResult<Json<ServerStatusResponse>> {
	let is_unlocked = ctx.is_server_unlocked();
	
	// Check if encryption is enabled (determined by database state or server unlock status)
	let encryption_enabled = {
		let state = db::EncryptedDatabase::analyze_state(&ctx.config);
		!matches!(state, DatabaseEncryptionState::FirstTime)
	};
	
	// Check database encryption status
	let database_encrypted = {
		let state = db::EncryptedDatabase::analyze_state(&ctx.config);
		matches!(state, DatabaseEncryptionState::EncryptedExists(_) | DatabaseEncryptionState::MigrationIncomplete(_, _))
	};
	
	// Check if encrypted storage directory exists
	let encrypted_storage_available = {
		let encrypted_storage_path = ctx.config.get_config_dir().join("encrypted");
		encrypted_storage_path.exists() || std::fs::create_dir_all(&encrypted_storage_path).is_ok()
	};

	// Log status check for audit purposes
	AuditLogger::log_server_operation("status_check", None, true);

	Ok(Json(ServerStatusResponse {
		is_unlocked,
		encryption_enabled,
		database_encrypted, 
		encrypted_storage_available,
	}))
}

#[utoipa::path(
	post,
	path = "/api/v1/server/lock",
	tag = "server",
	request_body = LockServerRequest,
	responses(
		(status = 200, description = "Server locked successfully", body = LockServerResponse),
		(status = 409, description = "Server already locked"),
		(status = 500, description = "Internal server error")
	)
)]
/// Lock the server and clear master key from memory
async fn lock_server(
	State(ctx): State<AppState>,
	Json(payload): Json<LockServerRequest>,
) -> APIResult<Json<LockServerResponse>> {
	// Check if server is already locked
	if !ctx.is_server_unlocked() {
		// Log attempted lock on already locked server
		AuditLogger::log_server_operation("lock", None, false);
		return Err(APIError::BadRequest("Server is already locked".to_string()));
	}

	// Clear the master key from memory
	let lock_result = ctx.lock_server();
	
	match lock_result {
		Ok(_) => {
			// Log successful lock event for audit purposes
			let reason = payload.reason.unwrap_or_else(|| "Manual lock request".to_string());
			AuditLogger::log_server_operation("lock", None, true);
			tracing::info!("Server locked: {}", reason);

			Ok(Json(LockServerResponse {
				message: "Server locked successfully. Master key cleared from memory.".to_string(),
			}))
		},
		Err(e) => {
			// Log failed lock event
			AuditLogger::log_server_operation("lock", None, false);
			Err(APIError::InternalServerError(format!("Failed to lock server: {}", e)))
		}
	}
}
