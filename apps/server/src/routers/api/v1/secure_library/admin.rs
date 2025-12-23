//! Admin handlers for secure library management
//!
//! - Create secure library
//! - Delete secure library
//! - Scan secure library (encrypt)

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Extension, Json,
};
use prisma_client_rust::or;
use serde_json::json;

use stump_core::{
	crypto::services::{
		encryption_task::SecureEncryptionJob, AccessControlService, KeyManagementService,
	},
	db::entity::{CryptoAuditEventType, SecureLibraryAccess},
	job::{Executor, JobStatus},
	prisma::{
		crypto_audit_log, job, library, library_config, library_encryption_metadata,
		secure_library_access,
	},
};

use crate::{
	config::state::AppState,
	errors::{secure_error_codes, APIError, APIResult},
	middleware::auth::RequestContext,
	secure::fs as secure_fs,
};

use super::{
	helpers::{extract_smk, secure_api_error},
	types::{
		CreateSecureLibraryRequest, CreateSecureLibraryResponse,
		DeleteSecureLibraryResponse, ScanSecureLibraryResponse,
	},
};

/// Create a secure library
///
/// This endpoint:
/// 1. Derives LMK from SMK for the library
/// 2. Marks library as secure in database
/// 3. Returns secure library record
///
/// **Requires:** X-SMK header with System Master Key
#[utoipa::path(
    post,
    path = "/api/v1/admin/secure/libraries",
    tag = "secure-library",
    request_body = CreateSecureLibraryRequest,
    responses(
        (status = 201, description = "Secure library created successfully", body = CreateSecureLibraryResponse),
        (status = 401, description = "Missing or invalid SMK"),
        (status = 404, description = "Library not found"),
    )
)]
pub(crate) async fn create_secure_library(
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	headers: axum::http::HeaderMap,
	Json(payload): Json<CreateSecureLibraryRequest>,
) -> APIResult<(StatusCode, Json<CreateSecureLibraryResponse>)> {
	let user = req.user();

	// Only server owners can create secure libraries
	if !user.is_server_owner {
		return Err(secure_api_error(
			StatusCode::FORBIDDEN,
			secure_error_codes::FORBIDDEN,
			"Only server owners can create secure libraries".to_string(),
		));
	}

	// Extract SMK from header
	let smk = extract_smk(&headers)?;

	// Validate SMK entropy
	smk.validate_entropy().map_err(|e| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_SMK,
			format!("Invalid SMK: {}", e),
		)
	})?;

	// Check if library path exists
	let library_path = std::path::PathBuf::from(&payload.path);
	if !library_path.exists() {
		return Err(secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::PATH_NOT_FOUND,
			"Library path does not exist".to_string(),
		));
	}

	if secure_fs::exists_secure_dir(&payload.path) {
		return Err(secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::SECURE_DIR_PRESENT,
			"Secure directory already exists for this path".to_string(),
		));
	}

	let CreateSecureLibraryRequest { name, path } = payload;

	// Create LibraryConfig with defaults, then Library linked to it
	let user_id = user.id.clone();
	let smk_for_tx = smk.clone();
	let (library, _access_grant): (library::Data, SecureLibraryAccess) = ctx
		.db
		._transaction()
		.run(|tx| {
			let name = name.clone();
			let path = path.clone();
			let user_id = user_id.clone();
			let smk = smk_for_tx.clone();

			async move {
				let lib_cfg = tx.library_config().create(vec![]).exec().await?;

				let library = tx
					.library()
					.create(
						name,
						path,
						library_config::id::equals(lib_cfg.id.clone()),
						vec![
							library::is_secure::set(true),
							library::encryption_status::set("NOT_ENCRYPTED".to_string()),
						],
					)
					.exec()
					.await?;

				// Derive LMK from SMK using the same KMS path used by validation and scans
				let lmk =
					KeyManagementService::derive_lmk(&smk, &library.id).map_err(|e| {
						APIError::InternalServerError(format!(
							"Failed to derive library key: {}",
							e
						))
					})?;

				let verification_tag =
					KeyManagementService::generate_verification_tag(&lmk, &library.id)
						.map_err(|e| {
							APIError::InternalServerError(format!(
								"Failed to generate SMK verification tag: {}",
								e
							))
						})?;

				tx.library_encryption_metadata()
					.create(library.id.clone(), verification_tag, vec![])
					.exec()
					.await?;

				let access_grant = AccessControlService::grant_access(
					&tx,
					&smk,
					&library.id,
					&user_id,
					&user_id,
				)
				.await
				.map_err(|e| {
					let msg = e.to_string();
					if msg.contains("User not found") {
						secure_api_error(
							StatusCode::NOT_FOUND,
							secure_error_codes::USER_NOT_FOUND,
							"User not found".to_string(),
						)
					} else if msg.contains("User has no X25519 keypair")
						|| msg.contains("has no X25519 keypair")
					{
						secure_api_error(
							StatusCode::BAD_REQUEST,
							secure_error_codes::MISSING_USER_KEYPAIR,
							"Target user has no X25519 keypair".to_string(),
						)
					} else {
						APIError::InternalServerError(format!(
							"Failed to auto-grant access to creator: {}",
							msg
						))
					}
				})?;

				Ok((library, access_grant)) as Result<_, APIError>
			}
		})
		.await?;
	let _ = _access_grant;

	let _ = ctx
		.db
		.crypto_audit_log()
		.create(
			CryptoAuditEventType::AccessGranted.to_string(),
			user.id.clone(),
			vec![
				crypto_audit_log::details::set(Some(
					json!({
						"library_id": library.id,
						"target_user_id": user.id,
						"auto_grant": true,
					})
					.to_string(),
				)),
				crypto_audit_log::target_id::set(Some(library.id.clone())),
			],
		)
		.exec()
		.await;

	// Log the operation
	let _ = ctx
		.db
		.crypto_audit_log()
		.create(
			CryptoAuditEventType::LibraryCreated.to_string(),
			user.id.clone(),
			vec![
				crypto_audit_log::details::set(Some(
					json!({
						"library_id": library.id,
						"library_name": library.name,
					})
					.to_string(),
				)),
				crypto_audit_log::target_id::set(Some(library.id.clone())),
			],
		)
		.exec()
		.await;

	Ok((
		StatusCode::CREATED,
		Json(CreateSecureLibraryResponse {
			id: library.id,
			name: library.name,
			is_secure: library.is_secure,
			encryption_status: library.encryption_status,
			path: library.path,
			created_at: library.created_at.to_rfc3339(),
		}),
	))
}

/// Delete a secure library
///
/// **Requires:** Server owner
#[utoipa::path(
	delete,
	path = "/api/v1/admin/secure/libraries/{id}",
	tag = "secure-library",
	params(("id" = String, Path, description = "Library ID")),
	responses(
		(status = 200, description = "Secure library deleted successfully", body = DeleteSecureLibraryResponse),
		(status = 403, description = "Not a server owner"),
		(status = 404, description = "Library not found"),
		(status = 409, description = "Cannot delete while encrypting"),
	)
)]
pub(crate) async fn delete_secure_library(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<DeleteSecureLibraryResponse>> {
	let user = req.user();

	// Only server owners can delete secure libraries
	if !user.is_server_owner {
		return Err(secure_api_error(
			StatusCode::FORBIDDEN,
			secure_error_codes::FORBIDDEN,
			"Only server owners can delete secure libraries".to_string(),
		));
	}

	let lib = ctx
		.db
		.library()
		.find_unique(library::id::equals(id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?
		.ok_or(APIError::NotFound("Library not found".to_string()))?;

	if !lib.is_secure {
		return Err(secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::NOT_SECURE_LIBRARY,
			"Library is not a secure library".to_string(),
		));
	}

	if lib.encryption_status == "ENCRYPTING" {
		return Err(secure_api_error(
			StatusCode::CONFLICT,
			secure_error_codes::ENCRYPTION_IN_PROGRESS,
			"Cannot delete secure library while encryption is in progress".to_string(),
		));
	}

	// Remove access grants for this library
	ctx.db
		.secure_library_access()
		.delete_many(vec![secure_library_access::library_id::equals(id.clone())])
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	// Remove encryption metadata for this library (if present)
	ctx.db
		.library_encryption_metadata()
		.delete_many(vec![library_encryption_metadata::library_id::equals(
			id.clone(),
		)])
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	// Finally delete the library record itself
	ctx.db
		.library()
		.delete(library::id::equals(id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	Ok(Json(DeleteSecureLibraryResponse {
		message: "Library deleted".to_string(),
	}))
}

/// Re-derive LMK from SMK and (re-)encrypt new files for a secure library
#[utoipa::path(
    post,
    path = "/api/v1/admin/secure/libraries/{id}/scan",
    tag = "secure-library",
    params(("id" = String, Path, description = "Library ID")),
    responses(
        (status = 202, description = "Secure encryption job enqueued", body = ScanSecureLibraryResponse),
        (status = 401, description = "Missing or invalid SMK"),
        (status = 403, description = "Not a server owner"),
        (status = 404, description = "Library not found"),
    )
)]
pub(crate) async fn scan_secure_library(
	Path(library_id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	headers: axum::http::HeaderMap,
) -> APIResult<(StatusCode, Json<ScanSecureLibraryResponse>)> {
	let user = req.user();

	if !user.is_server_owner {
		return Err(secure_api_error(
			StatusCode::FORBIDDEN,
			secure_error_codes::FORBIDDEN,
			"Only server owners can scan secure libraries".to_string(),
		));
	}

	// Global job queue guard: do not enqueue a new job if any job is already pending or running.
	// (at most one job of ANY type at a time).
	let blocking_job = ctx
		.db
		.job()
		.find_first(vec![or![
			job::status::equals(JobStatus::Running.to_string()),
			job::status::equals(JobStatus::Queued.to_string()),
			job::status::equals(JobStatus::Paused.to_string()),
		]])
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	if let Some(job) = blocking_job {
		return Err(secure_api_error(
			StatusCode::CONFLICT,
			secure_error_codes::JOB_ALREADY_RUNNING,
			format!(
				"A background job is already running; wait for it to finish before starting a secure scan (blocking_job_id={}, status={})",
				job.id,
				job.status
			),
		));
	}
	let _guard = ctx.lock_secure_library(&library_id).await;

	let smk = extract_smk(&headers)?;

	if let Err(_e) =
		KeyManagementService::validate_smk_for_library(&ctx.db, &smk, &library_id).await
	{
		let _ = ctx
			.db
			.crypto_audit_log()
			.create(
				CryptoAuditEventType::UnauthorizedAccessAttempt.to_string(),
				user.id.clone(),
				vec![
					crypto_audit_log::target_type::set(Some("LIBRARY".to_string())),
					crypto_audit_log::target_id::set(Some(library_id.clone())),
					crypto_audit_log::details::set(Some(
						serde_json::json!({
							"event": "smk_validation_failed",
							"operation": "scan_secure_library",
							"library_id": library_id,
						})
						.to_string(),
					)),
				],
			)
			.exec()
			.await;
		return Err(secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_SMK,
			"Invalid SMK for target library".to_string(),
		));
	}

	let library = ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?
		.ok_or(APIError::NotFound("Library not found".to_string()))?;

	let lmk = KeyManagementService::derive_lmk(&smk, &library_id)
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	let job = SecureEncryptionJob::new(library_id.clone(), library.path.clone(), lmk);
	let job_id = job.id().to_string();

	// Enqueue secure encryption as a job so it shows up in the job overlay/UI
	ctx.enqueue_job(job).map_err(|e| {
		APIError::InternalServerError(format!(
			"Failed to enqueue secure encryption job: {}",
			e
		))
	})?;

	let _ = ctx
		.db
		.crypto_audit_log()
		.create(
			CryptoAuditEventType::EncryptionStarted.to_string(),
			user.id.clone(),
			vec![
				crypto_audit_log::target_type::set(Some("LIBRARY".to_string())),
				crypto_audit_log::target_id::set(Some(library_id.clone())),
				crypto_audit_log::details::set(Some(
					json!({
						"event": "secure_library_scan_started",
						"library_id": library_id,
					})
					.to_string(),
				)),
			],
		)
		.exec()
		.await;

	Ok((
		StatusCode::ACCEPTED,
		Json(ScanSecureLibraryResponse {
			job_id,
			message: "Secure encryption job enqueued".to_string(),
		}),
	))
}
