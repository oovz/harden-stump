//! List and status handlers for secure libraries

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Extension, Json,
};
use tokio::fs as async_fs;

use stump_core::prisma::library;

use crate::{
	config::state::AppState,
	errors::{secure_error_codes, APIError, APIResult},
	middleware::auth::RequestContext,
	secure::fs as secure_fs,
};

use super::{
	helpers::secure_api_error,
	types::{
		AccessStatusResponse, JobProgressStatus, SecureLibraryStatus,
		SecureLibrarySummary,
	},
};

/// Get encryption status for a secure library (admin)
#[utoipa::path(
    get,
    path = "/api/v1/admin/secure/libraries/{id}/status",
    tag = "secure-library",
    params(("id" = String, Path, description = "Library ID")),
    responses((status = 200, description = "Secure library status", body = SecureLibraryStatus))
)]
pub(crate) async fn get_secure_library_status(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<SecureLibraryStatus>> {
	let user = req.user();
	if !user.is_server_owner {
		return Err(secure_api_error(
			StatusCode::FORBIDDEN,
			secure_error_codes::FORBIDDEN,
			"Only server owners can view status".to_string(),
		));
	}

	let lib = ctx
		.db
		.library()
		.find_unique(library::id::equals(id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?
		.ok_or_else(|| {
			secure_api_error(
				StatusCode::NOT_FOUND,
				secure_error_codes::LIBRARY_NOT_FOUND,
				"Library not found".to_string(),
			)
		})?;

	// Detect missing secure storage for libraries that have already attempted encryption.
	// If .secure or catalog.enc are missing while the library is marked ENCRYPTED or ENCRYPTION_FAILED,
	// mark the status as ENCRYPTION_BROKEN so clients can surface a clear error state.
	let mut encryption_status = lib.encryption_status.clone();
	let mut encryption_error = lib.encryption_error.clone();
	if lib.is_secure
		&& (encryption_status == "ENCRYPTED" || encryption_status == "ENCRYPTION_FAILED")
	{
		let secure_dir = secure_fs::secure_dir_for(&lib.path);
		let has_secure_dir = async_fs::metadata(&secure_dir).await.is_ok();
		let (catalog_path, _) = secure_fs::catalog_paths_for(&lib.path);
		let has_catalog = async_fs::metadata(catalog_path).await.is_ok();

		if !has_secure_dir || !has_catalog {
			let error_msg =
				"Secure storage missing; library is in ENCRYPTION_BROKEN state"
					.to_string();
			ctx.db
				.library()
				.update(
					library::id::equals(lib.id.clone()),
					vec![
						library::encryption_status::set("ENCRYPTION_BROKEN".to_string()),
						library::encryption_error::set(Some(error_msg.clone())),
					],
				)
				.exec()
				.await
				.map_err(|e| APIError::InternalServerError(e.to_string()))?;

			encryption_status = "ENCRYPTION_BROKEN".to_string();
			encryption_error = Some(error_msg);
		}
	}
	// Derive current_file from the library row while ENCRYPTING. The encryption job
	// uses `encryption_error` transiently in this state to hold the current file path.
	let current_file = if encryption_status == "ENCRYPTING" {
		lib.encryption_error.clone()
	} else {
		None
	};

	// Do not expose the transient current file path via the error field while ENCRYPTING.
	if encryption_status == "ENCRYPTING" {
		encryption_error = None;
	}

	let job_progress = JobProgressStatus {
		processed: lib.encrypted_files,
		total: lib.total_files,
		current_file,
	};

	let status = SecureLibraryStatus {
		library_id: lib.id.clone(),
		encryption_status,
		encrypted_files: lib.encrypted_files,
		total_files: lib.total_files,
		progress: lib.encryption_progress,
		error: encryption_error,
		job_progress,
	};

	Ok(Json(status))
}

/// Lightweight access-status endpoint for secure libraries
///
/// Returns `has_access: true` when the current user has an active
/// `SecureLibraryAccess` grant for the target library. When the user
/// lacks access (including revoked grants or missing keypair), this
/// endpoint returns 404 to preserve the 404-masking posture.
#[utoipa::path(
	get,
	path = "/api/v1/secure/libraries/{id}/access-status",
	tag = "secure-library",
	params(("id" = String, Path, description = "Library ID")),
	responses(
		(status = 200, description = "Access status for the current user", body = AccessStatusResponse),
		(status = 404, description = "Library not found or user has no access grant"),
	),
)]
pub(crate) async fn get_secure_library_access_status(
	Path(library_id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<AccessStatusResponse>> {
	let user = req.user();

	// `SecureLibraryAccess` is authoritative for access; we intentionally
	// do not distinguish between a missing library and a missing grant to
	// preserve 404-masking for unauthorized callers.
	let access_grant =
		stump_core::db::query::secure_library_access::get_user_library_access(
			&ctx.db,
			&user.id,
			&library_id,
		)
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	match access_grant {
		Some(_) => Ok(Json(AccessStatusResponse { has_access: true })),
		None => Err(APIError::NotFound("Library not found".to_string())),
	}
}

/// List secure libraries the current user can access
#[utoipa::path(
    get,
    path = "/api/v1/secure/libraries",
    tag = "secure-library",
    responses(
        (status = 200, description = "Accessible secure libraries", body = [SecureLibrarySummary]),
    )
)]
pub(crate) async fn list_secure_libraries(
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<Vec<SecureLibrarySummary>>> {
	let user = req.user();

	// Fetch library IDs with active access grants
	let ids =
		stump_core::db::query::secure_library_access::get_user_accessible_libraries(
			&ctx.db, &user.id,
		)
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	if ids.is_empty() {
		return Ok(Json(Vec::new()));
	}

	// Fetch secure libraries matching the IDs
	let libraries = ctx
		.db
		.library()
		.find_many(vec![
			library::id::in_vec(ids.clone()),
			library::is_secure::equals(true),
		])
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	let libraries = libraries
		.into_iter()
		.map(|l| SecureLibrarySummary {
			id: l.id,
			name: l.name,
			is_secure: l.is_secure,
			encryption_status: l.encryption_status,
		})
		.collect();

	Ok(Json(libraries))
}
