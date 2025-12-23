//! Access control handlers for secure libraries
//!
//! - Grant access
//! - Revoke access
//! - List access grants
//! - Get wrapped LMK

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Extension, Json,
};
use serde_json::json;

use stump_core::{
	crypto::services::{AccessControlService, KeyManagementService},
	db::entity::CryptoAuditEventType,
	prisma::{crypto_audit_log, library, secure_library_access, user},
};

use crate::{
	config::state::AppState,
	errors::{secure_error_codes, APIError, APIResult},
	middleware::auth::RequestContext,
};

use super::{
	helpers::{extract_smk, secure_api_error},
	types::{
		AccessListResponse, AccessListUser, GrantAccessRequest, GrantAccessResponse,
		RevokeAccessRequest, RevokeAccessResponse, WrappedLmkResponse,
	},
};

/// Grant a user access to a secure library
///
/// This endpoint:
/// 1. Retrieves user's X25519 public key
/// 2. Derives LMK from SMK
/// 3. Wraps LMK for user using ECDH
/// 4. Stores encrypted LMK in database
///
/// **Requires:** X-SMK header with System Master Key
#[utoipa::path(
	post,
	path = "/api/v1/admin/secure/libraries/{id}/grant-access",
	tag = "secure-library",
	params(("id" = String, Path, description = "Library ID")),
	request_body = GrantAccessRequest,
	responses(
		(status = 200, description = "Access granted successfully", body = GrantAccessResponse),
		(status = 401, description = "Missing or invalid SMK"),
		(status = 403, description = "Not a server owner"),
		(status = 404, description = "Library not found"),
	)
)]
pub(crate) async fn grant_library_access(
	Path(library_id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	headers: axum::http::HeaderMap,
	Json(payload): Json<GrantAccessRequest>,
) -> APIResult<Json<GrantAccessResponse>> {
	let user = req.user();

	// Only server owners can grant access
	if !user.is_server_owner {
		return Err(secure_api_error(
			StatusCode::FORBIDDEN,
			secure_error_codes::FORBIDDEN,
			"Only server owners can grant access".to_string(),
		));
	}

	// Extract SMK from header
	let smk = extract_smk(&headers)?;

	// Verify library exists and is secure
	let library = ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(format!("Database error: {}", e)))?
		.ok_or_else(|| {
			secure_api_error(
				StatusCode::NOT_FOUND,
				secure_error_codes::LIBRARY_NOT_FOUND,
				"Library not found".to_string(),
			)
		})?;

	if !library.is_secure {
		return Err(secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::NOT_SECURE_LIBRARY,
			"Library is not a secure library".to_string(),
		));
	}

	// Validate SMK against the target library
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
						json!({
							"event": "smk_validation_failed",
							"operation": "grant_library_access",
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

	// Grant access using AccessControlService
	let access_grant = match AccessControlService::grant_access(
		&ctx.db,
		&smk,
		&library_id,
		&payload.user_id,
		&user.id, // granted_by
	)
	.await
	{
		Ok(grant) => grant,
		Err(e) => {
			let msg = e.to_string();
			if msg.contains("User not found") {
				return Err(secure_api_error(
					StatusCode::NOT_FOUND,
					secure_error_codes::USER_NOT_FOUND,
					"User not found".to_string(),
				));
			} else if msg.contains("User has no X25519 keypair")
				|| msg.contains("has no X25519 keypair")
			{
				return Err(secure_api_error(
					StatusCode::BAD_REQUEST,
					secure_error_codes::MISSING_USER_KEYPAIR,
					"Target user has no X25519 keypair".to_string(),
				));
			} else {
				return Err(APIError::InternalServerError(format!(
					"Failed to grant access: {}",
					msg
				)));
			}
		},
	};

	let _ = ctx
		.db
		.crypto_audit_log()
		.create(
			CryptoAuditEventType::AccessGranted.to_string(),
			user.id.clone(),
			vec![
				crypto_audit_log::target_type::set(Some("LIBRARY".to_string())),
				crypto_audit_log::target_id::set(Some(library_id.clone())),
				crypto_audit_log::details::set(Some(
					json!({
						"library_id": library_id,
						"target_user_id": payload.user_id,
					})
					.to_string(),
				)),
			],
		)
		.exec()
		.await;

	Ok(Json(GrantAccessResponse {
		access_grant,
		message: "Access granted".to_string(),
	}))
}

/// Revoke a user's access to a secure library
///
/// This marks the access grant as revoked without deleting it,
/// preserving the audit trail.
#[utoipa::path(
	post,
	path = "/api/v1/admin/secure/libraries/{id}/revoke-access",
	tag = "secure-library",
	params(("id" = String, Path, description = "Library ID")),
	request_body = RevokeAccessRequest,
	responses(
		(status = 200, description = "Access revoked successfully", body = RevokeAccessResponse),
		(status = 403, description = "Not a server owner"),
		(status = 404, description = "Library not found"),
	)
)]
pub(crate) async fn revoke_library_access(
	Path(library_id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	Json(payload): Json<RevokeAccessRequest>,
) -> APIResult<Json<RevokeAccessResponse>> {
	let user = req.user();

	// Only server owners can revoke access
	if !user.is_server_owner {
		return Err(secure_api_error(
			StatusCode::FORBIDDEN,
			secure_error_codes::FORBIDDEN,
			"Only server owners can revoke access".to_string(),
		));
	}

	// Ensure the target library exists; return 404 if not found
	let _lib = ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
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

	// If there are no access grants at all for this user+library, surface a
	// canonical 404 error code. This distinguishes between "no grant exists"
	// (404/grant_not_found) and the idempotent case where a grant exists but is
	// already revoked (200 with revoked_count = 0).
	let existing_grants = ctx
		.db
		.secure_library_access()
		.find_many(vec![
			secure_library_access::library_id::equals(library_id.clone()),
			secure_library_access::user_id::equals(payload.user_id.clone()),
		])
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	if existing_grants.is_empty() {
		return Err(secure_api_error(
			StatusCode::NOT_FOUND,
			secure_error_codes::GRANT_NOT_FOUND,
			"No active grant for this user".to_string(),
		));
	}

	// Revoke access using AccessControlService (idempotent; may revoke 0 grants)
	let revoked_count = AccessControlService::revoke_access(
		&ctx.db,
		&library_id,
		&payload.user_id,
		&user.id,
	)
	.await
	.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	let _ = ctx
		.db
		.crypto_audit_log()
		.create(
			CryptoAuditEventType::AccessRevoked.to_string(),
			user.id.clone(),
			vec![
				crypto_audit_log::target_type::set(Some("LIBRARY".to_string())),
				crypto_audit_log::target_id::set(Some(library_id.clone())),
				crypto_audit_log::details::set(Some(
					json!({
						"library_id": library_id,
						"target_user_id": payload.user_id,
						"revoked_count": revoked_count,
					})
					.to_string(),
				)),
			],
		)
		.exec()
		.await;

	Ok(Json(RevokeAccessResponse {
		revoked_count,
		message: if revoked_count > 0 {
			"Access revoked successfully".to_string()
		} else {
			"Access already revoked".to_string()
		},
	}))
}

/// Get list of all access grants for a library
///
/// Returns both active and revoked access grants for audit purposes.
#[utoipa::path(
	get,
	path = "/api/v1/admin/secure/libraries/{id}/access",
	tag = "secure-library",
	params(("id" = String, Path, description = "Library ID")),
	responses(
		(status = 200, description = "Access list retrieved successfully", body = AccessListResponse),
		(status = 403, description = "Not a server owner"),
		(status = 404, description = "Library not found"),
	)
)]
pub(crate) async fn get_library_access_list(
	Path(library_id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<AccessListResponse>> {
	let user = req.user();

	if !user.is_server_owner {
		return Err(secure_api_error(
			StatusCode::FORBIDDEN,
			secure_error_codes::FORBIDDEN,
			"Only server owners can view access list".to_string(),
		));
	}

	let lib = ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
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

	if !lib.is_secure {
		return Err(secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::NOT_SECURE_LIBRARY,
			"Library is not a secure library".to_string(),
		));
	}

	let grants = ctx
		.db
		.secure_library_access()
		.find_many(vec![secure_library_access::library_id::equals(
			library_id.clone(),
		)])
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	let mut users = Vec::new();
	for grant in grants {
		let target_user = ctx
			.db
			.user()
			.find_unique(user::id::equals(grant.user_id.clone()))
			.exec()
			.await
			.map_err(|e| APIError::InternalServerError(e.to_string()))?;
		if let Some(u) = target_user {
			users.push(AccessListUser {
				user_id: u.id,
				username: u.username,
				granted_at: grant.granted_at.to_rfc3339(),
				is_revoked: grant.revoked_at.is_some(),
			});
		}
	}

	Ok(Json(AccessListResponse { users }))
}

/// Get wrapped LMK for a secure library
///
/// Returns the encrypted Library Master Key (LMK) wrapped for the user's
/// X25519 public key. The user must have an active access grant.
#[utoipa::path(
	get,
	path = "/api/v1/secure/libraries/{id}/access",
	tag = "secure-library",
	params(("id" = String, Path, description = "Library ID")),
	responses(
		(status = 200, description = "Wrapped LMK retrieved successfully", body = WrappedLmkResponse),
		(status = 404, description = "Library not found or user has no access grant"),
	)
)]
pub(crate) async fn get_wrapped_lmk(
	Path(library_id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<WrappedLmkResponse>> {
	let user = req.user();

	// Ensure the target library exists and is a secure library
	let library = ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?
		.ok_or(APIError::NotFound("Library not found".to_string()))?;

	if !library.is_secure {
		return Err(APIError::NotFound("Library not found".to_string()));
	}

	// Get user's access grant; return 404 when the caller lacks secure_library_access
	let access_grant =
		stump_core::db::query::secure_library_access::get_user_library_access(
			&ctx.db,
			&user.id,
			&library_id,
		)
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?
		.ok_or(APIError::NotFound("Library not found".to_string()))?;

	Ok(Json(WrappedLmkResponse {
		encrypted_lmk: access_grant.encrypted_lmk,
		lmk_ephemeral_public: access_grant.lmk_ephemeral_public,
		lmk_nonce: access_grant.lmk_nonce,
	}))
}
