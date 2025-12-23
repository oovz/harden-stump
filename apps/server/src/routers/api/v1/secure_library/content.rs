//! Content serving handlers for secure libraries
//!
//! - Catalog endpoint
//! - Media file endpoint
//! - Thumbnail endpoint

use axum::{
	body::Body,
	extract::{Path, State},
	http::{HeaderValue, StatusCode},
	response::{IntoResponse, Response},
	Extension,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use tokio::fs as async_fs;

use stump_core::{
	db::entity::CryptoAuditEventType,
	prisma::{crypto_audit_log, library},
};

use crate::{
	config::state::AppState,
	errors::{APIError, APIResult},
	middleware::auth::RequestContext,
	secure::fs as secure_fs,
};

use super::helpers::SECURE_CONTENT_CSP;

/// Return encrypted media bytes with nonce/tag headers for client-side decryption
#[utoipa::path(
    get,
    path = "/api/v1/secure/libraries/{library_id}/media/{id}/file",
    tag = "secure-library",
    params(("library_id" = String, Path, description = "Library ID"), ("id" = String, Path, description = "Media ID")),
    responses(
        (status = 200, description = "Encrypted media content"),
        (status = 404, description = "Media not found or inaccessible"),
        (status = 423, description = "File not yet encrypted; try later"),
        (status = 503, description = "Secure library unavailable due to encryption failure"),
    ),
)]
pub(crate) async fn get_secure_media_file_v2(
	Path((library_id, id)): Path<(String, String)>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Response> {
	let user = req.user();

	// Block API key contexts and OPDS JWTs
	if req.api_key().is_some() || matches!(req.token_type().as_deref(), Some("opds")) {
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
							"event": "secure_media_access_blocked",
							"reason": "api_key_or_opds_context",
							"library_id": library_id,
						})
						.to_string(),
					)),
				],
			)
			.exec()
			.await;
		return Err(APIError::NotFound("Media not found".to_string()));
	}

	// Enforce ACL: must be able to access the library
	let can_access = stump_core::db::query::library_acl::can_user_access_library(
		&ctx.db,
		&user.id,
		&library_id,
		user.is_server_owner,
	)
	.await
	.map_err(|e| APIError::InternalServerError(e.to_string()))?;
	if !can_access {
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
							"event": "secure_media_access_blocked",
							"reason": "no_access_grant",
							"library_id": library_id,
							"user_id": user.id,
						})
						.to_string(),
					)),
				],
			)
			.exec()
			.await;
		return Err(APIError::NotFound("Media not found".to_string()));
	}

	// Locate encrypted file and sidecar under <library_path>/.secure/
	let lib = ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?
		.ok_or(APIError::NotFound("Media not found".to_string()))?;

	// For secure libraries, enforce ENCRYPTION_FAILED/ENCRYPTING semantics for non-owner users
	if lib.is_secure && !user.is_server_owner {
		if lib.encryption_status == "ENCRYPTION_FAILED" {
			let body = serde_json::json!({
				"message": "Secure library is temporarily unavailable due to encryption errors. Contact the server owner.",
			})
			.to_string();
			let resp = Response::builder()
				.status(StatusCode::SERVICE_UNAVAILABLE)
				.header("Content-Type", HeaderValue::from_static("application/json"))
				.body(Body::from(body))
				.unwrap_or_else(|e| {
					(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
				});
			return Ok(resp);
		} else if lib.encryption_status == "ENCRYPTING" {
			let body = serde_json::json!({
				"message": "Secure library is currently being encrypted and is temporarily unavailable. Try again later or contact the server owner.",
			})
			.to_string();
			let resp = Response::builder()
				.status(StatusCode::LOCKED)
				.header("Retry-After", HeaderValue::from_static("60"))
				.header("Content-Type", HeaderValue::from_static("application/json"))
				.body(Body::from(body))
				.unwrap_or_else(|e| {
					(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
				});
			return Ok(resp);
		}
	}

	let (enc_path, meta_path) = secure_fs::media_paths_for(&lib.path, &id);

	let meta_bytes = match async_fs::read(&meta_path).await {
		Ok(b) => b,
		Err(e) => {
			// For non-owner callers on secure libraries that have already
			// attempted encryption, promote missing sidecars to
			// ENCRYPTION_BROKEN. New libraries in NOT_ENCRYPTED fall back to
			// a masked 404; the UI is responsible for interpreting
			// NOT_ENCRYPTED via the status endpoint.
			if lib.is_secure && !user.is_server_owner {
				match lib.encryption_status.as_str() {
					"ENCRYPTED" | "ENCRYPTION_FAILED" => {
						let error_msg = format!(
							"Secure media sidecar missing or unreadable ({}). Library is in ENCRYPTION_BROKEN state.",
							e,
						);
						let _ = ctx
							.db
							.library()
							.update(
								library::id::equals(lib.id.clone()),
								vec![
									library::encryption_status::set(
										"ENCRYPTION_BROKEN".to_string(),
									),
									library::encryption_error::set(Some(
										error_msg.clone(),
									)),
								],
							)
							.exec()
							.await;
						let body = serde_json::json!({
							"message": "Secure library is currently broken. Contact the server owner to restore from backup and rescan.",
						})
						.to_string();
						let resp = Response::builder()
							.status(StatusCode::SERVICE_UNAVAILABLE)
							.header(
								"Content-Type",
								HeaderValue::from_static("application/json"),
							)
							.body(Body::from(body))
							.unwrap_or_else(|e| {
								(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
									.into_response()
							});
						return Ok(resp);
					},
					_ => {},
				}
			}
			return Err(APIError::NotFound("Media not found".to_string()));
		},
	};
	let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	let enc_bytes = match async_fs::read(&enc_path).await {
		Ok(b) => b,
		Err(e) => {
			if lib.is_secure && !user.is_server_owner {
				match lib.encryption_status.as_str() {
					"ENCRYPTED" | "ENCRYPTION_FAILED" => {
						let error_msg = format!(
							"Secure media file missing or unreadable ({}). Library is in ENCRYPTION_BROKEN state.",
							e,
						);
						let _ = ctx
							.db
							.library()
							.update(
								library::id::equals(lib.id.clone()),
								vec![
									library::encryption_status::set(
										"ENCRYPTION_BROKEN".to_string(),
									),
									library::encryption_error::set(Some(
										error_msg.clone(),
									)),
								],
							)
							.exec()
							.await;
						let body = serde_json::json!({
							"message": "Secure library is currently broken. Contact the server owner to restore from backup and rescan.",
						})
						.to_string();
						let resp = Response::builder()
							.status(StatusCode::SERVICE_UNAVAILABLE)
							.header(
								"Content-Type",
								HeaderValue::from_static("application/json"),
							)
							.body(Body::from(body))
							.unwrap_or_else(|e| {
								(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
									.into_response()
							});
						return Ok(resp);
					},
					_ => {},
				}
			}
			return Err(APIError::NotFound("Media not found".to_string()));
		},
	};

	let nonce = meta.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
	let tag = meta.get("tag").and_then(|v| v.as_str()).unwrap_or("");
	let size_hint = meta
		.get("plaintext_size")
		.and_then(|v| v.as_i64())
		.or_else(|| meta.get("original_size").and_then(|v| v.as_i64()));

	// Fallback: if plaintext size is missing/invalid, try to locate the tag within enc_bytes
	let mut computed_plaintext_size: Option<usize> =
		size_hint.and_then(|v| if v > 0 { Some(v as usize) } else { None });
	if computed_plaintext_size
		.map(|sz| sz > enc_bytes.len() || sz < 16)
		.unwrap_or(true)
	{
		if let Ok(tag_bytes) = BASE64.decode(tag) {
			if tag_bytes.len() == 16 {
				// Search from the end for the 16-byte tag sequence
				let mut found: Option<usize> = None;
				let len = enc_bytes.len();
				if len >= 16 {
					for i in (16..=len).rev() {
						if enc_bytes[i - 16..i] == tag_bytes[..] {
							found = Some(i);
							break;
						}
					}
				}
				computed_plaintext_size = found;
			}
		}
	}

	let mut resp = Response::builder()
		.status(StatusCode::OK)
		.header(
			"Content-Type",
			HeaderValue::from_static("application/octet-stream"),
		)
		.header(
			"Cache-Control",
			HeaderValue::from_static("private, no-store"),
		)
		.header(
			"X-Nonce",
			HeaderValue::from_str(nonce).unwrap_or(HeaderValue::from_static("")),
		)
		.header(
			"X-Tag",
			HeaderValue::from_str(tag).unwrap_or(HeaderValue::from_static("")),
		)
		.header(
			"Content-Security-Policy",
			HeaderValue::from_static(SECURE_CONTENT_CSP),
		);

	if let Some(sz) = computed_plaintext_size {
		let size_str = sz.to_string();
		let header_value =
			HeaderValue::from_str(&size_str).unwrap_or(HeaderValue::from_static("0"));
		resp = resp
			.header("X-Plaintext-Size", header_value.clone())
			.header("X-Original-Size", header_value);
	}

	Ok(resp.body(Body::from(enc_bytes)).unwrap_or_else(|e| {
		(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
	}))
}

/// Return encrypted thumbnail bytes with nonce/tag headers
#[utoipa::path(
    get,
    path = "/api/v1/secure/libraries/{library_id}/media/{id}/thumbnail",
    tag = "secure-library",
    params(("library_id" = String, Path, description = "Library ID"), ("id" = String, Path, description = "Media ID")),
    responses(
        (status = 200, description = "Encrypted thumbnail"),
        (status = 404, description = "Thumbnail not found or inaccessible"),
        (status = 423, description = "Thumbnail not yet encrypted; try later"),
    ),
)]
pub(crate) async fn get_secure_media_thumbnail(
	Path((library_id, id)): Path<(String, String)>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Response> {
	let user = req.user();

	if req.api_key().is_some() || matches!(req.token_type().as_deref(), Some("opds")) {
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
							"event": "secure_thumbnail_access_blocked",
							"reason": "api_key_or_opds_context",
							"library_id": library_id,
						})
						.to_string(),
					)),
				],
			)
			.exec()
			.await;
		return Err(APIError::NotFound("Thumbnail not found".to_string()));
	}

	let can_access = stump_core::db::query::library_acl::can_user_access_library(
		&ctx.db,
		&user.id,
		&library_id,
		user.is_server_owner,
	)
	.await
	.map_err(|e| APIError::InternalServerError(e.to_string()))?;
	if !can_access {
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
							"event": "secure_thumbnail_access_blocked",
							"reason": "no_access_grant",
							"library_id": library_id,
						})
						.to_string(),
					)),
				],
			)
			.exec()
			.await;
		return Err(APIError::NotFound("Thumbnail not found".to_string()));
	}

	let lib = ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?
		.ok_or(APIError::NotFound("Thumbnail not found".to_string()))?;

	if lib.is_secure && !user.is_server_owner && lib.encryption_status == "ENCRYPTING" {
		let body = serde_json::json!({
			"message": "Secure library is currently being encrypted and is temporarily unavailable. Try again later or contact the server owner.",
		})
		.to_string();
		let resp = Response::builder()
			.status(StatusCode::LOCKED)
			.header("Retry-After", HeaderValue::from_static("60"))
			.header("Content-Type", HeaderValue::from_static("application/json"))
			.body(Body::from(body))
			.unwrap_or_else(|e| {
				(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
			});
		return Ok(resp);
	}

	let (enc_path, meta_path) = secure_fs::thumbnail_paths_for(&lib.path, &id);

	let meta_bytes = async_fs::read(&meta_path)
		.await
		.map_err(|_| APIError::NotFound("Thumbnail not found".to_string()))?;
	let enc_bytes = async_fs::read(&enc_path)
		.await
		.map_err(|_| APIError::NotFound("Thumbnail not found".to_string()))?;

	let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	let nonce = meta.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
	let tag = meta.get("tag").and_then(|v| v.as_str()).unwrap_or("");
	let size_hint = meta.get("plaintext_size").and_then(|v| v.as_u64());

	let mut resp = Response::builder()
		.status(StatusCode::OK)
		.header(
			"Content-Type",
			HeaderValue::from_static("application/octet-stream"),
		)
		.header(
			"Cache-Control",
			HeaderValue::from_static("private, no-store"),
		)
		.header(
			"X-Nonce",
			HeaderValue::from_str(nonce).unwrap_or(HeaderValue::from_static("")),
		)
		.header(
			"X-Tag",
			HeaderValue::from_str(tag).unwrap_or(HeaderValue::from_static("")),
		)
		.header(
			"Content-Security-Policy",
			HeaderValue::from_static(SECURE_CONTENT_CSP),
		);

	if let Some(sz) = size_hint {
		let size_str = sz.to_string();
		let header_value =
			HeaderValue::from_str(&size_str).unwrap_or(HeaderValue::from_static("0"));
		resp = resp
			.header("X-Plaintext-Size", header_value.clone())
			.header("X-Original-Size", header_value);
	}

	Ok(resp.body(Body::from(enc_bytes)).unwrap_or_else(|e| {
		(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
	}))
}

/// Return encrypted catalog bytes with nonce/tag headers
#[utoipa::path(
    get,
    path = "/api/v1/secure/libraries/{id}/catalog",
    tag = "secure-library",
    params(("id" = String, Path, description = "Library ID")),
    responses(
        (status = 200, description = "Encrypted catalog content"),
        (status = 404, description = "Library not found or inaccessible"),
        (status = 423, description = "Catalog not yet encrypted; try later"),
        (status = 503, description = "Secure library unavailable due to encryption failure"),
    )
)]
pub(crate) async fn get_secure_library_catalog(
	Path(library_id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Response> {
	let user = req.user();

	if req.api_key().is_some() || matches!(req.token_type().as_deref(), Some("opds")) {
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
							"event": "secure_catalog_access_blocked",
							"reason": "api_key_or_opds_context",
							"library_id": library_id,
						})
						.to_string(),
					)),
				],
			)
			.exec()
			.await;
		return Err(APIError::NotFound("Library not found".to_string()));
	}

	let can_access = stump_core::db::query::library_acl::can_user_access_library(
		&ctx.db,
		&user.id,
		&library_id,
		user.is_server_owner,
	)
	.await
	.map_err(|e| APIError::InternalServerError(e.to_string()))?;
	if !can_access {
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
							"event": "secure_catalog_access_blocked",
							"reason": "no_access_grant",
							"library_id": library_id,
							"user_id": user.id,
						})
						.to_string(),
					)),
				],
			)
			.exec()
			.await;
		return Err(APIError::NotFound("Library not found".to_string()));
	}

	// Resolve secure directory under the library's root path
	let lib = ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.map_err(|e| APIError::InternalServerError(e.to_string()))?
		.ok_or(APIError::NotFound("Library not found".to_string()))?;

	if lib.is_secure && !user.is_server_owner {
		if lib.encryption_status == "ENCRYPTION_FAILED" {
			let body = serde_json::json!({
				"message": "Secure library is temporarily unavailable due to encryption errors. Contact the server owner.",
			})
			.to_string();
			let resp = Response::builder()
				.status(StatusCode::SERVICE_UNAVAILABLE)
				.header("Content-Type", HeaderValue::from_static("application/json"))
				.body(Body::from(body))
				.unwrap_or_else(|e| {
					(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
				});
			return Ok(resp);
		} else if lib.encryption_status == "ENCRYPTING" {
			let body = serde_json::json!({
				"message": "Secure library is currently being encrypted and is temporarily unavailable. Try again later or contact the server owner.",
			})
			.to_string();
			let resp = Response::builder()
				.status(StatusCode::LOCKED)
				.header("Retry-After", HeaderValue::from_static("60"))
				.header("Content-Type", HeaderValue::from_static("application/json"))
				.body(Body::from(body))
				.unwrap_or_else(|e| {
					(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
				});
			return Ok(resp);
		}
	}

	let (catalog_path, meta_path) = secure_fs::catalog_paths_for(&lib.path);

	let meta_bytes = match async_fs::read(&meta_path).await {
		Ok(b) => b,
		Err(e) => {
			// For non-owner callers on secure libraries that have already
			// attempted encryption, promote missing catalog metadata to
			// ENCRYPTION_BROKEN. New libraries in NOT_ENCRYPTED fall back to
			// a masked 404; the UI is responsible for interpreting
			// NOT_ENCRYPTED via the status endpoint.
			if lib.is_secure && !user.is_server_owner {
				match lib.encryption_status.as_str() {
					"ENCRYPTED" | "ENCRYPTION_FAILED" => {
						let error_msg = format!(
							"Secure catalog metadata missing or unreadable ({}). Library is in ENCRYPTION_BROKEN state.",
							e,
						);
						let _ = ctx
							.db
							.library()
							.update(
								library::id::equals(lib.id.clone()),
								vec![
									library::encryption_status::set(
										"ENCRYPTION_BROKEN".to_string(),
									),
									library::encryption_error::set(Some(
										error_msg.clone(),
									)),
								],
							)
							.exec()
							.await;
						let body = serde_json::json!({
							"message": "Secure library is currently broken. Contact the server owner to restore from backup and rescan.",
						})
						.to_string();
						let resp = Response::builder()
							.status(StatusCode::SERVICE_UNAVAILABLE)
							.header(
								"Content-Type",
								HeaderValue::from_static("application/json"),
							)
							.body(Body::from(body))
							.unwrap_or_else(|e| {
								(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
									.into_response()
							});
						return Ok(resp);
					},
					_ => return Err(APIError::NotFound("Library not found".to_string())),
				}
			}
			return Err(APIError::NotFound("Library not found".to_string()));
		},
	};
	let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
		.map_err(|e| APIError::InternalServerError(e.to_string()))?;

	let enc_bytes = match async_fs::read(&catalog_path).await {
		Ok(b) => b,
		Err(e) => {
			if lib.is_secure && !user.is_server_owner {
				match lib.encryption_status.as_str() {
					"ENCRYPTED" | "ENCRYPTION_FAILED" => {
						let error_msg = format!(
							"Secure catalog file missing or unreadable ({}). Library is in ENCRYPTION_BROKEN state.",
							e,
						);
						let _ = ctx
							.db
							.library()
							.update(
								library::id::equals(lib.id.clone()),
								vec![
									library::encryption_status::set(
										"ENCRYPTION_BROKEN".to_string(),
									),
									library::encryption_error::set(Some(
										error_msg.clone(),
									)),
								],
							)
							.exec()
							.await;
						let body = serde_json::json!({
							"message": "Secure library is currently broken. Contact the server owner to restore from backup and rescan.",
						})
						.to_string();
						let resp = Response::builder()
							.status(StatusCode::SERVICE_UNAVAILABLE)
							.header(
								"Content-Type",
								HeaderValue::from_static("application/json"),
							)
							.body(Body::from(body))
							.unwrap_or_else(|e| {
								(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
									.into_response()
							});
						return Ok(resp);
					},
					_ => {},
				}
			}
			return Err(APIError::NotFound("Library not found".to_string()));
		},
	};

	let nonce = meta.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
	let tag = meta.get("tag").and_then(|v| v.as_str()).unwrap_or("");
	let plaintext_size = meta.get("plaintext_size").and_then(|v| v.as_u64());

	let mut resp = Response::builder()
		.status(StatusCode::OK)
		.header(
			"Content-Type",
			HeaderValue::from_static("application/octet-stream"),
		)
		.header(
			"Cache-Control",
			HeaderValue::from_static("private, no-store"),
		)
		.header(
			"X-Nonce",
			HeaderValue::from_str(nonce).unwrap_or(HeaderValue::from_static("")),
		)
		.header(
			"X-Tag",
			HeaderValue::from_str(tag).unwrap_or(HeaderValue::from_static("")),
		)
		.header(
			"Content-Security-Policy",
			HeaderValue::from_static(SECURE_CONTENT_CSP),
		);

	if let Some(sz) = plaintext_size {
		let size_str = sz.to_string();
		let header_value =
			HeaderValue::from_str(&size_str).unwrap_or(HeaderValue::from_static("0"));
		resp = resp
			.header("X-Plaintext-Size", header_value.clone())
			.header("X-Original-Size", header_value);
	}

	Ok(resp.body(Body::from(enc_bytes)).unwrap_or_else(|e| {
		(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
	}))
}
