//! Delete handlers for secure media and series

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Extension, Json,
};
use serde_json::json;
use tokio::fs as async_fs;

use stump_core::{
	db::entity::CryptoAuditEventType,
	prisma::{crypto_audit_log, library},
};

use crate::{
	config::state::AppState,
	errors::{secure_error_codes, APIResult},
	middleware::auth::RequestContext,
	secure::fs as secure_fs,
};

use super::{
	catalog::{
		normalize_catalog_v1, read_decrypted_catalog_v1, write_encrypted_catalog_v1,
	},
	helpers::{extract_lmk, secure_api_error},
	types::{DeleteMediaResponse, DeleteSeriesResponse},
};

/// Emit audit log for secure item deletion events
async fn emit_secure_item_deleted_audit(
	ctx: &AppState,
	user_id: &str,
	library_id: &str,
	details: serde_json::Value,
) {
	let _ = ctx
		.db
		.crypto_audit_log()
		.create(
			CryptoAuditEventType::SecureItemDeleted.to_string(),
			user_id.to_string(),
			vec![
				crypto_audit_log::target_type::set(Some("LIBRARY".to_string())),
				crypto_audit_log::target_id::set(Some(library_id.to_string())),
				crypto_audit_log::details::set(Some(details.to_string())),
			],
		)
		.exec()
		.await;
}

/// Delete a single media item from a secure library
///
/// This removes the media from the encrypted catalog and deletes the
/// encrypted media and thumbnail files from disk.
pub(crate) async fn delete_secure_media(
	Path((library_id, id)): Path<(String, String)>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	headers: axum::http::HeaderMap,
) -> APIResult<Json<DeleteMediaResponse>> {
	let user = req.user();
	if !user.is_server_owner {
		let has_access =
			stump_core::db::query::secure_library_access::user_has_library_access(
				&ctx.db,
				&user.id,
				&library_id,
			)
			.await
			.map_err(|e| {
				secure_api_error(
					StatusCode::INTERNAL_SERVER_ERROR,
					secure_error_codes::DELETION_FAILED,
					format!("Database error: {}", e),
				)
			})?;
		if !has_access {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_media_delete_attempt",
					"library_id": library_id,
					"media_id": id,
					"item_type": "media",
					"item_count": 1,
					"success": false,
					"error_code": secure_error_codes::LIBRARY_NOT_FOUND,
				}),
			)
			.await;
			return Err(secure_api_error(
				StatusCode::NOT_FOUND,
				secure_error_codes::LIBRARY_NOT_FOUND,
				"Library not found or no access".to_string(),
			));
		}
		emit_secure_item_deleted_audit(
			&ctx,
			&user.id,
			&library_id,
			json!({
				"event": "secure_media_delete_attempt",
				"library_id": library_id,
				"media_id": id,
				"item_type": "media",
				"item_count": 1,
				"success": false,
				"error_code": secure_error_codes::FORBIDDEN,
			}),
		)
		.await;
		return Err(secure_api_error(
			StatusCode::FORBIDDEN,
			secure_error_codes::FORBIDDEN,
			"Only server owners can delete secure items".to_string(),
		));
	}

	let lmk = match extract_lmk(&headers) {
		Ok(lmk) => lmk,
		Err(err) => {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_media_delete_attempt",
					"library_id": library_id,
					"media_id": id,
					"item_type": "media",
					"item_count": 1,
					"success": false,
					"error_code": secure_error_codes::INVALID_LMK,
				}),
			)
			.await;
			return Err(err);
		},
	};

	let lib = match ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
	{
		Ok(Some(lib)) => lib,
		Ok(None) => {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_media_delete_attempt",
					"library_id": library_id,
					"media_id": id,
					"item_type": "media",
					"item_count": 1,
					"success": false,
					"error_code": secure_error_codes::LIBRARY_NOT_FOUND,
				}),
			)
			.await;
			return Err(secure_api_error(
				StatusCode::NOT_FOUND,
				secure_error_codes::LIBRARY_NOT_FOUND,
				"Library not found or no access".to_string(),
			));
		},
		Err(e) => {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_media_delete_attempt",
					"library_id": library_id,
					"media_id": id,
					"item_type": "media",
					"item_count": 1,
					"success": false,
					"error_code": secure_error_codes::DELETION_FAILED,
				}),
			)
			.await;
			return Err(secure_api_error(
				StatusCode::INTERNAL_SERVER_ERROR,
				secure_error_codes::DELETION_FAILED,
				format!("Database error: {}", e),
			));
		},
	};
	if !lib.is_secure {
		emit_secure_item_deleted_audit(
			&ctx,
			&user.id,
			&library_id,
			json!({
				"event": "secure_media_delete_attempt",
				"library_id": library_id,
				"media_id": id,
				"item_type": "media",
				"item_count": 1,
				"success": false,
				"error_code": secure_error_codes::LIBRARY_NOT_FOUND,
			}),
		)
		.await;
		return Err(secure_api_error(
			StatusCode::NOT_FOUND,
			secure_error_codes::LIBRARY_NOT_FOUND,
			"Library not found or no access".to_string(),
		));
	}
	if lib.encryption_status == "ENCRYPTING" {
		emit_secure_item_deleted_audit(
			&ctx,
			&user.id,
			&library_id,
			json!({
				"event": "secure_media_delete_attempt",
				"library_id": library_id,
				"media_id": id,
				"item_type": "media",
				"item_count": 1,
				"success": false,
				"error_code": secure_error_codes::ENCRYPTION_IN_PROGRESS,
			}),
		)
		.await;
		return Err(secure_api_error(
			StatusCode::LOCKED,
			secure_error_codes::ENCRYPTION_IN_PROGRESS,
			"Cannot delete while encryption is in progress".to_string(),
		));
	}

	let _guard = ctx.lock_secure_library(&library_id).await;

	let mut catalog = match read_decrypted_catalog_v1(&lib.path, &lmk).await {
		Ok(catalog) => catalog,
		Err(err) => {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_media_delete_attempt",
					"library_id": library_id,
					"media_id": id,
					"success": false,
					"error_code": secure_error_codes::INVALID_LMK,
				}),
			)
			.await;
			return Err(err);
		},
	};
	let mut series_auto_deleted: Vec<String> = Vec::new();

	let media_idx = catalog.media.iter().position(|m| m.id == id);
	let removed = match media_idx {
		Some(idx) => catalog.media.remove(idx),
		None => {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_media_delete_attempt",
					"library_id": library_id,
					"media_id": id,
					"item_type": "media",
					"item_count": 1,
					"success": false,
					"error_code": secure_error_codes::ITEM_NOT_FOUND,
				}),
			)
			.await;
			return Err(secure_api_error(
				StatusCode::NOT_FOUND,
				secure_error_codes::ITEM_NOT_FOUND,
				"Media ID not found in catalog".to_string(),
			));
		},
	};

	if let Some(series_id) = removed.series_id.clone() {
		let still_has_media = catalog
			.media
			.iter()
			.any(|m| m.series_id.as_deref() == Some(series_id.as_str()));
		if !still_has_media {
			let before = catalog.series.len();
			catalog.series.retain(|s| s.id != series_id);
			if catalog.series.len() != before {
				series_auto_deleted.push(series_id);
			}
		}
	}

	normalize_catalog_v1(&mut catalog);
	if let Err(err) = write_encrypted_catalog_v1(&lib.path, &lmk, &catalog).await {
		emit_secure_item_deleted_audit(
			&ctx,
			&user.id,
			&library_id,
			json!({
				"event": "secure_media_delete_attempt",
				"library_id": library_id,
				"media_id": id,
				"item_type": "media",
				"item_count": 1,
				"success": false,
				"error_code": secure_error_codes::DELETION_FAILED,
			}),
		)
		.await;
		return Err(err);
	}
	drop(lmk);

	let (enc_path, meta_path) = secure_fs::media_paths_for(&lib.path, &id);
	let (thumb_path, thumb_meta_path) = secure_fs::thumbnail_paths_for(&lib.path, &id);
	for (label, path) in [
		("media.enc", &enc_path),
		("media.meta", &meta_path),
		("thumb.enc", &thumb_path),
		("thumb.meta", &thumb_meta_path),
	] {
		if let Err(e) = async_fs::remove_file(path).await {
			if e.kind() != std::io::ErrorKind::NotFound {
				tracing::warn!(
					library_id = %library_id,
					media_id = %id,
					file = %label,
					error = %e,
					"secure deletion: failed to remove encrypted file",
				);
			}
		}
	}

	emit_secure_item_deleted_audit(
		&ctx,
		&user.id,
		&library_id,
		json!({
			"event": "secure_media_deleted",
			"library_id": library_id,
			"media_id": id,
			"series_auto_deleted": series_auto_deleted,
			"item_type": "media",
			"item_count": 1,
			"success": true,
		}),
	)
	.await;

	Ok(Json(DeleteMediaResponse {
		deleted_ids: vec![removed.id],
		series_auto_deleted,
		message: "Media deleted successfully".to_string(),
	}))
}

/// Delete a series and all its media from a secure library
///
/// This removes the series and all associated media from the encrypted
/// catalog, and deletes all encrypted files from disk.
pub(crate) async fn delete_secure_series(
	Path((library_id, id)): Path<(String, String)>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	headers: axum::http::HeaderMap,
) -> APIResult<Json<DeleteSeriesResponse>> {
	let user = req.user();
	if !user.is_server_owner {
		let has_access =
			stump_core::db::query::secure_library_access::user_has_library_access(
				&ctx.db,
				&user.id,
				&library_id,
			)
			.await
			.map_err(|e| {
				secure_api_error(
					StatusCode::INTERNAL_SERVER_ERROR,
					secure_error_codes::DELETION_FAILED,
					format!("Database error: {}", e),
				)
			})?;
		if !has_access {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_series_delete_attempt",
					"library_id": library_id,
					"series_id": id,
					"item_type": "series",
					"item_count": 1,
					"success": false,
					"error_code": secure_error_codes::LIBRARY_NOT_FOUND,
				}),
			)
			.await;
			return Err(secure_api_error(
				StatusCode::NOT_FOUND,
				secure_error_codes::LIBRARY_NOT_FOUND,
				"Library not found or no access".to_string(),
			));
		}
		emit_secure_item_deleted_audit(
			&ctx,
			&user.id,
			&library_id,
			json!({
				"event": "secure_series_delete_attempt",
				"library_id": library_id,
				"series_id": id,
				"item_type": "series",
				"item_count": 1,
				"success": false,
				"error_code": secure_error_codes::FORBIDDEN,
			}),
		)
		.await;
		return Err(secure_api_error(
			StatusCode::FORBIDDEN,
			secure_error_codes::FORBIDDEN,
			"Only server owners can delete secure items".to_string(),
		));
	}

	let lmk = match extract_lmk(&headers) {
		Ok(lmk) => lmk,
		Err(err) => {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_series_delete_attempt",
					"library_id": library_id,
					"series_id": id,
					"item_type": "series",
					"item_count": 1,
					"success": false,
					"error_code": secure_error_codes::INVALID_LMK,
				}),
			)
			.await;
			return Err(err);
		},
	};

	let lib = match ctx
		.db
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
	{
		Ok(Some(lib)) => lib,
		Ok(None) => {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_series_delete_attempt",
					"library_id": library_id,
					"series_id": id,
					"item_type": "series",
					"item_count": 1,
					"success": false,
					"error_code": secure_error_codes::LIBRARY_NOT_FOUND,
				}),
			)
			.await;
			return Err(secure_api_error(
				StatusCode::NOT_FOUND,
				secure_error_codes::LIBRARY_NOT_FOUND,
				"Library not found or no access".to_string(),
			));
		},
		Err(e) => {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_series_delete_attempt",
					"library_id": library_id,
					"series_id": id,
					"item_type": "series",
					"item_count": 1,
					"success": false,
					"error_code": secure_error_codes::DELETION_FAILED,
				}),
			)
			.await;
			return Err(secure_api_error(
				StatusCode::INTERNAL_SERVER_ERROR,
				secure_error_codes::DELETION_FAILED,
				format!("Database error: {}", e),
			));
		},
	};
	if !lib.is_secure {
		emit_secure_item_deleted_audit(
			&ctx,
			&user.id,
			&library_id,
			json!({
				"event": "secure_series_delete_attempt",
				"library_id": library_id,
				"series_id": id,
				"item_type": "series",
				"item_count": 1,
				"success": false,
				"error_code": secure_error_codes::LIBRARY_NOT_FOUND,
			}),
		)
		.await;
		return Err(secure_api_error(
			StatusCode::NOT_FOUND,
			secure_error_codes::LIBRARY_NOT_FOUND,
			"Library not found or no access".to_string(),
		));
	}
	if lib.encryption_status == "ENCRYPTING" {
		emit_secure_item_deleted_audit(
			&ctx,
			&user.id,
			&library_id,
			json!({
				"event": "secure_series_delete_attempt",
				"library_id": library_id,
				"series_id": id,
				"item_type": "series",
				"item_count": 1,
				"success": false,
				"error_code": secure_error_codes::ENCRYPTION_IN_PROGRESS,
			}),
		)
		.await;
		return Err(secure_api_error(
			StatusCode::LOCKED,
			secure_error_codes::ENCRYPTION_IN_PROGRESS,
			"Cannot delete while encryption is in progress".to_string(),
		));
	}

	let _guard = ctx.lock_secure_library(&library_id).await;

	let mut catalog = match read_decrypted_catalog_v1(&lib.path, &lmk).await {
		Ok(catalog) => catalog,
		Err(err) => {
			emit_secure_item_deleted_audit(
				&ctx,
				&user.id,
				&library_id,
				json!({
					"event": "secure_series_delete_attempt",
					"library_id": library_id,
					"series_id": id,
					"success": false,
					"error_code": secure_error_codes::INVALID_LMK,
				}),
			)
			.await;
			return Err(err);
		},
	};
	let series_exists = catalog.series.iter().any(|s| s.id == id);
	if !series_exists {
		emit_secure_item_deleted_audit(
			&ctx,
			&user.id,
			&library_id,
			json!({
				"event": "secure_series_delete_attempt",
				"library_id": library_id,
				"series_id": id,
				"item_type": "series",
				"item_count": 1,
				"success": false,
				"error_code": secure_error_codes::ITEM_NOT_FOUND,
			}),
		)
		.await;
		return Err(secure_api_error(
			StatusCode::NOT_FOUND,
			secure_error_codes::ITEM_NOT_FOUND,
			"Series ID not found in catalog".to_string(),
		));
	}

	let deleted_media: Vec<String> = catalog
		.media
		.iter()
		.filter(|m| m.series_id.as_deref() == Some(id.as_str()))
		.map(|m| m.id.clone())
		.collect();

	catalog.series.retain(|s| s.id != id);
	catalog
		.media
		.retain(|m| m.series_id.as_deref() != Some(id.as_str()));

	normalize_catalog_v1(&mut catalog);
	if let Err(err) = write_encrypted_catalog_v1(&lib.path, &lmk, &catalog).await {
		emit_secure_item_deleted_audit(
			&ctx,
			&user.id,
			&library_id,
			json!({
				"event": "secure_series_delete_attempt",
				"library_id": library_id,
				"series_id": id,
				"item_type": "series",
				"item_count": 1,
				"success": false,
				"error_code": secure_error_codes::DELETION_FAILED,
			}),
		)
		.await;
		return Err(err);
	}
	drop(lmk);

	for media_id in deleted_media.iter() {
		let (enc_path, meta_path) =
			secure_fs::media_paths_for(&lib.path, media_id.as_str());
		let (thumb_path, thumb_meta_path) =
			secure_fs::thumbnail_paths_for(&lib.path, media_id.as_str());
		for (label, path) in [
			("media.enc", &enc_path),
			("media.meta", &meta_path),
			("thumb.enc", &thumb_path),
			("thumb.meta", &thumb_meta_path),
		] {
			if let Err(e) = async_fs::remove_file(path).await {
				if e.kind() != std::io::ErrorKind::NotFound {
					tracing::warn!(
						library_id = %library_id,
						series_id = %id,
						media_id = %media_id,
						file = %label,
						error = %e,
						"secure deletion: failed to remove encrypted file",
					);
				}
			}
		}
	}

	let mut deleted_ids = Vec::with_capacity(1 + deleted_media.len());
	deleted_ids.push(id.clone());
	deleted_ids.extend(deleted_media.clone());

	emit_secure_item_deleted_audit(
		&ctx,
		&user.id,
		&library_id,
		json!({
			"event": "secure_series_deleted",
			"library_id": library_id,
			"series_id": id,
			"media_count": deleted_media.len(),
			"item_type": "series",
			"item_count": deleted_media.len().saturating_add(1),
			"success": true,
		}),
	)
	.await;

	Ok(Json(DeleteSeriesResponse {
		deleted_ids,
		media_count: i32::try_from(deleted_media.len()).unwrap_or(i32::MAX),
		message: format!("Series and {} media items deleted", deleted_media.len()),
	}))
}
