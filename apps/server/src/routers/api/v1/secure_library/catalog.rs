//! Catalog V1 data structures and read/write operations

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use prisma_client_rust::chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::fs as async_fs;

use axum::http::StatusCode;
use stump_core::crypto::{
	encrypt::{decrypt_file, encrypt_file, EncryptedFile},
	keys::derive_data_encryption_key,
	types::{AesGcmNonce, AesGcmTag},
	LibraryMasterKey,
};

use crate::{
	errors::{secure_error_codes, APIResult},
	secure::fs as secure_fs,
};

use super::helpers::secure_api_error;

// ============================================================================
// Catalog Data Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct CatalogSeriesV1 {
	pub id: String,
	pub name: String,
	pub cover_media_id: Option<String>,
	pub sort_order: i32,
	pub volume: Option<i32>,
	pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct CatalogMediaV1 {
	pub id: String,
	pub series_id: Option<String>,
	pub name: String,
	pub pages: i32,
	pub extension: String,
	pub size: u64,
	pub sort_order: i32,
	pub number: Option<i32>,
	pub volume: Option<i32>,
	pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct CatalogV1 {
	pub version: u32,
	pub total_series: u32,
	pub total_media: u32,
	pub library_id: String,
	pub series: Vec<CatalogSeriesV1>,
	pub media: Vec<CatalogMediaV1>,
	pub updated_at: String,
}

// ============================================================================
// Catalog Operations
// ============================================================================

/// Normalize catalog entries - sort and assign sort orders
pub(crate) fn normalize_catalog_v1(catalog: &mut CatalogV1) {
	let now = Utc::now().to_rfc3339();

	catalog.media.sort_by(|a, b| {
		a.series_id
			.cmp(&b.series_id)
			.then_with(|| a.name.cmp(&b.name))
	});

	let mut current_series_id: Option<String> = None;
	let mut current_sort_order = 0;
	let mut cover_media_ids: HashMap<String, String> = HashMap::new();
	for media in catalog.media.iter_mut() {
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

	catalog.series.sort_by(|a, b| a.name.cmp(&b.name));
	for (idx, series) in catalog.series.iter_mut().enumerate() {
		series.sort_order = idx as i32;
		series.updated_at = now.clone();
		series.cover_media_id = cover_media_ids.get(&series.id).cloned();
	}

	catalog.total_series = catalog.series.len() as u32;
	catalog.total_media = catalog.media.len() as u32;
	catalog.updated_at = now;
}

/// Read and decrypt the catalog from disk
pub(crate) async fn read_decrypted_catalog_v1(
	library_path: &str,
	lmk: &LibraryMasterKey,
) -> APIResult<CatalogV1> {
	let (catalog_path, meta_path) = secure_fs::catalog_paths_for(library_path);

	let meta_bytes = async_fs::read(&meta_path).await.map_err(|e| {
		secure_api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			secure_error_codes::DELETION_FAILED,
			format!("Failed to read secure catalog metadata: {}", e),
		)
	})?;
	let enc_bytes = async_fs::read(&catalog_path).await.map_err(|e| {
		secure_api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			secure_error_codes::DELETION_FAILED,
			format!("Failed to read secure catalog: {}", e),
		)
	})?;

	let meta: serde_json::Value = serde_json::from_slice(&meta_bytes).map_err(|e| {
		secure_api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			secure_error_codes::DELETION_FAILED,
			format!("Invalid secure catalog metadata JSON: {}", e),
		)
	})?;
	let nonce_b64 = meta.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
	let tag_b64 = meta.get("tag").and_then(|v| v.as_str()).unwrap_or("");
	let plaintext_size = meta
		.get("plaintext_size")
		.and_then(|v| v.as_u64())
		.unwrap_or(0);
	let padded_size = meta
		.get("padded_size")
		.and_then(|v| v.as_u64())
		.unwrap_or(plaintext_size);
	if plaintext_size < 16 {
		return Err(secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			"X-LMK header missing or fails catalog decryption".to_string(),
		));
	}

	let nonce_bytes = BASE64.decode(nonce_b64).unwrap_or_default();
	let tag_bytes = BASE64.decode(tag_b64).unwrap_or_default();
	let nonce = AesGcmNonce::from_slice(&nonce_bytes).map_err(|_| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			"X-LMK header missing or fails catalog decryption".to_string(),
		)
	})?;
	let tag = AesGcmTag::from_slice(&tag_bytes).map_err(|_| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			"X-LMK header missing or fails catalog decryption".to_string(),
		)
	})?;

	let dek = derive_data_encryption_key(lmk, "catalog").map_err(|_| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			"X-LMK header missing or fails catalog decryption".to_string(),
		)
	})?;
	let encrypted = EncryptedFile {
		ciphertext: enc_bytes,
		nonce,
		tag,
		original_size: usize::try_from(plaintext_size).unwrap_or(0),
		padded_size: usize::try_from(padded_size).unwrap_or(0),
	};

	let json_bytes = decrypt_file(&dek, &encrypted).map_err(|_| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			"X-LMK header missing or fails catalog decryption".to_string(),
		)
	})?;

	let catalog: CatalogV1 = serde_json::from_slice(&json_bytes).map_err(|_| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			"X-LMK header missing or fails catalog decryption".to_string(),
		)
	})?;

	if catalog.version != 1 {
		return Err(secure_api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			secure_error_codes::DELETION_FAILED,
			"Unsupported secure catalog version".to_string(),
		));
	}

	Ok(catalog)
}

/// Encrypt and write the catalog to disk
pub(crate) async fn write_encrypted_catalog_v1(
	library_path: &str,
	lmk: &LibraryMasterKey,
	catalog: &CatalogV1,
) -> APIResult<()> {
	let (catalog_path, meta_path) = secure_fs::catalog_paths_for(library_path);
	let catalog_bytes = serde_json::to_vec(catalog).map_err(|e| {
		secure_api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			secure_error_codes::DELETION_FAILED,
			format!("Failed to serialize secure catalog: {}", e),
		)
	})?;

	let dek = derive_data_encryption_key(lmk, "catalog").map_err(|e| {
		secure_api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			secure_error_codes::DELETION_FAILED,
			format!("Failed to derive catalog DEK: {}", e),
		)
	})?;
	let encrypted = encrypt_file(&dek, &catalog_bytes).map_err(|e| {
		secure_api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			secure_error_codes::DELETION_FAILED,
			format!("Failed to encrypt secure catalog: {}", e),
		)
	})?;

	if let Some(dir) = catalog_path.parent() {
		async_fs::create_dir_all(dir).await.map_err(|e| {
			secure_api_error(
				StatusCode::INTERNAL_SERVER_ERROR,
				secure_error_codes::DELETION_FAILED,
				format!("Failed to create .secure directory: {}", e),
			)
		})?;
	}

	async_fs::write(&catalog_path, &encrypted.ciphertext)
		.await
		.map_err(|e| {
			secure_api_error(
				StatusCode::INTERNAL_SERVER_ERROR,
				secure_error_codes::DELETION_FAILED,
				format!("Failed to write secure catalog: {}", e),
			)
		})?;

	let meta = serde_json::json!({
		"nonce": encrypted.nonce.to_base64(),
		"tag": encrypted.tag.to_base64(),
		"plaintext_size": encrypted.original_size,
		"padded_size": encrypted.padded_size,
	});
	let meta_bytes = serde_json::to_vec(&meta).map_err(|e| {
		secure_api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			secure_error_codes::DELETION_FAILED,
			format!("Failed to serialize secure catalog metadata: {}", e),
		)
	})?;
	async_fs::write(&meta_path, meta_bytes).await.map_err(|e| {
		secure_api_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			secure_error_codes::DELETION_FAILED,
			format!("Failed to write secure catalog metadata: {}", e),
		)
	})?;

	Ok(())
}
