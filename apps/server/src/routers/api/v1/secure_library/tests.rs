#![allow(unused_imports)]
//! Tests for secure library endpoints

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::{
	extract::{Path, State},
	Extension, Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use prisma_client_rust::{raw, PrismaValue};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

use crate::{
	config::state::AppState,
	errors::{secure_error_codes, APIError},
	middleware::auth::RequestContext,
};

use stump_core::crypto::services::user_keypair::UserKeypairService;
use stump_core::crypto::SystemMasterKey;
use stump_core::job::JobStatus;
use stump_core::{
	db::{
		admin_reset_user_password,
		entity::{CryptoAuditEventType, LibraryPattern, User},
		migration::run_migrations,
		CountQueryReturn,
	},
	prisma::{job, library, library_config, secure_library_access, user, PrismaClient},
	Ctx,
};
use tempfile::TempDir;

use super::{
	catalog::normalize_catalog_v1, create_secure_library, delete_secure_media,
	delete_secure_series, get_library_access_list, get_secure_library_catalog,
	get_secure_library_status, get_secure_media_file_v2, get_secure_media_thumbnail,
	get_wrapped_lmk, grant_library_access, read_decrypted_catalog_v1,
	revoke_library_access, scan_secure_library, write_encrypted_catalog_v1,
	CatalogMediaV1, CatalogSeriesV1, CatalogV1, CreateSecureLibraryRequest,
	GrantAccessRequest, RevokeAccessRequest, SECURE_CONTENT_CSP,
};

async fn extract_status_and_error(err: APIError) -> (StatusCode, serde_json::Value) {
	match err {
		APIError::Custom(response) => {
			let status = response.status();
			let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
				.await
				.expect("failed to read response body");
			let json: serde_json::Value =
				serde_json::from_slice(&bytes).expect("failed to parse JSON body");
			(status, json)
		},
		other => panic!("expected APIError::Custom, got: {:?}", other),
	}
}

async fn setup_secure_library_env() -> (AppState, User, String) {
	let ctx = Ctx::integration_test_mock().await;
	let client: &PrismaClient = ctx.db.as_ref();

	run_migrations(client)
		.await
		.expect("Failed to run migrations for secure library tests");

	let target_path = "/tmp/secure-error-posture-lib".to_string();

	let existing = client
		.library()
		.find_unique(library::path::equals(target_path.clone()))
		.exec()
		.await
		.expect("Failed to query existing secure library");

	let library = if let Some(lib) = existing {
		lib
	} else {
		let lib_cfg = client
			.library_config()
			.create(vec![library_config::library_pattern::set(
				LibraryPattern::SeriesBased.to_string(),
			)])
			.exec()
			.await
			.expect("Failed to create library config");

		client
			.library()
			.create(
				"secure-error-posture-lib".to_string(),
				target_path.clone(),
				library_config::id::equals(lib_cfg.id.clone()),
				vec![library::is_secure::set(true)],
			)
			.exec()
			.await
			.expect("Failed to create secure library")
	};

	let app_state = AppState::new(Arc::new(ctx));

	let user = User {
		id: "user-no-access".to_string(),
		username: "user-no-access".to_string(),
		..Default::default()
	};

	(app_state, user, library.id)
}

#[tokio::test]
async fn delete_secure_media_removes_media_and_auto_deletes_empty_series() {
	let ctx = Ctx::integration_test_mock().await;
	let client: &PrismaClient = ctx.db.as_ref();
	run_migrations(client)
		.await
		.expect("Failed to run migrations for delete media test");

	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-delete-media");
	std::fs::create_dir_all(&library_path).expect("failed to create library dir");
	let library_path_str = library_path.to_string_lossy().to_string();

	let lib_cfg = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("failed to create library config");

	let library = client
		.library()
		.create(
			"secure-lib-delete-media".to_string(),
			library_path_str.clone(),
			library_config::id::equals(lib_cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("failed to create secure library");

	update_library_encryption_status_with_retry(client, &library.id, "ENCRYPTED").await;

	let app_state = AppState::new(Arc::new(ctx));
	let owner = User {
		id: "owner-delete-media".to_string(),
		username: "owner-delete-media".to_string(),
		is_server_owner: true,
		..Default::default()
	};

	let lmk = stump_core::crypto::LibraryMasterKey::from_bytes([7u8; 32]);
	let lmk_b64 = BASE64.encode(lmk.expose_secret());
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-LMK",
		HeaderValue::from_str(&lmk_b64).expect("valid X-LMK"),
	);

	let series_id = "series-1".to_string();
	let media_id = "media-1".to_string();
	let now = prisma_client_rust::chrono::Utc::now().to_rfc3339();
	let mut catalog = CatalogV1 {
		version: 1,
		total_series: 1,
		total_media: 1,
		library_id: library.id.clone(),
		series: vec![CatalogSeriesV1 {
			id: series_id.clone(),
			name: "Series One".to_string(),
			cover_media_id: Some(media_id.clone()),
			sort_order: 0,
			volume: None,
			updated_at: now.clone(),
		}],
		media: vec![CatalogMediaV1 {
			id: media_id.clone(),
			series_id: Some(series_id.clone()),
			name: "Media One".to_string(),
			pages: 0,
			extension: "cbz".to_string(),
			size: 1,
			sort_order: 0,
			number: None,
			volume: None,
			updated_at: now.clone(),
		}],
		updated_at: now,
	};
	normalize_catalog_v1(&mut catalog);
	write_encrypted_catalog_v1(&library.path, &lmk, &catalog)
		.await
		.expect("failed to write encrypted catalog");

	let (enc_path, meta_path) =
		crate::secure::fs::media_paths_for(&library.path, &media_id);
	let (thumb_path, thumb_meta_path) =
		crate::secure::fs::thumbnail_paths_for(&library.path, &media_id);
	std::fs::write(&enc_path, b"enc").expect("write enc");
	std::fs::write(&meta_path, b"meta").expect("write meta");
	std::fs::write(&thumb_path, b"thumb").expect("write thumb");
	std::fs::write(&thumb_meta_path, b"thumbmeta").expect("write thumb meta");

	let req_ctx = RequestContext::new_for_tests(owner, None, None);
	let Json(resp) = delete_secure_media(
		Path((library.id.clone(), media_id.clone())),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await
	.expect("expected delete_secure_media ok");
	assert_eq!(resp.deleted_ids, vec![media_id.clone()]);
	assert_eq!(resp.series_auto_deleted, vec![series_id.clone()]);

	assert!(std::fs::metadata(&enc_path).is_err());
	assert!(std::fs::metadata(&meta_path).is_err());
	assert!(std::fs::metadata(&thumb_path).is_err());
	assert!(std::fs::metadata(&thumb_meta_path).is_err());

	let catalog_after = read_decrypted_catalog_v1(&library.path, &lmk)
		.await
		.expect("failed to decrypt catalog after delete");
	assert!(catalog_after.media.is_empty());
	assert!(catalog_after.series.is_empty());
}

#[tokio::test]
async fn delete_secure_series_removes_series_and_all_media() {
	let ctx = Ctx::integration_test_mock().await;
	let client: &PrismaClient = ctx.db.as_ref();
	run_migrations(client)
		.await
		.expect("Failed to run migrations for delete series test");

	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-delete-series");
	std::fs::create_dir_all(&library_path).expect("failed to create library dir");
	let library_path_str = library_path.to_string_lossy().to_string();

	let lib_cfg = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("failed to create library config");

	let library = client
		.library()
		.create(
			"secure-lib-delete-series".to_string(),
			library_path_str.clone(),
			library_config::id::equals(lib_cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("failed to create secure library");

	update_library_encryption_status_with_retry(client, &library.id, "ENCRYPTED").await;

	let app_state = AppState::new(Arc::new(ctx));
	let owner = User {
		id: "owner-delete-series".to_string(),
		username: "owner-delete-series".to_string(),
		is_server_owner: true,
		..Default::default()
	};

	let lmk = stump_core::crypto::LibraryMasterKey::from_bytes([9u8; 32]);
	let lmk_b64 = BASE64.encode(lmk.expose_secret());
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-LMK",
		HeaderValue::from_str(&lmk_b64).expect("valid X-LMK"),
	);

	let series_id = "series-2".to_string();
	let media_1 = "media-a".to_string();
	let media_2 = "media-b".to_string();
	let now = prisma_client_rust::chrono::Utc::now().to_rfc3339();
	let mut catalog = CatalogV1 {
		version: 1,
		total_series: 1,
		total_media: 2,
		library_id: library.id.clone(),
		series: vec![CatalogSeriesV1 {
			id: series_id.clone(),
			name: "Series Two".to_string(),
			cover_media_id: Some(media_1.clone()),
			sort_order: 0,
			volume: None,
			updated_at: now.clone(),
		}],
		media: vec![
			CatalogMediaV1 {
				id: media_1.clone(),
				series_id: Some(series_id.clone()),
				name: "A".to_string(),
				pages: 0,
				extension: "cbz".to_string(),
				size: 1,
				sort_order: 0,
				number: None,
				volume: None,
				updated_at: now.clone(),
			},
			CatalogMediaV1 {
				id: media_2.clone(),
				series_id: Some(series_id.clone()),
				name: "B".to_string(),
				pages: 0,
				extension: "cbz".to_string(),
				size: 1,
				sort_order: 0,
				number: None,
				volume: None,
				updated_at: now.clone(),
			},
		],
		updated_at: now,
	};
	normalize_catalog_v1(&mut catalog);
	write_encrypted_catalog_v1(&library.path, &lmk, &catalog)
		.await
		.expect("failed to write encrypted catalog");

	for media_id in [&media_1, &media_2] {
		let (enc_path, meta_path) =
			crate::secure::fs::media_paths_for(&library.path, media_id);
		let (thumb_path, thumb_meta_path) =
			crate::secure::fs::thumbnail_paths_for(&library.path, media_id);
		std::fs::write(&enc_path, b"enc").expect("write enc");
		std::fs::write(&meta_path, b"meta").expect("write meta");
		std::fs::write(&thumb_path, b"thumb").expect("write thumb");
		std::fs::write(&thumb_meta_path, b"thumbmeta").expect("write thumb meta");
	}

	let req_ctx = RequestContext::new_for_tests(owner, None, None);
	let Json(resp) = delete_secure_series(
		Path((library.id.clone(), series_id.clone())),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await
	.expect("expected delete_secure_series ok");
	assert_eq!(resp.media_count, 2);
	assert_eq!(resp.deleted_ids.len(), 3);

	for media_id in [&media_1, &media_2] {
		let (enc_path, meta_path) =
			crate::secure::fs::media_paths_for(&library.path, media_id);
		let (thumb_path, thumb_meta_path) =
			crate::secure::fs::thumbnail_paths_for(&library.path, media_id);
		assert!(std::fs::metadata(&enc_path).is_err());
		assert!(std::fs::metadata(&meta_path).is_err());
		assert!(std::fs::metadata(&thumb_path).is_err());
		assert!(std::fs::metadata(&thumb_meta_path).is_err());
	}

	let catalog_after = read_decrypted_catalog_v1(&library.path, &lmk)
		.await
		.expect("failed to decrypt catalog after series delete");
	assert!(catalog_after.series.is_empty());
	assert!(catalog_after.media.is_empty());
}

#[tokio::test]
async fn delete_secure_media_with_invalid_lmk_returns_invalid_lmk_and_does_not_delete_files(
) {
	let ctx = Ctx::integration_test_mock().await;
	let client: &PrismaClient = ctx.db.as_ref();
	run_migrations(client)
		.await
		.expect("Failed to run migrations for invalid lmk test");

	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-delete-invalid-lmk");
	std::fs::create_dir_all(&library_path).expect("failed to create library dir");
	let library_path_str = library_path.to_string_lossy().to_string();

	let lib_cfg = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("failed to create library config");

	let library = client
		.library()
		.create(
			"secure-lib-delete-invalid-lmk".to_string(),
			library_path_str.clone(),
			library_config::id::equals(lib_cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("failed to create secure library");

	update_library_encryption_status_with_retry(client, &library.id, "ENCRYPTED").await;

	let app_state = AppState::new(Arc::new(ctx));
	let owner = User {
		id: "owner-invalid-lmk".to_string(),
		username: "owner-invalid-lmk".to_string(),
		is_server_owner: true,
		..Default::default()
	};

	let correct_lmk = stump_core::crypto::LibraryMasterKey::from_bytes([1u8; 32]);
	let wrong_lmk = stump_core::crypto::LibraryMasterKey::from_bytes([2u8; 32]);
	let wrong_b64 = BASE64.encode(wrong_lmk.expose_secret());
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-LMK",
		HeaderValue::from_str(&wrong_b64).expect("valid X-LMK"),
	);

	let series_id = "series-x".to_string();
	let media_id = "media-x".to_string();
	let now = prisma_client_rust::chrono::Utc::now().to_rfc3339();
	let mut catalog = CatalogV1 {
		version: 1,
		total_series: 1,
		total_media: 1,
		library_id: library.id.clone(),
		series: vec![CatalogSeriesV1 {
			id: series_id.clone(),
			name: "Series".to_string(),
			cover_media_id: Some(media_id.clone()),
			sort_order: 0,
			volume: None,
			updated_at: now.clone(),
		}],
		media: vec![CatalogMediaV1 {
			id: media_id.clone(),
			series_id: Some(series_id.clone()),
			name: "Media".to_string(),
			pages: 0,
			extension: "cbz".to_string(),
			size: 1,
			sort_order: 0,
			number: None,
			volume: None,
			updated_at: now.clone(),
		}],
		updated_at: now,
	};
	normalize_catalog_v1(&mut catalog);
	write_encrypted_catalog_v1(&library.path, &correct_lmk, &catalog)
		.await
		.expect("failed to write encrypted catalog");

	let (enc_path, meta_path) =
		crate::secure::fs::media_paths_for(&library.path, &media_id);
	std::fs::write(&enc_path, b"enc").expect("write enc");
	std::fs::write(&meta_path, b"meta").expect("write meta");

	let req_ctx = RequestContext::new_for_tests(owner, None, None);
	let result = delete_secure_media(
		Path((library.id.clone(), media_id.clone())),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], secure_error_codes::INVALID_LMK);

	assert!(std::fs::metadata(&enc_path).is_ok());
	assert!(std::fs::metadata(&meta_path).is_ok());
}

#[tokio::test]
async fn delete_secure_media_waits_for_library_lock() {
	let ctx = Ctx::integration_test_mock().await;
	let client: &PrismaClient = ctx.db.as_ref();
	run_migrations(client)
		.await
		.expect("Failed to run migrations for lock test");

	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-delete-lock");
	std::fs::create_dir_all(&library_path).expect("failed to create library dir");
	let library_path_str = library_path.to_string_lossy().to_string();

	let lib_cfg = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("failed to create library config");

	let library = client
		.library()
		.create(
			"secure-lib-delete-lock".to_string(),
			library_path_str.clone(),
			library_config::id::equals(lib_cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("failed to create secure library");

	update_library_encryption_status_with_retry(client, &library.id, "ENCRYPTED").await;

	let app_state = AppState::new(Arc::new(ctx));
	let owner = User {
		id: "owner-lock".to_string(),
		username: "owner-lock".to_string(),
		is_server_owner: true,
		..Default::default()
	};

	let lmk = stump_core::crypto::LibraryMasterKey::from_bytes([3u8; 32]);
	let lmk_b64 = BASE64.encode(lmk.expose_secret());
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-LMK",
		HeaderValue::from_str(&lmk_b64).expect("valid X-LMK"),
	);

	let series_id = "series-lock".to_string();
	let media_id = "media-lock".to_string();
	let now = prisma_client_rust::chrono::Utc::now().to_rfc3339();
	let mut catalog = CatalogV1 {
		version: 1,
		total_series: 1,
		total_media: 1,
		library_id: library.id.clone(),
		series: vec![CatalogSeriesV1 {
			id: series_id.clone(),
			name: "Series".to_string(),
			cover_media_id: Some(media_id.clone()),
			sort_order: 0,
			volume: None,
			updated_at: now.clone(),
		}],
		media: vec![CatalogMediaV1 {
			id: media_id.clone(),
			series_id: Some(series_id.clone()),
			name: "Media".to_string(),
			pages: 0,
			extension: "cbz".to_string(),
			size: 1,
			sort_order: 0,
			number: None,
			volume: None,
			updated_at: now.clone(),
		}],
		updated_at: now,
	};
	normalize_catalog_v1(&mut catalog);
	write_encrypted_catalog_v1(&library.path, &lmk, &catalog)
		.await
		.expect("failed to write encrypted catalog");

	let (enc_path, meta_path) =
		crate::secure::fs::media_paths_for(&library.path, &media_id);
	std::fs::write(&enc_path, b"enc").expect("write enc");
	std::fs::write(&meta_path, b"meta").expect("write meta");

	let held = app_state.lock_secure_library(&library.id).await;
	let app_state_for_task = app_state.clone();
	let req_ctx = RequestContext::new_for_tests(owner, None, None);
	let delete_task = tokio::spawn(async move {
		delete_secure_media(
			Path((library.id.clone(), media_id.clone())),
			State(app_state_for_task),
			Extension(req_ctx),
			headers,
		)
		.await
	});

	tokio::pin!(delete_task);
	let timed = timeout(Duration::from_millis(50), &mut delete_task).await;
	assert!(timed.is_err(), "delete should block on held lock");
	drop(held);
	let result = timeout(Duration::from_secs(2), &mut delete_task)
		.await
		.expect("delete task should complete after lock release")
		.expect("delete task join should succeed");
	assert!(result.is_ok(), "delete should succeed after lock release");

	assert!(std::fs::metadata(&enc_path).is_err());
	assert!(std::fs::metadata(&meta_path).is_err());
}

#[tokio::test]
async fn delete_secure_media_returns_423_when_encrypting() {
	let (app_state, _user_no_access, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();
	update_library_encryption_status_with_retry(client, &library_id, "ENCRYPTING").await;

	let owner = User {
		id: "owner-delete-423".to_string(),
		username: "owner-delete-423".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let lmk = stump_core::crypto::LibraryMasterKey::from_bytes([8u8; 32]);
	let lmk_b64 = BASE64.encode(lmk.expose_secret());
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-LMK",
		HeaderValue::from_str(&lmk_b64).expect("valid X-LMK"),
	);

	let result = delete_secure_media(
		Path((library_id.clone(), "any-media".to_string())),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::LOCKED);
	assert_eq!(body["error"], secure_error_codes::ENCRYPTION_IN_PROGRESS);
}

#[tokio::test]
async fn delete_secure_media_returns_404_for_non_owner_without_access() {
	let (app_state, user_no_access, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();
	client
		.secure_library_access()
		.delete_many(vec![
			secure_library_access::user_id::equals(user_no_access.id.clone()),
			secure_library_access::library_id::equals(library_id.clone()),
		])
		.exec()
		.await
		.expect("failed to clean secure_library_access before delete media auth test");

	let req_ctx = RequestContext::new_for_tests(user_no_access, None, None);
	let headers = HeaderMap::new();
	let result = delete_secure_media(
		Path((library_id.clone(), "any-media".to_string())),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body["error"], secure_error_codes::LIBRARY_NOT_FOUND);
}

#[tokio::test]
async fn delete_secure_media_returns_403_for_non_owner_with_access() {
	let (app_state, _user_no_access, library_id) = setup_secure_library_env().await;
	let user_with_access = User {
		id: "user-delete-403".to_string(),
		username: "user-delete-403".to_string(),
		is_server_owner: false,
		..Default::default()
	};
	grant_secure_access_for_tests(&app_state, &user_with_access.id, &library_id).await;
	let req_ctx = RequestContext::new_for_tests(user_with_access, None, None);

	let headers = HeaderMap::new();
	let result = delete_secure_media(
		Path((library_id.clone(), "any-media".to_string())),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_eq!(body["error"], secure_error_codes::FORBIDDEN);
}

#[tokio::test]
async fn delete_secure_series_returns_404_for_non_owner_without_access() {
	let (app_state, user_no_access, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();
	client
		.secure_library_access()
		.delete_many(vec![
			secure_library_access::user_id::equals(user_no_access.id.clone()),
			secure_library_access::library_id::equals(library_id.clone()),
		])
		.exec()
		.await
		.expect("failed to clean secure_library_access before delete series auth test");

	let req_ctx = RequestContext::new_for_tests(user_no_access, None, None);
	let headers = HeaderMap::new();
	let result = delete_secure_series(
		Path((library_id.clone(), "any-series".to_string())),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body["error"], secure_error_codes::LIBRARY_NOT_FOUND);
}

#[tokio::test]
async fn delete_secure_series_returns_403_for_non_owner_with_access() {
	let (app_state, _user_no_access, library_id) = setup_secure_library_env().await;
	let user_with_access = User {
		id: "user-delete-series-403".to_string(),
		username: "user-delete-series-403".to_string(),
		is_server_owner: false,
		..Default::default()
	};
	grant_secure_access_for_tests(&app_state, &user_with_access.id, &library_id).await;
	let req_ctx = RequestContext::new_for_tests(user_with_access, None, None);

	let headers = HeaderMap::new();
	let result = delete_secure_series(
		Path((library_id.clone(), "any-series".to_string())),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_eq!(body["error"], secure_error_codes::FORBIDDEN);
}

#[tokio::test]
async fn get_secure_library_status_exposes_current_file_while_encrypting() {
	let (app_state, _user, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();

	// Simulate an in-progress encryption run by marking the library ENCRYPTING
	// and using encryption_error to carry the current file path.
	let lib = client
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.expect("failed to query library for status test")
		.expect("library should exist for status test");

	let current_file_path = format!("{}/.secure/current-book.cbz", lib.path);
	client
		.library()
		.update(
			library::id::equals(lib.id.clone()),
			vec![
				library::is_secure::set(true),
				library::encryption_status::set("ENCRYPTING".to_string()),
				library::encryption_error::set(Some(current_file_path.clone())),
				library::total_files::set(10),
				library::encrypted_files::set(3),
				library::encryption_progress::set(30.0),
			],
		)
		.exec()
		.await
		.expect("failed to update library for status test");

	let owner = User {
		id: "owner-status".to_string(),
		username: "owner-status".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let Json(status) = get_secure_library_status(
		Path(library_id.clone()),
		State(app_state),
		Extension(req_ctx),
	)
	.await
	.expect("expected get_secure_library_status to succeed for owner");

	assert_eq!(status.encryption_status, "ENCRYPTING");
	assert_eq!(
		status.error, None,
		"error field should be suppressed while ENCRYPTING"
	);
	assert_eq!(status.job_progress.processed, 3);
	assert_eq!(status.job_progress.total, 10);
	assert_eq!(
		status.job_progress.current_file.as_deref(),
		Some(current_file_path.as_str()),
	);
}

#[tokio::test]
async fn admin_password_reset_revokes_access_and_clears_keypair_and_sessions() {
	let ctx = Ctx::integration_test_mock().await;
	let app_state = AppState::new(Arc::new(ctx));
	let client: &PrismaClient = app_state.db.as_ref();
	run_migrations(client)
		.await
		.expect("Failed to run migrations for admin password reset test");

	let owner_id = "owner-admin-reset".to_string();
	client
		.user()
		.delete_many(vec![user::id::equals(owner_id.clone())])
		.exec()
		.await
		.expect("failed to cleanup owner user before admin reset test");
	client
		.user()
		.create(
			"owner-admin-reset".to_string(),
			"hashed-password".to_string(),
			vec![
				user::id::set(owner_id.clone()),
				user::is_server_owner::set(true),
			],
		)
		.exec()
		.await
		.expect("failed to create owner user for admin reset test");

	let target_id = "target-admin-reset".to_string();
	let target_username = "target-admin-reset".to_string();
	client
		.user()
		.delete_many(vec![user::id::equals(target_id.clone())])
		.exec()
		.await
		.expect("failed to cleanup target user before admin reset test");

	let keypair = UserKeypairService::generate_keypair();
	let public_b64 =
		UserKeypairService::public_key_to_base64(&keypair.public_key_bytes());
	client
		.user()
		.create(
			target_username.clone(),
			"old-hash".to_string(),
			vec![
				user::id::set(target_id.clone()),
				user::x_25519_public_key::set(Some(public_b64)),
				user::encrypted_x_25519_private::set(Some("enc".to_string())),
				user::x_25519_private_nonce::set(Some("nonce".to_string())),
				user::x_25519_password_salt::set(Some("salt".to_string())),
			],
		)
		.exec()
		.await
		.expect("failed to create target user for admin reset test");

	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-admin-reset");
	std::fs::create_dir_all(&library_path).expect("failed to create library directory");
	let library_path_str = library_path.to_string_lossy().to_string();

	let lib_cfg = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("failed to create library config");

	let library = client
		.library()
		.create(
			"secure-lib-admin-reset".to_string(),
			library_path_str,
			library_config::id::equals(lib_cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("failed to create secure library for admin reset test");

	// Ensure active access grant exists
	client
		.secure_library_access()
		.delete_many(vec![
			secure_library_access::user_id::equals(target_id.clone()),
			secure_library_access::library_id::equals(library.id.clone()),
		])
		.exec()
		.await
		.expect("failed to cleanup secure_library_access before admin reset test");
	client
		.secure_library_access()
		.create(
			target_id.clone(),
			library.id.clone(),
			"ciphertext".to_string(),
			"ephemeral".to_string(),
			"nonce".to_string(),
			owner_id.clone(),
			vec![],
		)
		.exec()
		.await
		.expect("failed to create secure_library_access before admin reset test");

	let target_user = User {
		id: target_id.clone(),
		username: target_username.clone(),
		is_server_owner: false,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(target_user.clone(), None, None);

	let wrapped_before = get_wrapped_lmk(
		Path(library.id.clone()),
		State(app_state.clone()),
		Extension(req_ctx),
	)
	.await
	.expect("expected wrapped LMK before admin reset");
	assert!(!wrapped_before.encrypted_lmk.is_empty());

	// Create a session and refresh token for the target user
	let now: prisma_client_rust::chrono::DateTime<
		prisma_client_rust::chrono::FixedOffset,
	> = prisma_client_rust::chrono::Utc::now().into();
	let expires_at = now + prisma_client_rust::chrono::Duration::hours(1);
	let session_id = Uuid::new_v4().to_string();
	client
		._execute_raw(raw!(
			"INSERT INTO sessions (id, expiry_time, data, user_id) VALUES ({}, {}, {}, {})",
			PrismaValue::String(session_id),
			PrismaValue::DateTime(expires_at),
			PrismaValue::Bytes(vec![1, 2, 3]),
			PrismaValue::String(target_id.clone())
		))
		.exec()
		.await
		.expect("failed to insert session for admin reset test");

	let refresh_id = Uuid::new_v4().to_string();
	let family_id = Uuid::new_v4().to_string();
	let token_hash = "test-hash".to_string();
	let refresh_expires_at = now + prisma_client_rust::chrono::Duration::days(1);
	client
		._execute_raw(raw!(
			"INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at) VALUES ({}, {}, {}, {}, {})",
			PrismaValue::String(refresh_id),
			PrismaValue::String(target_id.clone()),
			PrismaValue::String(family_id),
			PrismaValue::String(token_hash),
			PrismaValue::DateTime(refresh_expires_at)
		))
		.exec()
		.await
		.expect("failed to insert refresh token for admin reset test");

	let outcome = admin_reset_user_password(
		client,
		&owner_id,
		&target_username,
		"new-password-123",
	)
	.await
	.expect("expected admin_reset_user_password to succeed");
	assert_eq!(outcome.target_user_id, target_id);

	let updated_user = client
		.user()
		.find_unique(user::id::equals(target_id.clone()))
		.exec()
		.await
		.expect("failed to query target user after reset")
		.expect("target user should exist after reset");
	assert!(updated_user.hashed_password.starts_with("$argon2id$"));
	assert!(updated_user.x_25519_public_key.is_none());
	assert!(updated_user.encrypted_x_25519_private.is_none());
	assert!(updated_user.x_25519_private_nonce.is_none());
	assert!(updated_user.x_25519_password_salt.is_none());

	let grants = client
		.secure_library_access()
		.find_many(vec![
			secure_library_access::user_id::equals(target_id.clone()),
			secure_library_access::library_id::equals(library.id.clone()),
		])
		.exec()
		.await
		.expect("failed to query grants after admin reset");
	assert_eq!(grants.len(), 1);
	assert!(grants[0].revoked_at.is_some());
	assert_eq!(grants[0].revoked_by.as_deref(), Some(owner_id.as_str()));

	let req_ctx_after = RequestContext::new_for_tests(target_user, None, None);
	let result = get_wrapped_lmk(
		Path(library.id.clone()),
		State(app_state.clone()),
		Extension(req_ctx_after),
	)
	.await;
	match result {
		Err(APIError::NotFound(_)) => {},
		other => panic!(
			"expected NotFound for wrapped LMK after admin reset, got: {:?}",
			other
		),
	}

	let session_counts: Vec<CountQueryReturn> = client
		._query_raw(raw!(
			"SELECT COUNT(*) as count FROM sessions WHERE user_id = {}",
			PrismaValue::String(target_id.clone())
		))
		.exec()
		.await
		.expect("failed to count sessions after admin reset");
	assert_eq!(session_counts.first().map(|r| r.count).unwrap_or(0), 0);

	let refresh_counts: Vec<CountQueryReturn> = client
		._query_raw(raw!(
			"SELECT COUNT(*) as count FROM refresh_tokens WHERE user_id = {}",
			PrismaValue::String(target_id.clone())
		))
		.exec()
		.await
		.expect("failed to count refresh tokens after admin reset");
	assert_eq!(refresh_counts.first().map(|r| r.count).unwrap_or(0), 0);

	let audit_logs = client
		.crypto_audit_log()
		.find_many(vec![])
		.exec()
		.await
		.expect("failed to fetch crypto_audit_log after admin reset");
	let found = audit_logs.iter().any(|log| {
		log.event_type == "ADMIN_PASSWORD_RESET"
			&& log.user_id == owner_id
			&& log.target_id.as_deref() == Some(&target_id)
	});
	assert!(found, "expected ADMIN_PASSWORD_RESET audit event");
}

#[tokio::test]
async fn scan_and_delete_mutually_exclude_via_library_lock() {
	let ctx = Ctx::integration_test_mock().await;
	let client: &PrismaClient = ctx.db.as_ref();
	run_migrations(client)
		.await
		.expect("Failed to run migrations for scan/delete lock test");

	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-scan-delete-lock");
	std::fs::create_dir_all(&library_path).expect("failed to create library dir");
	let library_path_str = library_path.to_string_lossy().to_string();

	let lib_cfg = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("failed to create library config");

	let library = client
		.library()
		.create(
			"secure-lib-scan-delete-lock".to_string(),
			library_path_str.clone(),
			library_config::id::equals(lib_cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("failed to create secure library");

	update_library_encryption_status_with_retry(client, &library.id, "ENCRYPTED").await;

	let app_state = AppState::new(Arc::new(ctx));
	let owner = User {
		id: "owner-scan-delete-lock".to_string(),
		username: "owner-scan-delete-lock".to_string(),
		is_server_owner: true,
		..Default::default()
	};

	let lmk = stump_core::crypto::LibraryMasterKey::from_bytes([3u8; 32]);
	let lmk_b64 = BASE64.encode(lmk.expose_secret());
	let mut delete_headers = HeaderMap::new();
	delete_headers.insert(
		"X-LMK",
		HeaderValue::from_str(&lmk_b64).expect("valid X-LMK"),
	);

	let series_id = "series-scan-delete-lock".to_string();
	let media_id = "media-scan-delete-lock".to_string();
	let now = prisma_client_rust::chrono::Utc::now().to_rfc3339();
	let mut catalog = CatalogV1 {
		version: 1,
		total_series: 1,
		total_media: 1,
		library_id: library.id.clone(),
		series: vec![CatalogSeriesV1 {
			id: series_id.clone(),
			name: "Series".to_string(),
			cover_media_id: Some(media_id.clone()),
			sort_order: 0,
			volume: None,
			updated_at: now.clone(),
		}],
		media: vec![CatalogMediaV1 {
			id: media_id.clone(),
			series_id: Some(series_id.clone()),
			name: "Media".to_string(),
			pages: 0,
			extension: "cbz".to_string(),
			size: 1,
			sort_order: 0,
			number: None,
			volume: None,
			updated_at: now.clone(),
		}],
		updated_at: now,
	};
	normalize_catalog_v1(&mut catalog);
	write_encrypted_catalog_v1(&library.path, &lmk, &catalog)
		.await
		.expect("failed to write encrypted catalog");

	let (enc_path, meta_path) =
		crate::secure::fs::media_paths_for(&library.path, &media_id);
	std::fs::write(&enc_path, b"enc").expect("write enc");
	std::fs::write(&meta_path, b"meta").expect("write meta");

	let held = app_state.lock_secure_library(&library.id).await;
	let owner_ctx = RequestContext::new_for_tests(owner.clone(), None, None);
	let app_state_for_delete = app_state.clone();
	let library_id_for_delete = library.id.clone();
	let media_id_for_delete = media_id.clone();
	let delete_task = tokio::spawn(async move {
		delete_secure_media(
			Path((library_id_for_delete, media_id_for_delete)),
			State(app_state_for_delete),
			Extension(owner_ctx),
			delete_headers,
		)
		.await
	});

	let smk = SystemMasterKey::generate();
	let mut scan_headers = HeaderMap::new();
	scan_headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);
	let app_state_for_scan = app_state.clone();
	let library_id_for_scan = library.id.clone();
	let scan_ctx = RequestContext::new_for_tests(owner, None, None);
	let scan_task = tokio::spawn(async move {
		scan_secure_library(
			Path(library_id_for_scan),
			State(app_state_for_scan),
			Extension(scan_ctx),
			scan_headers,
		)
		.await
	});

	tokio::pin!(scan_task);
	let scan_timed = timeout(Duration::from_millis(50), &mut scan_task).await;
	assert!(scan_timed.is_err(), "scan should block while lock is held");
	let delete_task = delete_task;
	tokio::pin!(delete_task);
	let delete_timed = timeout(Duration::from_millis(50), &mut delete_task).await;
	assert!(
		delete_timed.is_err(),
		"delete should block while lock is held"
	);
	drop(held);

	let delete_result = timeout(Duration::from_secs(2), &mut delete_task)
		.await
		.expect("delete task should complete after lock release")
		.expect("delete task join should succeed");
	assert!(delete_result.is_ok());
	let _ = delete_result.expect("delete should succeed");

	let scan_result = timeout(Duration::from_secs(2), &mut scan_task)
		.await
		.expect("scan task should complete after lock release")
		.expect("scan task join should succeed");
	let (status, body) =
		extract_status_and_error(scan_result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], secure_error_codes::INVALID_SMK);
}

#[tokio::test]
async fn grant_then_revoke_access_makes_wrapped_lmk_unavailable() {
	let (app_state, user, library_id) = setup_secure_library_env().await;
	let client = app_state.db.clone();

	// Ensure user initially has access by inserting a SecureLibraryAccess row.
	grant_secure_access_for_tests(&app_state, &user.id, &library_id).await;

	// Wrapped LMK should be available before revocation.
	let req_ctx_before = RequestContext::new_for_tests(user.clone(), None, None);
	let wrapped_before = get_wrapped_lmk(
		Path(library_id.clone()),
		State(app_state.clone()),
		Extension(req_ctx_before),
	)
	.await
	.expect("expected wrapped LMK before revoke");
	assert!(!wrapped_before.encrypted_lmk.is_empty());

	// Revoke access as a server owner via the HTTP handler.
	let owner = User {
		id: "owner-revoke".to_string(),
		username: "owner-revoke".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let owner_ctx = RequestContext::new_for_tests(owner, None, None);
	let payload = RevokeAccessRequest {
		user_id: user.id.clone(),
	};

	let Json(resp) = revoke_library_access(
		Path(library_id.clone()),
		State(app_state.clone()),
		Extension(owner_ctx),
		Json(payload),
	)
	.await
	.expect("expected revoke_library_access to succeed");
	assert!(resp.revoked_count >= 1);

	// All grants for this user+library should now be marked revoked.
	let grants = client
		.secure_library_access()
		.find_many(vec![
			secure_library_access::user_id::equals(user.id.clone()),
			secure_library_access::library_id::equals(library_id.clone()),
		])
		.exec()
		.await
		.expect("failed to query secure_library_access after revoke");
	assert!(
		grants.iter().all(|g| g.revoked_at.is_some()),
		"all grants should have revoked_at set after revoke_access",
	);

	// Wrapped LMK should now be unavailable (404 / NotFound).
	let req_ctx_after = RequestContext::new_for_tests(user, None, None);
	let result = get_wrapped_lmk(
		Path(library_id.clone()),
		State(app_state),
		Extension(req_ctx_after),
	)
	.await;

	match result {
		Err(APIError::NotFound(_)) => {},
		other => panic!("expected NotFound for LMK after revoke, got: {:?}", other),
	}

	// Verify an AccessRevoked audit event exists for this library
	let audit_logs = client
		.crypto_audit_log()
		.find_many(vec![])
		.exec()
		.await
		.expect("failed to fetch crypto_audit_log after revoke");
	let revoked = audit_logs.iter().any(|log| {
		log.event_type == CryptoAuditEventType::AccessRevoked.as_str()
			&& log.target_id.as_deref() == Some(&library_id)
	});
	assert!(
		revoked,
		"expected AccessRevoked audit event for revoked access",
	);
}

#[tokio::test]
async fn create_secure_library_missing_smk_returns_invalid_smk_format() {
	let (app_state, _user, _library_id) = setup_secure_library_env().await;
	let owner = User {
		id: "owner".to_string(),
		username: "owner".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let headers = HeaderMap::new();
	let payload = CreateSecureLibraryRequest {
		name: "Secure Library".to_string(),
		path: "/nonexistent-path".to_string(),
	};

	let result = create_secure_library(
		State(app_state),
		Extension(req_ctx),
		headers,
		Json(payload),
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], secure_error_codes::INVALID_SMK_FORMAT);
}

#[tokio::test]
async fn create_secure_library_with_nonexistent_path_returns_path_not_found() {
	let (app_state, _user, _library_id) = setup_secure_library_env().await;
	let owner = User {
		id: "owner".to_string(),
		username: "owner".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	// Use a temp directory and a non-existent subdirectory to ensure the path check fails.
	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let missing_path = temp_dir.path().join("nonexistent-subdir-for-secure-lib");
	let missing_path_str = missing_path.to_string_lossy().to_string();

	let payload = CreateSecureLibraryRequest {
		name: "Secure Library Missing Path".to_string(),
		path: missing_path_str,
	};

	let result = create_secure_library(
		State(app_state),
		Extension(req_ctx),
		headers,
		Json(payload),
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], secure_error_codes::PATH_NOT_FOUND);
}

#[tokio::test]
async fn create_secure_library_non_owner_returns_forbidden_error() {
	let (app_state, _user, _library_id) = setup_secure_library_env().await;
	let non_owner = User {
		id: "user".to_string(),
		username: "user".to_string(),
		is_server_owner: false,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(non_owner, None, None);

	let headers = HeaderMap::new();
	let payload = CreateSecureLibraryRequest {
		name: "Secure Library".to_string(),
		path: "/nonexistent-path".to_string(),
	};

	let result = create_secure_library(
		State(app_state),
		Extension(req_ctx),
		headers,
		Json(payload),
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_eq!(body["error"], secure_error_codes::FORBIDDEN);
}

#[tokio::test]
async fn create_secure_library_owner_without_keypair_fails_and_does_not_persist_library()
{
	let (app_state, _user, _library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();

	let owner_id = "owner-no-keypair".to_string();
	client
		.user()
		.delete_many(vec![user::username::equals("owner-no-keypair".to_string())])
		.exec()
		.await
		.expect("failed to clean up test user");

	client
		.user()
		.create(
			"owner-no-keypair".to_string(),
			"hashed-password".to_string(),
			vec![
				user::id::set(owner_id.clone()),
				user::is_server_owner::set(true),
			],
		)
		.exec()
		.await
		.expect("failed to create owner user without keypair");

	// Create a temporary library path on disk
	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-no-keypair");
	std::fs::create_dir_all(&library_path).expect("failed to create library directory");
	let library_path_str = library_path.to_string_lossy().to_string();

	let owner = User {
		id: owner_id.clone(),
		username: "owner-no-keypair".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	let payload = CreateSecureLibraryRequest {
		name: "Secure Library No Keypair".to_string(),
		path: library_path_str.clone(),
	};

	let result = create_secure_library(
		State(app_state.clone()),
		Extension(req_ctx),
		headers,
		Json(payload),
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], secure_error_codes::MISSING_USER_KEYPAIR);

	// Ensure the library was not persisted in the database
	let persisted = client
		.library()
		.find_unique(library::path::equals(library_path_str.clone()))
		.exec()
		.await
		.expect("failed to query library by path after failed create");
	assert!(persisted.is_none());
}

#[tokio::test]
async fn create_secure_library_with_existing_secure_dir_returns_secure_dir_present() {
	let (app_state, _user, _library_id) = setup_secure_library_env().await;

	let owner = User {
		id: "owner-secure-dir".to_string(),
		username: "owner-secure-dir".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	// Create a library path on disk with a pre-existing .secure directory.
	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-with-secure-dir");
	std::fs::create_dir_all(&library_path).expect("failed to create library directory");
	let secure_dir = library_path.join(".secure");
	std::fs::create_dir_all(&secure_dir).expect("failed to create .secure directory");
	let library_path_str = library_path.to_string_lossy().to_string();

	let payload = CreateSecureLibraryRequest {
		name: "Secure Library Existing Secure Dir".to_string(),
		path: library_path_str,
	};

	let result = create_secure_library(
		State(app_state),
		Extension(req_ctx),
		headers,
		Json(payload),
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], secure_error_codes::SECURE_DIR_PRESENT);
}

#[tokio::test]
async fn create_secure_library_owner_with_keypair_succeeds_and_auto_grants_access() {
	let (app_state, _user, _library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();

	let owner_id = "owner-with-keypair".to_string();
	let library_name = "Secure Library With Keypair".to_string();

	// Ensure idempotency: remove any existing library and user with these identifiers
	client
		.library()
		.delete_many(vec![library::name::equals(library_name.clone())])
		.exec()
		.await
		.expect("failed to clean up test library");

	client
		.user()
		.delete_many(vec![user::username::equals(
			"owner-with-keypair".to_string(),
		)])
		.exec()
		.await
		.expect("failed to clean up test user");

	let keypair = UserKeypairService::generate_keypair();
	let public_key = keypair.public_key_bytes();
	let public_b64 = UserKeypairService::public_key_to_base64(&public_key);

	client
		.user()
		.create(
			"owner-with-keypair".to_string(),
			"hashed-password".to_string(),
			vec![
				user::id::set(owner_id.clone()),
				user::is_server_owner::set(true),
				user::x_25519_public_key::set(Some(public_b64)),
			],
		)
		.exec()
		.await
		.expect("failed to create owner user with keypair");

	// Create a temporary library path on disk
	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-with-keypair");
	std::fs::create_dir_all(&library_path).expect("failed to create library directory");
	let library_path_str = library_path.to_string_lossy().to_string();

	let owner = User {
		id: owner_id.clone(),
		username: "owner-with-keypair".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	let payload = CreateSecureLibraryRequest {
		name: library_name.clone(),
		path: library_path_str.clone(),
	};

	let result = create_secure_library(
		State(app_state.clone()),
		Extension(req_ctx),
		headers,
		Json(payload),
	)
	.await;

	let (status, Json(resp)) =
		result.expect("expected success result from create_secure_library");
	assert_eq!(status, StatusCode::CREATED);
	assert!(resp.is_secure);

	// Ensure the library was persisted in the database
	let persisted = client
		.library()
		.find_unique(library::id::equals(resp.id.clone()))
		.exec()
		.await
		.expect("failed to query library by id after create")
		.expect("expected library to exist after create");
	assert_eq!(persisted.path, library_path_str);

	// Ensure a SecureLibraryAccess row exists for the creator
	let access = client
		.secure_library_access()
		.find_first(vec![
			secure_library_access::user_id::equals(owner_id.clone()),
			secure_library_access::library_id::equals(resp.id.clone()),
		])
		.exec()
		.await
		.expect("failed to query secure_library_access for creator");
	assert!(access.is_some());

	// Verify audit logs include LibraryCreated and AccessGranted for this library
	let audit_logs = client
		.crypto_audit_log()
		.find_many(vec![])
		.exec()
		.await
		.expect("failed to fetch crypto_audit_log after create");

	let created = audit_logs.iter().any(|log| {
		log.event_type == CryptoAuditEventType::LibraryCreated.as_str()
			&& log.target_id.as_deref() == Some(&resp.id)
	});
	assert!(
		created,
		"expected LibraryCreated audit event for new secure library",
	);

	let granted = audit_logs.iter().any(|log| {
		log.event_type == CryptoAuditEventType::AccessGranted.as_str()
			&& log.target_id.as_deref() == Some(&resp.id)
			&& log.user_id == owner_id
	});
	assert!(granted, "expected AccessGranted audit event for creator",);
}

#[tokio::test]
async fn grant_library_access_with_valid_smk_succeeds() {
	let ctx = Ctx::integration_test_mock().await;
	let app_state = AppState::new(Arc::new(ctx));
	let client: &PrismaClient = app_state.db.as_ref();
	run_migrations(client).await.expect(
		"Failed to run migrations for grant_library_access_with_valid_smk_succeeds",
	);

	let owner_id = "owner-grant-valid".to_string();
	let owner_keypair = UserKeypairService::generate_keypair();
	let owner_public_b64 =
		UserKeypairService::public_key_to_base64(&owner_keypair.public_key_bytes());
	client
		.user()
		.create(
			"owner-grant-valid".to_string(),
			"hashed-password".to_string(),
			vec![
				user::id::set(owner_id.clone()),
				user::is_server_owner::set(true),
				user::x_25519_public_key::set(Some(owner_public_b64)),
			],
		)
		.exec()
		.await
		.expect("failed to create owner user for grant_access test");

	let target_id = "target-grant-valid".to_string();
	let target_keypair = UserKeypairService::generate_keypair();
	let target_public_b64 =
		UserKeypairService::public_key_to_base64(&target_keypair.public_key_bytes());
	client
		.user()
		.create(
			"target-grant-valid".to_string(),
			"hashed-password".to_string(),
			vec![
				user::id::set(target_id.clone()),
				user::x_25519_public_key::set(Some(target_public_b64)),
			],
		)
		.exec()
		.await
		.expect("failed to create target user for grant_access test");

	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-grant-valid");
	std::fs::create_dir_all(&library_path).expect("failed to create library directory");
	let library_path_str = library_path.to_string_lossy().to_string();

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	let owner_user = User {
		id: owner_id.clone(),
		username: "owner-grant-valid".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let owner_ctx = RequestContext::new_for_tests(owner_user, None, None);

	let payload = CreateSecureLibraryRequest {
		name: "Secure Library Grant Valid".to_string(),
		path: library_path_str,
	};
	let (status, Json(created)) = create_secure_library(
		State(app_state.clone()),
		Extension(owner_ctx.clone()),
		headers.clone(),
		Json(payload),
	)
	.await
	.expect("expected create_secure_library to succeed for grant_access test");
	assert_eq!(status, StatusCode::CREATED);

	let Json(resp) = grant_library_access(
		Path(created.id.clone()),
		State(app_state.clone()),
		Extension(owner_ctx),
		headers,
		Json(GrantAccessRequest {
			user_id: target_id.clone(),
		}),
	)
	.await
	.expect("expected grant_library_access to succeed");
	assert_eq!(resp.access_grant.user_id, target_id);
	assert_eq!(resp.access_grant.library_id, created.id);

	let persisted = client
		.secure_library_access()
		.find_first(vec![
			secure_library_access::user_id::equals(target_id),
			secure_library_access::library_id::equals(resp.access_grant.library_id),
		])
		.exec()
		.await
		.expect("failed to query secure_library_access after grant")
		.expect("expected secure_library_access row to exist after grant");
	assert_eq!(persisted.revoked_at, None);
}

#[tokio::test]
async fn grant_library_access_without_target_keypair_returns_missing_user_keypair() {
	let ctx = Ctx::integration_test_mock().await;
	let app_state = AppState::new(Arc::new(ctx));
	let client: &PrismaClient = app_state.db.as_ref();
	run_migrations(client)
		.await
		.expect("Failed to run migrations for grant_library_access_without_target_keypair_returns_missing_user_keypair");

	let owner_id = "owner-grant-missing-keypair".to_string();
	let owner_keypair = UserKeypairService::generate_keypair();
	let owner_public_b64 =
		UserKeypairService::public_key_to_base64(&owner_keypair.public_key_bytes());
	client
		.user()
		.create(
			"owner-grant-missing-keypair".to_string(),
			"hashed-password".to_string(),
			vec![
				user::id::set(owner_id.clone()),
				user::is_server_owner::set(true),
				user::x_25519_public_key::set(Some(owner_public_b64)),
			],
		)
		.exec()
		.await
		.expect("failed to create owner user for missing_user_keypair test");

	let target_id = "target-missing-keypair".to_string();
	client
		.user()
		.create(
			"target-missing-keypair".to_string(),
			"hashed-password".to_string(),
			vec![user::id::set(target_id.clone())],
		)
		.exec()
		.await
		.expect("failed to create target user without keypair");

	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-grant-missing-keypair");
	std::fs::create_dir_all(&library_path).expect("failed to create library directory");
	let library_path_str = library_path.to_string_lossy().to_string();

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	let owner_user = User {
		id: owner_id.clone(),
		username: "owner-grant-missing-keypair".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let owner_ctx = RequestContext::new_for_tests(owner_user, None, None);

	let payload = CreateSecureLibraryRequest {
		name: "Secure Library Missing Keypair".to_string(),
		path: library_path_str,
	};
	let (_status, Json(created)) = create_secure_library(
		State(app_state.clone()),
		Extension(owner_ctx.clone()),
		headers.clone(),
		Json(payload),
	)
	.await
	.expect("expected create_secure_library to succeed for missing_user_keypair test");

	let result = grant_library_access(
		Path(created.id.clone()),
		State(app_state),
		Extension(owner_ctx),
		headers,
		Json(GrantAccessRequest { user_id: target_id }),
	)
	.await;

	let (status, body) = extract_status_and_error(
		result.expect_err("expected error from grant_library_access"),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], secure_error_codes::MISSING_USER_KEYPAIR);
}

#[tokio::test]
async fn get_library_access_list_returns_expected_users() {
	let ctx = Ctx::integration_test_mock().await;
	let app_state = AppState::new(Arc::new(ctx));
	let client: &PrismaClient = app_state.db.as_ref();
	run_migrations(client).await.expect(
		"Failed to run migrations for get_library_access_list_returns_expected_users",
	);

	let owner_id = "owner-access-list".to_string();
	let owner_keypair = UserKeypairService::generate_keypair();
	let owner_public_b64 =
		UserKeypairService::public_key_to_base64(&owner_keypair.public_key_bytes());
	client
		.user()
		.create(
			"owner-access-list".to_string(),
			"hashed-password".to_string(),
			vec![
				user::id::set(owner_id.clone()),
				user::is_server_owner::set(true),
				user::x_25519_public_key::set(Some(owner_public_b64)),
			],
		)
		.exec()
		.await
		.expect("failed to create owner user for access list test");

	let target_id = "target-access-list".to_string();
	let target_keypair = UserKeypairService::generate_keypair();
	let target_public_b64 =
		UserKeypairService::public_key_to_base64(&target_keypair.public_key_bytes());
	client
		.user()
		.create(
			"target-access-list".to_string(),
			"hashed-password".to_string(),
			vec![
				user::id::set(target_id.clone()),
				user::x_25519_public_key::set(Some(target_public_b64)),
			],
		)
		.exec()
		.await
		.expect("failed to create target user for access list test");

	let temp_dir = TempDir::new().expect("failed to create temp dir");
	let library_path = temp_dir.path().join("secure-lib-access-list");
	std::fs::create_dir_all(&library_path).expect("failed to create library directory");
	let library_path_str = library_path.to_string_lossy().to_string();

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	let owner_user = User {
		id: owner_id.clone(),
		username: "owner-access-list".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let owner_ctx = RequestContext::new_for_tests(owner_user, None, None);

	let payload = CreateSecureLibraryRequest {
		name: "Secure Library Access List".to_string(),
		path: library_path_str,
	};
	let (_status, Json(created)) = create_secure_library(
		State(app_state.clone()),
		Extension(owner_ctx.clone()),
		headers.clone(),
		Json(payload),
	)
	.await
	.expect("expected create_secure_library to succeed for access list test");

	let _ = grant_library_access(
		Path(created.id.clone()),
		State(app_state.clone()),
		Extension(owner_ctx.clone()),
		headers,
		Json(GrantAccessRequest {
			user_id: target_id.clone(),
		}),
	)
	.await
	.expect("expected grant_library_access to succeed for access list test");

	let Json(list) = get_library_access_list(
		Path(created.id.clone()),
		State(app_state),
		Extension(owner_ctx),
	)
	.await
	.expect("expected get_library_access_list to succeed");

	assert!(
		list.users
			.iter()
			.any(|u| u.user_id == owner_id && u.username == "owner-access-list"),
		"expected owner in access list",
	);
	assert!(
		list.users
			.iter()
			.any(|u| u.user_id == target_id && u.username == "target-access-list"),
		"expected target user in access list",
	);
}

#[tokio::test]
async fn scan_secure_library_invalid_smk_returns_invalid_smk_code() {
	let (app_state, _user, library_id) = setup_secure_library_env().await;
	let owner = User {
		id: "owner".to_string(),
		username: "owner".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	let result = scan_secure_library(
		Path(library_id.clone()),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], secure_error_codes::INVALID_SMK);
}

#[tokio::test]
async fn scan_secure_library_returns_job_already_running_when_job_exists() {
	let (app_state, _user, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();

	// Insert a queued job to simulate an existing background job
	client
		.job()
		.create(
			"secure-encryption-test-job".to_string(),
			"Test job".to_string(),
			vec![job::status::set(JobStatus::Queued.to_string())],
		)
		.exec()
		.await
		.expect("failed to create test job");

	let owner = User {
		id: "owner-job-running".to_string(),
		username: "owner-job-running".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	let result = scan_secure_library(
		Path(library_id.clone()),
		State(app_state),
		Extension(req_ctx),
		headers,
	)
	.await;

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(body["error"], secure_error_codes::JOB_ALREADY_RUNNING);
}

#[tokio::test]
async fn scan_secure_library_waits_for_library_lock() {
	let (app_state, _user, library_id) = setup_secure_library_env().await;
	let owner = User {
		id: "owner-scan-lock".to_string(),
		username: "owner-scan-lock".to_string(),
		is_server_owner: true,
		..Default::default()
	};
	let req_ctx = RequestContext::new_for_tests(owner, None, None);

	let smk = SystemMasterKey::generate();
	let mut headers = HeaderMap::new();
	headers.insert(
		"X-SMK",
		HeaderValue::from_str(&smk.to_base64()).expect("valid X-SMK header"),
	);

	let held = app_state.lock_secure_library(&library_id).await;
	let app_state_for_task = app_state.clone();
	let library_id_for_task = library_id.clone();
	let scan_task = tokio::spawn(async move {
		scan_secure_library(
			Path(library_id_for_task),
			State(app_state_for_task),
			Extension(req_ctx),
			headers,
		)
		.await
	});

	tokio::pin!(scan_task);
	let timed = timeout(Duration::from_millis(50), &mut scan_task).await;
	assert!(timed.is_err(), "scan should block on held lock");
	drop(held);
	let result = timeout(Duration::from_secs(2), &mut scan_task)
		.await
		.expect("scan task should complete after lock release")
		.expect("scan task join should succeed");

	let (status, body) =
		extract_status_and_error(result.expect_err("expected error result")).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"], secure_error_codes::INVALID_SMK);
}

#[tokio::test]
async fn lmk_returns_404_when_user_lacks_access() {
	let (app_state, user, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();
	client
		.secure_library_access()
		.delete_many(vec![
			secure_library_access::user_id::equals(user.id.clone()),
			secure_library_access::library_id::equals(library_id.clone()),
		])
		.exec()
		.await
		.expect("failed to clean secure_library_access before LMK test");
	let req_ctx = RequestContext::new_for_tests(user, None, None);

	let result = get_wrapped_lmk(
		Path(library_id.clone()),
		State(app_state),
		Extension(req_ctx),
	)
	.await;

	match result {
		Err(APIError::NotFound(_)) => {},
		other => panic!("expected NotFound for LMK, got: {:?}", other),
	}
}

#[tokio::test]
async fn catalog_returns_404_when_user_lacks_access() {
	let (app_state, user, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();
	client
		.secure_library_access()
		.delete_many(vec![
			secure_library_access::user_id::equals(user.id.clone()),
			secure_library_access::library_id::equals(library_id.clone()),
		])
		.exec()
		.await
		.expect("failed to clean secure_library_access before catalog test");
	let req_ctx = RequestContext::new_for_tests(user, None, None);

	let result = get_secure_library_catalog(
		Path(library_id.clone()),
		State(app_state),
		Extension(req_ctx),
	)
	.await;

	match result {
		Err(APIError::NotFound(_)) => {},
		other => panic!("expected NotFound for catalog, got: {:?}", other),
	}
}

async fn grant_secure_access_for_tests(
	app_state: &AppState,
	user_id: &str,
	library_id: &str,
) {
	let client: &PrismaClient = app_state.db.as_ref();
	// Ensure idempotency across test runs sharing the same test.db
	client
		.secure_library_access()
		.delete_many(vec![
			secure_library_access::user_id::equals(user_id.to_string()),
			secure_library_access::library_id::equals(library_id.to_string()),
		])
		.exec()
		.await
		.expect(
			"failed to clean secure_library_access before grant_secure_access_for_tests",
		);
	client
		.secure_library_access()
		.create(
			user_id.to_string(),
			library_id.to_string(),
			"ciphertext".to_string(),
			"ephemeral".to_string(),
			"nonce".to_string(),
			user_id.to_string(),
			vec![],
		)
		.exec()
		.await
		.expect("failed to create secure_library_access for tests");
}

async fn update_library_encryption_status_with_retry(
	client: &PrismaClient,
	library_id: &str,
	status: &str,
) {
	let mut attempts = 0;
	loop {
		attempts += 1;
		let result = client
			.library()
			.update(
				library::id::equals(library_id.to_string()),
				vec![library::encryption_status::set(status.to_string())],
			)
			.exec()
			.await;
		match result {
			Ok(_) => break,
			Err(e) => {
				let msg = e.to_string();
				if attempts < 3 && msg.contains("Timed out during query execution") {
					tokio::time::sleep(std::time::Duration::from_millis(100)).await;
					continue;
				}
				panic!(
					"failed to update library encryption_status to {}: {}",
					status, e
				);
			},
		}
	}
}

#[tokio::test]
async fn media_thumbnail_catalog_return_423_with_retry_after_when_encrypting() {
	let (app_state, _user_no_access, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();

	// Mark library as ENCRYPTING (with small retry to avoid flaky timeouts)
	update_library_encryption_status_with_retry(client, &library_id, "ENCRYPTING").await;

	// Use a dedicated user for this test so other tests manipulating the
	// default "no-access" user do not interfere with our access grant.
	let user_with_access = User {
		id: "user-encrypting-access".to_string(),
		username: "user-encrypting-access".to_string(),
		..Default::default()
	};
	grant_secure_access_for_tests(&app_state, &user_with_access.id, &library_id).await;

	let req_ctx = RequestContext::new_for_tests(user_with_access, None, None);

	// Media file
	let media_resp = get_secure_media_file_v2(
		Path((library_id.clone(), "media-id".to_string())),
		State(app_state.clone()),
		Extension(req_ctx.clone()),
	)
	.await
	.expect("expected Ok response for media while ENCRYPTING");
	assert_eq!(media_resp.status(), StatusCode::LOCKED);
	assert_eq!(
		media_resp
			.headers()
			.get("Retry-After")
			.and_then(|v| v.to_str().ok()),
		Some("60"),
	);

	// Thumbnail
	let thumb_resp = get_secure_media_thumbnail(
		Path((library_id.clone(), "media-id".to_string())),
		State(app_state.clone()),
		Extension(req_ctx.clone()),
	)
	.await
	.expect("expected Ok response for thumbnail while ENCRYPTING");
	assert_eq!(thumb_resp.status(), StatusCode::LOCKED);
	assert_eq!(
		thumb_resp
			.headers()
			.get("Retry-After")
			.and_then(|v| v.to_str().ok()),
		Some("60"),
	);

	// Catalog
	let catalog_resp = get_secure_library_catalog(
		Path(library_id.clone()),
		State(app_state.clone()),
		Extension(req_ctx),
	)
	.await
	.expect("expected Ok response for catalog while ENCRYPTING");
	assert_eq!(catalog_resp.status(), StatusCode::LOCKED);
	assert_eq!(
		catalog_resp
			.headers()
			.get("Retry-After")
			.and_then(|v| v.to_str().ok()),
		Some("60"),
	);
}

#[tokio::test]
async fn catalog_and_media_return_404_when_not_encrypted_and_no_secure_artifacts() {
	let (app_state, _user_no_access, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();

	// Explicitly mark the library as NOT_ENCRYPTED to model a new secure library
	// that has not yet been scanned.
	update_library_encryption_status_with_retry(client, &library_id, "NOT_ENCRYPTED")
		.await;

	// Ensure there is no lingering .secure directory or catalog/media artifacts
	// from other tests that might cause the endpoints to succeed with 200.
	let lib = client
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.expect("failed to query library for NOT_ENCRYPTED test")
		.expect("library should exist for NOT_ENCRYPTED test");
	let library_path = std::path::PathBuf::from(&lib.path);
	let secure_dir = library_path.join(".secure");
	if secure_dir.exists() {
		std::fs::remove_dir_all(&secure_dir)
			.expect("failed to remove existing .secure dir for NOT_ENCRYPTED test");
	}

	// Grant access to a non-owner user so we exercise the secure error posture
	// rather than owner-only admin paths.
	let user_with_access = User {
		id: "user-not-encrypted-access".to_string(),
		username: "user-not-encrypted-access".to_string(),
		..Default::default()
	};
	grant_secure_access_for_tests(&app_state, &user_with_access.id, &library_id).await;

	let req_ctx = RequestContext::new_for_tests(user_with_access, None, None);

	// Catalog: with no .secure/catalog files on disk and NOT_ENCRYPTED status,
	// the backend should mask this as a generic 404. The UI is responsible for
	// interpreting NOT_ENCRYPTED via the status endpoint.
	let catalog_result = get_secure_library_catalog(
		Path(library_id.clone()),
		State(app_state.clone()),
		Extension(req_ctx.clone()),
	)
	.await;
	match catalog_result {
		Err(APIError::NotFound(_)) => {},
		other => panic!(
			"expected NotFound for catalog while NOT_ENCRYPTED, got: {:?}",
			other,
		),
	}

	// Media: same posture when attempting to fetch an encrypted media file that
	// does not yet exist because encryption has never run.
	let media_result = get_secure_media_file_v2(
		Path((library_id.clone(), "media-id".to_string())),
		State(app_state.clone()),
		Extension(req_ctx),
	)
	.await;
	match media_result {
		Err(APIError::NotFound(_)) => {},
		other => panic!(
			"expected NotFound for media while NOT_ENCRYPTED, got: {:?}",
			other,
		),
	}
}

#[tokio::test]
async fn catalog_missing_for_encrypted_library_promotes_broken_and_returns_503() {
	let (app_state, _user_no_access, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();

	// Mark library as ENCRYPTED while leaving the on-disk catalog absent to
	// trigger lazy ENCRYPTION_BROKEN promotion.
	update_library_encryption_status_with_retry(client, &library_id, "ENCRYPTED").await;

	// Remove any existing .secure directory so catalog/meta reads fail and the
	// handler promotes the library into ENCRYPTION_BROKEN.
	let lib = client
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.expect("failed to query library for ENCRYPTED-broken test")
		.expect("library should exist for ENCRYPTED-broken test");
	let library_path = std::path::PathBuf::from(&lib.path);
	let secure_dir = library_path.join(".secure");
	if secure_dir.exists() {
		std::fs::remove_dir_all(&secure_dir)
			.expect("failed to remove existing .secure dir for ENCRYPTED-broken test");
	}

	let user_with_access = User {
		id: "user-encrypted-broken-catalog".to_string(),
		username: "user-encrypted-broken-catalog".to_string(),
		..Default::default()
	};
	grant_secure_access_for_tests(&app_state, &user_with_access.id, &library_id).await;

	let req_ctx = RequestContext::new_for_tests(user_with_access, None, None);

	let resp = get_secure_library_catalog(
		Path(library_id.clone()),
		State(app_state.clone()),
		Extension(req_ctx),
	)
	.await
	.expect("expected Ok response for catalog when ENCRYPTED but missing files");
	assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

	// Library row should now be marked ENCRYPTION_BROKEN.
	let lib_after = client
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.expect("failed to query library after broken catalog fetch")
		.expect("library should exist after broken catalog fetch");
	assert_eq!(lib_after.encryption_status, "ENCRYPTION_BROKEN");
}

#[tokio::test]
async fn media_missing_for_encrypted_library_promotes_broken_and_returns_503() {
	let (app_state, _user_no_access, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();

	update_library_encryption_status_with_retry(client, &library_id, "ENCRYPTED").await;

	// As above, ensure there is no .secure directory so media/meta reads fail
	// and we exercise the ENCRYPTION_BROKEN posture.
	let lib = client
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.expect("failed to query library for ENCRYPTED-broken media test")
		.expect("library should exist for ENCRYPTED-broken media test");
	let library_path = std::path::PathBuf::from(&lib.path);
	let secure_dir = library_path.join(".secure");
	if secure_dir.exists() {
		std::fs::remove_dir_all(&secure_dir).expect(
			"failed to remove existing .secure dir for ENCRYPTED-broken media test",
		);
	}

	let user_with_access = User {
		id: "user-encrypted-broken-media".to_string(),
		username: "user-encrypted-broken-media".to_string(),
		..Default::default()
	};
	grant_secure_access_for_tests(&app_state, &user_with_access.id, &library_id).await;

	let req_ctx = RequestContext::new_for_tests(user_with_access, None, None);

	let resp = get_secure_media_file_v2(
		Path((library_id.clone(), "media-id".to_string())),
		State(app_state.clone()),
		Extension(req_ctx),
	)
	.await
	.expect("expected Ok response for media when ENCRYPTED but missing files");
	assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

	let lib_after = client
		.library()
		.find_unique(library::id::equals(library_id.clone()))
		.exec()
		.await
		.expect("failed to query library after broken media fetch")
		.expect("library should exist after broken media fetch");
	assert_eq!(lib_after.encryption_status, "ENCRYPTION_BROKEN");
}

#[tokio::test]
async fn media_file_returns_404_when_user_lacks_access() {
	let (app_state, user, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();
	client
		.secure_library_access()
		.delete_many(vec![
			secure_library_access::user_id::equals(user.id.clone()),
			secure_library_access::library_id::equals(library_id.clone()),
		])
		.exec()
		.await
		.expect("failed to clean secure_library_access before media file test");
	let req_ctx = RequestContext::new_for_tests(user, None, None);

	let result = get_secure_media_file_v2(
		Path((library_id.clone(), "media-id".to_string())),
		State(app_state),
		Extension(req_ctx),
	)
	.await;

	match result {
		Err(APIError::NotFound(_)) => {},
		other => panic!("expected NotFound for media file, got: {:?}", other),
	}
}

#[tokio::test]
async fn thumbnail_returns_404_when_user_lacks_access() {
	let (app_state, user, library_id) = setup_secure_library_env().await;
	let client: &PrismaClient = app_state.db.as_ref();
	client
		.secure_library_access()
		.delete_many(vec![
			secure_library_access::user_id::equals(user.id.clone()),
			secure_library_access::library_id::equals(library_id.clone()),
		])
		.exec()
		.await
		.expect("failed to clean secure_library_access before thumbnail test");
	let req_ctx = RequestContext::new_for_tests(user, None, None);

	let result = get_secure_media_thumbnail(
		Path((library_id.clone(), "media-id".to_string())),
		State(app_state),
		Extension(req_ctx),
	)
	.await;

	match result {
		Err(APIError::NotFound(_)) => {},
		other => panic!("expected NotFound for thumbnail, got: {:?}", other),
	}
}

#[tokio::test]
async fn catalog_endpoint_returns_crypto_headers_and_body_isolated() {
	let ctx = Ctx::integration_test_mock().await;
	let client: &PrismaClient = ctx.db.as_ref();

	run_migrations(client)
		.await
		.expect("Failed to run migrations for catalog success test");

	let temp_dir = TempDir::new().expect("failed to create temp dir for catalog test");
	let library_path = temp_dir.path().join("secure-lib-catalog-success");
	std::fs::create_dir_all(&library_path)
		.expect("failed to create library directory for catalog test");
	let library_path_str = library_path.to_string_lossy().to_string();

	let lib_cfg = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("failed to create library config for catalog test");

	let library = client
		.library()
		.create(
			"secure-lib-catalog-success".to_string(),
			library_path_str.clone(),
			library_config::id::equals(lib_cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("failed to create secure library for catalog test");

	update_library_encryption_status_with_retry(client, &library.id, "ENCRYPTED").await;

	let (catalog_path, meta_path) = crate::secure::fs::catalog_paths_for(&library.path);
	if let Some(dir) = catalog_path.parent() {
		std::fs::create_dir_all(dir)
			.expect("failed to create .secure directory for catalog test");
	}

	let enc_bytes = b"encrypted catalog bytes";
	let nonce = "catalog-nonce";
	let tag = "catalog-tag";
	let plaintext_size: u64 = 123;
	let meta = serde_json::json!({
		"nonce": nonce,
		"tag": tag,
		"plaintext_size": plaintext_size,
	});
	std::fs::write(&meta_path, meta.to_string())
		.expect("failed to write catalog meta for catalog test");
	std::fs::write(&catalog_path, enc_bytes)
		.expect("failed to write catalog bytes for catalog test");

	let app_state = AppState::new(Arc::new(ctx));
	let user = User {
		id: "catalog-success-user".to_string(),
		username: "catalog-success-user".to_string(),
		..Default::default()
	};
	grant_secure_access_for_tests(&app_state, &user.id, &library.id).await;
	let req_ctx = RequestContext::new_for_tests(user, None, None);

	let resp = get_secure_library_catalog(
		Path(library.id.clone()),
		State(app_state),
		Extension(req_ctx),
	)
	.await
	.expect("expected Ok response for catalog success test");
	assert_eq!(resp.status(), StatusCode::OK);

	let (parts, body) = resp.into_parts();
	let headers = parts.headers;

	assert_eq!(
		headers.get("Content-Type").and_then(|v| v.to_str().ok()),
		Some("application/octet-stream"),
	);
	assert_eq!(
		headers.get("Cache-Control").and_then(|v| v.to_str().ok()),
		Some("private, no-store"),
	);
	assert_eq!(
		headers.get("X-Nonce").and_then(|v| v.to_str().ok()),
		Some(nonce),
	);
	assert_eq!(
		headers.get("X-Tag").and_then(|v| v.to_str().ok()),
		Some(tag),
	);
	assert_eq!(
		headers
			.get("X-Plaintext-Size")
			.and_then(|v| v.to_str().ok()),
		Some(plaintext_size.to_string().as_str()),
	);
	assert_eq!(
		headers
			.get("Content-Security-Policy")
			.and_then(|v| v.to_str().ok()),
		Some(SECURE_CONTENT_CSP),
	);

	let body_bytes = axum::body::to_bytes(body, usize::MAX)
		.await
		.expect("failed to read catalog body for catalog test");
	assert_eq!(body_bytes.as_ref(), &enc_bytes[..]);
}

#[tokio::test]
async fn media_endpoint_returns_encrypted_bytes_and_headers_isolated() {
	let ctx = Ctx::integration_test_mock().await;
	let client: &PrismaClient = ctx.db.as_ref();

	run_migrations(client)
		.await
		.expect("Failed to run migrations for media success test");

	let temp_dir = TempDir::new().expect("failed to create temp dir for media test");
	let library_path = temp_dir.path().join("secure-lib-media-success");
	std::fs::create_dir_all(&library_path)
		.expect("failed to create library directory for media test");
	let library_path_str = library_path.to_string_lossy().to_string();

	let lib_cfg = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("failed to create library config for media test");

	let library = client
		.library()
		.create(
			"secure-lib-media-success".to_string(),
			library_path_str.clone(),
			library_config::id::equals(lib_cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("failed to create secure library for media test");

	update_library_encryption_status_with_retry(client, &library.id, "ENCRYPTED").await;

	let media_id = "media-success-id".to_string();
	let (enc_path, meta_path) =
		crate::secure::fs::media_paths_for(&library.path, &media_id);
	if let Some(dir) = enc_path.parent() {
		std::fs::create_dir_all(dir)
			.expect("failed to create .secure directory for media test");
	}

	let enc_bytes = b"encrypted media bytes";
	let nonce = "media-nonce";
	let tag = "media-tag";
	let plaintext_size: u64 = 456;
	let meta = serde_json::json!({
		"nonce": nonce,
		"tag": tag,
		"plaintext_size": plaintext_size,
	});
	std::fs::write(&meta_path, meta.to_string())
		.expect("failed to write media meta for media test");
	std::fs::write(&enc_path, enc_bytes)
		.expect("failed to write media bytes for media test");

	let app_state = AppState::new(Arc::new(ctx));
	let user = User {
		id: "media-success-user".to_string(),
		username: "media-success-user".to_string(),
		..Default::default()
	};
	grant_secure_access_for_tests(&app_state, &user.id, &library.id).await;
	let req_ctx = RequestContext::new_for_tests(user, None, None);

	let resp = get_secure_media_file_v2(
		Path((library.id.clone(), media_id.clone())),
		State(app_state),
		Extension(req_ctx),
	)
	.await
	.expect("expected Ok response for media success test");
	assert_eq!(resp.status(), StatusCode::OK);

	let (parts, body) = resp.into_parts();
	let headers = parts.headers;

	assert_eq!(
		headers.get("Content-Type").and_then(|v| v.to_str().ok()),
		Some("application/octet-stream"),
	);
	assert_eq!(
		headers.get("Cache-Control").and_then(|v| v.to_str().ok()),
		Some("private, no-store"),
	);
	assert_eq!(
		headers.get("X-Nonce").and_then(|v| v.to_str().ok()),
		Some(nonce),
	);
	assert_eq!(
		headers.get("X-Tag").and_then(|v| v.to_str().ok()),
		Some(tag),
	);
	assert_eq!(
		headers
			.get("X-Plaintext-Size")
			.and_then(|v| v.to_str().ok()),
		Some(plaintext_size.to_string().as_str()),
	);
	assert_eq!(
		headers
			.get("Content-Security-Policy")
			.and_then(|v| v.to_str().ok()),
		Some(SECURE_CONTENT_CSP),
	);

	let body_bytes = axum::body::to_bytes(body, usize::MAX)
		.await
		.expect("failed to read media body for media test");
	assert_eq!(body_bytes.as_ref(), &enc_bytes[..]);
}

#[tokio::test]
async fn catalog_and_media_return_404_for_opds_context() {
	let (app_state, _user_no_access, library_id) = setup_secure_library_env().await;

	let opds_user = User {
		id: "opds-user".to_string(),
		username: "opds-user".to_string(),
		..Default::default()
	};
	let req_ctx =
		RequestContext::new_for_tests(opds_user.clone(), None, Some("opds".to_string()));

	// Catalog should be 404 for OPDS token contexts
	let catalog_result = get_secure_library_catalog(
		Path(library_id.clone()),
		State(app_state.clone()),
		Extension(req_ctx.clone()),
	)
	.await;

	match catalog_result {
		Err(APIError::NotFound(_)) => {},
		other => panic!(
			"expected NotFound for catalog in OPDS context, got: {:?}",
			other
		),
	}

	// Media file should also be 404 for OPDS token contexts
	let media_result = get_secure_media_file_v2(
		Path((library_id.clone(), "media-id".to_string())),
		State(app_state),
		Extension(req_ctx),
	)
	.await;

	match media_result {
		Err(APIError::NotFound(_)) => {},
		other => panic!(
			"expected NotFound for media file in OPDS context, got: {:?}",
			other,
		),
	}
}
