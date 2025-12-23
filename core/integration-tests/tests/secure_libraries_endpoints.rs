extern crate stump_core;

use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use prisma_client_rust::serde_json;
use tempfile::TempDir;

use stump_core::crypto::encrypt::{decrypt_file, encrypt_file, EncryptedFile};
use stump_core::crypto::keys::derive_data_encryption_key;
use stump_core::crypto::services::encryption_task::spawn_encryption_task;
use stump_core::crypto::services::key_management::KeyManagementService;
use stump_core::crypto::smk::SystemMasterKey;
use stump_core::crypto::types::{AesGcmNonce, AesGcmTag, DataEncryptionKey};
use stump_core::db::{
	create_client_with_url, entity::LibraryPattern, migration::run_migrations,
};
use stump_core::prisma::{
	library, library_config, library_encryption_metadata, media, series, PrismaClient,
};

fn read_test_file(name: &str) -> Vec<u8> {
	let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	std::fs::read(manifest.join("data").join(name)).expect("read test file")
}

/// End-to-end invariants for secure library encryption and storage when viewed as an
/// "offline snapshot" consisting of the primary database and <Library.path>/.secure.
///
/// This test exercises SecureEncryptionJob via spawn_encryption_task and then asserts:
/// - No plaintext secure metadata or thumbnails exist in the main database or outside
///   <Library.path>/.secure.
/// - Logs and metadata do not contain raw SMK/LMK/DEK material.
/// - The on-disk layout under .secure contains only ciphertext plus minimal crypto
///   metadata (nonce/tag/size), with no item-level titles stored in plaintext.
#[tokio::test]
async fn secure_library_offline_snapshot_invariants() {
	// Use a dedicated SQLite DB for this test to avoid contention on the shared test DB.
	let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("integration-tests/secure-libraries-endpoints");
	std::fs::create_dir_all(&test_dir).expect("create test db dir");
	let sqlite_url = format!(
		"file:{}/secure_libraries_endpoints.db",
		test_dir.to_str().unwrap()
	);
	let client: PrismaClient = create_client_with_url(&sqlite_url).await;
	let db_arc = Arc::new(client);
	let db: &PrismaClient = db_arc.as_ref();

	run_migrations(db)
		.await
		.expect("run migrations for secure_libraries_endpoints");

	// Create a temporary series-based library on disk with a small fixture CBZ.
	let temp_dir = TempDir::new().expect("tmp dir");
	let library_root = temp_dir.path().join("secure-endpoints-lib");
	let series_1 = library_root.join("series-1");
	std::fs::create_dir_all(&series_1).expect("mkdirs");

	// Root-level book and one series book.
	std::fs::write(
		library_root.join("root_book.cbz"),
		read_test_file("science_comics_001.cbz"),
	)
	.expect("write root book");
	std::fs::write(
		series_1.join("science_comics_001.cbz"),
		read_test_file("science_comics_001.cbz"),
	)
	.expect("write series book");

	// Insert library_config and secure library rows.
	let cfg = db
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("create library_config");

	let unique = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_millis();
	let lib_name = format!("secure-endpoints-lib-{}", unique);

	let lib = db
		.library()
		.create(
			lib_name,
			library_root.to_string_lossy().to_string(),
			library_config::id::equals(cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("create secure library");

	// Derive LMK from a generated SMK for this library.
	let smk = SystemMasterKey::generate();
	let lmk = KeyManagementService::derive_lmk(&smk, &lib.id).expect("derive LMK");

	// Run SecureEncryptionJob via spawn_encryption_task.
	let enc_tmp = TempDir::new().expect("enc tmpdir");
	let enc_base = PathBuf::from(enc_tmp.path());
	let handle = spawn_encryption_task(
		lib.id.clone(),
		PathBuf::from(&lib.path),
		lmk.clone(),
		enc_base.clone(),
		db_arc.clone(),
	);
	let result = handle.await.expect("join encryption task");
	result.expect("encryption task should succeed");

	// ---------------------------------------------------------------------
	// (a) No plaintext secure metadata or thumbnails in DB or outside .secure
	// ---------------------------------------------------------------------

	// For this dedicated DB, there should be no media/series rows populated for the
	// secure library by the encryption job (it uses filesystem sidecars only).
	let media_rows = db
		.media()
		.find_many(vec![media::series::is(vec![series::library_id::equals(
			Some(lib.id.clone()),
		)])])
		.exec()
		.await
		.expect("query media rows for secure library");
	assert!(
		media_rows.is_empty(),
		"secure encryption should not create plaintext media rows for secure library",
	);

	let series_rows = db
		.series()
		.find_many(vec![series::library_id::equals(Some(lib.id.clone()))])
		.exec()
		.await
		.expect("query series rows for secure library");
	assert!(
		series_rows.is_empty(),
		"secure encryption should not create plaintext series rows for secure library",
	);

	// Walk the library root and ensure that any image-like files (thumbnails) live
	// only under <Library.path>/.secure. This protects against accidentally writing
	// derived plaintext thumbnails alongside the library content.
	let secure_dir = PathBuf::from(&lib.path).join(".secure");
	assert!(
		secure_dir.exists(),
		".secure directory should exist after encryption"
	);

	let mut catalog_enc_present = false;
	let mut catalog_meta_present = false;
	let mut has_media_ciphertext = false;

	for entry in walkdir::WalkDir::new(&lib.path) {
		let entry = entry.expect("walkdir entry");
		if !entry.file_type().is_file() {
			continue;
		}
		let path = entry.path();
		let rel = path.strip_prefix(&lib.path).unwrap_or(path);

		let is_under_secure =
			rel.components().next().map(|c| c.as_os_str()) == Some(".secure".as_ref());
		let ext = path
			.extension()
			.and_then(|s| s.to_str())
			.unwrap_or("")
			.to_ascii_lowercase();

		if !is_under_secure {
			// Outside .secure, there must be no derived thumbnail images such as jpg/png/webp/gif/avif.
			if ["jpg", "jpeg", "png", "webp", "gif", "avif"].contains(&ext.as_str()) {
				panic!(
					"found unexpected plaintext image thumbnail outside .secure: {:?}",
					path
				);
			}
		} else {
			// Under .secure, track presence of catalog and at least one media ciphertext.
			let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
			if file_name == "catalog.enc" {
				catalog_enc_present = true;
			}
			if file_name == "catalog.meta.json" {
				catalog_meta_present = true;
			}
			if file_name.ends_with(".enc") && file_name != "catalog.enc" {
				has_media_ciphertext = true;
			}
		}
	}

	assert!(
		catalog_enc_present,
		"catalog.enc should exist under .secure"
	);
	assert!(
		catalog_meta_present,
		"catalog.meta.json should exist under .secure"
	);
	assert!(
		has_media_ciphertext,
		"at least one encrypted media file (*.enc) should exist under .secure",
	);

	// Decrypt catalog to ensure that item-level metadata is only present inside the
	// encrypted catalog, not duplicated elsewhere in plaintext.
	let catalog_path = secure_dir.join("catalog.enc");
	let meta_path = secure_dir.join("catalog.meta.json");
	let meta_bytes = std::fs::read(&meta_path).expect("read catalog meta");
	let meta_json: serde_json::Value =
		serde_json::from_slice(&meta_bytes).expect("parse catalog meta json");

	let nonce_b64 = meta_json.get("nonce").and_then(|v| v.as_str()).unwrap();
	let tag_b64 = meta_json.get("tag").and_then(|v| v.as_str()).unwrap();
	let original_size = meta_json
		.get("plaintext_size")
		.and_then(|v| v.as_u64())
		.unwrap() as usize;
	let padded_size = meta_json
		.get("padded_size")
		.and_then(|v| v.as_u64())
		.unwrap() as usize;

	let dek: DataEncryptionKey =
		derive_data_encryption_key(&lmk, "catalog").expect("derive DEK for catalog");
	let padded_ciphertext = std::fs::read(&catalog_path).expect("read catalog.enc");

	let nonce_bytes = BASE64.decode(nonce_b64).expect("decode nonce");
	let tag_bytes = BASE64.decode(tag_b64).expect("decode tag");
	let nonce = AesGcmNonce::from_slice(&nonce_bytes).expect("nonce slice");
	let tag = AesGcmTag::from_slice(&tag_bytes).expect("tag slice");

	let encrypted = EncryptedFile {
		ciphertext: padded_ciphertext,
		nonce,
		tag,
		original_size,
		padded_size,
	};

	let plaintext = decrypt_file(&dek, &encrypted).expect("decrypt catalog");
	let catalog_json: serde_json::Value =
		serde_json::from_slice(&plaintext).expect("parse catalog json");

	// Sanity check: catalog contains media list with titles, but this metadata only
	// lives in the encrypted payload, not in DB rows.
	let media_items = catalog_json
		.get("media")
		.and_then(|v| v.as_array())
		.cloned()
		.unwrap_or_default();
	assert!(
		!media_items.is_empty(),
		"catalog should contain at least one media item",
	);

	// ---------------------------------------------------------------------
	// (b) & (c) No SMK/LMK/DEK leakage into DB/logs (offline attacker view)
	// ---------------------------------------------------------------------

	let smk_b64 = smk.to_base64();
	let lmk_b64 = BASE64.encode(lmk.expose_secret());
	let dek_b64 = BASE64.encode(dek.expose_secret());
	let secrets = [smk_b64.as_str(), lmk_b64.as_str(), dek_b64.as_str()];

	// CryptoAuditLog: ensure no string fields contain raw key material.
	let logs = db
		.crypto_audit_log()
		.find_many(vec![])
		.exec()
		.await
		.expect("query crypto_audit_log");

	for log in logs {
		let candidates = [
			log.event_type,
			log.target_type.unwrap_or_default(),
			log.target_id.unwrap_or_default(),
			log.ip_address.unwrap_or_default(),
			log.user_agent.unwrap_or_default(),
			log.details.unwrap_or_default(),
			log.error_message.unwrap_or_default(),
		];
		for value in &candidates {
			for secret in &secrets {
				assert!(
					!value.contains(secret),
					"crypto_audit_log row unexpectedly contained raw key material",
				);
			}
		}
	}

	// LibraryEncryptionMetadata: verification_tag is HMAC(LMK, library_id) and must not
	// equal raw SMK/LMK/DEK bytes.
	if let Some(meta) = db
		.library_encryption_metadata()
		.find_unique(library_encryption_metadata::library_id::equals(
			lib.id.clone(),
		))
		.exec()
		.await
		.expect("query library_encryption_metadata")
	{
		let vt_b64 = BASE64.encode(&meta.verification_tag);
		for secret in &secrets {
			assert_ne!(
				vt_b64, *secret,
				"verification_tag should not equal raw key material",
			);
		}
	}
}

/// Encrypted catalog version handling (T078/T079): MVP supports only version 1. If a
/// catalog with an unknown version is encountered on disk, the server must treat it as
/// unsupported/broken and regenerate from scratch without attempting to partially
/// interpret it.
#[tokio::test]
async fn secure_library_catalog_unknown_version_is_ignored_and_regenerated() {
	// Use a dedicated SQLite DB for this test, similar to the offline snapshot test.
	let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("integration-tests/secure-libraries-endpoints-versioning");
	std::fs::create_dir_all(&test_dir).expect("create test db dir");
	let sqlite_url = format!(
		"file:{}/secure_libraries_endpoints_versioning.db",
		test_dir.to_str().unwrap()
	);
	let client: PrismaClient = create_client_with_url(&sqlite_url).await;
	let db_arc = Arc::new(client);
	let db: &PrismaClient = db_arc.as_ref();

	run_migrations(db)
		.await
		.expect("run migrations for secure_libraries_endpoints_versioning");

	// Create a temporary library root with one CBZ to ensure catalog has at least one
	// media item.
	let temp_dir = TempDir::new().expect("tmp dir");
	let library_root = temp_dir.path().join("secure-endpoints-lib-versioning");
	std::fs::create_dir_all(&library_root).expect("mkdirs");

	std::fs::write(
		library_root.join("root_book.cbz"),
		read_test_file("science_comics_001.cbz"),
	)
	.expect("write root book");

	// Insert library_config and secure library rows.
	let cfg = db
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("create library_config");

	let lib = db
		.library()
		.create(
			"secure-endpoints-lib-versioning".to_string(),
			library_root.to_string_lossy().to_string(),
			library_config::id::equals(cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("create secure library");

	// Derive LMK from a generated SMK for this library.
	let smk = SystemMasterKey::generate();
	let lmk = KeyManagementService::derive_lmk(&smk, &lib.id).expect("derive LMK");

	// Run SecureEncryptionJob once to create an initial v1 catalog.
	let enc_tmp = TempDir::new().expect("enc tmpdir");
	let enc_base = PathBuf::from(enc_tmp.path());
	let handle = spawn_encryption_task(
		lib.id.clone(),
		PathBuf::from(&lib.path),
		lmk.clone(),
		enc_base.clone(),
		db_arc.clone(),
	);
	let result = handle.await.expect("join encryption task");
	result.expect("encryption task should succeed");

	let secure_dir = PathBuf::from(&lib.path).join(".secure");
	let catalog_path = secure_dir.join("catalog.enc");
	let meta_path = secure_dir.join("catalog.meta.json");

	// Decrypt initial catalog to confirm it is version 1 and capture its media count.
	let meta_bytes = std::fs::read(&meta_path).expect("read catalog meta");
	let meta_json: serde_json::Value =
		serde_json::from_slice(&meta_bytes).expect("parse catalog meta json");
	let nonce_b64 = meta_json.get("nonce").and_then(|v| v.as_str()).unwrap();
	let tag_b64 = meta_json.get("tag").and_then(|v| v.as_str()).unwrap();
	let original_size = meta_json
		.get("plaintext_size")
		.and_then(|v| v.as_u64())
		.unwrap() as usize;
	let padded_size = meta_json
		.get("padded_size")
		.and_then(|v| v.as_u64())
		.unwrap() as usize;

	let dek: DataEncryptionKey =
		derive_data_encryption_key(&lmk, "catalog").expect("derive DEK for catalog");
	let padded_ciphertext = std::fs::read(&catalog_path).expect("read catalog.enc");

	let nonce_bytes = BASE64.decode(nonce_b64).expect("decode nonce");
	let tag_bytes = BASE64.decode(tag_b64).expect("decode tag");
	let nonce = AesGcmNonce::from_slice(&nonce_bytes).expect("nonce slice");
	let tag = AesGcmTag::from_slice(&tag_bytes).expect("tag slice");

	let encrypted = EncryptedFile {
		ciphertext: padded_ciphertext,
		nonce,
		tag,
		original_size,
		padded_size,
	};

	let plaintext = decrypt_file(&dek, &encrypted).expect("decrypt initial catalog");
	let initial_catalog: serde_json::Value =
		serde_json::from_slice(&plaintext).expect("parse initial catalog json");
	assert_eq!(
		initial_catalog.get("version").and_then(|v| v.as_u64()),
		Some(1),
		"initial catalog version should be 1",
	);
	let initial_media = initial_catalog
		.get("media")
		.and_then(|v| v.as_array())
		.cloned()
		.unwrap_or_default();
	assert!(
		!initial_media.is_empty(),
		"initial v1 catalog should contain at least one media item",
	);

	// Overwrite catalog.enc with a bogus v2 catalog that the server must ignore.
	let bogus_v2 = serde_json::json!({
		"version": 2,
		"library_id": lib.id,
		"library_name": "bogus-v2",
		"generated_at": "2025-01-01T00:00:00Z",
		"series": [],
		"media": [
			{"id": "bogus-id", "series_id": null, "title": "Bogus Item"}
		],
	});
	let bogus_bytes = serde_json::to_vec(&bogus_v2).expect("serialize bogus v2 catalog");
	let bogus_enc = encrypt_file(&dek, &bogus_bytes).expect("encrypt bogus v2 catalog");
	std::fs::write(&catalog_path, &bogus_enc.ciphertext)
		.expect("overwrite catalog.enc with bogus v2");
	let bogus_meta = serde_json::json!({
		"nonce": bogus_enc.nonce.to_base64(),
		"tag": bogus_enc.tag.to_base64(),
		"plaintext_size": bogus_enc.original_size,
		"padded_size": bogus_enc.padded_size,
	});
	std::fs::write(&meta_path, serde_json::to_vec(&bogus_meta).unwrap())
		.expect("overwrite catalog.meta.json for bogus v2");

	// Rerun SecureEncryptionJob. The write_encrypted_catalog logic should detect the
	// unsupported version and regenerate a fresh v1 catalog instead of attempting to
	// partially interpret the bogus v2 payload.
	let handle2 = spawn_encryption_task(
		lib.id.clone(),
		PathBuf::from(&lib.path),
		lmk.clone(),
		enc_base.clone(),
		db_arc.clone(),
	);
	let result2 = handle2.await.expect("join encryption task (retry)");
	result2.expect("encryption retry should succeed");

	// Decrypt the regenerated catalog and assert it is version 1 and does not preserve
	// the bogus v2 payload.
	let meta_bytes2 = std::fs::read(&meta_path).expect("read regenerated catalog meta");
	let meta_json2: serde_json::Value =
		serde_json::from_slice(&meta_bytes2).expect("parse regenerated catalog meta");
	let nonce_b64_2 = meta_json2.get("nonce").and_then(|v| v.as_str()).unwrap();
	let tag_b64_2 = meta_json2.get("tag").and_then(|v| v.as_str()).unwrap();
	let original_size2 = meta_json2
		.get("plaintext_size")
		.and_then(|v| v.as_u64())
		.unwrap() as usize;
	let padded_size2 = meta_json2
		.get("padded_size")
		.and_then(|v| v.as_u64())
		.unwrap() as usize;

	let padded_ciphertext2 =
		std::fs::read(&catalog_path).expect("read regenerated catalog.enc");
	let nonce_bytes2 = BASE64.decode(nonce_b64_2).expect("decode nonce 2");
	let tag_bytes2 = BASE64.decode(tag_b64_2).expect("decode tag 2");
	let nonce2 = AesGcmNonce::from_slice(&nonce_bytes2).expect("nonce slice 2");
	let tag2 = AesGcmTag::from_slice(&tag_bytes2).expect("tag slice 2");

	let encrypted2 = EncryptedFile {
		ciphertext: padded_ciphertext2,
		nonce: nonce2,
		tag: tag2,
		original_size: original_size2,
		padded_size: padded_size2,
	};

	let plaintext2 =
		decrypt_file(&dek, &encrypted2).expect("decrypt regenerated catalog");
	let regenerated: serde_json::Value =
		serde_json::from_slice(&plaintext2).expect("parse regenerated catalog json");
	assert_eq!(
		regenerated.get("version").and_then(|v| v.as_u64()),
		Some(1),
		"regenerated catalog should be version 1",
	);
	let media2 = regenerated
		.get("media")
		.and_then(|v| v.as_array())
		.cloned()
		.unwrap_or_default();
	assert!(
		!media2.is_empty(),
		"regenerated v1 catalog should contain at least one media item",
	);
	assert!(
		media2
			.iter()
			.all(|m| m.get("id").and_then(|v| v.as_str()) != Some("bogus-id")),
		"regenerated catalog must not preserve bogus v2 media entries",
	);
}
