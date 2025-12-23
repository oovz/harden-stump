extern crate stump_core;

use std::path::PathBuf;
use tempfile::TempDir;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use prisma_client_rust::serde_json;
use std::fs;
use stump_core::crypto::encrypt::{decrypt_file, EncryptedFile};
use stump_core::crypto::keys::derive_data_encryption_key;
use stump_core::crypto::services::encryption_task::spawn_encryption_task;
use stump_core::crypto::services::key_management::KeyManagementService;
use stump_core::crypto::smk::SystemMasterKey;
use stump_core::crypto::types::{AesGcmNonce, AesGcmTag, DataEncryptionKey};
use stump_core::db::create_client_with_url;
use stump_core::db::entity::LibraryPattern;
use stump_core::db::migration::run_migrations;
use stump_core::prisma::{library_config, PrismaClient};

fn read_test_file(name: &str) -> Vec<u8> {
	let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	std::fs::read(manifest.join("data").join(name)).expect("read test file")
}

#[tokio::test]
async fn test_secure_library_catalog_and_layout() {
	// Initialize a dedicated SQLite DB for this test to avoid contention on the
	// shared integration test database used by other tests.
	let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("integration-tests/secure-library");
	std::fs::create_dir_all(&test_dir).expect("create test db dir");
	let sqlite_url = format!("file:{}/secure_library.db", test_dir.to_str().unwrap());
	let client: PrismaClient = create_client_with_url(&sqlite_url).await;
	let db_arc = std::sync::Arc::new(client);
	let db: &PrismaClient = db_arc.as_ref();

	// Ensure schema exists for test database
	run_migrations(db).await.expect("run migrations");

	// Create a temporary series-based library on disk
	let temp_dir = TempDir::new().expect("tmp dir");
	let library_root = temp_dir.path().join("series-lib");
	let series_1 = library_root.join("series-1");
	fs::create_dir_all(&series_1).expect("mkdirs");
	fs::write(library_root.join("book.zip"), read_test_file("book.zip"))
		.expect("write root book");
	fs::write(
		series_1.join("science_comics_001.cbz"),
		read_test_file("science_comics_001.cbz"),
	)
	.expect("write series book");

	// Insert library_config and library rows
	let opts = db
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("create options");

	let unique = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_millis();
	let lib_name = format!("secure-test-{}", unique);

	let lib = db
		.library()
		.create(
			lib_name,
			library_root.to_string_lossy().to_string(),
			library_config::id::equals(opts.id.clone()),
			vec![],
		)
		.exec()
		.await
		.expect("create library");

	// Note: Do NOT run DB-based scanner; secure library encryption scans filesystem directly.

	// Derive LMK from a generated SMK
	let smk = SystemMasterKey::generate();
	let lmk = KeyManagementService::derive_lmk(&smk, &lib.id).expect("derive lmk");

	// Encrypted storage base
	let enc_tmp = TempDir::new().expect("enc tmpdir");
	let enc_base = PathBuf::from(enc_tmp.path());

	// Spawn encryption task and wait for completion
	let handle = spawn_encryption_task(
		lib.id.clone(),
		PathBuf::from(&lib.path),
		lmk.clone(),
		enc_base.clone(),
		db_arc.clone(),
	);
	let result = handle.await.expect("join");
	result.expect("encryption task should succeed");

	// Verify catalog files exist in-place under <library.path>/.secure
	let lib_dir = PathBuf::from(&lib.path).join(".secure");
	let catalog_path = lib_dir.join("catalog.enc");
	let meta_path = lib_dir.join("catalog.meta.json");
	assert!(catalog_path.exists(), "catalog.enc should exist");
	assert!(meta_path.exists(), "catalog.meta.json should exist");

	// Verify meta JSON has required fields
	let meta_bytes = std::fs::read(&meta_path).expect("read meta");
	let meta_json: serde_json::Value =
		serde_json::from_slice(&meta_bytes).expect("parse meta");
	assert!(meta_json.get("nonce").and_then(|v| v.as_str()).is_some());
	assert!(meta_json.get("tag").and_then(|v| v.as_str()).is_some());
	assert!(meta_json
		.get("plaintext_size")
		.and_then(|v| v.as_u64())
		.is_some());
	assert!(meta_json
		.get("padded_size")
		.and_then(|v| v.as_u64())
		.is_some());

	// Decrypt catalog JSON using LMK-derived DEK("catalog") and verify fields
	let dek: DataEncryptionKey =
		derive_data_encryption_key(&lmk, "catalog").expect("derive DEK");
	let padded_ciphertext = std::fs::read(&catalog_path).expect("read catalog.enc");
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

	let nonce_bytes = BASE64.decode(nonce_b64).expect("decode nonce");
	let tag_bytes = BASE64.decode(tag_b64).expect("decode tag");
	let nonce = AesGcmNonce::from_slice(&nonce_bytes).expect("nonce slice");
	let tag = AesGcmTag::from_slice(&tag_bytes).expect("tag slice");

	// Build EncryptedFile to feed into decrypt_file
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
	assert_eq!(
		catalog_json
			.get("version")
			.and_then(|v| v.as_u64())
			.unwrap_or(0),
		1
	);
	assert_eq!(
		catalog_json
			.get("library_id")
			.and_then(|v| v.as_str())
			.unwrap(),
		lib.id
	);

	// Verify total counts are present
	assert!(
		catalog_json
			.get("total_series")
			.and_then(|v| v.as_u64())
			.is_some(),
		"catalog should have total_series field"
	);
	assert!(
		catalog_json
			.get("total_media")
			.and_then(|v| v.as_u64())
			.is_some(),
		"catalog should have total_media field"
	);

	// Verify on-disk layout: .secure directory should contain catalog and at least one *.enc
	let secure_dir = PathBuf::from(&lib.path).join(".secure");
	assert!(secure_dir.exists(), ".secure directory should exist");
	let mut has_enc = false;
	if let Ok(rd) = std::fs::read_dir(&secure_dir) {
		for entry in rd.flatten() {
			let p = entry.path();
			if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
				if name.ends_with(".enc") && name != "catalog.enc" {
					has_enc = true;
					break;
				}
			}
		}
	}
	assert!(has_enc, "At least one encrypted media file should exist");
}
