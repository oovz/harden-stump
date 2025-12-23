extern crate stump_core;

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use prisma_client_rust::serde_json;
use tempfile::TempDir;
use walkdir::WalkDir;

use stump_core::crypto::keys::derive_data_encryption_key;
use stump_core::crypto::services::encryption_task::spawn_encryption_task;
use stump_core::crypto::services::key_management::KeyManagementService;
use stump_core::crypto::smk::SystemMasterKey;
use stump_core::crypto::types::{AesGcmNonce, AesGcmTag, DataEncryptionKey};
use stump_core::db::{
	create_client_with_url, entity::LibraryPattern, migration::run_migrations,
};
use stump_core::prisma::{library, library_config, PrismaClient};

fn read_test_file(name: &str) -> Vec<u8> {
	let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	std::fs::read(manifest.join("data").join(name)).expect("read test file")
}

fn list_media_ciphertexts(secure_dir: &PathBuf) -> Vec<String> {
	let mut files = Vec::new();
	for entry in WalkDir::new(secure_dir) {
		let entry = entry.expect("walkdir entry");
		if !entry.file_type().is_file() {
			continue;
		}
		let path = entry.path();
		let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
		if file_name.ends_with(".enc") && file_name != "catalog.enc" {
			files.push(file_name.to_string());
		}
	}
	files.sort();
	files
}

/// T071 (retry safety): running SecureEncryptionJob multiple times for the same secure
/// library must be idempotent at the catalog/DB level and must not introduce duplicate
/// ciphertexts or plaintext metadata.
#[tokio::test]
async fn secure_encryption_job_retry_is_idempotent() {
	// Dedicated SQLite DB for this test.
	let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("integration-tests/secure-encryption-job-retry");
	std::fs::create_dir_all(&test_dir).expect("create test db dir");
	let sqlite_url = format!(
		"file:{}/secure_encryption_job_retry.db",
		test_dir.to_str().unwrap()
	);
	let client: PrismaClient = create_client_with_url(&sqlite_url).await;
	let db_arc = Arc::new(client);
	let db: &PrismaClient = db_arc.as_ref();

	run_migrations(db)
		.await
		.expect("run migrations for secure_encryption_job_retry");

	// Create a small secure library with two plaintext files.
	let temp_dir = TempDir::new().expect("tmp dir");
	let library_root = temp_dir.path().join("secure-retry-lib");
	let series_1 = library_root.join("series-1");
	std::fs::create_dir_all(&series_1).expect("mkdirs");

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
			"secure-retry-lib".to_string(),
			library_root.to_string_lossy().to_string(),
			library_config::id::equals(cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("create secure library");

	// Derive LMK and run SecureEncryptionJob once.
	let smk = SystemMasterKey::generate();
	let lmk = KeyManagementService::derive_lmk(&smk, &lib.id).expect("derive LMK");

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
	result.expect("encryption task should succeed (first run)");

	let secure_dir = PathBuf::from(&lib.path).join(".secure");
	assert!(
		secure_dir.exists(),
		".secure directory should exist after first run"
	);

	let enc_files_first = list_media_ciphertexts(&secure_dir);
	assert!(
		!enc_files_first.is_empty(),
		"first run should produce at least one encrypted media ciphertext",
	);

	// Decrypt catalog to ensure it is valid v1 and record media count.
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

	let nonce_bytes = base64::engine::general_purpose::STANDARD
		.decode(nonce_b64)
		.expect("decode nonce");
	let tag_bytes = base64::engine::general_purpose::STANDARD
		.decode(tag_b64)
		.expect("decode tag");
	let nonce = AesGcmNonce::from_slice(&nonce_bytes).expect("nonce slice");
	let tag = AesGcmTag::from_slice(&tag_bytes).expect("tag slice");

	let encrypted = stump_core::crypto::encrypt::EncryptedFile {
		ciphertext: padded_ciphertext,
		nonce,
		tag,
		original_size,
		padded_size,
	};

	let plaintext = stump_core::crypto::encrypt::decrypt_file(&dek, &encrypted)
		.expect("decrypt catalog");
	let catalog_json: serde_json::Value =
		serde_json::from_slice(&plaintext).expect("parse catalog json");
	assert_eq!(
		catalog_json.get("version").and_then(|v| v.as_u64()),
		Some(1),
		"initial catalog should be version 1",
	);
	let media = catalog_json
		.get("media")
		.and_then(|v| v.as_array())
		.cloned()
		.unwrap_or_default();
	assert!(
		!media.is_empty(),
		"initial catalog should contain at least one media item",
	);

	// Capture DB encryption counters after first run.
	let lib_after_first = db
		.library()
		.find_unique(library::id::equals(lib.id.clone()))
		.exec()
		.await
		.expect("query library after first run")
		.expect("library should still exist");
	assert_eq!(lib_after_first.encryption_status, "ENCRYPTED");

	// Run SecureEncryptionJob a second time with the same inputs. This simulates a safe
	// retry where the job is scheduled again for an already-encrypted secure library.
	let handle2 = spawn_encryption_task(
		lib.id.clone(),
		PathBuf::from(&lib.path),
		lmk.clone(),
		enc_base.clone(),
		db_arc.clone(),
	);
	let result2 = handle2.await.expect("join encryption task (retry)");
	result2.expect("encryption task should succeed (second run)");

	let enc_files_second = list_media_ciphertexts(&secure_dir);
	assert_eq!(
		enc_files_first, enc_files_second,
		"retry should not create duplicate or additional encrypted media files",
	);

	let lib_after_second = db
		.library()
		.find_unique(library::id::equals(lib.id.clone()))
		.exec()
		.await
		.expect("query library after second run")
		.expect("library should still exist after retry");
	assert_eq!(lib_after_second.encryption_status, "ENCRYPTED");
	assert_eq!(
		lib_after_second.total_files, lib_after_first.total_files,
		"total_files should remain stable across retries",
	);
	assert_eq!(
		lib_after_second.encrypted_files, lib_after_first.encrypted_files,
		"encrypted_files count should remain stable across retries",
	);

	// Ensure that plaintext secure media/series are still not indexed in the DB.
	let media_rows = db
		.media()
		.find_many(vec![stump_core::prisma::media::series::is(vec![
			stump_core::prisma::series::library_id::equals(Some(lib.id.clone())),
		])])
		.exec()
		.await
		.expect("query media rows for secure library after retry");
	assert!(
		media_rows.is_empty(),
		"retry should not introduce plaintext media rows for secure library",
	);
}
