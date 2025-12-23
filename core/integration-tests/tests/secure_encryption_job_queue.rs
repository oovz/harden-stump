extern crate stump_core;

use std::path::PathBuf;

use base64::Engine as _;
use prisma_client_rust::serde_json;
use tempfile::TempDir;
use walkdir::WalkDir;

use stump_core::crypto::keys::derive_data_encryption_key;
use stump_core::crypto::services::encryption_task::SecureEncryptionJob;
use stump_core::crypto::services::key_management::KeyManagementService;
use stump_core::crypto::smk::SystemMasterKey;
use stump_core::crypto::types::{AesGcmNonce, AesGcmTag, DataEncryptionKey};
use stump_core::db::{entity::LibraryPattern, migration::run_migrations};
use stump_core::prisma::{library, library_config, PrismaClient};
use stump_core::Ctx;

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

async fn wait_for_library_encryption_status(
	client: &PrismaClient,
	lib_id: &str,
	target_status: &str,
) {
	use std::time::Instant;
	use tokio::time::sleep;

	let deadline = Instant::now() + std::time::Duration::from_secs(30);
	loop {
		let lib = client
			.library()
			.find_unique(library::id::equals(lib_id.to_string()))
			.exec()
			.await
			.expect("query library during wait")
			.expect("library should exist during wait");

		if lib.encryption_status == target_status {
			break;
		}

		if Instant::now() > deadline {
			panic!(
				"Timed out waiting for library {} to reach status {} (current: {})",
				lib_id, target_status, lib.encryption_status
			);
		}

		sleep(std::time::Duration::from_millis(50)).await;
	}
}

async fn wait_for_plaintext_deleted(path: &std::path::Path) {
	use std::time::Instant;
	use tokio::time::sleep;

	let deadline = Instant::now() + std::time::Duration::from_secs(30);
	loop {
		if !path.exists() {
			break;
		}

		if Instant::now() > deadline {
			panic!(
				"Timed out waiting for plaintext file to be deleted: {}",
				path.display()
			);
		}

		sleep(std::time::Duration::from_millis(50)).await;
	}
}

/// Verify incremental secure encryption semantics when using SecureEncryptionJob
/// via the job queue instead of the ad-hoc spawn_encryption_task helper.
#[tokio::test(flavor = "multi_thread")]
async fn secure_encryption_job_incremental_via_queue() {
	// Use the shared integration-test context so the job queue and DB client
	// point at the same underlying SQLite file.
	let ctx = Ctx::integration_test_mock().await;
	let client: &PrismaClient = ctx.db.as_ref();

	run_migrations(client)
		.await
		.expect("run migrations for secure_encryption_job_queue");

	// Create a small secure library with one plaintext file.
	let temp_dir = TempDir::new().expect("tmp dir");
	let library_root = temp_dir.path().join("secure-queue-lib");
	let series_1 = library_root.join("series-1");
	std::fs::create_dir_all(&series_1).expect("mkdirs");

	let root_book_path = library_root.join("root_book.cbz");
	std::fs::write(&root_book_path, read_test_file("science_comics_001.cbz"))
		.expect("write root book");

	let cfg = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("create library_config");

	let lib = client
		.library()
		.create(
			"secure-queue-lib".to_string(),
			library_root.to_string_lossy().to_string(),
			library_config::id::equals(cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("create secure library");

	// Derive LMK and enqueue SecureEncryptionJob.
	let smk = SystemMasterKey::generate();
	let lmk = KeyManagementService::derive_lmk(&smk, &lib.id).expect("derive LMK");

	ctx.enqueue_job(SecureEncryptionJob::new(
		lib.id.clone(),
		lib.path.clone(),
		lmk.clone(),
	))
	.expect("enqueue first secure encryption job");

	// Wait for the library to become ENCRYPTED.
	wait_for_library_encryption_status(client, &lib.id, "ENCRYPTED").await;

	let lib_after_first = client
		.library()
		.find_unique(library::id::equals(lib.id.clone()))
		.exec()
		.await
		.expect("query library after first queue run")
		.expect("library should still exist after first run");
	assert_eq!(lib_after_first.encryption_status, "ENCRYPTED");
	assert!(
		lib_after_first.encrypted_files > 0,
		"first queued run should encrypt at least one file",
	);

	let secure_dir = PathBuf::from(&lib.path).join(".secure");
	assert!(
		secure_dir.exists(),
		".secure directory should exist after first queued run",
	);
	let enc_files_first = list_media_ciphertexts(&secure_dir);
	assert!(
		!enc_files_first.is_empty(),
		"first queued run should produce at least one encrypted media ciphertext",
	);

	// Add a new plaintext file and run the job again; only the new file should be processed.
	let new_plain = series_1.join("new_title_002.cbz");
	std::fs::write(&new_plain, read_test_file("science_comics_001.cbz"))
		.expect("write new book");

	ctx.enqueue_job(SecureEncryptionJob::new(
		lib.id.clone(),
		lib.path.clone(),
		lmk.clone(),
	))
	.expect("enqueue second secure encryption job");

	// Wait for the new plaintext file to be deleted as evidence that the queued
	// job has processed it.
	wait_for_plaintext_deleted(&new_plain).await;

	let _lib_after_second = client
		.library()
		.find_unique(library::id::equals(lib.id.clone()))
		.exec()
		.await
		.expect("query library after second queue run")
		.expect("library should still exist after second run");

	let enc_files_second = list_media_ciphertexts(&secure_dir);
	assert!(
		enc_files_second.len() >= enc_files_first.len(),
		"second queued run should not reduce ciphertext count",
	);

	// Run a third time with no new plaintext; this should be idempotent.
	ctx.enqueue_job(SecureEncryptionJob::new(
		lib.id.clone(),
		lib.path.clone(),
		lmk.clone(),
	))
	.expect("enqueue third secure encryption job");

	wait_for_library_encryption_status(client, &lib.id, "ENCRYPTED").await;

	let _lib_after_third = client
		.library()
		.find_unique(library::id::equals(lib.id.clone()))
		.exec()
		.await
		.expect("query library after third queue run")
		.expect("library should still exist after third run");

	let enc_files_third = list_media_ciphertexts(&secure_dir);
	assert_eq!(
		enc_files_second, enc_files_third,
		"third queued run should not create additional encrypted media files",
	);

	// Decrypt catalog to ensure it remains a valid v1 catalog and includes the new media.
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
		"catalog should be version 1 after queued runs",
	);

	// media uses `name` field, not `title`
	let media = catalog_json
		.get("media")
		.and_then(|v| v.as_array())
		.cloned()
		.unwrap_or_default();
	let mut found_new = false;
	for m in media {
		if let Some(name) = m.get("name").and_then(|v| v.as_str()) {
			if name == "new_title_002" {
				found_new = true;
				break;
			}
		}
	}
	assert!(
		found_new,
		"catalog should contain the newly added media by name after queued runs",
	);
}
