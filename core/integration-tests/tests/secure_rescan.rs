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
use stump_core::db::entity::LibraryPattern;
use stump_core::db::migration::run_migrations;
use stump_core::prisma::{library_config, PrismaClient};
use stump_core::Ctx;

fn read_test_file(name: &str) -> Vec<u8> {
	let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	std::fs::read(manifest.join("data").join(name)).expect("read test file")
}

#[tokio::test]
async fn test_secure_library_rescan_updates_catalog() {
	// Initialize DB and create library
	let ctx = Ctx::integration_test_mock().await;
	let db_arc = ctx.db.clone();
	let db: &PrismaClient = db_arc.as_ref();

	run_migrations(db).await.expect("run migrations");

	// Create a temporary series-based library on disk
	let temp_dir = TempDir::new().expect("tmp dir");
	let library_root = temp_dir.path().join("series-lib-rescan");
	let series_1 = library_root.join("series-1");
	fs::create_dir_all(&series_1).expect("mkdirs");

	// Initial plaintext book
	let initial_book_name = "initial_001.cbz";
	fs::write(
		series_1.join(initial_book_name),
		read_test_file("science_comics_001.cbz"),
	)
	.expect("write initial book");

	// Insert library rows
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
	let lib_name = format!("secure-rescan-{}", unique);

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

	// Derive LMK
	let smk = SystemMasterKey::generate();
	let lmk = KeyManagementService::derive_lmk(&smk, &lib.id).expect("derive lmk");

	// First encryption run
	let enc_tmp = TempDir::new().expect("enc tmpdir");
	let enc_base = PathBuf::from(enc_tmp.path());
	let handle = spawn_encryption_task(
		lib.id.clone(),
		PathBuf::from(&lib.path),
		lmk.clone(),
		enc_base.clone(),
		ctx.db.clone(),
	);
	let result = handle.await.expect("join");
	result.expect("encryption task should succeed (first)");

	// Verify catalog exists
	let secure_dir = PathBuf::from(&lib.path).join(".secure");
	let catalog_path = secure_dir.join("catalog.enc");
	let meta_path = secure_dir.join("catalog.meta.json");
	assert!(catalog_path.exists());
	assert!(meta_path.exists());

	// Add a new plaintext book
	let new_book_name = "new_title_002.cbz";
	let new_plain = series_1.join(new_book_name);
	fs::write(&new_plain, read_test_file("science_comics_001.cbz"))
		.expect("write new book");

	// Second encryption run (rescan)
	let handle2 = spawn_encryption_task(
		lib.id.clone(),
		PathBuf::from(&lib.path),
		lmk.clone(),
		enc_base.clone(),
		ctx.db.clone(),
	);
	let result2 = handle2.await.expect("join");
	result2.expect("encryption task should succeed (second)");

	// Verify plaintext removed for new file
	assert!(
		!new_plain.exists(),
		"new plaintext book should be deleted after encryption"
	);

	// Decrypt catalog and verify new title present
	let meta_bytes = std::fs::read(&meta_path).expect("read meta");
	let meta_json: serde_json::Value =
		serde_json::from_slice(&meta_bytes).expect("parse meta");
	let nonce_b64 = meta_json.get("nonce").and_then(|v| v.as_str()).unwrap();
	let tag_b64 = meta_json.get("tag").and_then(|v| v.as_str()).unwrap();
	let original_size = meta_json
		.get("plaintext_size")
		.and_then(|v| v.as_u64())
		.unwrap() as usize;

	let dek: DataEncryptionKey =
		derive_data_encryption_key(&lmk, "catalog").expect("derive DEK");
	let padded_ciphertext = std::fs::read(&catalog_path).expect("read catalog.enc");

	let nonce_bytes = BASE64.decode(nonce_b64).expect("decode nonce");
	let tag_bytes = BASE64.decode(tag_b64).expect("decode tag");
	let nonce = AesGcmNonce::from_slice(&nonce_bytes).expect("nonce slice");
	let tag = AesGcmTag::from_slice(&tag_bytes).expect("tag slice");

	// Need padded_size as well; provide fallback if not present
	let padded_size = meta_json
		.get("padded_size")
		.and_then(|v| v.as_u64())
		.unwrap_or(original_size as u64) as usize;

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

	// Ensure media list has an item with expected name (file stem)
	// media uses `name` field, not `title`
	let media = catalog_json
		.get("media")
		.and_then(|v| v.as_array())
		.cloned()
		.unwrap_or_default();
	let mut found = false;
	for m in media {
		if let Some(name) = m.get("name").and_then(|v| v.as_str()) {
			if name == "new_title_002" {
				found = true;
				break;
			}
		}
	}
	assert!(
		found,
		"catalog should contain the newly added media by name"
	);
}
