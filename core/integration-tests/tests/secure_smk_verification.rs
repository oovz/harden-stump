extern crate stump_core;

use stump_core::crypto::errors::CryptoError;
use stump_core::crypto::services::key_management::KeyManagementService;
use stump_core::crypto::smk::SystemMasterKey;
use stump_core::db::create_client_with_url;
use stump_core::db::entity::CryptoAuditEventType;
use stump_core::db::migration::run_migrations;
use stump_core::prisma::{crypto_audit_log, library, library_config, PrismaClient};
use tempfile::TempDir;

#[tokio::test]
async fn smk_verification_succeeds_for_correct_key() {
	let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("integration-tests/smk-verification");
	std::fs::create_dir_all(&test_dir).expect("create test db dir");
	let sqlite_url = format!("file:{}/smk_verification.db", test_dir.to_str().unwrap());
	let client: PrismaClient = create_client_with_url(&sqlite_url).await;
	let db: &PrismaClient = &client;

	run_migrations(db).await.expect("run migrations");

	let cfg = db
		.library_config()
		.create(vec![])
		.exec()
		.await
		.expect("create library_config");

	let temp_dir = TempDir::new().expect("tmp dir");
	let unique = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_millis();
	let lib_name = format!("smk-verification-lib-{}", unique);
	let library_root = temp_dir.path().join(&lib_name);
	std::fs::create_dir_all(&library_root).expect("mkdir library root");

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

	let smk = SystemMasterKey::generate();
	let lmk = KeyManagementService::derive_lmk(&smk, &lib.id).expect("derive LMK");
	let tag = KeyManagementService::generate_verification_tag(&lmk, &lib.id)
		.expect("generate verification tag");

	db.library_encryption_metadata()
		.create(lib.id.clone(), tag, vec![])
		.exec()
		.await
		.expect("create library_encryption_metadata");

	KeyManagementService::validate_smk_for_library(db, &smk, &lib.id)
		.await
		.expect("SMK should be valid for library");
}

#[tokio::test]
async fn smk_verification_fails_for_wrong_key() {
	let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("integration-tests/smk-verification-wrong");
	std::fs::create_dir_all(&test_dir).expect("create test db dir");
	let sqlite_url = format!(
		"file:{}/smk_verification_wrong.db",
		test_dir.to_str().unwrap()
	);
	let client: PrismaClient = create_client_with_url(&sqlite_url).await;
	let db: &PrismaClient = &client;

	run_migrations(db).await.expect("run migrations");

	let cfg = db
		.library_config()
		.create(vec![])
		.exec()
		.await
		.expect("create library_config");

	let temp_dir = TempDir::new().expect("tmp dir");
	let unique = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_millis();
	let lib_name = format!("smk-verification-lib-wrong-{}", unique);
	let library_root = temp_dir.path().join(&lib_name);
	std::fs::create_dir_all(&library_root).expect("mkdir library root");

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

	let smk = SystemMasterKey::generate();
	let lmk = KeyManagementService::derive_lmk(&smk, &lib.id).expect("derive LMK");
	let tag = KeyManagementService::generate_verification_tag(&lmk, &lib.id)
		.expect("generate verification tag");

	db.library_encryption_metadata()
		.create(lib.id.clone(), tag, vec![])
		.exec()
		.await
		.expect("create library_encryption_metadata");

	let wrong_smk = SystemMasterKey::generate();

	let result =
		KeyManagementService::validate_smk_for_library(db, &wrong_smk, &lib.id).await;

	match result {
		Err(CryptoError::InvalidKey(_)) => {},
		other => panic!("expected InvalidKey error for wrong SMK, got: {:?}", other),
	}
}

#[tokio::test]
async fn cli_setup_creates_system_initialized_sentinel() {
	let temp_dir = TempDir::new().expect("tmp dir");
	let sqlite_path = temp_dir.path().join("cli_setup_sentinel.db");
	let sqlite_url = format!("file:{}", sqlite_path.to_string_lossy());
	let client: PrismaClient = create_client_with_url(&sqlite_url).await;
	let db: &PrismaClient = &client;

	run_migrations(db).await.expect("run migrations");

	let _owner = stump_core::db::setup::create_server_owner_and_initialize(
		db,
		"cli-owner",
		"test_password_123",
	)
	.await
	.expect("run system setup helper");

	// Assert that exactly one SystemInitialized sentinel exists.
	let sentinels = db
		.crypto_audit_log()
		.find_many(vec![crypto_audit_log::event_type::equals(
			CryptoAuditEventType::SystemInitialized.to_string(),
		)])
		.exec()
		.await
		.expect("query sentinels");

	assert_eq!(
		1,
		sentinels.len(),
		"expected exactly one SystemInitialized sentinel row",
	);
}
