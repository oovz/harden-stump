extern crate stump_core;

use stump_core::db::{
	create_client_with_url, entity::LibraryPattern, migration::run_migrations,
};
use stump_core::prisma::{library, library_config, PrismaClient};
use tempfile::TempDir;

#[tokio::test]
async fn secure_library_delete_does_not_remove_secure_dir() {
	// Use a dedicated SQLite DB for this test to avoid contention on the shared test.db
	let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("integration-tests/path-lifecycle");
	std::fs::create_dir_all(&test_dir).expect("create test db dir");
	let sqlite_url = format!("file:{}/path_lifecycle.db", test_dir.to_str().unwrap());
	let client: PrismaClient = create_client_with_url(&sqlite_url).await;
	let db: &PrismaClient = &client;

	run_migrations(db).await.expect("run migrations");

	let temp_dir = TempDir::new().expect("tmp dir");
	let library_root = temp_dir.path().join("secure-lib-path-lifecycle");
	std::fs::create_dir_all(&library_root).expect("mkdir library root");

	let secure_dir = library_root.join(".secure");
	std::fs::create_dir_all(&secure_dir).expect("mkdir .secure dir");
	let marker_path = secure_dir.join("marker");
	std::fs::write(&marker_path, b"marker").expect("write marker file");

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
			"secure-lib-path-lifecycle".to_string(),
			library_root.to_string_lossy().to_string(),
			library_config::id::equals(cfg.id.clone()),
			vec![library::is_secure::set(true)],
		)
		.exec()
		.await
		.expect("create secure library");

	db.library()
		.delete(library::id::equals(lib.id.clone()))
		.exec()
		.await
		.expect("delete library");

	assert!(
		secure_dir.exists(),
		".secure directory should remain after deleting secure library",
	);
	assert!(
		marker_path.exists(),
		"files under .secure should remain after deleting secure library",
	);
}
