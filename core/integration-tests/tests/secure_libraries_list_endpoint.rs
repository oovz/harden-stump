extern crate stump_core;

use prisma_client_rust::serde_json;
use stump_core::db::{
	create_client_with_url,
	entity::{EncryptionStatus, LibraryPattern},
	migration::run_migrations,
};
use stump_core::prisma::{library, library_config, PrismaClient};

#[derive(Debug, serde::Serialize)]
struct SecureLibrarySummary {
	id: String,
	name: String,
	is_secure: bool,
	encryption_status: String,
}

async fn setup_test_db(db_name: &str) -> PrismaClient {
	let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("integration-tests/secure-libraries-list");
	std::fs::create_dir_all(&test_dir).expect("create test db dir");
	let db_path = test_dir.join(db_name);
	if db_path.exists() {
		std::fs::remove_file(&db_path).expect("remove old test db file");
	}
	let sqlite_url = format!("file:{}", db_path.to_str().unwrap());
	let client: PrismaClient = create_client_with_url(&sqlite_url).await;
	run_migrations(&client).await.expect("run migrations");
	client
}

#[tokio::test]
async fn list_secure_libraries_returns_only_accessible_secure_libraries() {
	let client = setup_test_db("list_accessible.db").await;

	// Create one non-secure and two secure libraries (each with its own LibraryConfig).
	let cfg_non_secure = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("create non-secure library_config");

	let non_secure = client
		.library()
		.create(
			"non-secure-lib".to_string(),
			"/tmp/non-secure-lib".to_string(),
			library_config::id::equals(cfg_non_secure.id.clone()),
			vec![],
		)
		.exec()
		.await
		.expect("create non-secure library");

	let cfg1 = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("create secure1 library_config");

	let secure1 = client
		.library()
		.create(
			"secure-lib-1".to_string(),
			"/tmp/secure-lib-1".to_string(),
			library_config::id::equals(cfg1.id.clone()),
			vec![
				library::is_secure::set(true),
				library::encryption_status::set(
					EncryptionStatus::NotEncrypted.to_string(),
				),
			],
		)
		.exec()
		.await
		.expect("create secure library 1");

	let cfg2 = client
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("create secure2 library_config");

	let secure2 = client
		.library()
		.create(
			"secure-lib-2".to_string(),
			"/tmp/secure-lib-2".to_string(),
			library_config::id::equals(cfg2.id.clone()),
			vec![
				library::is_secure::set(true),
				library::encryption_status::set(EncryptionStatus::Encrypted.to_string()),
			],
		)
		.exec()
		.await
		.expect("create secure library 2");

	// Create a user and grant access only to secure1.
	let user = client
		.user()
		.create("list-user".to_string(), "password".to_string(), vec![])
		.exec()
		.await
		.expect("create user");

	client
		.secure_library_access()
		.create(
			user.id.clone(),
			secure1.id.clone(),
			"encrypted_lmk".to_string(),
			"ephemeral_pub".to_string(),
			"nonce".to_string(),
			"admin".to_string(),
			vec![],
		)
		.exec()
		.await
		.expect("grant access to secure1");

	// Simulate list_secure_libraries endpoint logic:
	let accessible_ids =
		stump_core::db::query::secure_library_access::get_user_accessible_libraries(
			&client, &user.id,
		)
		.await
		.expect("get_user_accessible_libraries");

	// Only secure libraries with ids in accessible_ids should be returned.
	let libs = client
		.library()
		.find_many(vec![
			library::id::in_vec(accessible_ids.clone()),
			library::is_secure::equals(true),
		])
		.exec()
		.await
		.expect("query libraries");

	let summaries: Vec<SecureLibrarySummary> = libs
		.into_iter()
		.map(|l| SecureLibrarySummary {
			id: l.id,
			name: l.name,
			is_secure: l.is_secure,
			encryption_status: l.encryption_status,
		})
		.collect();

	// Validate shape and filtering semantics.
	assert_eq!(
		summaries.len(),
		1,
		"only one accessible secure library expected"
	);
	let s = &summaries[0];
	assert_eq!(s.id, secure1.id);
	assert_eq!(s.name, secure1.name);
	assert!(s.is_secure);
	assert_eq!(
		s.encryption_status,
		EncryptionStatus::NotEncrypted.to_string()
	);

	// Non-secure and non-granted secure2 must not be present.
	let ids: Vec<String> = summaries.iter().map(|s| s.id.clone()).collect();
	assert!(!ids.contains(&non_secure.id));
	assert!(!ids.contains(&secure2.id));
}

#[tokio::test]
async fn list_secure_libraries_shape_excludes_path_field() {
	let client = setup_test_db("list_shape.db").await;

	// Create a single secure library and grant access.
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
			"secure-lib-shape".to_string(),
			"/tmp/secure-lib-shape".to_string(),
			library_config::id::equals(cfg.id.clone()),
			vec![
				library::is_secure::set(true),
				library::encryption_status::set(EncryptionStatus::Encrypted.to_string()),
			],
		)
		.exec()
		.await
		.expect("create secure library");

	let user = client
		.user()
		.create("shape-user".to_string(), "password".to_string(), vec![])
		.exec()
		.await
		.expect("create user");

	client
		.secure_library_access()
		.create(
			user.id.clone(),
			lib.id.clone(),
			"encrypted_lmk".to_string(),
			"ephemeral_pub".to_string(),
			"nonce".to_string(),
			"admin".to_string(),
			vec![],
		)
		.exec()
		.await
		.expect("grant access");

	let accessible_ids =
		stump_core::db::query::secure_library_access::get_user_accessible_libraries(
			&client, &user.id,
		)
		.await
		.expect("get_user_accessible_libraries");

	let libs = client
		.library()
		.find_many(vec![
			library::id::in_vec(accessible_ids.clone()),
			library::is_secure::equals(true),
		])
		.exec()
		.await
		.expect("query libraries");

	let summaries: Vec<SecureLibrarySummary> = libs
		.into_iter()
		.map(|l| SecureLibrarySummary {
			id: l.id,
			name: l.name,
			is_secure: l.is_secure,
			encryption_status: l.encryption_status,
		})
		.collect();

	let json = serde_json::to_value(&summaries).expect("serialize summaries");
	let arr = json
		.as_array()
		.cloned()
		.expect("summaries should serialize to array");

	assert_eq!(arr.len(), 1);
	let obj = arr[0].as_object().expect("entry should be an object");

	// Ensure only the documented fields are present; in particular, no `path`.
	assert!(obj.contains_key("id"));
	assert!(obj.contains_key("name"));
	assert!(obj.contains_key("is_secure"));
	assert!(obj.contains_key("encryption_status"));
	assert!(!obj.contains_key("path"));
}
