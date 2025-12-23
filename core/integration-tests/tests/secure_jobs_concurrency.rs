extern crate stump_core;

use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::time::sleep;

use stump_core::{
	crypto::services::{
		encryption_task::SecureEncryptionJob, key_management::KeyManagementService,
	},
	crypto::smk::SystemMasterKey,
	db::{entity::LibraryPattern, migration::run_migrations},
	filesystem::scanner::LibraryScanJob,
	prisma::{job, library, library_config, PrismaClient},
	Ctx,
};

/// Ensure FR-024: at most one library scan or secure encryption job is RUNNING at any time
#[tokio::test(flavor = "multi_thread")]
async fn secure_and_normal_library_jobs_are_never_running_concurrently() {
	// Initialize real test database and job system
	let ctx = Ctx::integration_test_mock().await;
	let db_arc = ctx.db.clone();
	let db: &PrismaClient = db_arc.as_ref();

	run_migrations(db)
		.await
		.expect("failed to run migrations for job concurrency test");

	// Create two library roots on disk
	let temp_dir = TempDir::new().expect("tmp dir");
	let lib1_root = temp_dir.path().join("job-concurrency-lib-1");
	let lib2_root = temp_dir.path().join("job-concurrency-lib-2");
	std::fs::create_dir_all(&lib1_root).expect("mkdir lib1 root");
	std::fs::create_dir_all(&lib2_root).expect("mkdir lib2 root");
	let lib1_root_str = lib1_root.to_string_lossy().to_string();
	let lib2_root_str = lib2_root.to_string_lossy().to_string();

	// Insert a normal library for scan jobs
	let cfg1 = db
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("create library_config 1");

	let unique = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_millis();
	let lib1_name = format!("job-concurrency-lib-1-{}", unique);

	let lib1 = db
		.library()
		.create(
			lib1_name,
			lib1_root.to_string_lossy().to_string(),
			library_config::id::equals(cfg1.id.clone()),
			vec![],
		)
		.exec()
		.await
		.expect("create library 1");

	// Insert a secure library for SecureEncryptionJob
	let cfg2 = db
		.library_config()
		.create(vec![library_config::library_pattern::set(
			LibraryPattern::SeriesBased.to_string(),
		)])
		.exec()
		.await
		.expect("create library_config 2");

	let secure_lib_name = format!("job-concurrency-secure-lib-{}", unique);

	let secure_lib = db
		.library()
		.create(
			secure_lib_name,
			lib2_root.to_string_lossy().to_string(),
			library_config::id::equals(cfg2.id.clone()),
			vec![
				library::is_secure::set(true),
				library::encryption_status::set("NOT_ENCRYPTED".to_string()),
			],
		)
		.exec()
		.await
		.expect("create secure library");

	// Derive LMK for the secure library to construct a SecureEncryptionJob
	let smk = SystemMasterKey::generate();
	let lmk = KeyManagementService::derive_lmk(&smk, &secure_lib.id)
		.expect("derive LMK for secure library");

	// Enqueue jobs on the global job queue in quick succession:
	// 1) normal library scan
	// 2) secure encryption job
	// 3) another normal library scan
	ctx.enqueue_job(LibraryScanJob::new(
		lib1.id.clone(),
		lib1.path.clone(),
		None,
	))
	.expect("enqueue first library scan job");

	ctx.enqueue_job(SecureEncryptionJob::new(
		secure_lib.id.clone(),
		secure_lib.path.clone(),
		lmk,
	))
	.expect("enqueue secure encryption job");

	ctx.enqueue_job(LibraryScanJob::new(
		secure_lib.id.clone(),
		secure_lib.path.clone(),
		None,
	))
	.expect("enqueue second library scan job");

	// Warmup: wait until at least one relevant job for this test has been
	// persisted to the jobs table before we start asserting on concurrency.
	// This avoids racing the asynchronous job controller/enqueue pipeline.
	let warmup_deadline = Instant::now() + Duration::from_secs(5);
	loop {
		let jobs = db
			.job()
			.find_many(vec![])
			.exec()
			.await
			.expect("query jobs table during warmup");

		let has_target = jobs.iter().any(|j| {
			let desc = j.description.as_deref().unwrap_or("");
			let belongs_to_this_test =
				desc.contains(&lib1_root_str) || desc.contains(&lib2_root_str);
			let is_target = j.name == "library_scan" || j.name == "secure_encryption";
			belongs_to_this_test && is_target
		});

		if has_target {
			break;
		}

		if Instant::now() > warmup_deadline {
			panic!("Timed out waiting for jobs to be persisted for concurrency test");
		}

		sleep(Duration::from_millis(25)).await;
	}

	// Poll the jobs table while any relevant jobs are QUEUED or RUNNING and assert
	// that we never observe more than one library_scan/secure_encryption job RUNNING
	// at the same time.
	let deadline = Instant::now() + Duration::from_secs(30);

	loop {
		let jobs = db
			.job()
			.find_many(vec![])
			.exec()
			.await
			.expect("query jobs table");

		let mut running_secure_or_scan = 0usize;
		let mut pending_secure_or_scan = 0usize;

		for j in &jobs {
			let desc = j.description.as_deref().unwrap_or("");
			let belongs_to_this_test =
				desc.contains(&lib1_root_str) || desc.contains(&lib2_root_str);
			if !belongs_to_this_test {
				continue;
			}

			let is_target = j.name == "library_scan" || j.name == "secure_encryption";
			if !is_target {
				continue;
			}

			let status = j.status.as_str();
			if status == "RUNNING" {
				running_secure_or_scan += 1;
			}
			if status == "RUNNING" || status == "QUEUED" {
				pending_secure_or_scan += 1;
			}
		}

		assert!(
			running_secure_or_scan <= 1,
			"More than one library_scan/secure_encryption job RUNNING concurrently: {:?}",
			jobs.iter()
				.filter(|j| {
					(j.name == "library_scan" || j.name == "secure_encryption")
						&& j.status == "RUNNING"
				})
				.map(|j| (&j.id, &j.name, &j.status))
				.collect::<Vec<_>>()
		);

		if pending_secure_or_scan == 0 {
			break;
		}

		if Instant::now() > deadline {
			panic!("Timed out waiting for secure/library jobs to complete");
		}

		sleep(Duration::from_millis(25)).await;
	}

	// Sanity check: at least one secure_encryption job should have been persisted
	let secure_jobs = db
		.job()
		.find_many(vec![job::name::equals("secure_encryption".to_string())])
		.exec()
		.await
		.expect("query final jobs");

	assert!(
		!secure_jobs.is_empty(),
		"Expected at least one secure_encryption job to have been persisted",
	);
}
