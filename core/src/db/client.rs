use std::{
	fs,
	path::Path,
	sync::atomic::{AtomicU64, Ordering},
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{config::StumpConfig, prisma};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct JournalModeQueryResult {
	pub journal_mode: String,
}

/// Creates the [`prisma::PrismaClient`]. Will call `create_data_dir` as well
pub async fn create_client(config: &StumpConfig) -> prisma::PrismaClient {
	let config_dir = config
		.get_config_dir()
		.to_str()
		.expect("Error parsing config directory")
		.to_string();
	// NOTE: Prisma 5.16.0 will potentially have a few fixes related to SQLite, in particular fixes for timeouts
	// during query execution. It seems the latest PCR is on 5.1.0 (with a custom patch for PCR-specific things).
	// Hopefully once 5.16.0 is released, PCR will be updated shortly after to take advantage of the improvements.
	// I also believe JOIN performance improvements are coming in 5.16.0, which is exciting too.
	// See https://github.com/prisma/prisma/issues/9562#issuecomment-2162441695
	// See also this note about WAL mode with these fixes: https://github.com/prisma/prisma-engines/pull/4907#issuecomment-2152943591
	// TODO: experiment with this. I experienced some issues with concurrent writes still :/
	// let postfix = "?socket_timeout=15000&busy_timeout=15000&connection_limit=1";

	let sqlite_url = if let Some(path) = config.db_path.clone() {
		format!("file:{path}/stump.db")
	} else if config.profile == "release" {
		tracing::trace!("file:{config_dir}/stump.db");
		format!("file:{config_dir}/stump.db")
	} else {
		format!("file:{}/prisma/dev.db", env!("CARGO_MANIFEST_DIR"))
	};

	tracing::trace!(?sqlite_url, "Creating Prisma client");
	create_client_with_url(&sqlite_url).await
}

pub async fn create_client_with_url(url: &str) -> prisma::PrismaClient {
	prisma::new_client_with_url(url)
		.await
		.expect("Failed to create Prisma client")
}

fn prune_old_test_dbs(test_dir: &Path) {
	const MAX_AGE: Duration = Duration::from_secs(60 * 60); // 1 hour
	let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
		Ok(d) => d.as_nanos(),
		Err(_) => return,
	};
	let cutoff = now.saturating_sub(MAX_AGE.as_nanos());

	let entries = match fs::read_dir(test_dir) {
		Ok(entries) => entries,
		Err(_) => return,
	};

	for entry in entries.flatten() {
		let path = entry.path();
		if !path.is_file() {
			continue;
		}
		let name = match path.file_name().and_then(|s| s.to_str()) {
			Some(name) => name,
			None => continue,
		};
		// Only consider files we created as per-test DBs: test-<nanos>.db
		if !name.starts_with("test-") || !name.ends_with(".db") {
			continue;
		}
		let ts_str = &name[5..name.len() - 3];
		let ts = match ts_str.parse::<u128>() {
			Ok(ts) => ts,
			Err(_) => continue,
		};
		if ts < cutoff {
			let _ = fs::remove_file(&path);
		}
	}
}

static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

pub async fn create_test_client() -> prisma::PrismaClient {
	let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("integration-tests");
	prune_old_test_dbs(&test_dir);
	let ts = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("time went backwards")
		.as_nanos();
	let counter = TEST_DB_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
	let unique_ts = ts.saturating_add(counter);
	let base = format!("file:{}/test-{}.db", test_dir.to_str().unwrap(), unique_ts);
	// For tests, allow longer timeouts to reduce spurious SQLite lock timeouts when tests
	// run in parallel. Each invocation gets its own SQLite file to avoid cross-test
	// contention on a single test.db.
	let url = format!("{base}?socket_timeout=15000&busy_timeout=15000");

	create_client_with_url(&url).await
}
