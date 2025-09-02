use std::time::Duration;

use diesel::r2d2::{ConnectionManager, CustomizeConnection, Pool};
use diesel::sqlite::SqliteConnection;
use diesel::RunQueryDsl;
use secrecy::{ExposeSecret, SecretBox};
use tracing::{error, info};

/// Wrapper that applies SQLCipher PRAGMAs immediately after a connection is established.
#[derive(Debug)]
pub struct SqlcipherCustomizer {
	/// Raw key bytes (derived master key). Must be 32 bytes for SQLCipher default.
	key: SecretBox<Vec<u8>>,
}

impl SqlcipherCustomizer {
	pub fn new(key: SecretBox<Vec<u8>>) -> Self {
		Self { key }
	}
}

impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqlcipherCustomizer {
	fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
		// IMPORTANT: PRAGMA key must be the first statement
		let key_hex = hex::encode(self.key.expose_secret());
		let key_stmt = format!("PRAGMA key = \"x'{}'\";", key_hex);

		// run key pragma first
		diesel::sql_query(key_stmt)
			.execute(conn)
			.map_err(|e| diesel::r2d2::Error::QueryError(e))?;

		// optional: verify cipher version (ensures SQLCipher backing)
		if let Err(e) = diesel::sql_query("PRAGMA cipher_version;").execute(conn) {
			error!(error = %e, "SQLCipher not available or key incorrect");
			return Err(diesel::r2d2::Error::QueryError(e));
		}

		// safety & perf PRAGMAs AFTER key
		diesel::sql_query("PRAGMA foreign_keys = ON;")
			.execute(conn)
			.map_err(|e| diesel::r2d2::Error::QueryError(e))?;
		// WAL mode
		let _ = diesel::sql_query("PRAGMA journal_mode = WAL;").execute(conn);
		// reasonable sync
		let _ = diesel::sql_query("PRAGMA synchronous = NORMAL;").execute(conn);

		Ok(())
	}
}

pub type SqlcipherPool = Pool<ConnectionManager<SqliteConnection>>;

pub fn build_sqlcipher_pool(
	db_url: &str,
	key: SecretBox<Vec<u8>>,
) -> anyhow::Result<SqlcipherPool> {
	let manager = ConnectionManager::<SqliteConnection>::new(db_url);
	let customizer = SqlcipherCustomizer::new(key);

	let pool = Pool::builder()
		.max_size(8)
		.connection_timeout(Duration::from_secs(5))
		.connection_customizer(Box::new(customizer))
		.build(manager)?;

	// smoke-test: acquire one connection so PRAGMAs run
	let _conn = pool.get()?;
	info!("SQLCipher connection pool initialized");
	Ok(pool)
}
