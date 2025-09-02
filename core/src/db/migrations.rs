use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use diesel::sqlite::SqliteConnection;
use tracing::info;

// Empty scaffold for now; add migration files under core/migrations when schema is defined.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub fn run_migrations(conn: &mut SqliteConnection) -> Result<(), String> {
    info!("Running Diesel migrations (if any)");
    match conn.run_pending_migrations(MIGRATIONS) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
