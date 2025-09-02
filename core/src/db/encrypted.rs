use std::path::{Path, PathBuf};

use rusqlite::{backup::Backup, Connection, Result as SqliteResult};
use secrecy::{ExposeSecret, SecretBox};
use tracing::{debug, info, warn};

use crate::{config::StumpConfig, CoreError};

const ENCRYPTED_DB_FILENAME: &str = "stump.db";
const UNENCRYPTED_BACKUP_SUFFIX: &str = ".unencrypted.bak";

/// Represents the state of database encryption for a Stump installation
#[derive(Debug, Clone)]
pub enum DatabaseEncryptionState {
    /// No database exists yet - first time setup
    FirstTime,
    /// Unencrypted database exists - needs migration
    UnencryptedExists(PathBuf),
    /// Encrypted database exists - ready to use
    EncryptedExists(PathBuf),
    /// Both encrypted and unencrypted exist - migration was interrupted
    MigrationIncomplete(PathBuf, PathBuf),
}

/// Utilities for managing SQLCipher encrypted databases
pub struct EncryptedDatabase;

impl EncryptedDatabase {
    /// Analyze the current database state for the given config
    pub fn analyze_state(config: &StumpConfig) -> DatabaseEncryptionState {
        let db_dir = config.db_path.clone().unwrap_or_else(|| {
            if config.profile == "release" {
                config.get_config_dir().to_string_lossy().to_string()
            } else {
                format!("{}/prisma", env!("CARGO_MANIFEST_DIR"))
            }
        });

        let db_path = PathBuf::from(db_dir);
        let encrypted_path = db_path.join(ENCRYPTED_DB_FILENAME);
        let unencrypted_backup = db_path.join(format!("{}{}", ENCRYPTED_DB_FILENAME, UNENCRYPTED_BACKUP_SUFFIX));

        match (encrypted_path.exists(), unencrypted_backup.exists()) {
            (false, false) => DatabaseEncryptionState::FirstTime,
            (false, true) => DatabaseEncryptionState::UnencryptedExists(unencrypted_backup),
            (true, false) => DatabaseEncryptionState::EncryptedExists(encrypted_path),
            (true, true) => DatabaseEncryptionState::MigrationIncomplete(encrypted_path, unencrypted_backup),
        }
    }

    /// Open an encrypted SQLite connection using the provided key
    pub fn open_encrypted_connection<P: AsRef<Path>>(
        path: P, 
        key: &SecretBox<Vec<u8>>
    ) -> Result<Connection, CoreError> {
        debug!("Opening encrypted database connection to {:?}", path.as_ref());
        
        let conn = Connection::open(path)?;
        
        // Set encryption key using PRAGMA key with hex encoding
        let key_hex = hex::encode(key.expose_secret());
        conn.execute(&format!("PRAGMA key = \"x'{}'\";", key_hex), [])?;
        
        // Verify the database is accessible and encrypted
        Self::verify_encrypted_database(&conn)?;
        
        info!("Successfully opened encrypted database connection");
        Ok(conn)
    }

    /// Create a new encrypted database with the given key
    pub fn create_encrypted_database<P: AsRef<Path>>(
        path: P,
        key: &SecretBox<Vec<u8>>
    ) -> Result<Connection, CoreError> {
        debug!("Creating new encrypted database at {:?}", path.as_ref());
        
        let conn = Connection::open(path)?;
        
        // Set encryption key
        let key_hex = hex::encode(key.expose_secret());
        conn.execute(&format!("PRAGMA key = \"x'{}'\";", key_hex), [])?;
        
        // Create a simple table to verify encryption is working
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _encryption_test (id INTEGER PRIMARY KEY, value TEXT);",
            [],
        )?;
        
        conn.execute(
            "INSERT INTO _encryption_test (value) VALUES ('encryption_verified');",
            [],
        )?;
        
        info!("Successfully created encrypted database");
        Ok(conn)
    }

    /// Migrate an unencrypted database to encrypted format
    pub fn migrate_to_encrypted<P1: AsRef<Path>, P2: AsRef<Path>>(
        unencrypted_path: P1,
        encrypted_path: P2,
        key: &SecretBox<Vec<u8>>
    ) -> Result<(), CoreError> {
        info!("Starting database encryption migration");
        
        // Open unencrypted source database
        let source_conn = Connection::open(&unencrypted_path)?;
        
        // Create encrypted destination database
        let mut dest_conn = Self::create_encrypted_database(&encrypted_path, key)?;
        
        // Perform backup (copy all data)
        {
            let backup = Backup::new(&source_conn, &mut dest_conn)?;
            backup.run_to_completion(
                5,        // pages per step
                std::time::Duration::from_millis(250), // step delay
                None      // progress callback
            )?;
        } // Drop backup here to release mutable borrow
        
        // Verify the migration was successful
        Self::verify_encrypted_database(&dest_conn)?;
        
        info!("Database encryption migration completed successfully");
        Ok(())
    }

    /// Verify that a database connection is properly encrypted
    fn verify_encrypted_database(conn: &Connection) -> Result<(), CoreError> {
        // Try to read from our test table
        let mut stmt = conn.prepare("SELECT value FROM _encryption_test WHERE value = 'encryption_verified'")?;
        let rows: SqliteResult<Vec<String>> = stmt.query_map([], |row| {
            Ok(row.get(0)?)
        })?.collect();
        
        match rows {
            Ok(values) if !values.is_empty() => {
                debug!("Database encryption verification successful");
                Ok(())
            }
            Ok(_) => {
                warn!("Database encryption verification failed - no test data found");
                Err(CoreError::Unknown("Encrypted database verification failed".to_string()))
            }
            Err(e) => {
                warn!("Database encryption verification failed: {}", e);
                Err(CoreError::Unknown(format!("Database verification error: {}", e)))
            }
        }
    }

    /// Get the database URL for Prisma that points to the encrypted database
    pub fn get_encrypted_database_url(config: &StumpConfig) -> String {
        let db_dir = config.db_path.clone().unwrap_or_else(|| {
            if config.profile == "release" {
                config.get_config_dir().to_string_lossy().to_string()
            } else {
                format!("{}/prisma", env!("CARGO_MANIFEST_DIR"))
            }
        });

        let db_path = PathBuf::from(db_dir);
        let encrypted_path = db_path.join(ENCRYPTED_DB_FILENAME);
        format!("file:{}", encrypted_path.to_string_lossy())
    }

    /// Handle database migration during server startup
    pub async fn handle_startup_migration(
        config: &StumpConfig,
        key: &SecretBox<Vec<u8>>
    ) -> Result<(), CoreError> {
        let state = Self::analyze_state(config);
        
        match state {
            DatabaseEncryptionState::FirstTime => {
                info!("First time setup - encrypted database will be created by Prisma migrations");
                Ok(())
            }
            DatabaseEncryptionState::EncryptedExists(_) => {
                info!("Encrypted database already exists - no migration needed");
                Ok(())
            }
            DatabaseEncryptionState::UnencryptedExists(unencrypted_path) => {
                info!("Unencrypted database found - starting migration to encrypted format");
                
                let db_dir = config.db_path.clone().unwrap_or_else(|| {
                    if config.profile == "release" {
                        config.get_config_dir().to_string_lossy().to_string()
                    } else {
                        format!("{}/prisma", env!("CARGO_MANIFEST_DIR"))
                    }
                });
                
                let db_path = PathBuf::from(db_dir);
                let encrypted_path = db_path.join(ENCRYPTED_DB_FILENAME);
                let backup_path = db_path.join(format!("{}{}", ENCRYPTED_DB_FILENAME, UNENCRYPTED_BACKUP_SUFFIX));
                
                // Rename existing database to backup
                std::fs::rename(&unencrypted_path, &backup_path)?;
                
                // Migrate to encrypted format
                Self::migrate_to_encrypted(backup_path, encrypted_path, key)?;
                
                info!("Database migration to encrypted format completed");
                Ok(())
            }
            DatabaseEncryptionState::MigrationIncomplete(encrypted_path, backup_path) => {
                warn!("Incomplete migration detected - encrypted database exists but backup remains");
                
                // Verify the encrypted database is valid
                let test_conn = Self::open_encrypted_connection(&encrypted_path, key)?;
                Self::verify_encrypted_database(&test_conn)?;
                drop(test_conn);
                
                // Remove the backup since migration appears complete
                std::fs::remove_file(backup_path)?;
                
                info!("Cleaned up incomplete migration - encrypted database is ready");
                Ok(())
            }
        }
    }
}
