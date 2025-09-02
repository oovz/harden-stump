use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use prisma_client_rust::not;
use secrecy::{ExposeSecret, SecretBox};
use tokio::sync::{
	broadcast::{channel, Receiver, Sender},
	mpsc::error::SendError,
};

use crate::{
	config::StumpConfig,
	db::{self, build_sqlcipher_pool, run_migrations, SqlcipherPool},
	event::CoreEvent,
	filesystem::{scanner::LibraryWatcher, FileEncryptionService},
	job::{Executor, JobController, JobControllerCommand},
	prisma::{self, server_config},
	CoreError, CoreResult,
};

type EventChannel = (Sender<CoreEvent>, Receiver<CoreEvent>);

/// Server encryption state for hardened security
#[derive(Debug, Clone, PartialEq)]
pub enum ServerEncryptionMode {
	/// Server is locked - only unlock endpoint available, MEK not in memory
	Locked,
	/// Server is unlocked - all endpoints available, MEK available for operations
	Unlocked,
}

/// Struct that holds the main context for a Stump application. This is passed around
/// to all the different parts of the application, and is used to access the database
/// and manage the event channels.
#[derive(Clone)]
pub struct Ctx {
	pub config: Arc<StumpConfig>,
	pub db: Arc<prisma::PrismaClient>,
	/// Optional Diesel SQLCipher connection pool (present when unlocked)
	pub diesel_pool: Arc<RwLock<Option<SqlcipherPool>>>,
	pub job_controller: Arc<JobController>,
	pub event_channel: Arc<EventChannel>,
	pub library_watcher: Arc<LibraryWatcher>,
	/// Server encryption mode and master encryption key storage
	pub encryption_mode: Arc<RwLock<ServerEncryptionMode>>,
	pub master_encryption_key: Arc<RwLock<Option<SecretBox<Vec<u8>>>>>,
	/// Optional encrypted database path and key for SQLCipher operations
	pub encrypted_db: Arc<RwLock<Option<(String, SecretBox<Vec<u8>>)>>>,
	/// File encryption service for comic archives and assets
	pub file_encryption: Arc<RwLock<FileEncryptionService>>,
}

impl Ctx {
	/// Creates a new [Ctx] instance, creating a new prisma client. This should only be called
	/// once per application. It takes a sender for the internal event channel, so the
	/// core can send events to the consumer.
	///
	/// ## Example
	/// ```no_run
	/// use stump_core::{Ctx, config::StumpConfig};
	/// use tokio::sync::mpsc::unbounded_channel;
	///
	/// #[tokio::main]
	/// async fn main() {
	///    let config = StumpConfig::debug();
	///    let ctx = Ctx::new(config).await;
	/// }
	/// ```
	pub async fn new(config: StumpConfig) -> Ctx {
		let config = Arc::new(config.clone());
		let db = Arc::new(db::create_client(&config).await);
		let event_channel = Arc::new(channel::<CoreEvent>(1024));
		let job_controller =
			JobController::new(db.clone(), config.clone(), event_channel.0.clone());
		let library_watcher =
			Arc::new(LibraryWatcher::new(db.clone(), job_controller.clone()));

		// Initialize file encryption service with encrypted storage path
		let encrypted_storage_path = config.get_config_dir().join("encrypted_files");
		let file_encryption_service = FileEncryptionService::new(encrypted_storage_path);

		Ctx {
			config,
			db,
			diesel_pool: Arc::new(RwLock::new(None)),
			job_controller,
			event_channel,
			library_watcher,
			encryption_mode: Arc::new(RwLock::new(ServerEncryptionMode::Locked)),
			master_encryption_key: Arc::new(RwLock::new(None)),
			encrypted_db: Arc::new(RwLock::new(None)),
			file_encryption: Arc::new(RwLock::new(file_encryption_service)),
		}
	}

	// Note: I cannot use #[cfg(test)] here because the tests are in a different crate and
	// the `cfg` attribute only works for the current crate. Potential workarounds:
	// - https://github.com/rust-lang/cargo/issues/8379

	/// Creates a [Ctx] instance for testing **only**. The prisma client is created
	/// pointing to the `integration-tests` crate relative to the `core` crate.
	///
	/// **This should not be used in production.**
	pub async fn integration_test_mock() -> Ctx {
		let config = Arc::new(StumpConfig::debug());
		let db = Arc::new(db::create_test_client().await);
		let event_channel = Arc::new(channel::<CoreEvent>(1024));

		// Create job manager
		let job_controller =
			JobController::new(db.clone(), config.clone(), event_channel.0.clone());

		let library_watcher =
			Arc::new(LibraryWatcher::new(db.clone(), job_controller.clone()));

		// Initialize file encryption service with encrypted storage path
		let encrypted_storage_path = PathBuf::from("/tmp/encrypted_files"); // Use temp for integration tests
		let file_encryption_service = FileEncryptionService::new(encrypted_storage_path);

		Ctx {
			config,
			db,
			diesel_pool: Arc::new(RwLock::new(None)),
			job_controller,
			event_channel,
			library_watcher,
			encryption_mode: Arc::new(RwLock::new(ServerEncryptionMode::Locked)),
			master_encryption_key: Arc::new(RwLock::new(None)),
			encrypted_db: Arc::new(RwLock::new(None)),
			file_encryption: Arc::new(RwLock::new(file_encryption_service)),
		}
	}

	/// Creates a [Ctx] instance for testing **only**. The prisma client is created
	/// with a mock store, allowing for easy testing of the core without needing to
	/// connect to a real database.
	pub fn mock() -> (Ctx, prisma_client_rust::MockStore) {
		let config = Arc::new(StumpConfig::debug());
		let (client, mock) = prisma::PrismaClient::_mock();

		let event_channel = Arc::new(channel::<CoreEvent>(1024));
		let db = Arc::new(client);

		// Create job manager
		let job_controller =
			JobController::new(db.clone(), config.clone(), event_channel.0.clone());

		let library_watcher =
			Arc::new(LibraryWatcher::new(db.clone(), job_controller.clone()));

		// Initialize file encryption service with encrypted storage path
		let encrypted_storage_path = PathBuf::from("/tmp/encrypted_files"); // Use temp for mock tests
		let file_encryption_service = FileEncryptionService::new(encrypted_storage_path);

		let ctx = Ctx {
			config,
			db,
			diesel_pool: Arc::new(RwLock::new(None)),
			job_controller,
			event_channel,
			library_watcher,
			encryption_mode: Arc::new(RwLock::new(ServerEncryptionMode::Locked)),
			master_encryption_key: Arc::new(RwLock::new(None)),
			encrypted_db: Arc::new(RwLock::new(None)),
			file_encryption: Arc::new(RwLock::new(file_encryption_service)),
		};

		(ctx, mock)
	}

	/// Wraps the [Ctx] in an [Arc], allowing it to be shared across threads. This
	/// is just a simple utility function.
	///
	/// ## Example
	/// ```no_run
	/// use stump_core::{Ctx, config::StumpConfig};
	/// use std::sync::Arc;
	///
	/// #[tokio::main]
	/// async fn main() {
	///     let config = StumpConfig::debug();
	///
	///     let ctx = Ctx::new(config).await;
	///     let arced_ctx = ctx.arced();
	///     let ctx_clone = arced_ctx.clone();
	///
	///     assert_eq!(2, Arc::strong_count(&ctx_clone))
	/// }
	/// ```
	pub fn arced(&self) -> Arc<Ctx> {
		Arc::new(self.clone())
	}

	/// Returns the receiver for the `CoreEvent` channel. See [`emit_event`]
	/// for more information and an example usage.
	pub fn get_client_receiver(&self) -> Receiver<CoreEvent> {
		self.event_channel.0.subscribe()
	}

	pub fn get_event_tx(&self) -> Sender<CoreEvent> {
		self.event_channel.0.clone()
	}

	/// Emits a [`CoreEvent`] to the client event channel.
	///
	/// ## Example
	/// ```no_run
	/// use stump_core::{Ctx, config::StumpConfig, CoreEvent};
	///
	/// #[tokio::main]
	/// async fn main() {
	///    let config = StumpConfig::debug();
	///    let ctx = Ctx::new(config).await;
	///
	///    let event = CoreEvent::CreatedMedia {
	///        id: "id_for_the_media".to_string(),
	///        series_id: "id_for_its_series".to_string(),
	///    };
	///
	///    let ctx_cpy = ctx.clone();
	///    tokio::spawn(async move {
	///        let mut receiver = ctx_cpy.get_client_receiver();
	///        let received_event = receiver.recv().await;
	///        assert_eq!(received_event.is_ok(), true);
	///        match received_event.unwrap() {
	///            CoreEvent::CreatedMedia { id, series_id } => {
	///                assert_eq!(id, "id_for_the_media");
	///                assert_eq!(series_id, "id_for_its_series");
	///            }
	///            _ => unreachable!("Wrong event type received"),
	///        }
	///    });
	///
	///    ctx.emit_event(event.clone());
	/// }
	/// ```
	pub fn emit_event(&self, event: CoreEvent) {
		let _ = self.event_channel.0.send(event);
	}

	/// Sends a [`JobControllerCommand`] to the job controller
	pub fn send_job_controller_command(
		&self,
		command: JobControllerCommand,
	) -> Result<(), SendError<JobControllerCommand>> {
		self.job_controller.push_command(command)
	}

	/// Sends an [`JobControllerCommand::EnqueueJob`] event to the job manager.
	pub fn enqueue_job(
		&self,
		job: Box<dyn Executor>,
	) -> Result<(), SendError<JobControllerCommand>> {
		self.send_job_controller_command(JobControllerCommand::EnqueueJob(job))
	}

	/// Send a [`CoreEvent`] through the event channel to any clients listening
	pub fn send_core_event(&self, event: CoreEvent) {
		if let Err(error) = self.event_channel.0.send(event) {
			tracing::error!(error = ?error, "Failed to send core event");
		} else {
			tracing::trace!("Sent core event");
		}
	}

	pub async fn get_encryption_key(&self) -> CoreResult<String> {
		let server_config = self
			.db
			.server_config()
			.find_first(vec![not![server_config::encryption_key::equals(None)]])
			.exec()
			.await?;

		let encryption_key = server_config
			.and_then(|config| config.encryption_key)
			.ok_or(CoreError::EncryptionKeyNotSet)?;

		Ok(encryption_key)
	}

	/// Get the current server encryption mode
	pub fn get_encryption_mode(&self) -> ServerEncryptionMode {
		self.encryption_mode.read().unwrap().clone()
	}

	/// Check if the server is currently unlocked
	pub fn is_server_unlocked(&self) -> bool {
		matches!(self.get_encryption_mode(), ServerEncryptionMode::Unlocked)
	}

	/// Unlock the server by storing the master encryption key in memory
	pub fn unlock_server(&self, master_key: SecretBox<Vec<u8>>) -> CoreResult<()> {
		let mut mode = self.encryption_mode.write().unwrap();
		let mut key = self.master_encryption_key.write().unwrap();

		*mode = ServerEncryptionMode::Unlocked;

		// Create a clone of the master key for the file encryption service
		let key_clone = SecretBox::new(Box::new(master_key.expose_secret().clone()));
		*key = Some(master_key);

		// Also unlock the file encryption service
		let mut file_encryption = self.file_encryption.write().unwrap();
		file_encryption.set_master_key(key_clone);

		// Initialize Diesel SQLCipher pool if encrypted db info is available
		if let Some((db_url, key)) = self.encrypted_db.read().unwrap().as_ref() {
			let key_cpy = SecretBox::new(Box::new(key.expose_secret().clone()));
			match build_sqlcipher_pool(db_url, key_cpy) {
				Ok(pool) => {
					// Run migrations with a one-off connection
					if let Ok(mut conn) = pool.get() {
						if let Err(e) = run_migrations(&mut conn) {
							tracing::error!(error = ?e, "Failed to run Diesel migrations");
							return Err(CoreError::MigrationError(format!(
								"Failed to run Diesel migrations: {}",
								e
							)));
						}
					}
					*self.diesel_pool.write().unwrap() = Some(pool);
					tracing::info!("Initialized Diesel SQLCipher pool on unlock");
				},
				Err(e) => {
					tracing::error!(error = ?e, "Failed to initialize SQLCipher pool");
					return Err(CoreError::InitializationError(format!(
						"Failed to initialize SQLCipher pool: {}",
						e
					)));
				},
			}
		} else {
			tracing::warn!(
				"Encrypted DB info not set; Diesel pool not initialized on unlock"
			);
		}

		tracing::info!("Server unlocked successfully");
		Ok(())
	}

	/// Lock the server by clearing the master encryption key from memory
	pub fn lock_server(&self) -> CoreResult<()> {
		let mut mode = self.encryption_mode.write().unwrap();
		let mut key = self.master_encryption_key.write().unwrap();

		*mode = ServerEncryptionMode::Locked;
		*key = None;

		// Also lock the file encryption service
		let mut file_encryption = self.file_encryption.write().unwrap();
		file_encryption.clear_master_key();

		// Drop Diesel pool (close all SQLCipher connections)
		let mut pool_guard = self.diesel_pool.write().unwrap();
		*pool_guard = None;

		tracing::info!("Server locked successfully");
		Ok(())
	}

	/// Get a clone of the master encryption key for cryptographic operations
	pub fn get_master_encryption_key(&self) -> Option<SecretBox<Vec<u8>>> {
		let guard = self.master_encryption_key.read().unwrap();
		match guard.as_ref() {
			Some(secret) => {
				// Create a new SecretBox with the same data since Clone is not implemented
				// This is safe because we're only duplicating the encrypted key material
				Some(SecretBox::new(Box::new(secret.expose_secret().clone())))
			},
			None => None,
		}
	}

	/// Set the master encryption key (used for testing and key transfer)
	pub fn set_master_encryption_key(&self, key: SecretBox<Vec<u8>>) {
		let mut guard = self.master_encryption_key.write().unwrap();
		*guard = Some(key);
	}

	/// Gets the encrypted database path and key if server is unlocked
	pub fn get_encrypted_db_info(&self) -> CoreResult<Option<(String, Vec<u8>)>> {
		if self.is_server_unlocked() {
			if let Some((path, key)) = self.encrypted_db.read().unwrap().as_ref() {
				return Ok(Some((path.clone(), key.expose_secret().clone())));
			}
		}
		Ok(None)
	}

	/// Sets the encrypted database path and key when server is unlocked
	pub fn set_encrypted_db_info(
		&self,
		path: String,
		key: SecretBox<Vec<u8>>,
	) -> CoreResult<()> {
		if self.is_server_unlocked() {
			*self.encrypted_db.write().unwrap() = Some((path, key));
			// Optionally (re)initialize Diesel pool immediately when unlocked
			// so subsequent DB calls can use Diesel. If pool exists, replace it.
			if let Some((db_url, key)) = self.encrypted_db.read().unwrap().as_ref() {
				let key_cpy = SecretBox::new(Box::new(key.expose_secret().clone()));
				match build_sqlcipher_pool(db_url, key_cpy) {
					Ok(pool) => {
						if let Ok(mut conn) = pool.get() {
							if let Err(e) = run_migrations(&mut conn) {
								tracing::error!(error = ?e, "Failed to run Diesel migrations");
								return Err(CoreError::MigrationError(format!(
									"Failed to run Diesel migrations: {}",
									e
								)));
							}
						}
						*self.diesel_pool.write().unwrap() = Some(pool);
						tracing::info!("Initialized/updated Diesel SQLCipher pool after setting db info");
					},
					Err(e) => {
						tracing::error!(error = ?e, "Failed to initialize SQLCipher pool");
						return Err(CoreError::InitializationError(format!(
							"Failed to initialize SQLCipher pool: {}",
							e
						)));
					},
				}
			}
			Ok(())
		} else {
			Err(CoreError::BadRequest(
				"Server must be unlocked first".to_string(),
			))
		}
	}

	/// Get access to the file encryption service
	pub fn get_file_encryption_service(&self) -> Arc<RwLock<FileEncryptionService>> {
		self.file_encryption.clone()
	}

	/// Create a decryption middleware instance
	pub fn create_decryption_middleware(
		&self,
	) -> crate::filesystem::DecryptionMiddleware {
		crate::filesystem::DecryptionMiddleware::new(self.clone())
	}

	/// Create a decryption middleware instance with caching enabled
	pub fn create_decryption_middleware_with_cache(
		&self,
	) -> CoreResult<crate::filesystem::DecryptionMiddleware> {
		let cache_config = crate::filesystem::DecryptionCacheConfig::default();
		crate::filesystem::DecryptionMiddleware::with_cache(self.clone(), cache_config)
	}

	/// Create a decryption middleware instance with custom cache configuration
	pub fn create_decryption_middleware_with_cache_config(
		&self,
		cache_config: crate::filesystem::DecryptionCacheConfig,
	) -> CoreResult<crate::filesystem::DecryptionMiddleware> {
		crate::filesystem::DecryptionMiddleware::with_cache(self.clone(), cache_config)
	}

	/// Initialize the file encryption storage directory
	pub async fn init_file_encryption_storage(&self) -> CoreResult<()> {
		let file_encryption = self.file_encryption.read().unwrap();
		file_encryption.initialize_storage().await
	}

	/// Get a clone of the Diesel SQLCipher pool if initialized
	pub fn get_diesel_pool(&self) -> Option<SqlcipherPool> {
		self.diesel_pool.read().unwrap().clone()
	}
}
