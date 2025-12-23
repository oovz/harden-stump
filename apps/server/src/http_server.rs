use std::net::SocketAddr;

use axum::{extract::connect_info::Connected, serve::IncomingStream, Router};
use stump_core::{
	config::{bootstrap_config_dir, logging::init_tracing},
	job::JobControllerCommand,
	StumpCore,
};
use tokio::{net::TcpListener, sync::oneshot};
use tower_http::trace::TraceLayer;

use crate::{
	config::{cors, session::get_session_layer},
	errors::{EntryError, ServerError, ServerResult},
	routers,
	utils::shutdown_signal_with_cleanup,
};
use stump_core::config::StumpConfig;
use stump_core::db::entity::CryptoAuditEventType;
use stump_core::prisma::{crypto_audit_log, PrismaClient};

async fn ensure_system_initialized(db: &PrismaClient) -> ServerResult<()> {
	let initialized = match db
		.crypto_audit_log()
		.find_first(vec![crypto_audit_log::event_type::equals(
			CryptoAuditEventType::SystemInitialized.to_string(),
		)])
		.exec()
		.await
	{
		Ok(row) => row.is_some(),
		Err(error) => {
			tracing::error!(
				?error,
				"Failed to determine system initialization state: database query for CryptoAuditLog sentinel failed",
			);
			let msg = "Failed to determine system initialization state because the database query for the CryptoAuditLog sentinel failed. Refusing to start HTTP server; check database connectivity and migrations, then retry.";
			return Err(ServerError::ServerStartError(msg.to_string()));
		},
	};

	if !initialized {
		let msg = "System is not initialized. Run `stump_server system setup` once to generate the System Master Key and create the server owner.";
		tracing::error!(
			"System is not initialized; refusing to start HTTP server. Run `stump_server system setup` once to generate the System Master Key and create the server owner.",
		);
		return Err(ServerError::ServerStartError(msg.to_string()));
	}

	Ok(())
}

pub async fn run_http_server(config: StumpConfig) -> ServerResult<()> {
	let core = StumpCore::new(config.clone()).await;

	if let Err(error) = core.run_migrations().await {
		tracing::error!(?error, "Failed to run migrations");
		return Err(ServerError::ServerStartError(error.to_string()));
	}

	// Guard startup on explicit system initialization (CLI `system setup`).
	// The system is considered initialized only when a CryptoAuditLog row exists
	// with event_type = "SYSTEM_INITIALIZED" (see Secure Libraries spec).
	let ctx = core.get_context();
	let db = ctx.db.as_ref();

	ensure_system_initialized(db).await?;

	core.get_job_controller()
		.initialize()
		.await
		.map_err(|e| ServerError::ServerStartError(e.to_string()))?;

	// Initialize the server configuration. If it already exists, nothing will happen.
	core.init_server_config()
		.await
		.map_err(|e| ServerError::ServerStartError(e.to_string()))?;

	// Initialize the encryption key, if it doesn't exist
	core.init_encryption()
		.await
		.map_err(|e| ServerError::ServerStartError(e.to_string()))?;

	core.init_journal_mode()
		.await
		.map_err(|e| ServerError::ServerStartError(e.to_string()))?;

	// Initialize JWT manager for RS256 authentication
	crate::config::jwt_manager::JWT_MANAGER
		.initialize()
		.await
		.map_err(|e| {
			ServerError::ServerStartError(format!(
				"Failed to initialize JWT manager: {}",
				e
			))
		})?;
	tracing::info!("JWT manager initialized successfully");

	// Initialize the scheduler
	core.init_scheduler()
		.await
		.map_err(|e| ServerError::ServerStartError(e.to_string()))?;

	core.init_library_watcher()
		.await
		.map_err(|e| ServerError::ServerStartError(e.to_string()))?;

	let server_ctx = core.get_context();
	let app_state = crate::config::state::AppState::new(server_ctx.arced());
	let cors_layer = cors::get_cors_layer(config.clone());

	println!("{}", core.get_shadow_text());

	let app = Router::new()
		.merge(routers::mount(app_state.clone()))
		.with_state(app_state.clone())
		.layer(get_session_layer(app_state.ctx.clone()))
		.layer(cors_layer)
		.layer(TraceLayer::new_for_http());

	// TODO: Refactor to use https://docs.rs/async-shutdown/latest/async_shutdown/
	let cleanup = || async move {
		println!("Initializing graceful shutdown...");

		let (shutdown_tx, shutdown_rx) = oneshot::channel();

		let _ = core
			.get_context()
			.send_job_controller_command(JobControllerCommand::Shutdown(shutdown_tx));

		let _ = core.get_context().library_watcher.stop().await;

		shutdown_rx
			.await
			.expect("Failed to successfully handle shutdown");
	};

	let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
	let listener = tokio::net::TcpListener::bind(&addr)
		.await
		.map_err(|e| ServerError::ServerStartError(e.to_string()))?;

	tracing::info!("⚡️ Stump HTTP server starting on http://{}", addr);

	axum::serve(
		listener,
		app.into_make_service_with_connect_info::<StumpRequestInfo>(),
	)
	.with_graceful_shutdown(shutdown_signal_with_cleanup(Some(cleanup)))
	.await
	.expect("Failed to start Stump HTTP server!");

	Ok(())
}

#[allow(dead_code)]
pub async fn bootstrap_http_server_config() -> Result<StumpConfig, EntryError> {
	// Get STUMP_CONFIG_DIR to bootstrap startup
	let config_dir = bootstrap_config_dir();

	let config = StumpCore::init_config(config_dir)
		.map_err(|e| EntryError::InvalidConfig(e.to_string()))?;

	// Note: init_tracing after loading the environment so the correct verbosity
	// level is used for logging.
	init_tracing(&config);

	if config.verbosity >= 3 {
		tracing::trace!(?config, "App config");
	}

	Ok(config)
}

#[derive(Clone, Debug)]
pub struct StumpRequestInfo {
	pub ip_addr: std::net::IpAddr,
}

impl Connected<IncomingStream<'_, TcpListener>> for StumpRequestInfo {
	fn connect_info(target: IncomingStream<'_, TcpListener>) -> Self {
		StumpRequestInfo {
			ip_addr: target.remote_addr().ip(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use stump_core::db::{create_test_client, migration};

	#[tokio::test]
	async fn startup_guard_fails_when_not_initialized() {
		let client = create_test_client().await;
		migration::run_migrations(&client)
			.await
			.expect("run migrations for startup guard test");

		// Ensure no existing crypto audit logs remain from previous tests.
		client
			.crypto_audit_log()
			.delete_many(vec![])
			.exec()
			.await
			.expect("clear crypto_audit_log");

		let result = ensure_system_initialized(&client).await;

		match result {
			Err(ServerError::ServerStartError(msg)) => {
				assert!(
					msg.contains("System is not initialized"),
					"unexpected error message: {msg}",
				);
			},
			other => panic!("expected ServerStartError, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn startup_guard_succeeds_after_system_initialized_event() {
		let client = create_test_client().await;
		migration::run_migrations(&client)
			.await
			.expect("run migrations for startup guard test (initialized)");

		// Ensure a clean slate for crypto audit logs.
		client
			.crypto_audit_log()
			.delete_many(vec![])
			.exec()
			.await
			.expect("clear crypto_audit_log");

		client
			.crypto_audit_log()
			.create(
				CryptoAuditEventType::SystemInitialized.to_string(),
				"test-user-id".to_string(),
				vec![],
			)
			.exec()
			.await
			.expect("insert SystemInitialized audit row");

		let result = ensure_system_initialized(&client).await;

		assert!(
			result.is_ok(),
			"startup guard should succeed when SystemInitialized audit exists: {result:?}",
		);
	}
}
