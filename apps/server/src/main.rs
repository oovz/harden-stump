#![recursion_limit = "512"]
#![type_length_limit = "2000000"]

use clap::Parser;
use cli::{handle_command, Cli};
use errors::EntryError;
use stump_core::{
	config::bootstrap_config_dir, config::logging::init_tracing, StumpCore,
};

mod config;
mod errors;
mod filter;
mod http_server;
mod middleware;
mod routers;
mod secure;
mod utils;

#[cfg(debug_assertions)]
fn debug_setup() {
	std::env::set_var(
		"STUMP_CLIENT_DIR",
		env!("CARGO_MANIFEST_DIR").to_string() + "/../web/dist",
	);
	std::env::set_var("STUMP_PROFILE", "debug");
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), EntryError> {
	#[cfg(debug_assertions)]
	debug_setup();

	// Get STUMP_CONFIG_DIR to bootstrap startup
	let config_dir = bootstrap_config_dir();

	let config = StumpCore::init_config(config_dir)
		.map_err(|e| EntryError::InvalidConfig(e.to_string()))?;

	let cli = Cli::parse();

	// Merge CLI overrides into config
	let config = cli.config.merge_stump_config(config);

	// If a subcommand was provided, handle it and exit
	if let Some(cmd) = cli.command {
		if let Err(e) = handle_command(cmd, &config).await {
			return Err(EntryError::InvalidConfig(e.to_string()));
		}
		return Ok(());
	}

	// Note: init_tracing after loading the environment so the correct verbosity
	// level is used for logging.
	init_tracing(&config);

	if config.verbosity >= 3 {
		tracing::trace!(?config, "App config");
	}

	Ok(http_server::run_http_server(config).await?)
}
