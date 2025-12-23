/// Command-line interface for Stump server administration

pub mod setup;

use clap::{Parser, Subcommand};

/// Stump Server - Manga and Comic Server
#[derive(Parser)]
#[command(name = "stump_server")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available CLI commands
#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the server with first-time setup
    Setup,
    /// Start the server (default)
    Start,
}

/// Process CLI commands
pub async fn process_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Some(Commands::Setup) => {
            setup::setup_command().await?;
            // Exit after setup completes
            std::process::exit(0);
        }
        Some(Commands::Start) | None => {
            // Continue to normal server startup
            Ok(())
        }
    }
}
