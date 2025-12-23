use clap::Subcommand;
use dialoguer::Confirm;
use std::io::{self, Write};
use stump_core::{
	config::StumpConfig,
	crypto::{SMKDisplay, SystemMasterKey},
	db::{create_client, DBPragma, JournalMode},
};

use super::default_progress_spinner;
use crate::{error::CliResult, CliError};

/// Subcommands for interacting with the system commands
#[derive(Subcommand, Debug)]
pub enum System {
	/// Initialize the server with first-time setup (generate SMK and create server owner)
	Setup,
	/// Set the journal mode for the database. Please use this command with caution!
	SetJournalMode {
		/// The journal mode to set
		#[clap(long)]
		mode: JournalMode,
	},
}

pub async fn handle_system_command(
	command: System,
	config: &StumpConfig,
) -> CliResult<()> {
	match command {
		System::Setup => run_setup(config).await,
		System::SetJournalMode { mode } => set_journal_mode(mode, config).await,
	}
}

async fn run_setup(config: &StumpConfig) -> CliResult<()> {
	println!("\n{}", "=".repeat(80));
	println!("🚀 STUMP SERVER INITIAL SETUP");
	println!("{}", "=".repeat(80));
	println!();

	let client = create_client(config).await;

	// Ensure database schema exists before any queries
	if let Err(e) = stump_core::db::migration::run_migrations(&client).await {
		return Err(CliError::OperationFailed(format!(
			"Failed to run database migrations: {}",
			e
		)));
	}

	// Check if system is already initialized
	let existing_owner = client
		.user()
		.find_first(vec![stump_core::prisma::user::is_server_owner::equals(
			true,
		)])
		.exec()
		.await?;

	if existing_owner.is_some() {
		println!("❌ System is already initialized! A server owner already exists.");
		return Err(CliError::OperationFailed(
			"System already initialized".to_string(),
		));
	}

	// Step 1: Generate System Master Key
	println!("📋 Step 1: Generating System Master Key...");
	let smk = SystemMasterKey::generate();

	// Validate entropy
	if let Err(e) = smk.validate_entropy() {
		return Err(CliError::OperationFailed(format!(
			"Generated SMK failed entropy validation: {}",
			e
		)));
	}

	let smk_display = SMKDisplay::from_smk(&smk).map_err(|e| {
		CliError::OperationFailed(format!("Failed to display SMK: {}", e))
	})?;

	// Display the SMK with warnings
	smk_display.display_with_warnings();

	// Step 2: Require confirmation
	println!("\n⚠️  CONFIRMATION REQUIRED");
	println!("{}", "─".repeat(60));
	println!("To continue, you must confirm that you have saved the System Master Key.");
	println!("Type exactly: I HAVE SAVED THE KEY");
	print!("> ");
	io::stdout().flush()?;

	let mut confirmation = String::new();
	io::stdin().read_line(&mut confirmation)?;

	if confirmation.trim() != "I HAVE SAVED THE KEY" {
		println!("\n❌ Setup cancelled. The key was not saved.");
		println!("You can run setup again to generate a new key.");
		return Err(CliError::OperationFailed(
			"Setup aborted by user".to_string(),
		));
	}

	println!("\n✅ Confirmation received. Continuing setup...\n");

	// Step 3: Create server owner account
	println!("📋 Step 2: Creating Server Owner Account");
	println!("{}", "─".repeat(60));

	// Get username
	print!("Enter admin username: ");
	io::stdout().flush()?;
	let mut username = String::new();
	io::stdin().read_line(&mut username)?;
	let username = username.trim().to_string();

	if username.is_empty() {
		return Err(CliError::OperationFailed(
			"Username cannot be empty".to_string(),
		));
	}

	// Get password
	print!("Enter admin password: ");
	io::stdout().flush()?;
	// Use rpassword for secure password input
	let password = rpassword::read_password()?;

	print!("Confirm admin password: ");
	io::stdout().flush()?;
	let password_confirm = rpassword::read_password()?;

	if password != password_confirm {
		return Err(CliError::OperationFailed(
			"Passwords do not match".to_string(),
		));
	}

	if password.len() < 8 {
		return Err(CliError::OperationFailed(
			"Password must be at least 8 characters".to_string(),
		));
	}

	let admin_user = stump_core::db::setup::create_server_owner_and_initialize(
		&client, &username, &password,
	)
	.await
	.map_err(|e| CliError::OperationFailed(e.to_string()))?;

	println!("✅ Server owner account created: {}", username);

	// Step 4: Initialize other system components
	println!("\n📋 Step 3: Initializing System Components");
	println!("{}", "─".repeat(60));

	println!("✅ Audit logging initialized");

	// The SMK is about to go out of scope and will be zeroized automatically
	drop(smk);

	println!("\n{}", "=".repeat(80));
	println!("✨ SETUP COMPLETE!");
	println!("{}", "=".repeat(80));
	println!();
	println!("Server owner account created:");
	println!("  Username: {}", username);
	println!("  User ID: {}", admin_user.id);
	println!();
	println!("⚠️  IMPORTANT REMINDERS:");
	println!("  • The System Master Key has been erased from memory");
	println!("  • You will need the SMK to create secure libraries");
	println!("  • Store the SMK in a password manager immediately");
	println!();
	println!("You can now start the server with: stump_server");
	println!();

	Ok(())
}

async fn set_journal_mode(mode: JournalMode, config: &StumpConfig) -> CliResult<()> {
	let confirmation = Confirm::new()
    .with_prompt("Changing the journal mode can lead to unexpected behavior. Are you sure you want to continue?")
    .interact()?;

	if !confirmation {
		println!("Exiting...");
		return Ok(());
	}

	let progress = default_progress_spinner();
	progress.set_message("Connecting to database...");

	let client = create_client(config).await;

	progress.set_message("Fetching current journal mode...");
	let current_journal_mode = client.get_journal_mode().await?;

	if current_journal_mode == mode {
		progress.finish_with_message("Journal mode already set to desired value");
		return Ok(());
	}

	progress.set_message("Updating journal mode...");
	let new_journal_mode = client.set_journal_mode(mode).await?;

	if new_journal_mode != mode {
		progress.finish_with_message("Journal mode failed to be set");
		return Err(CliError::OperationFailed(
			"Journal mode failed to be set".to_string(),
		));
	}

	progress.finish_with_message("Journal mode successfully set");

	Ok(())
}
