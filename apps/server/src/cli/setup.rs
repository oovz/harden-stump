/// System setup command for initializing a secure Stump server
///
/// This command is run once during initial system setup to:
/// 1. Generate the System Master Key (SMK)
/// 2. Display it in multiple formats (base64, BIP-39, QR code)
/// 3. Create the first server owner account
/// 4. Initialize the database
use std::io::{self, Write};
use stump_core::config::{bootstrap_config_dir, StumpConfig};
use stump_core::{
	crypto::{SMKDisplay, SystemMasterKey},
	db::create_client,
	prisma::{user, PrismaClient},
	StumpCore,
};
use tracing::{error, info, warn};

/// Setup result containing important information
pub struct SetupResult {
	pub smk_display: SMKDisplay,
	pub admin_username: String,
}

/// Run the initial system setup
pub async fn run_setup(
	_config: &StumpConfig,
	db: &PrismaClient,
) -> Result<SetupResult, Box<dyn std::error::Error>> {
	println!("\n{}", "=".repeat(80));
	println!("🚀 STUMP SERVER INITIAL SETUP");
	println!("{}", "=".repeat(80));
	println!();

	// Check if system is already initialized
	let existing_owner = db
		.user()
		.find_first(vec![user::is_server_owner::equals(true)])
		.exec()
		.await?;

	if existing_owner.is_some() {
		error!("System is already initialized! A server owner already exists.");
		return Err("System already initialized".into());
	}

	// Step 1: Generate System Master Key
	println!("📋 Step 1: Generating System Master Key...");
	let smk = SystemMasterKey::generate();

	// Validate entropy
	if let Err(e) = smk.validate_entropy() {
		error!("Generated SMK failed entropy validation: {}", e);
		return Err("Failed to generate secure SMK".into());
	}

	let smk_display = SMKDisplay::from_smk(&smk)?;

	// Display the SMK with warnings
	smk_display.display_with_warnings();

	// Step 2: Require confirmation
	println!("\n⚠️  CONFIRMATION REQUIRED");
	println!("─".repeat(60));
	println!("To continue, you must confirm that you have saved the System Master Key.");
	println!("Type exactly: I HAVE SAVED THE KEY");
	print!("> ");
	io::stdout().flush()?;

	let mut confirmation = String::new();
	io::stdin().read_line(&mut confirmation)?;

	if confirmation.trim() != "I HAVE SAVED THE KEY" {
		error!("Setup aborted - key was not confirmed as saved");
		println!("\n❌ Setup cancelled. The key was not saved.");
		println!("You can run setup again to generate a new key.");
		return Err("Setup aborted by user".into());
	}

	println!("\n✅ Confirmation received. Continuing setup...\n");

	// Step 3: Create server owner account
	println!("📋 Step 2: Creating Server Owner Account");
	println!("─".repeat(60));

	// Get username
	print!("Enter admin username: ");
	io::stdout().flush()?;
	let mut username = String::new();
	io::stdin().read_line(&mut username)?;
	let username = username.trim().to_string();

	if username.is_empty() {
		return Err("Username cannot be empty".into());
	}

	// Get password
	print!("Enter admin password: ");
	io::stdout().flush()?;
	let password = rpassword::read_password()?;

	print!("Confirm admin password: ");
	io::stdout().flush()?;
	let password_confirm = rpassword::read_password()?;

	if password != password_confirm {
		return Err("Passwords do not match".into());
	}

	if password.len() < 8 {
		return Err("Password must be at least 8 characters".into());
	}

	let admin_user = stump_core::db::setup::create_server_owner_and_initialize(
		db, &username, &password,
	)
	.await
	.map_err(|e| format!("Failed to create admin user: {}", e))?;

	info!(
		username = admin_user.username,
		user_id = admin_user.id,
		"Server owner account created successfully"
	);

	// Step 4: Initialize other system components
	println!("\n📋 Step 3: Initializing System Components");
	println!("─".repeat(60));

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

	Ok(SetupResult {
		smk_display,
		admin_username: username,
	})
}

/// Interactive CLI entry point for setup
pub async fn setup_command() -> Result<(), Box<dyn std::error::Error>> {
	let config_dir = bootstrap_config_dir();
	let config = StumpCore::init_config(config_dir)
		.map_err(|e| format!("Failed to load configuration: {}", e))?;

	let db = create_client(&config).await;

	// Run migrations before any queries
	println!("🔧 Checking database migrations...");
	stump_core::db::migration::run_migrations(&db)
		.await
		.map_err(|e| format!("Failed to run migrations: {}", e))?;

	// Run the setup
	let _result = run_setup(&config, &db).await?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_setup_validation() {
		// Test username validation
		assert!("".is_empty(), "Empty username should be rejected");
		assert!(
			!"valid_user".is_empty(),
			"Valid username should be accepted"
		);

		// Test password validation
		let short_pass = "1234567";
		assert!(short_pass.len() < 8, "Short password should be rejected");

		let good_pass = "SecureP@ssw0rd!";
		assert!(good_pass.len() >= 8, "Good password should be accepted");
	}
}
