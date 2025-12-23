use argon2::{
	password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
	Argon2,
};
use prisma_client_rust::chrono::Utc;

use crate::{
	crypto::services::UserKeypairService,
	db::entity::CryptoAuditEventType,
	prisma::{crypto_audit_log, user, user_preferences, PrismaClient},
	CoreError, CoreResult,
};

pub async fn create_server_owner_and_initialize(
	db: &PrismaClient,
	username: &str,
	password: &str,
) -> CoreResult<user::Data> {
	let username = username.trim();
	if username.is_empty() {
		return Err(CoreError::BadRequest(
			"Username cannot be empty".to_string(),
		));
	}

	if password.len() < 8 {
		return Err(CoreError::BadRequest(
			"Password must be at least 8 characters".to_string(),
		));
	}

	let existing_owner = db
		.user()
		.find_first(vec![user::is_server_owner::equals(true)])
		.exec()
		.await?;
	if existing_owner.is_some() {
		return Err(CoreError::BadRequest(
			"System already initialized".to_string(),
		));
	}

	let salt = SaltString::generate(&mut OsRng);
	let hashed_password = Argon2::default()
		.hash_password(password.as_bytes(), &salt)
		.map_err(|e| CoreError::InternalError(format!("Failed to hash password: {}", e)))?
		.to_string();

	let keypair = UserKeypairService::generate_keypair();
	let encrypted =
		UserKeypairService::encrypt_private_key_with_password(&keypair, password)?;
	let (encrypted_private_b64, nonce_b64, salt_b64) =
		UserKeypairService::encrypted_private_key_to_base64(&encrypted);
	let public_b64 =
		UserKeypairService::public_key_to_base64(&keypair.public_key_bytes());

	let admin_user = db
		.user()
		.create(
			username.to_string(),
			hashed_password,
			vec![
				user::is_server_owner::set(true),
				user::x_25519_public_key::set(Some(public_b64)),
				user::encrypted_x_25519_private::set(Some(encrypted_private_b64)),
				user::x_25519_private_nonce::set(Some(nonce_b64)),
				user::x_25519_password_salt::set(Some(salt_b64)),
				user::keypair_created_at::set(Some(Utc::now().into())),
			],
		)
		.exec()
		.await?;

	db.user_preferences()
		.create(vec![
			user_preferences::user::connect(user::id::equals(admin_user.id.clone())),
			user_preferences::user_id::set(Some(admin_user.id.clone())),
		])
		.exec()
		.await?;

	let library_config_count = db.library_config().count(vec![]).exec().await?;
	if library_config_count == 0 {
		db.library_config().create(vec![]).exec().await?;
	}

	db.crypto_audit_log()
		.create(
			CryptoAuditEventType::SystemInitialized.to_string(),
			admin_user.id.clone(),
			vec![crypto_audit_log::details::set(Some(format!(
				"System initialized with server owner: {}",
				username
			)))],
		)
		.exec()
		.await?;

	Ok(admin_user)
}
