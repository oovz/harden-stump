use argon2::{
	password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
	Argon2,
};
use prisma_client_rust::chrono::Utc;
use prisma_client_rust::{raw, PrismaValue};
use serde_json::json;

use crate::{
	prisma::{crypto_audit_log, secure_library_access, session, user, PrismaClient},
	CoreError, CoreResult,
};

#[derive(Debug, Clone)]
pub struct AdminPasswordResetOutcome {
	pub target_user_id: String,
	pub admin_user_id: String,
	pub revoked_grants: i64,
	pub deleted_sessions: i64,
	pub deleted_refresh_tokens: i64,
}

pub async fn admin_reset_user_password(
	db: &PrismaClient,
	admin_user_id: &str,
	target_username: &str,
	new_password: &str,
) -> CoreResult<AdminPasswordResetOutcome> {
	let target_username = target_username.trim();
	if target_username.is_empty() {
		return Err(CoreError::BadRequest(
			"Username cannot be empty".to_string(),
		));
	}

	if new_password.len() < 8 {
		return Err(CoreError::BadRequest(
			"Password must be at least 8 characters".to_string(),
		));
	}

	let target_user = db
		.user()
		.find_unique(user::username::equals(target_username.to_string()))
		.exec()
		.await?
		.ok_or_else(|| {
			CoreError::NotFound("No account with that username was found".to_string())
		})?;

	let salt = SaltString::generate(&mut OsRng);
	let hashed_password = Argon2::default()
		.hash_password(new_password.as_bytes(), &salt)
		.map_err(|e| CoreError::InternalError(format!("Failed to hash password: {}", e)))?
		.to_string();

	let target_user_id = target_user.id.clone();
	let target_username = target_user.username.clone();
	let admin_user_id = admin_user_id.to_string();

	let (revoked_grants, deleted_sessions, deleted_refresh_tokens) = db
		._transaction()
		.run(|client| {
			let hashed_password = hashed_password.clone();
			let target_user_id = target_user_id.clone();
			let target_username = target_username.clone();
			let admin_user_id = admin_user_id.clone();
			async move {
				let _updated_user = client
					.user()
					.update(
						user::id::equals(target_user_id.clone()),
						vec![
							user::hashed_password::set(hashed_password),
							user::x_25519_public_key::set(None),
							user::encrypted_x_25519_private::set(None),
							user::x_25519_private_nonce::set(None),
							user::x_25519_password_salt::set(None),
							user::keypair_created_at::set(None),
						],
					)
					.exec()
					.await?;

				let now = Utc::now();
				let revoked_grants = client
					.secure_library_access()
					.update_many(
						vec![
							secure_library_access::user_id::equals(
								target_user_id.clone(),
							),
							secure_library_access::revoked_at::equals(None),
						],
						vec![
							secure_library_access::revoked_at::set(Some(now.into())),
							secure_library_access::revoked_by::set(Some(
								admin_user_id.clone(),
							)),
						],
					)
					.exec()
					.await?;

				let deleted_sessions = client
					.session()
					.delete_many(vec![session::user_id::equals(target_user_id.clone())])
					.exec()
					.await?;

				let deleted_refresh_tokens = client
					._execute_raw(raw!(
						"DELETE FROM refresh_tokens WHERE user_id = {}",
						PrismaValue::String(target_user_id.clone())
					))
					.exec()
					.await?;

				let _ = client
					.crypto_audit_log()
					.create(
						"ADMIN_PASSWORD_RESET".to_string(),
						admin_user_id.clone(),
						vec![
							crypto_audit_log::target_type::set(Some("USER".to_string())),
							crypto_audit_log::target_id::set(Some(
								target_user_id.clone(),
							)),
							crypto_audit_log::details::set(Some(
								json!({
									"event": "admin_password_reset",
									"target_user_id": target_user_id,
									"target_username": target_username,
								})
								.to_string(),
							)),
						],
					)
					.exec()
					.await?;

				Ok::<(i64, i64, i64), prisma_client_rust::QueryError>((
					revoked_grants,
					deleted_sessions,
					deleted_refresh_tokens,
				))
			}
		})
		.await?;

	Ok(AdminPasswordResetOutcome {
		target_user_id,
		admin_user_id,
		revoked_grants,
		deleted_sessions,
		deleted_refresh_tokens,
	})
}

pub async fn admin_reset_user_password_as_server_owner(
	db: &PrismaClient,
	target_username: &str,
	new_password: &str,
) -> CoreResult<AdminPasswordResetOutcome> {
	let owner = db
		.user()
		.find_first(vec![user::is_server_owner::equals(true)])
		.exec()
		.await?
		.ok_or_else(|| {
			CoreError::BadRequest("No server owner account was found".to_string())
		})?;

	admin_reset_user_password(db, &owner.id, target_username, new_password).await
}
