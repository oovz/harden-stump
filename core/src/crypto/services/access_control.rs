//! Access Control Service - Grant and revoke library access
//!
//! Manages per-library access control, wrapping Library Master Keys (LMKs)
//! for authorized users using their X25519 public keys.

use base64::{engine::general_purpose::STANDARD, Engine};
use prisma_client_rust::chrono::Utc;

use crate::{
	crypto::{
		errors::{CryptoError, CryptoResult},
		services::key_management::KeyManagementService,
		services::user_keypair::UserKeypairService,
		smk::SystemMasterKey,
	},
	db::entity::SecureLibraryAccess,
	prisma::{secure_library_access, user, PrismaClient},
};

/// Service for managing library access control
pub struct AccessControlService;

impl AccessControlService {
	/// Grant a user access to a secure library
	///
	/// This function:
	/// 1. Derives the Library Master Key (LMK) from the System Master Key (SMK)
	/// 2. Fetches the user's X25519 public key from the database
	/// 3. Wraps the LMK for the user's public key using X25519-ECDH + AES-256-GCM
	/// 4. Stores the encrypted LMK in the SecureLibraryAccess table
	///
	/// # Arguments
	/// * `client` - Database client
	/// * `smk` - System Master Key (provided by admin)
	/// * `library_id` - The library to grant access to
	/// * `user_id` - The user to grant access to
	/// * `granted_by` - User ID of the admin granting access
	///
	/// # Returns
	/// The created access grant record
	///
	/// # Errors
	/// Returns error if:
	/// - User doesn't exist
	/// - User doesn't have an X25519 keypair
	/// - Key derivation fails
	/// - Database operation fails
	pub async fn grant_access(
		client: &PrismaClient,
		smk: &SystemMasterKey,
		library_id: &str,
		user_id: &str,
		granted_by: &str,
	) -> CryptoResult<SecureLibraryAccess> {
		// 1. Derive LMK from SMK
		let lmk = KeyManagementService::derive_lmk(smk, library_id)?;

		// 2. Get user's public key from database
		let user = client
			.user()
			.find_unique(user::id::equals(user_id.to_string()))
			.exec()
			.await
			.map_err(|e| CryptoError::Generic(format!("Database error: {}", e)))?
			.ok_or_else(|| CryptoError::Generic("User not found".into()))?;

		let user_public_key_b64 = user
			.x_25519_public_key
			.ok_or_else(|| CryptoError::Generic("User has no X25519 keypair".into()))?;

		let public_key_bytes =
			UserKeypairService::public_key_from_base64(&user_public_key_b64)?;

		// 3. Wrap LMK for user's public key
		let encrypted_lmk =
			KeyManagementService::wrap_lmk_for_user(&lmk, &public_key_bytes)?;

		// 4. Store in database (idempotent upsert semantics)
		let encrypted_lmk_b64 = STANDARD.encode(&encrypted_lmk.ciphertext);
		let ephemeral_b64 = STANDARD.encode(&encrypted_lmk.ephemeral_public);
		let nonce_b64 = STANDARD.encode(&encrypted_lmk.nonce);

		let now = Utc::now();

		// Try to find an existing access grant for this user+library
		let existing = client
			.secure_library_access()
			.find_first(vec![
				secure_library_access::user_id::equals(user_id.to_string()),
				secure_library_access::library_id::equals(library_id.to_string()),
			])
			.exec()
			.await
			.map_err(|e| {
				CryptoError::Generic(format!(
					"Failed to query existing access grant: {}",
					e
				))
			})?;

		let access = if let Some(row) = existing {
			// Re-grant: update existing record, refresh LMK fields and metadata,
			// and clear any previous revocation.
			client
				.secure_library_access()
				.update(
					secure_library_access::id::equals(row.id.clone()),
					vec![
						secure_library_access::encrypted_lmk::set(encrypted_lmk_b64),
						secure_library_access::lmk_ephemeral_public::set(ephemeral_b64),
						secure_library_access::lmk_nonce::set(nonce_b64),
						secure_library_access::granted_at::set(now.into()),
						secure_library_access::granted_by::set(granted_by.to_string()),
						secure_library_access::revoked_at::set(None),
						secure_library_access::revoked_by::set(None),
					],
				)
				.exec()
				.await
				.map_err(|e| {
					CryptoError::Generic(format!("Failed to update access grant: {}", e))
				})?
		} else {
			client
				.secure_library_access()
				.create(
					user_id.to_string(),
					library_id.to_string(),
					encrypted_lmk_b64,
					ephemeral_b64,
					nonce_b64,
					granted_by.to_string(),
					vec![],
				)
				.exec()
				.await
				.map_err(|e| {
					CryptoError::Generic(format!("Failed to create access grant: {}", e))
				})?
		};

		tracing::info!(
			library_id = %library_id,
			user_id = %user_id,
			granted_by = %granted_by,
			"Granted library access"
		);

		Ok(access.into())
	}

	/// Revoke a user's access to a secure library
	///
	/// This marks the access grant as revoked without deleting it,
	/// preserving the audit trail.
	///
	/// # Arguments
	/// * `client` - Database client
	/// * `library_id` - The library to revoke access from
	/// * `user_id` - The user to revoke access from
	/// * `revoked_by` - User ID of the admin revoking access
	///
	/// # Returns
	/// Number of access grants revoked (should be 0 or 1)
	///
	/// # Errors
	/// Returns error if database operation fails
	pub async fn revoke_access(
		client: &PrismaClient,
		library_id: &str,
		user_id: &str,
		revoked_by: &str,
	) -> CryptoResult<i64> {
		let now = Utc::now();

		let updated_count = client
			.secure_library_access()
			.update_many(
				vec![
					secure_library_access::user_id::equals(user_id.to_string()),
					secure_library_access::library_id::equals(library_id.to_string()),
					secure_library_access::revoked_at::equals(None), // Only revoke active grants
				],
				vec![
					secure_library_access::revoked_at::set(Some(now.into())),
					secure_library_access::revoked_by::set(Some(revoked_by.to_string())),
				],
			)
			.exec()
			.await
			.map_err(|e| {
				CryptoError::Generic(format!("Failed to revoke access: {}", e))
			})?;

		if updated_count > 0 {
			tracing::info!(
				library_id = %library_id,
				user_id = %user_id,
				revoked_by = %revoked_by,
				count = updated_count,
				"Revoked library access"
			);
		} else {
			tracing::warn!(
				library_id = %library_id,
				user_id = %user_id,
				"No active access grant found to revoke"
			);
		}

		Ok(updated_count)
	}

	/// Revoke all access to a library (e.g., when deleting the library)
	///
	/// # Arguments
	/// * `client` - Database client
	/// * `library_id` - The library to revoke all access from
	/// * `revoked_by` - User ID of the admin revoking access
	///
	/// # Returns
	/// Number of access grants revoked
	pub async fn revoke_all_library_access(
		client: &PrismaClient,
		library_id: &str,
		revoked_by: &str,
	) -> CryptoResult<i64> {
		let now = Utc::now();

		let updated_count = client
			.secure_library_access()
			.update_many(
				vec![
					secure_library_access::library_id::equals(library_id.to_string()),
					secure_library_access::revoked_at::equals(None),
				],
				vec![
					secure_library_access::revoked_at::set(Some(now.into())),
					secure_library_access::revoked_by::set(Some(revoked_by.to_string())),
				],
			)
			.exec()
			.await
			.map_err(|e| {
				CryptoError::Generic(format!("Failed to revoke library access: {}", e))
			})?;

		tracing::info!(
			library_id = %library_id,
			revoked_by = %revoked_by,
			count = updated_count,
			"Revoked all access to library"
		);

		Ok(updated_count)
	}

	/// Revoke all of a user's library access (e.g., when deleting the user)
	///
	/// # Arguments
	/// * `client` - Database client
	/// * `user_id` - The user whose access to revoke
	/// * `revoked_by` - User ID of the admin revoking access
	///
	/// # Returns
	/// Number of access grants revoked
	pub async fn revoke_all_user_access(
		client: &PrismaClient,
		user_id: &str,
		revoked_by: &str,
	) -> CryptoResult<i64> {
		let now = Utc::now();

		let updated_count = client
			.secure_library_access()
			.update_many(
				vec![
					secure_library_access::user_id::equals(user_id.to_string()),
					secure_library_access::revoked_at::equals(None),
				],
				vec![
					secure_library_access::revoked_at::set(Some(now.into())),
					secure_library_access::revoked_by::set(Some(revoked_by.to_string())),
				],
			)
			.exec()
			.await
			.map_err(|e| {
				CryptoError::Generic(format!("Failed to revoke user access: {}", e))
			})?;

		tracing::info!(
			user_id = %user_id,
			revoked_by = %revoked_by,
			count = updated_count,
			"Revoked all user's library access"
		);

		Ok(updated_count)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::services::user_keypair::UserKeypairService;
	use crate::crypto::SystemMasterKey;
	use crate::prisma::{secure_library_access, user, PrismaClient};

	async fn setup_test_client() -> PrismaClient {
		PrismaClient::_builder()
			.build()
			.await
			.expect("Failed to create test client")
	}

	#[tokio::test]
	async fn test_access_control_service_exists() {
		// Just verify the service compiles and can be instantiated
		let _service = AccessControlService;
	}

	#[tokio::test]
	async fn grant_access_upserts_and_clears_revocation() {
		let client = setup_test_client().await;

		// Ensure a clean slate for this user/library pair
		let library_id = "lib-ac-upsert".to_string();
		let username = "ac-upsert-user".to_string();

		let _ = client
			.secure_library_access()
			.delete_many(vec![secure_library_access::library_id::equals(
				library_id.clone(),
			)])
			.exec()
			.await;

		let _ = client
			.user()
			.delete_many(vec![user::username::equals(username.clone())])
			.exec()
			.await;

		// Create a user with an X25519 public key so grants can be created
		let keypair = UserKeypairService::generate_keypair();
		let public_b64 =
			UserKeypairService::public_key_to_base64(&keypair.public_key_bytes());

		let user = client
			.user()
			.create(
				username.clone(),
				"hashed-password".to_string(),
				vec![user::x_25519_public_key::set(Some(public_b64))],
			)
			.exec()
			.await
			.expect("failed to create access-control test user");
		let user_id = user.id.clone();

		let smk = SystemMasterKey::generate();

		// First grant should create a single access row
		let first = AccessControlService::grant_access(
			&client,
			&smk,
			&library_id,
			&user_id,
			"admin-1",
		)
		.await
		.expect("first grant should succeed");

		// Revoke the grant so we can test re-grant behavior
		let revoked_count = AccessControlService::revoke_access(
			&client,
			&library_id,
			&user_id,
			"admin-2",
		)
		.await
		.expect("revoke should succeed");
		assert_eq!(revoked_count, 1, "expected exactly one grant to be revoked");

		// Second grant should update the existing row, clear revocation, and
		// not create a duplicate.
		let second = AccessControlService::grant_access(
			&client,
			&smk,
			&library_id,
			&user_id,
			"admin-3",
		)
		.await
		.expect("second grant should succeed");

		// The logical grant row should be the same
		assert_eq!(first.id, second.id, "re-grant should reuse the same row id");

		// There should be exactly one DB row for this user+library
		let grants = client
			.secure_library_access()
			.find_many(vec![
				secure_library_access::user_id::equals(user_id.clone()),
				secure_library_access::library_id::equals(library_id.clone()),
			])
			.exec()
			.await
			.expect("failed to query access grants after re-grant");
		assert_eq!(grants.len(), 1, "should only have one access grant row");

		let grant_row = &grants[0];
		assert!(
			grant_row.revoked_at.is_none(),
			"revoked_at should be cleared"
		);
		assert!(
			grant_row.revoked_by.is_none(),
			"revoked_by should be cleared"
		);
		assert_eq!(grant_row.granted_by, "admin-3");
	}
}
