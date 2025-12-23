//! JWT Manager - Centralized JWT keypair management and token operations
//!
//! This module manages the RSA keypair for RS256 JWT signing and provides
//! functions for token creation and verification.

use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
	config::jwt_rs256::{CreatedJwtToken, JwtKeypair},
	errors::{APIError, APIResult},
};
use stump_core::{config::StumpConfig, prisma::PrismaClient};

/// Global JWT manager instance
pub static JWT_MANAGER: Lazy<Arc<JwtManager>> = Lazy::new(|| Arc::new(JwtManager::new()));

/// JWT Manager - Handles RSA keypair and token operations
pub struct JwtManager {
	keypair: RwLock<Option<JwtKeypair>>,
}

impl JwtManager {
	/// Create a new JWT manager
	pub fn new() -> Self {
		Self {
			keypair: RwLock::new(None),
		}
	}

	/// Initialize the JWT manager with a keypair
	///
	/// This should be called on server startup, either:
	/// 1. Loading existing keypair from config
	/// 2. Generating a new keypair if none exists
	pub async fn initialize(&self) -> APIResult<()> {
		let mut keypair_lock = self.keypair.write().await;

		if keypair_lock.is_some() {
			tracing::debug!("JWT manager already initialized");
			return Ok(());
		}

		// TODO: Load keypair from config file if exists
		// For now, generate a new keypair
		tracing::info!("Generating new RSA keypair for JWT signing");
		let keypair = JwtKeypair::generate()?;

		// TODO: Save keypair to config file
		// let private_pem = keypair.private_key_pem()?;
		// save_to_config(&private_pem)?;

		*keypair_lock = Some(keypair);
		tracing::info!("JWT manager initialized successfully");

		Ok(())
	}

	/// Create a JWT token using RS256
	///
	/// # Arguments
	/// * `user_id` - The user's unique identifier
	/// * `config` - Server configuration for TTL
	/// * `db` - Database client to fetch secure library access
	/// * `token_type` - Optional token type ("standard" or "opds")
	///
	/// # Returns
	/// A signed JWT token with JTI for revocation tracking and secure library access
	pub async fn create_token(
		&self,
		user_id: &str,
		config: &StumpConfig,
		db: &PrismaClient,
		token_type: Option<&str>,
	) -> APIResult<CreatedJwtToken> {
		let keypair_lock = self.keypair.read().await;

		let keypair = keypair_lock.as_ref().ok_or_else(|| {
			tracing::error!("JWT manager not initialized");
			APIError::InternalServerError("JWT system not initialized".to_string())
		})?;

		let private_pem = keypair.private_key_pem()?;

		// Fetch user's accessible secure libraries (secure-only)
		let secure_library_access = if token_type == Some("opds") {
			// OPDS tokens never have secure library access
			vec![]
		} else {
			use stump_core::db::query::secure_library_access as sla;
			sla::get_user_accessible_libraries(db, user_id)
				.await
				.unwrap_or_default()
		};

		crate::config::jwt_rs256::create_jwt_rs256(
			user_id,
			&private_pem,
			config,
			Some(secure_library_access),
			token_type,
		)
	}

	/// Verify a JWT token using RS256
	///
	/// # Arguments
	/// * `token` - The JWT token to verify
	///
	/// # Returns
	/// Tuple of (user_id, jti) if token is valid
	pub async fn verify_token(&self, token: &str) -> APIResult<(String, String)> {
		let keypair_lock = self.keypair.read().await;

		let keypair = keypair_lock.as_ref().ok_or_else(|| {
			tracing::error!("JWT manager not initialized");
			APIError::Unauthorized
		})?;

		let public_pem = keypair.public_key_pem()?;

		crate::config::jwt_rs256::verify_jwt_rs256(token, &public_pem)
	}

	/// Get the public key PEM for external verification (if needed)
	pub async fn public_key_pem(&self) -> APIResult<String> {
		let keypair_lock = self.keypair.read().await;

		let keypair = keypair_lock.as_ref().ok_or_else(|| {
			APIError::InternalServerError("JWT system not initialized".to_string())
		})?;

		keypair.public_key_pem()
	}
}

impl Default for JwtManager {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn test_jwt_manager_initialization() {
		let manager = JwtManager::new();
		manager.initialize().await.unwrap();

		// Should not error on second initialization
		manager.initialize().await.unwrap();
	}

	#[tokio::test]
	async fn test_create_and_verify_token() {
		let manager = JwtManager::new();
		manager.initialize().await.unwrap();

		let config = StumpConfig::debug();
		let user_id = "test_user_123";

		// Create mock database
		let (client, mock) = PrismaClient::_mock();
		// Expect secure_library_access query to return empty set
		mock.expect(
			client.secure_library_access().find_many(vec![
				stump_core::prisma::secure_library_access::user_id::equals(
					user_id.to_string(),
				),
				stump_core::prisma::secure_library_access::revoked_at::equals(None),
			]),
			Vec::<stump_core::prisma::secure_library_access::Data>::new(),
		)
		.await;

		// Create token
		let token = manager
			.create_token(user_id, &config, &client, None)
			.await
			.unwrap();

		// Verify token
		let (verified_user_id, _jti) =
			manager.verify_token(&token.access_token).await.unwrap();

		assert_eq!(verified_user_id, user_id);
	}

	#[tokio::test]
	async fn test_token_has_unique_jti() {
		let manager = JwtManager::new();
		manager.initialize().await.unwrap();

		let config = StumpConfig::debug();
		let (client, mock) = PrismaClient::_mock();
		// Expect secure_library_access query to return empty set for user1
		mock.expect(
			client.secure_library_access().find_many(vec![
				stump_core::prisma::secure_library_access::user_id::equals(
					"user1".to_string(),
				),
				stump_core::prisma::secure_library_access::revoked_at::equals(None),
			]),
			Vec::<stump_core::prisma::secure_library_access::Data>::new(),
		)
		.await;
		// Second call expectation for the second token creation
		mock.expect(
			client.secure_library_access().find_many(vec![
				stump_core::prisma::secure_library_access::user_id::equals(
					"user1".to_string(),
				),
				stump_core::prisma::secure_library_access::revoked_at::equals(None),
			]),
			Vec::<stump_core::prisma::secure_library_access::Data>::new(),
		)
		.await;

		let token1 = manager
			.create_token("user1", &config, &client, None)
			.await
			.unwrap();
		let token2 = manager
			.create_token("user1", &config, &client, None)
			.await
			.unwrap();

		assert_ne!(token1.jti, token2.jti);
	}
}
