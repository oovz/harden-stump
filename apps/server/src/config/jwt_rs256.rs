//! RS256 JWT Authentication
//!
//! Asymmetric JWT authentication using RSA public/private keypairs.
//! This replaces the HS256 symmetric key approach for better security.

use chrono::{DateTime, Duration, FixedOffset, Utc};
use jsonwebtoken::{
	decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use specta::Type;
use stump_core::config::StumpConfig;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::errors::{APIError, APIResult};

/// JWT keypair (RSA 2048-bit)
pub struct JwtKeypair {
	pub private_key: RsaPrivateKey,
	pub public_key: RsaPublicKey,
}

impl JwtKeypair {
	/// Generate a new RSA keypair for JWT signing
	///
	/// # Security
	/// Uses 2048-bit RSA keys, which is sufficient for JWT use cases.
	/// For higher security requirements, increase to 4096 bits.
	pub fn generate() -> APIResult<Self> {
		let mut rng = OsRng;
		let bits = 2048;

		let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|e| {
			APIError::InternalServerError(format!("Failed to generate RSA key: {}", e))
		})?;

		let public_key = RsaPublicKey::from(&private_key);

		Ok(Self {
			private_key,
			public_key,
		})
	}

	/// Export private key as PEM
	pub fn private_key_pem(&self) -> APIResult<String> {
		self.private_key
			.to_pkcs8_pem(Default::default())
			.map(|pem| pem.to_string())
			.map_err(|e| {
				APIError::InternalServerError(format!(
					"Failed to encode private key: {}",
					e
				))
			})
	}

	/// Export public key as PEM
	pub fn public_key_pem(&self) -> APIResult<String> {
		self.public_key
			.to_public_key_pem(Default::default())
			.map_err(|e| {
				APIError::InternalServerError(format!(
					"Failed to encode public key: {}",
					e
				))
			})
	}

	#[allow(dead_code)]
	pub fn from_private_pem(pem: &str) -> APIResult<Self> {
		use pkcs8::DecodePrivateKey;

		let private_key = RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| {
			APIError::InternalServerError(format!("Failed to decode private key: {}", e))
		})?;

		let public_key = RsaPublicKey::from(&private_key);

		Ok(Self {
			private_key,
			public_key,
		})
	}
}

/// JWT Claims for RS256 tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
	/// Subject (user ID)
	pub sub: String,
	/// JWT ID (for revocation tracking)
	pub jti: String,
	/// Issued at (Unix timestamp)
	pub iat: usize,
	/// Expiry time (Unix timestamp)
	pub exp: usize,
	/// Secure libraries the user has access to (array of library IDs)
	#[serde(default)]
	pub secure_library_access: Vec<String>,
	/// Token type: "standard" or "opds"
	#[serde(default = "default_token_type")]
	pub token_type: String,
}

fn default_token_type() -> String {
	"standard".to_string()
}

/// Created JWT token with metadata
#[derive(Debug, Serialize, Type, ToSchema)]
pub struct CreatedJwtToken {
	/// The JWT access token
	pub access_token: String,
	/// JWT ID (for revocation)
	pub jti: String,
	/// Token expiry time
	pub expires_at: DateTime<FixedOffset>,
}

/// Create a JWT token using RS256 algorithm
///
/// # Arguments
/// * `user_id` - The user's unique identifier
/// * `private_key_pem` - RSA private key in PEM format
/// * `config` - Server configuration (for TTL)
/// * `secure_library_access` - Optional list of secure library IDs user can access
/// * `token_type` - Token type ("standard" or "opds")
///
/// # Returns
/// A signed JWT token with JTI for revocation tracking
pub fn create_jwt_rs256(
	user_id: &str,
	private_key_pem: &str,
	config: &StumpConfig,
	secure_library_access: Option<Vec<String>>,
	token_type: Option<&str>,
) -> APIResult<CreatedJwtToken> {
	let now = Utc::now();
	let jti = Uuid::new_v4().to_string();

	let claims = JwtClaims {
		sub: user_id.to_string(),
		jti: jti.clone(),
		iat: now.timestamp() as usize,
		exp: (now + Duration::seconds(config.access_token_ttl)).timestamp() as usize,
		secure_library_access: secure_library_access.unwrap_or_default(),
		token_type: token_type.unwrap_or("standard").to_string(),
	};

	let header = Header::new(Algorithm::RS256);
	let encoding_key =
		EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|e| {
			tracing::error!("Failed to create encoding key: {:?}", e);
			APIError::InternalServerError("Failed to create JWT".to_string())
		})?;

	let token = encode(&header, &claims, &encoding_key).map_err(|e| {
		tracing::error!("Failed to encode JWT: {:?}", e);
		APIError::InternalServerError("Failed to create JWT".to_string())
	})?;

	Ok(CreatedJwtToken {
		access_token: token,
		jti,
		expires_at: DateTime::from(now + Duration::seconds(config.access_token_ttl)),
	})
}

/// Verify and decode a JWT token using RS256 algorithm
///
/// # Arguments
/// * `token` - The JWT token to verify
/// * `public_key_pem` - RSA public key in PEM format
///
/// # Returns
/// Tuple of (user_id, jti) if token is valid
///
/// # Errors
/// Returns `APIError::Unauthorized` if:
/// - Token signature is invalid
/// - Token has expired
/// - Token format is malformed
pub fn verify_jwt_rs256(
	token: &str,
	public_key_pem: &str,
) -> APIResult<(String, String)> {
	let mut validation = Validation::new(Algorithm::RS256);
	validation.validate_exp = true;

	let decoding_key =
		DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|e| {
			tracing::error!("Failed to create decoding key: {:?}", e);
			APIError::Unauthorized
		})?;

	let token_data =
		decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| {
			tracing::debug!("Failed to decode JWT: {:?}", e);
			APIError::Unauthorized
		})?;

	Ok((token_data.claims.sub, token_data.claims.jti))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_keypair_generation() {
		let keypair = JwtKeypair::generate().unwrap();

		let private_pem = keypair.private_key_pem().unwrap();
		let public_pem = keypair.public_key_pem().unwrap();

		assert!(private_pem.contains("BEGIN PRIVATE KEY"));
		assert!(public_pem.contains("BEGIN PUBLIC KEY"));
	}

	#[test]
	fn test_keypair_roundtrip() {
		let keypair1 = JwtKeypair::generate().unwrap();
		let private_pem = keypair1.private_key_pem().unwrap();

		let keypair2 = JwtKeypair::from_private_pem(&private_pem).unwrap();
		let public_pem2 = keypair2.public_key_pem().unwrap();

		assert_eq!(keypair1.public_key_pem().unwrap(), public_pem2);
	}

	#[test]
	fn test_jwt_creation_and_verification() {
		let keypair = JwtKeypair::generate().unwrap();
		let private_pem = keypair.private_key_pem().unwrap();
		let public_pem = keypair.public_key_pem().unwrap();

		let config = StumpConfig::debug();
		let user_id = "test_user_123";

		// Create token
		let token_result =
			create_jwt_rs256(user_id, &private_pem, &config, None, None).unwrap();

		// Verify token
		let (verified_user_id, jti) =
			verify_jwt_rs256(&token_result.access_token, &public_pem).unwrap();

		assert_eq!(verified_user_id, user_id);
		assert_eq!(jti, token_result.jti);
	}

	#[test]
	fn test_jwt_wrong_key_fails() {
		let keypair1 = JwtKeypair::generate().unwrap();
		let keypair2 = JwtKeypair::generate().unwrap();

		let config = StumpConfig::debug();

		// Create token with keypair1
		let token = create_jwt_rs256(
			"user123",
			&keypair1.private_key_pem().unwrap(),
			&config,
			None,
			None,
		)
		.unwrap();

		// Try to verify with keypair2 (should fail)
		let result =
			verify_jwt_rs256(&token.access_token, &keypair2.public_key_pem().unwrap());

		assert!(result.is_err());
	}

	#[test]
	fn test_secure_library_claims_are_ignored_by_verify() {
		let keypair = JwtKeypair::generate().unwrap();
		let private_pem = keypair.private_key_pem().unwrap();
		let public_pem = keypair.public_key_pem().unwrap();

		let config = StumpConfig::debug();

		let secure_libraries = vec!["lib-1".to_string(), "lib-2".to_string()];

		let token = create_jwt_rs256(
			"user-secure-claims",
			&private_pem,
			&config,
			Some(secure_libraries.clone()),
			Some("standard"),
		)
		.unwrap();

		let (user_id, jti) = verify_jwt_rs256(&token.access_token, &public_pem).unwrap();
		assert_eq!(user_id, "user-secure-claims");
		assert_eq!(jti, token.jti);

		let mut validation = Validation::new(Algorithm::RS256);
		validation.validate_exp = true;
		let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap();
		let data =
			decode::<JwtClaims>(&token.access_token, &decoding_key, &validation).unwrap();
		assert_eq!(data.claims.secure_library_access, secure_libraries);
	}

	#[test]
	fn test_jti_is_unique() {
		let keypair = JwtKeypair::generate().unwrap();
		let private_pem = keypair.private_key_pem().unwrap();
		let config = StumpConfig::debug();

		let token1 =
			create_jwt_rs256("user1", &private_pem, &config, None, None).unwrap();
		let token2 =
			create_jwt_rs256("user1", &private_pem, &config, None, None).unwrap();

		// Same user, but different JTIs
		assert_ne!(token1.jti, token2.jti);
	}
}
