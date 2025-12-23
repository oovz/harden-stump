//! Entity types for JWT revocation tracking

use prisma_client_rust::chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use specta::Type;
use utoipa::ToSchema;

use crate::prisma::revoked_jwt;

/// Revoked JWT token entry for RS256 authentication
#[derive(Debug, Clone, Serialize, Deserialize, Type, ToSchema)]
pub struct RevokedJWT {
	pub id: String,
	/// JWT ID claim (jti) - unique identifier for the token
	pub jti: String,
	/// User ID who owned the token
	pub user_id: String,
	/// When the token was revoked
	pub revoked_at: DateTime<FixedOffset>,
	/// User ID of the admin who revoked it (or same as user_id for self-revoke)
	pub revoked_by: String,
	/// Optional reason for revocation
	pub reason: Option<String>,
	/// Original expiry time of the token
	pub expires_at: DateTime<FixedOffset>,
}

impl From<revoked_jwt::Data> for RevokedJWT {
	fn from(data: revoked_jwt::Data) -> Self {
		Self {
			id: data.id,
			jti: data.jti,
			user_id: data.user_id,
			revoked_at: data.revoked_at,
			revoked_by: data.revoked_by,
			reason: data.reason,
			expires_at: data.expires_at,
		}
	}
}

impl RevokedJWT {
	/// Check if this revoked token has expired
	pub fn has_expired(&self) -> bool {
		use prisma_client_rust::chrono::Utc;
		let now: DateTime<FixedOffset> = Utc::now().into();
		self.expires_at < now
	}
}
