//! Entity types for secure library access control and encryption metadata

use prisma_client_rust::chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use specta::Type;
use utoipa::ToSchema;

use crate::prisma::{library_encryption_metadata, secure_library_access};

/// Library encryption metadata entity
#[derive(Debug, Clone, Serialize, Deserialize, Type, ToSchema)]
pub struct LibraryEncryptionMetadata {
	pub id: String,
	pub library_id: String,
	pub created_at: DateTime<FixedOffset>,
	pub updated_at: DateTime<FixedOffset>,
	pub crypto_version: i32,
	pub verification_tag: Vec<u8>,
}

impl From<library_encryption_metadata::Data> for LibraryEncryptionMetadata {
	fn from(data: library_encryption_metadata::Data) -> Self {
		Self {
			id: data.id,
			library_id: data.library_id,
			created_at: data.created_at,
			updated_at: data.updated_at,
			crypto_version: data.crypto_version,
			verification_tag: data.verification_tag,
		}
	}
}

/// Secure library access control entry
/// Represents a user's access to a secure library with their encrypted LMK
#[derive(Debug, Clone, Serialize, Deserialize, Type, ToSchema)]
pub struct SecureLibraryAccess {
	pub id: String,
	pub user_id: String,
	pub library_id: String,

	/// Encrypted LMK for this user (AES-256-GCM)
	pub encrypted_lmk: String,
	/// Ephemeral X25519 public key used for ECDH
	pub lmk_ephemeral_public: String,
	/// Nonce for AES-256-GCM encryption
	pub lmk_nonce: String,

	pub granted_at: DateTime<FixedOffset>,
	pub granted_by: String,
	pub revoked_at: Option<DateTime<FixedOffset>>,
	pub revoked_by: Option<String>,
}

impl From<secure_library_access::Data> for SecureLibraryAccess {
	fn from(data: secure_library_access::Data) -> Self {
		Self {
			id: data.id,
			user_id: data.user_id,
			library_id: data.library_id,
			encrypted_lmk: data.encrypted_lmk,
			lmk_ephemeral_public: data.lmk_ephemeral_public,
			lmk_nonce: data.lmk_nonce,
			granted_at: data.granted_at,
			granted_by: data.granted_by,
			revoked_at: data.revoked_at,
			revoked_by: data.revoked_by,
		}
	}
}

impl SecureLibraryAccess {
	/// Check if access is currently active (not revoked)
	pub fn is_active(&self) -> bool {
		self.revoked_at.is_none()
	}
}

/// Encryption status for a library
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type, ToSchema)]
pub enum EncryptionStatus {
	NotEncrypted,
	Encrypting,
	Encrypted,
	EncryptionFailed,
	EncryptionBroken,
}

impl EncryptionStatus {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::NotEncrypted => "NOT_ENCRYPTED",
			Self::Encrypting => "ENCRYPTING",
			Self::Encrypted => "ENCRYPTED",
			Self::EncryptionFailed => "ENCRYPTION_FAILED",
			Self::EncryptionBroken => "ENCRYPTION_BROKEN",
		}
	}
}

impl std::str::FromStr for EncryptionStatus {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"NOT_ENCRYPTED" => Ok(Self::NotEncrypted),
			"ENCRYPTING" => Ok(Self::Encrypting),
			"ENCRYPTED" => Ok(Self::Encrypted),
			"ENCRYPTION_FAILED" => Ok(Self::EncryptionFailed),
			"ENCRYPTION_BROKEN" => Ok(Self::EncryptionBroken),
			_ => Err(()),
		}
	}
}

impl std::fmt::Display for EncryptionStatus {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.as_str())
	}
}
