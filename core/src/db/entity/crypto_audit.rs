//! Entity types for cryptographic audit logging

use prisma_client_rust::chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use specta::Type;
use utoipa::ToSchema;

use crate::prisma::crypto_audit_log;

/// Audit log entry for security-sensitive operations
#[derive(Debug, Clone, Serialize, Deserialize, Type, ToSchema)]
pub struct CryptoAuditLog {
	pub id: i32,
	pub event_type: CryptoAuditEventType,
	pub user_id: String,
	pub target_type: Option<String>,
	pub target_id: Option<String>,
	pub ip_address: Option<String>,
	pub user_agent: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub details: Option<JsonValue>,
	pub succeeded: bool,
	pub error_message: Option<String>,
	pub timestamp: DateTime<FixedOffset>,
}

impl From<crypto_audit_log::Data> for CryptoAuditLog {
	fn from(data: crypto_audit_log::Data) -> Self {
		let details = data
			.details
			.as_ref()
			.and_then(|d| serde_json::from_str(d).ok());

		Self {
			id: data.id,
			event_type: data
				.event_type
				.parse()
				.unwrap_or(CryptoAuditEventType::Unknown),
			user_id: data.user_id,
			target_type: data.target_type,
			target_id: data.target_id,
			ip_address: data.ip_address,
			user_agent: data.user_agent,
			details,
			succeeded: data.succeeded,
			error_message: data.error_message,
			timestamp: data.timestamp,
		}
	}
}

/// Types of cryptographic audit events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CryptoAuditEventType {
	/// System was initialized with SMK
	SystemInitialized,
	/// Secure library was created
	LibraryCreated,
	/// User was granted access to a secure library
	AccessGranted,
	/// User's access to a secure library was revoked
	AccessRevoked,
	/// Library encryption process started
	EncryptionStarted,
	/// Library encryption completed successfully
	EncryptionCompleted,
	/// Library encryption failed
	EncryptionFailed,
	/// User generated their X25519 keypair
	KeypairGenerated,
	/// User changed their password (requires re-encrypting private key)
	PasswordChanged,
	/// JWT token was revoked
	JwtRevoked,
	/// User login event
	Login,
	/// SMK was used to derive LMK (admin operation)
	SmkUsed,
	/// Unauthorized access attempt to secure library
	UnauthorizedAccessAttempt,
	/// Secure media/series deletion attempt
	SecureItemDeleted,
	/// Unknown event type
	Unknown,
}

impl CryptoAuditEventType {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::SystemInitialized => "SYSTEM_INITIALIZED",
			Self::LibraryCreated => "LIBRARY_CREATED",
			Self::AccessGranted => "ACCESS_GRANTED",
			Self::AccessRevoked => "ACCESS_REVOKED",
			Self::EncryptionStarted => "ENCRYPTION_STARTED",
			Self::EncryptionCompleted => "ENCRYPTION_COMPLETED",
			Self::EncryptionFailed => "ENCRYPTION_FAILED",
			Self::KeypairGenerated => "KEYPAIR_GENERATED",
			Self::PasswordChanged => "PASSWORD_CHANGED",
			Self::JwtRevoked => "JWT_REVOKED",
			Self::Login => "LOGIN",
			Self::SmkUsed => "SMK_USED",
			Self::UnauthorizedAccessAttempt => "UNAUTHORIZED_ACCESS_ATTEMPT",
			Self::SecureItemDeleted => "SECURE_ITEM_DELETED",
			Self::Unknown => "UNKNOWN",
		}
	}
}

impl std::str::FromStr for CryptoAuditEventType {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s {
			"SYSTEM_INITIALIZED" => Self::SystemInitialized,
			"LIBRARY_CREATED" => Self::LibraryCreated,
			"ACCESS_GRANTED" => Self::AccessGranted,
			"ACCESS_REVOKED" => Self::AccessRevoked,
			"ENCRYPTION_STARTED" => Self::EncryptionStarted,
			"ENCRYPTION_COMPLETED" => Self::EncryptionCompleted,
			"ENCRYPTION_FAILED" => Self::EncryptionFailed,
			"KEYPAIR_GENERATED" => Self::KeypairGenerated,
			"PASSWORD_CHANGED" => Self::PasswordChanged,
			"JWT_REVOKED" => Self::JwtRevoked,
			"LOGIN" => Self::Login,
			"SMK_USED" => Self::SmkUsed,
			"UNAUTHORIZED_ACCESS_ATTEMPT" => Self::UnauthorizedAccessAttempt,
			"SECURE_ITEM_DELETED" => Self::SecureItemDeleted,
			_ => Self::Unknown,
		})
	}
}

impl std::fmt::Display for CryptoAuditEventType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.as_str())
	}
}
