//! Audit Service - Security audit logging

use serde_json::json;

use crate::db::entity::CryptoAuditEventType;

/// Audit log entry builder
pub struct AuditLogBuilder {
	event_type: CryptoAuditEventType,
	user_id: String,
	target_type: Option<String>,
	target_id: Option<String>,
	ip_address: Option<String>,
	user_agent: Option<String>,
	details: Option<serde_json::Value>,
	succeeded: bool,
	error_message: Option<String>,
}

type AuditInsertData = (
	String,         // event_type
	String,         // user_id
	Option<String>, // target_type
	Option<String>, // target_id
	Option<String>, // ip_address
	Option<String>, // user_agent
	Option<String>, // details (JSON string)
	bool,           // succeeded
	Option<String>, // error_message
);

impl AuditLogBuilder {
	pub fn new(event_type: CryptoAuditEventType, user_id: String) -> Self {
		Self {
			event_type,
			user_id,
			target_type: None,
			target_id: None,
			ip_address: None,
			user_agent: None,
			details: None,
			succeeded: true,
			error_message: None,
		}
	}

	pub fn target(
		mut self,
		target_type: impl Into<String>,
		target_id: impl Into<String>,
	) -> Self {
		self.target_type = Some(target_type.into());
		self.target_id = Some(target_id.into());
		self
	}

	pub fn request_info(
		mut self,
		ip_address: impl Into<String>,
		user_agent: impl Into<String>,
	) -> Self {
		self.ip_address = Some(ip_address.into());
		self.user_agent = Some(user_agent.into());
		self
	}

	pub fn details(mut self, details: serde_json::Value) -> Self {
		self.details = Some(details);
		self
	}

	pub fn failed(mut self, error_message: impl Into<String>) -> Self {
		self.succeeded = false;
		self.error_message = Some(error_message.into());
		self
	}

	/// Build the audit log data for database insertion
	pub fn build_for_insert(self) -> AuditInsertData {
		(
			self.event_type.as_str().to_string(),
			self.user_id,
			self.target_type,
			self.target_id,
			self.ip_address,
			self.user_agent,
			self.details.map(|d| d.to_string()),
			self.succeeded,
			self.error_message,
		)
	}
}

/// Service for creating audit log entries
pub struct AuditService;

impl AuditService {
	/// Create an audit log for library creation
	pub fn library_created(
		user_id: String,
		library_id: String,
		library_name: String,
	) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::LibraryCreated, user_id)
			.target("LIBRARY", library_id)
			.details(json!({
				"library_name": library_name,
			}))
	}

	/// Create an audit log for access grant
	pub fn access_granted(
		admin_user_id: String,
		target_user_id: String,
		library_id: String,
	) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::AccessGranted, admin_user_id)
			.target("USER", target_user_id.clone())
			.details(json!({
				"target_user_id": target_user_id,
				"library_id": library_id,
			}))
	}

	/// Create an audit log for access revocation
	pub fn access_revoked(
		admin_user_id: String,
		target_user_id: String,
		library_id: String,
		reason: Option<String>,
	) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::AccessRevoked, admin_user_id)
			.target("USER", target_user_id.clone())
			.details(json!({
				"target_user_id": target_user_id,
				"library_id": library_id,
				"reason": reason,
			}))
	}

	/// Create an audit log for encryption started
	pub fn encryption_started(
		user_id: String,
		library_id: String,
		total_files: i32,
	) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::EncryptionStarted, user_id)
			.target("LIBRARY", library_id)
			.details(json!({
				"total_files": total_files,
			}))
	}

	/// Create an audit log for encryption completed
	pub fn encryption_completed(
		user_id: String,
		library_id: String,
		files_encrypted: i32,
		duration_seconds: f64,
	) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::EncryptionCompleted, user_id)
			.target("LIBRARY", library_id)
			.details(json!({
				"files_encrypted": files_encrypted,
				"duration_seconds": duration_seconds,
			}))
	}

	/// Create an audit log for encryption failed
	pub fn encryption_failed(
		user_id: String,
		library_id: String,
		error: String,
	) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::EncryptionFailed, user_id)
			.target("LIBRARY", library_id)
			.failed(error)
	}

	/// Create an audit log for keypair generation
	pub fn keypair_generated(user_id: String) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::KeypairGenerated, user_id.clone())
			.target("USER", user_id)
	}

	/// Create an audit log for password changed
	pub fn password_changed(user_id: String) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::PasswordChanged, user_id.clone())
			.target("USER", user_id)
	}

	/// Create an audit log for JWT revoked
	pub fn jwt_revoked(
		user_id: String,
		jti: String,
		reason: Option<String>,
	) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::JwtRevoked, user_id).details(json!({
			"jti": jti,
			"reason": reason,
		}))
	}

	/// Create an audit log for SMK used
	pub fn smk_used(user_id: String, operation: String) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::SmkUsed, user_id).details(json!({
			"operation": operation,
		}))
	}

	/// Create an audit log for unauthorized access attempt
	pub fn unauthorized_access_attempt(
		user_id: String,
		library_id: String,
		reason: String,
	) -> AuditLogBuilder {
		AuditLogBuilder::new(CryptoAuditEventType::UnauthorizedAccessAttempt, user_id)
			.target("LIBRARY", library_id)
			.details(json!({
				"reason": reason,
			}))
	}
}
