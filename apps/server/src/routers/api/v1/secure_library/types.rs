//! DTOs and response types for secure library endpoints

use serde::{Deserialize, Serialize};
use specta::Type;
use stump_core::db::entity::SecureLibraryAccess;
use utoipa::ToSchema;

// ============================================================================
// Delete Operations
// ============================================================================

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct DeleteMediaResponse {
	pub deleted_ids: Vec<String>,
	pub series_auto_deleted: Vec<String>,
	pub message: String,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct DeleteSeriesResponse {
	pub deleted_ids: Vec<String>,
	pub media_count: i32,
	pub message: String,
}

// ============================================================================
// Library Status
// ============================================================================

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct JobProgressStatus {
	pub processed: i32,
	pub total: i32,
	pub current_file: Option<String>,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct SecureLibraryStatus {
	pub library_id: String,
	pub encryption_status: String,
	pub encrypted_files: i32,
	pub total_files: i32,
	pub progress: f64,
	pub error: Option<String>,
	pub job_progress: JobProgressStatus,
}

// ============================================================================
// Library List
// ============================================================================

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct SecureLibrarySummary {
	pub id: String,
	pub name: String,
	pub is_secure: bool,
	pub encryption_status: String,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct AccessStatusResponse {
	pub has_access: bool,
}

// ============================================================================
// Create Library
// ============================================================================

#[derive(Debug, Deserialize, Type, ToSchema)]
pub(crate) struct CreateSecureLibraryRequest {
	/// Name for the new secure library
	pub name: String,
	/// Physical path to the library directory
	pub path: String,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct CreateSecureLibraryResponse {
	pub id: String,
	pub name: String,
	pub is_secure: bool,
	pub encryption_status: String,
	pub path: String,
	pub created_at: String,
}

// ============================================================================
// Delete Library
// ============================================================================

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct DeleteSecureLibraryResponse {
	pub message: String,
}

// ============================================================================
// Scan Library
// ============================================================================

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct ScanSecureLibraryResponse {
	pub job_id: String,
	pub message: String,
}

// ============================================================================
// Access Control
// ============================================================================

#[derive(Debug, Deserialize, Type, ToSchema)]
pub(crate) struct GrantAccessRequest {
	/// User ID to grant access to
	pub user_id: String,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct GrantAccessResponse {
	pub access_grant: SecureLibraryAccess,
	pub message: String,
}

#[derive(Debug, Deserialize, Type, ToSchema)]
pub(crate) struct RevokeAccessRequest {
	/// User ID to revoke access from
	pub user_id: String,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct RevokeAccessResponse {
	pub revoked_count: i64,
	pub message: String,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct AccessListUser {
	pub user_id: String,
	pub username: String,
	pub granted_at: String,
	pub is_revoked: bool,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct AccessListResponse {
	pub users: Vec<AccessListUser>,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub(crate) struct WrappedLmkResponse {
	pub encrypted_lmk: String,
	pub lmk_ephemeral_public: String,
	pub lmk_nonce: String,
}
