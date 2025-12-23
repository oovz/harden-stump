//! Secure Library API Endpoints
//!
//! Admin endpoints for managing secure libraries and user access grants.
//!
//! This module is organized into several submodules:
//! - `access` - Grant, revoke, list access and get wrapped LMK
//! - `admin` - Create, delete, scan secure libraries
//! - `catalog` - Encrypted catalog read/write operations
//! - `content` - Serve encrypted catalog, media files, thumbnails
//! - `delete` - Delete media and series from secure libraries
//! - `helpers` - Key extraction, error helpers, middleware
//! - `list` - List libraries, get status, access status
//! - `types` - DTOs and response types

mod access;
mod admin;
mod catalog;
mod content;
mod delete;
mod helpers;
mod list;
mod types;

#[cfg(test)]
mod tests;

use axum::{
	middleware,
	routing::{delete as delete_route, get, post},
	Router,
};

use crate::config::state::AppState;
use crate::middleware::auth::auth_middleware;

// Re-export handlers for router construction
pub(crate) use access::{
	get_library_access_list, get_wrapped_lmk, grant_library_access, revoke_library_access,
};
pub(crate) use admin::{
	create_secure_library, delete_secure_library, scan_secure_library,
};
pub(crate) use content::{
	get_secure_library_catalog, get_secure_media_file_v2, get_secure_media_thumbnail,
};
pub(crate) use delete::{delete_secure_media, delete_secure_series};
pub(crate) use helpers::block_api_key_and_opds_for_secure_routes;
pub(crate) use list::{
	get_secure_library_access_status, get_secure_library_status, list_secure_libraries,
};

// Re-export types for use in tests and OpenAPI schema generation
// (unused_imports warning suppressed: these are consumed by utoipa proc macros)
#[allow(unused_imports)]
pub(crate) use catalog::{
	read_decrypted_catalog_v1, write_encrypted_catalog_v1, CatalogMediaV1,
	CatalogSeriesV1, CatalogV1,
};
#[allow(unused_imports)]
pub(crate) use helpers::SECURE_CONTENT_CSP;
#[allow(unused_imports)]
pub(crate) use types::{
	AccessListResponse, AccessListUser, AccessStatusResponse, CreateSecureLibraryRequest,
	CreateSecureLibraryResponse, DeleteMediaResponse, DeleteSecureLibraryResponse,
	DeleteSeriesResponse, GrantAccessRequest, GrantAccessResponse, JobProgressStatus,
	RevokeAccessRequest, RevokeAccessResponse, ScanSecureLibraryResponse,
	SecureLibraryStatus, SecureLibrarySummary, WrappedLmkResponse,
};

/// Mount secure library routes
pub(crate) fn mount(app_state: AppState) -> Router<AppState> {
	Router::new()
		// Admin endpoints (require SMK in header)
		.route("/admin/secure/libraries", post(create_secure_library))
		.route(
			"/admin/secure/libraries/{id}",
			delete_route(delete_secure_library),
		)
		// User endpoints (no creation here; admin-only create)
		.route("/secure/libraries", get(list_secure_libraries))
		.route(
			"/secure/libraries/{id}/access-status",
			get(get_secure_library_access_status),
		)
		.route(
			"/admin/secure/libraries/{id}/grant-access",
			post(grant_library_access),
		)
		.route(
			"/admin/secure/libraries/{id}/revoke-access",
			post(revoke_library_access),
		)
		.route(
			"/admin/secure/libraries/{id}/access",
			get(get_library_access_list),
		)
		.route(
			"/admin/secure/libraries/{id}/scan",
			post(scan_secure_library),
		)
		.route(
			"/admin/secure/libraries/{id}/status",
			get(get_secure_library_status),
		)
		.route("/secure/libraries/{id}/access", get(get_wrapped_lmk))
		.route(
			"/secure/libraries/{library_id}/media/{id}/file",
			get(get_secure_media_file_v2),
		)
		.route(
			"/secure/libraries/{library_id}/media/{id}/thumbnail",
			get(get_secure_media_thumbnail),
		)
		.route(
			"/secure/libraries/{library_id}/media/{id}",
			delete_route(delete_secure_media),
		)
		.route(
			"/secure/libraries/{library_id}/series/{id}",
			delete_route(delete_secure_series),
		)
		.route(
			"/secure/libraries/{id}/catalog",
			get(get_secure_library_catalog),
		)
		.layer(middleware::from_fn(
			block_api_key_and_opds_for_secure_routes,
		))
		.layer(middleware::from_fn_with_state(app_state, auth_middleware))
}
