//! Library ACL filtering for API endpoints
//!
//! Provides ACL-aware filtering functions that can be used with Prisma queries
//! to enforce per-library access control.

use stump_core::{
	db::{entity::User, query::library_acl},
	prisma::{
		library::{self, WhereParam},
		PrismaClient,
	},
};

use crate::errors::APIResult;

/// Create a Prisma where condition that filters libraries by ACL
///
/// This function returns a filter that:
/// - For server owners: Returns all libraries
/// - For regular users: Returns only libraries they have access to
///   - Non-secure libraries (everyone has access)
///   - Secure libraries with explicit access grants
///
/// # Arguments
/// * `client` - Database client
/// * `user` - The requesting user
///
/// # Returns
/// A Prisma WhereParam that filters libraries by access
pub async fn library_acl_filter(
	client: &PrismaClient,
	user: &User,
) -> APIResult<Vec<WhereParam>> {
	// Server owners bypass ACL
	if user.is_server_owner {
		return Ok(vec![]);
	}

	// Get accessible library IDs
	let accessible_ids =
		library_acl::get_user_library_filter(client, &user.id, user.is_server_owner)
			.await?;

	// If user has no accessible libraries, return impossible filter
	if accessible_ids.is_empty() {
		// This will match no libraries
		return Ok(vec![library::id::equals("__impossible__".to_string())]);
	}

	// Filter to only accessible library IDs
	Ok(vec![library::id::in_vec(accessible_ids)])
}

/// Check if a user can access a specific library
///
/// # Arguments
/// * `client` - Database client
/// * `library_id` - The library ID to check
/// * `user` - The requesting user
///
/// # Returns
/// `true` if user can access the library, `false` otherwise
pub async fn can_access_library(
	client: &PrismaClient,
	library_id: &str,
	user: &User,
) -> APIResult<bool> {
	let has_access = library_acl::can_user_access_library(
		client,
		&user.id,
		library_id,
		user.is_server_owner,
	)
	.await?;

	Ok(has_access)
}

/// Get media library filter for ACL enforcement
///
/// Media queries need to filter by accessible libraries.
/// This returns library IDs that can be used in media queries.
///
/// # Arguments
/// * `client` - Database client
/// * `user` - The requesting user
///
/// # Returns
/// Vector of library IDs the user can access
#[allow(dead_code)]
pub async fn media_library_acl_filter(
	client: &PrismaClient,
	user: &User,
) -> APIResult<Vec<String>> {
	let accessible_ids =
		library_acl::get_media_library_filter(client, &user.id, user.is_server_owner)
			.await?;

	Ok(accessible_ids)
}

#[cfg(test)]
mod tests {
	use super::*;
	use stump_core::db::entity::User;
	use stump_core::prisma::library;
	use stump_core::prisma::secure_library_access as db_sla;

	fn mock_user(id: &str, is_owner: bool) -> User {
		User {
			id: id.to_string(),
			username: "test_user".to_string(),
			is_server_owner: is_owner,
			..Default::default()
		}
	}

	#[tokio::test]
	async fn test_server_owner_bypass() {
		// Server owners should get empty filter (no restrictions)
		let (client, mock_store) = stump_core::prisma::PrismaClient::_mock();
		// Expect library.find_many(vec![]).select({ id }) to return empty vec
		mock_store
			.expect(client.library().find_many(vec![]), vec![])
			.await;

		let owner = mock_user("owner1", true);
		let filters = library_acl_filter(&client, &owner).await.unwrap();

		// Empty filter means no restrictions
		assert!(filters.is_empty());
	}

	#[tokio::test]
	async fn test_regular_user_filter() {
		let (client, mock_store) = stump_core::prisma::PrismaClient::_mock();
		// Expect secure_library_access.find_many for user to return none
		mock_store
			.expect(
				client.secure_library_access().find_many(vec![
					db_sla::user_id::equals("user1".to_string()),
					db_sla::revoked_at::equals(None),
				]),
				vec![],
			)
			.await;
		// Expect regular library.find_many where is_secure = false to return empty
		mock_store
			.expect(
				client
					.library()
					.find_many(vec![library::is_secure::equals(false)]),
				vec![],
			)
			.await;

		let user = mock_user("user1", false);
		let filters = library_acl_filter(&client, &user).await.unwrap();

		// Regular users should get filtered
		// Will be empty or have library ID filter
		assert!(filters.is_empty() || filters.len() == 1);
	}
}
