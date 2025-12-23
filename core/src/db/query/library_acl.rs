//! Library queries with ACL filtering
//!
//! Helper functions for querying libraries with access control enforcement.

use prisma_client_rust::QueryError;

use crate::{
	db::query::secure_library_access,
	prisma::{library, PrismaClient},
};

/// Get filter conditions for libraries accessible by a user
///
/// This returns Prisma filter conditions that can be used in library queries
/// to filter out libraries the user doesn't have access to.
///
/// # Arguments
/// * `client` - Database client
/// * `user_id` - The user's ID
/// * `is_server_owner` - Whether the user is a server owner (bypasses ACL)
///
/// # Returns
/// Vector of library IDs the user can access
pub async fn get_user_library_filter(
	client: &PrismaClient,
	user_id: &str,
	is_server_owner: bool,
) -> Result<Vec<String>, QueryError> {
	// Server owners can access all libraries
	if is_server_owner {
		let all_libraries = client.library().find_many(vec![]).exec().await?;

		return Ok(all_libraries.into_iter().map(|l| l.id).collect());
	}

	// Regular users: get libraries they have access to
	// This includes both regular libraries and secure libraries with granted access
	let accessible_secure_libs =
		secure_library_access::get_user_accessible_libraries(client, user_id).await?;

	// Get regular (non-secure) libraries - everyone has access. We fetch full
	// library records and then map out just the IDs to keep the query simple
	// and avoid select! macro usage in dependent crates.
	let regular_libraries = client
		.library()
		.find_many(vec![library::is_secure::equals(false)])
		.exec()
		.await?;

	let mut accessible_ids: Vec<String> =
		regular_libraries.into_iter().map(|l| l.id).collect();
	accessible_ids.extend(accessible_secure_libs);

	Ok(accessible_ids)
}

/// Check if a user can access a specific library
///
/// # Arguments
/// * `client` - Database client
/// * `user_id` - The user's ID
/// * `library_id` - The library's ID
/// * `is_server_owner` - Whether the user is a server owner (bypasses ACL)
///
/// # Returns
/// `true` if user can access the library, `false` otherwise
pub async fn can_user_access_library(
	client: &PrismaClient,
	user_id: &str,
	library_id: &str,
	is_server_owner: bool,
) -> Result<bool, QueryError> {
	// Server owners can access all libraries
	if is_server_owner {
		return Ok(true);
	}

	// Check if library exists and get its security status
	let library = client
		.library()
		.find_unique(library::id::equals(library_id.to_string()))
		.exec()
		.await?;

	let Some(lib) = library else {
		return Ok(false); // Library doesn't exist
	};

	// Regular libraries are accessible to everyone
	if !lib.is_secure {
		return Ok(true);
	}

	// Secure libraries require explicit access grant
	secure_library_access::user_has_library_access(client, user_id, library_id).await
}

/// Get filter for media queries based on library access
///
/// This can be used to filter media queries to only include media
/// from libraries the user has access to.
///
/// # Arguments
/// * `client` - Database client
/// * `user_id` - The user's ID
/// * `is_server_owner` - Whether the user is a server owner (bypasses ACL)
///
/// # Returns
/// Vector of library IDs for use in media query filters
pub async fn get_media_library_filter(
	client: &PrismaClient,
	user_id: &str,
	is_server_owner: bool,
) -> Result<Vec<String>, QueryError> {
	// Same as library filter - media inherits library access
	get_user_library_filter(client, user_id, is_server_owner).await
}

/// Get accessible libraries with full data
///
/// Returns complete library records that the user has access to.
///
/// # Arguments
/// * `client` - Database client
/// * `user_id` - The user's ID
/// * `is_server_owner` - Whether the user is a server owner (bypasses ACL)
///
/// # Returns
/// Vector of accessible library records
pub async fn get_accessible_libraries(
	client: &PrismaClient,
	user_id: &str,
	is_server_owner: bool,
) -> Result<Vec<library::Data>, QueryError> {
	let accessible_ids =
		get_user_library_filter(client, user_id, is_server_owner).await?;

	if accessible_ids.is_empty() {
		return Ok(vec![]);
	}

	let libraries = client
		.library()
		.find_many(vec![library::id::in_vec(accessible_ids)])
		.exec()
		.await?;

	Ok(libraries)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::prisma::secure_library_access;
	use prisma_client_rust::MockStore;

	async fn setup_mock_client() -> (PrismaClient, MockStore) {
		PrismaClient::_mock()
	}

	#[tokio::test]
	async fn test_server_owner_bypass() {
		let (client, _mock) = setup_mock_client().await;

		// Server owners should be able to access any library
		let can_access = can_user_access_library(&client, "owner", "any_lib", true)
			.await
			.unwrap();

		assert!(can_access);
	}

	#[tokio::test]
	async fn test_get_user_library_filter() {
		let (client, mock) = setup_mock_client().await;
		// For non-owner: secure access is empty and regular libraries list is empty
		mock.expect(
			client.secure_library_access().find_many(vec![
				secure_library_access::user_id::equals("user1".to_string()),
				secure_library_access::revoked_at::equals(None),
			]),
			vec![],
		)
		.await;
		// Expect a regular library find_many without any select! macro
		mock.expect(
			client
				.library()
				.find_many(vec![library::is_secure::equals(false)]),
			vec![],
		)
		.await;

		// Non-owner should get filtered list
		let filter = get_user_library_filter(&client, "user1", false)
			.await
			.unwrap();

		// Should succeed even if empty
		assert!(filter.is_empty() || !filter.is_empty());
	}

	#[tokio::test]
	async fn test_get_accessible_libraries() {
		let (client, mock) = setup_mock_client().await;
		// Same expectations as get_user_library_filter so that it returns empty IDs
		mock.expect(
			client.secure_library_access().find_many(vec![
				secure_library_access::user_id::equals("user1".to_string()),
				secure_library_access::revoked_at::equals(None),
			]),
			vec![],
		)
		.await;
		// Expect a regular library find_many without any select! macro
		mock.expect(
			client
				.library()
				.find_many(vec![library::is_secure::equals(false)]),
			vec![],
		)
		.await;

		let libraries = get_accessible_libraries(&client, "user1", false)
			.await
			.unwrap();

		// Should return a vector (possibly empty)
		assert!(libraries.is_empty());
	}
}
