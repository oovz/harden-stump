//! Secure Library Access Control List (ACL) queries
//!
//! Functions for querying and managing per-library access permissions.

use prisma_client_rust::QueryError;

use crate::{
	db::entity::SecureLibraryAccess,
	prisma::{secure_library_access, PrismaClient},
};

/// Check if a user has active (non-revoked) access to a secure library
///
/// # Arguments
/// * `client` - Database client
/// * `user_id` - The user's ID
/// * `library_id` - The library's ID
///
/// # Returns
/// `true` if user has active access, `false` otherwise
pub async fn user_has_library_access(
	client: &PrismaClient,
	user_id: &str,
	library_id: &str,
) -> Result<bool, QueryError> {
	let access = client
		.secure_library_access()
		.find_first(vec![
			secure_library_access::user_id::equals(user_id.to_string()),
			secure_library_access::library_id::equals(library_id.to_string()),
			secure_library_access::revoked_at::equals(None),
		])
		.exec()
		.await?;

	Ok(access.is_some())
}

/// Get all library IDs that a user has active access to
///
/// # Arguments
/// * `client` - Database client
/// * `user_id` - The user's ID
///
/// # Returns
/// Vector of library IDs the user can access
pub async fn get_user_accessible_libraries(
	client: &PrismaClient,
	user_id: &str,
) -> Result<Vec<String>, QueryError> {
	let accesses = client
		.secure_library_access()
		.find_many(vec![
			secure_library_access::user_id::equals(user_id.to_string()),
			secure_library_access::revoked_at::equals(None),
		])
		.exec()
		.await?;

	Ok(accesses.into_iter().map(|a| a.library_id).collect())
}

/// Get all users with active access to a specific library
///
/// # Arguments
/// * `client` - Database client
/// * `library_id` - The library's ID
///
/// # Returns
/// Vector of user IDs with access to the library
pub async fn get_library_authorized_users(
	client: &PrismaClient,
	library_id: &str,
) -> Result<Vec<String>, QueryError> {
	let accesses = client
		.secure_library_access()
		.find_many(vec![
			secure_library_access::library_id::equals(library_id.to_string()),
			secure_library_access::revoked_at::equals(None),
		])
		.exec()
		.await?;

	Ok(accesses.into_iter().map(|a| a.user_id).collect())
}

/// Get access grant details including encrypted LMK
///
/// # Arguments
/// * `client` - Database client
/// * `user_id` - The user's ID
/// * `library_id` - The library's ID
///
/// # Returns
/// Full access record if it exists and is not revoked
pub async fn get_user_library_access(
	client: &PrismaClient,
	user_id: &str,
	library_id: &str,
) -> Result<Option<SecureLibraryAccess>, QueryError> {
	let access = client
		.secure_library_access()
		.find_first(vec![
			secure_library_access::user_id::equals(user_id.to_string()),
			secure_library_access::library_id::equals(library_id.to_string()),
			secure_library_access::revoked_at::equals(None),
		])
		.exec()
		.await?;

	Ok(access.map(Into::into))
}

/// Get all access grants for a specific library (including revoked)
///
/// # Arguments
/// * `client` - Database client
/// * `library_id` - The library's ID
///
/// # Returns
/// All access records for the library
pub async fn get_all_library_access(
	client: &PrismaClient,
	library_id: &str,
) -> Result<Vec<SecureLibraryAccess>, QueryError> {
	let accesses = client
		.secure_library_access()
		.find_many(vec![secure_library_access::library_id::equals(
			library_id.to_string(),
		)])
		.exec()
		.await?;

	Ok(accesses.into_iter().map(Into::into).collect())
}

/// Count active access grants for a library
///
/// # Arguments
/// * `client` - Database client
/// * `library_id` - The library's ID
///
/// # Returns
/// Number of active access grants
pub async fn count_library_access(
	client: &PrismaClient,
	library_id: &str,
) -> Result<i64, QueryError> {
	let count = client
		.secure_library_access()
		.count(vec![
			secure_library_access::library_id::equals(library_id.to_string()),
			secure_library_access::revoked_at::equals(None),
		])
		.exec()
		.await?;

	Ok(count)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::prisma::secure_library_access as db_sla;
	use crate::prisma::PrismaClient;
	use prisma_client_rust::MockStore;

	async fn setup_mock_client() -> (PrismaClient, MockStore) {
		PrismaClient::_mock()
	}

	#[tokio::test]
	async fn test_user_has_library_access() {
		let (client, mock) = setup_mock_client().await;
		// No access record exists
		mock.expect(
			client.secure_library_access().find_first(vec![
				db_sla::user_id::equals("user1".to_string()),
				db_sla::library_id::equals("lib1".to_string()),
				db_sla::revoked_at::equals(None),
			]),
			None,
		)
		.await;

		// Test with non-existent access
		let has_access = user_has_library_access(&client, "user1", "lib1")
			.await
			.unwrap();

		assert!(!has_access);
	}

	#[tokio::test]
	async fn test_get_user_accessible_libraries() {
		let (client, mock) = setup_mock_client().await;
		mock.expect(
			client.secure_library_access().find_many(vec![
				db_sla::user_id::equals("user1".to_string()),
				db_sla::revoked_at::equals(None),
			]),
			vec![],
		)
		.await;

		let libraries = get_user_accessible_libraries(&client, "user1")
			.await
			.unwrap();

		assert!(libraries.is_empty());
	}

	#[tokio::test]
	async fn test_count_library_access() {
		let (client, mock) = setup_mock_client().await;
		mock.expect(
			client.secure_library_access().count(vec![
				db_sla::library_id::equals("lib1".to_string()),
				db_sla::revoked_at::equals(None),
			]),
			0,
		)
		.await;

		let count = count_library_access(&client, "lib1").await.unwrap();

		assert_eq!(count, 0);
	}
}
