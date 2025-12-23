//! Integration tests for Secure Library Access ACL queries

#[cfg(test)]
mod integration_tests {
    use crate::{
        db::query::secure_library_access::*,
        prisma::{library, secure_library_access, user, PrismaClient},
    };
    use chrono::Utc;

    async fn setup_test_db() -> PrismaClient {
        PrismaClient::_builder()
            .build()
            .await
            .expect("Failed to create test client")
    }

    async fn cleanup_test_data(client: &PrismaClient) {
        // Clean up test data
        let _ = client.secure_library_access().delete_many(vec![]).exec().await;
        let _ = client.library().delete_many(vec![]).exec().await;
        let _ = client.user().delete_many(vec![]).exec().await;
    }

    #[tokio::test]
    async fn test_user_has_library_access_granted() {
        let client = setup_test_db().await;
        cleanup_test_data(&client).await;

        // Create test user
        let user = client
            .user()
            .create("test_user".to_string(), vec![])
            .exec()
            .await
            .expect("Failed to create test user");

        // Create test library
        let library = client
            .library()
            .create(
                "Test Library".to_string(),
                "/test/path".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to create test library");

        // Grant access
        client
            .secure_library_access()
            .create(
                user.id.clone(),
                library.id.clone(),
                "encrypted_lmk".to_string(),
                "ephemeral_public".to_string(),
                "nonce".to_string(),
                "admin".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to grant access");

        // Test access check
        let has_access = user_has_library_access(&client, &user.id, &library.id)
            .await
            .expect("Query failed");

        assert!(has_access, "User should have access to library");

        cleanup_test_data(&client).await;
    }

    #[tokio::test]
    async fn test_user_has_library_access_denied() {
        let client = setup_test_db().await;
        cleanup_test_data(&client).await;

        // Test with non-existent user/library
        let has_access = user_has_library_access(&client, "nonexistent_user", "nonexistent_lib")
            .await
            .expect("Query failed");

        assert!(!has_access, "User should not have access to non-existent library");

        cleanup_test_data(&client).await;
    }

    #[tokio::test]
    async fn test_user_has_library_access_revoked() {
        let client = setup_test_db().await;
        cleanup_test_data(&client).await;

        // Create test user and library
        let user = client
            .user()
            .create("test_user2".to_string(), vec![])
            .exec()
            .await
            .expect("Failed to create test user");

        let library = client
            .library()
            .create(
                "Test Library 2".to_string(),
                "/test/path2".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to create test library");

        // Grant access
        client
            .secure_library_access()
            .create(
                user.id.clone(),
                library.id.clone(),
                "encrypted_lmk".to_string(),
                "ephemeral_public".to_string(),
                "nonce".to_string(),
                "admin".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to grant access");

        // Revoke access
        let now = Utc::now();
        client
            .secure_library_access()
            .update_many(
                vec![
                    secure_library_access::user_id::equals(user.id.clone()),
                    secure_library_access::library_id::equals(library.id.clone()),
                ],
                vec![
                    secure_library_access::revoked_at::set(Some(now.into())),
                    secure_library_access::revoked_by::set(Some("admin".to_string())),
                ],
            )
            .exec()
            .await
            .expect("Failed to revoke access");

        // Test access check after revocation
        let has_access = user_has_library_access(&client, &user.id, &library.id)
            .await
            .expect("Query failed");

        assert!(!has_access, "User should not have access after revocation");

        cleanup_test_data(&client).await;
    }

    #[tokio::test]
    async fn test_get_user_accessible_libraries() {
        let client = setup_test_db().await;
        cleanup_test_data(&client).await;

        // Create test user
        let user = client
            .user()
            .create("test_user3".to_string(), vec![])
            .exec()
            .await
            .expect("Failed to create test user");

        // Create multiple libraries
        let lib1 = client
            .library()
            .create(
                "Library 1".to_string(),
                "/test/path/lib1".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to create library 1");

        let lib2 = client
            .library()
            .create(
                "Library 2".to_string(),
                "/test/path/lib2".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to create library 2");

        // Grant access to lib1 only
        client
            .secure_library_access()
            .create(
                user.id.clone(),
                lib1.id.clone(),
                "encrypted_lmk".to_string(),
                "ephemeral_public".to_string(),
                "nonce".to_string(),
                "admin".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to grant access");

        // Get accessible libraries
        let accessible_libs = get_user_accessible_libraries(&client, &user.id)
            .await
            .expect("Query failed");

        assert_eq!(accessible_libs.len(), 1, "User should have access to 1 library");
        assert!(accessible_libs.contains(&lib1.id), "Should contain lib1");
        assert!(!accessible_libs.contains(&lib2.id), "Should not contain lib2");

        cleanup_test_data(&client).await;
    }

    #[tokio::test]
    async fn test_get_library_authorized_users() {
        let client = setup_test_db().await;
        cleanup_test_data(&client).await;

        // Create test library
        let library = client
            .library()
            .create(
                "Shared Library".to_string(),
                "/test/shared".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to create library");

        // Create multiple users
        let user1 = client
            .user()
            .create("user1".to_string(), vec![])
            .exec()
            .await
            .expect("Failed to create user1");

        let user2 = client
            .user()
            .create("user2".to_string(), vec![])
            .exec()
            .await
            .expect("Failed to create user2");

        // Grant access to both users
        client
            .secure_library_access()
            .create(
                user1.id.clone(),
                library.id.clone(),
                "encrypted_lmk_1".to_string(),
                "ephemeral_public_1".to_string(),
                "nonce_1".to_string(),
                "admin".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to grant access to user1");

        client
            .secure_library_access()
            .create(
                user2.id.clone(),
                library.id.clone(),
                "encrypted_lmk_2".to_string(),
                "ephemeral_public_2".to_string(),
                "nonce_2".to_string(),
                "admin".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to grant access to user2");

        // Get authorized users
        let authorized_users = get_library_authorized_users(&client, &library.id)
            .await
            .expect("Query failed");

        assert_eq!(authorized_users.len(), 2, "Library should have 2 authorized users");
        assert!(authorized_users.contains(&user1.id), "Should contain user1");
        assert!(authorized_users.contains(&user2.id), "Should contain user2");

        cleanup_test_data(&client).await;
    }

    #[tokio::test]
    async fn test_count_library_access() {
        let client = setup_test_db().await;
        cleanup_test_data(&client).await;

        // Create test library
        let library = client
            .library()
            .create(
                "Count Test Library".to_string(),
                "/test/count".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to create library");

        // Initially should have zero access grants
        let initial_count = count_library_access(&client, &library.id)
            .await
            .expect("Count query failed");

        assert_eq!(initial_count, 0, "Library should have 0 access grants initially");

        // Create user and grant access
        let user = client
            .user()
            .create("count_user".to_string(), vec![])
            .exec()
            .await
            .expect("Failed to create user");

        client
            .secure_library_access()
            .create(
                user.id.clone(),
                library.id.clone(),
                "encrypted_lmk".to_string(),
                "ephemeral_public".to_string(),
                "nonce".to_string(),
                "admin".to_string(),
                vec![],
            )
            .exec()
            .await
            .expect("Failed to grant access");

        // Should now have one access grant
        let updated_count = count_library_access(&client, &library.id)
            .await
            .expect("Count query failed");

        assert_eq!(updated_count, 1, "Library should have 1 access grant");

        cleanup_test_data(&client).await;
    }
}
