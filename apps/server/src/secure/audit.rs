#![allow(clippy::empty_line_after_doc_comments)]

use serde_json::json;
use stump_core::{
	db::entity::CryptoAuditEventType,
	prisma::{crypto_audit_log, PrismaClient},
};

/// Convenience helpers for emitting crypto audit events for secure flows.

/// Log a user login event for audit purposes.
pub async fn log_login(client: &PrismaClient, user_id: &str) {
	let _ = client
		.crypto_audit_log()
		.create(
			CryptoAuditEventType::Login.to_string(),
			user_id.to_string(),
			vec![crypto_audit_log::details::set(Some(
				json!({
					"event": "login",
				})
				.to_string(),
			))],
		)
		.exec()
		.await;
}

#[cfg(test)]
mod tests {
	use super::*;
	use stump_core::db::{create_test_client, migration};

	#[tokio::test]
	async fn log_login_writes_login_audit_row() {
		let client = create_test_client().await;
		migration::run_migrations(&client)
			.await
			.expect("run migrations for log_login test");

		// Ensure a clean slate for audit logs
		client
			.crypto_audit_log()
			.delete_many(vec![])
			.exec()
			.await
			.expect("clear crypto_audit_log for log_login test");

		let user_id = "login-user-id";

		log_login(&client, user_id).await;

		let logs = client
			.crypto_audit_log()
			.find_many(vec![])
			.exec()
			.await
			.expect("fetch crypto_audit_log after log_login");

		let found = logs.iter().any(|log| {
			log.event_type == CryptoAuditEventType::Login.as_str()
				&& log.user_id == user_id
		});

		assert!(found, "expected Login audit event for user_id={}", user_id,);
	}
}
