#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "user",
    responses((status = 200, description = "Fetched users", body = Vec<User>))
)]
async fn get_users(
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<Vec<User>>> {
	// Only server owners can list users
	req.enforce_server_owner()?;
	let users = ctx
		.db
		.user()
		.find_many(vec![])
		.with(user::age_restriction::fetch())
		.with(user::user_preferences::fetch())
		.exec()
		.await?;
	Ok(Json(users.into_iter().map(User::from).collect()))
}

#[derive(Debug, Deserialize, Type, ToSchema)]
pub struct CreateUserPayload {
	username: String,
	password: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "user",
    request_body = CreateUserPayload,
    responses((status = 200, description = "Created user", body = User))
)]
async fn create_user(
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	Json(input): Json<CreateUserPayload>,
) -> APIResult<Json<User>> {
	// Only server owners can create users
	req.enforce_server_owner()?;
	let hash = crate::utils::argon2_auth::hash_password(&input.password, &ctx.config)
		.map_err(|e| {
			APIError::InternalServerError(format!("Password hashing failed: {}", e))
		})?;
	let created = ctx
		.db
		.user()
		.create(input.username.clone(), hash, vec![])
		.with(user::age_restriction::fetch())
		.with(user::user_preferences::fetch())
		.exec()
		.await?;
	Ok(Json(User::from(created)))
}

#[utoipa::path(
    get,
    path = "/api/v1/users/login-activity",
    tag = "user",
    responses((status = 200, description = "Fetched login activity", body = Vec<LoginActivity>))
)]
async fn get_user_login_activity(
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<Vec<LoginActivity>>> {
	let user = req.user();
	let logs = ctx
		.db
		.user_login_activity()
		.find_many(vec![user_login_activity::user_id::equals(user.id.clone())])
		.order_by(user_login_activity::timestamp::order(Direction::Desc))
		.exec()
		.await?;
	Ok(Json(logs.into_iter().map(LoginActivity::from).collect()))
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/login-activity",
    tag = "user",
    responses((status = 200, description = "Deleted login activity"))
)]
async fn delete_user_login_activity(
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<()> {
	let user = req.user();
	ctx.db
		.user_login_activity()
		.delete_many(vec![user_login_activity::user_id::equals(user.id.clone())])
		.exec()
		.await?;
	Ok(())
}
use std::{fs::File, io::Write};

#[derive(Debug, Deserialize, Type, ToSchema)]
pub struct UpdateUser {
	pub username: Option<String>,
	pub permissions: Option<String>,
	pub max_sessions_allowed: Option<i32>,
	pub is_server_owner: Option<bool>,
}

#[utoipa::path(
    put,
    path = "/api/v1/users/me",
    tag = "user",
    request_body = UpdateUser,
    responses(
        (status = 200, description = "Successfully updated current user", body = User),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error"),
    )
)]
async fn update_current_user(
	Extension(req): Extension<RequestContext>,
	State(ctx): State<AppState>,
	Json(input): Json<UpdateUser>,
) -> APIResult<Json<User>> {
	let db = &ctx.db;
	let user = req.user();

	let updated_user =
		update_user(user.clone(), db, user.id.clone(), input, &ctx.config).await?;
	Ok(Json(updated_user))
}

async fn update_preferences(
	db: &PrismaClient,
	prefs_id: String,
	input: UpdateUserPreferences,
) -> APIResult<UserPreferences> {
	let updated = db
		.user_preferences()
		.update(
			user_preferences::id::equals(prefs_id),
			vec![
				user_preferences::locale::set(input.locale),
				user_preferences::preferred_layout_mode::set(input.preferred_layout_mode),
				user_preferences::primary_navigation_mode::set(
					input.primary_navigation_mode,
				),
				user_preferences::layout_max_width_px::set(input.layout_max_width_px),
				user_preferences::app_theme::set(input.app_theme),
				user_preferences::enable_gradients::set(input.enable_gradients),
				user_preferences::app_font::set(input.app_font.to_string()),
				user_preferences::show_query_indicator::set(input.show_query_indicator),
				user_preferences::enable_live_refetch::set(input.enable_live_refetch),
				user_preferences::enable_discord_presence::set(
					input.enable_discord_presence,
				),
				user_preferences::enable_compact_display::set(
					input.enable_compact_display,
				),
				user_preferences::enable_double_sidebar::set(input.enable_double_sidebar),
				user_preferences::enable_replace_primary_sidebar::set(
					input.enable_replace_primary_sidebar,
				),
				user_preferences::enable_hide_scrollbar::set(input.enable_hide_scrollbar),
				user_preferences::prefer_accent_color::set(input.prefer_accent_color),
				user_preferences::show_thumbnails_in_headers::set(
					input.show_thumbnails_in_headers,
				),
				user_preferences::enable_job_overlay::set(input.enable_job_overlay),
			],
		)
		.exec()
		.await?;

	Ok(UserPreferences::from(updated))
}

async fn update_user(
	current_user: User,
	db: &PrismaClient,
	target_id: String,
	input: UpdateUser,
	_config: &StumpConfig,
) -> APIResult<User> {
	let mut params: Vec<user::SetParam> = Vec::new();

	if let Some(username) = input.username {
		params.push(user::username::set(username));
	}
	if let Some(perms) = input.permissions {
		params.push(user::permissions::set(Some(perms)));
	}
	if let Some(max) = input.max_sessions_allowed {
		params.push(user::max_sessions_allowed::set(Some(max)));
	}
	if let Some(is_owner) = input.is_server_owner {
		if current_user.is_server_owner {
			params.push(user::is_server_owner::set(is_owner));
		}
	}

	let updated = db
		.user()
		.update(user::id::equals(target_id), params)
		.with(user::user_preferences::fetch())
		.with(user::age_restriction::fetch())
		.exec()
		.await?;

	Ok(User::from(updated))
}

use axum::{
	extract::{DefaultBodyLimit, Multipart, Path, State},
	http::StatusCode,
	middleware,
	response::IntoResponse,
	routing::{delete, get, patch, put},
	Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use prisma_client_rust::{chrono::Utc, Direction};
use serde::{Deserialize, Serialize};
use serde_json::json;
use specta::Type;
use stump_core::{
	config::StumpConfig,
	db::entity::{
		Arrangement, LoginActivity, NavigationItem, SupportedFont, User, UserPermission,
		UserPreferences,
	},
	filesystem::{get_unknown_image, ContentType, FileParts, PathUtils},
	prisma::{
		crypto_audit_log, session, user, user_login_activity, user_preferences,
		PrismaClient,
	},
};
use tokio::fs;
use tower_sessions::Session;
use tracing::{debug, trace};
use utoipa::ToSchema;

use crate::{
	config::{session::SESSION_USER_KEY, state::AppState},
	errors::{APIError, APIResult},
	middleware::auth::{auth_middleware, RequestContext},
	utils::{get_session_user, http::ImageResponse, validate_and_load_image},
};

pub(crate) fn mount(app_state: AppState) -> Router<AppState> {
	Router::new()
		.route("/users", get(get_users).post(create_user))
		.route(
			"/users/login-activity",
			get(get_user_login_activity).delete(delete_user_login_activity),
		)
		.nest(
			"/users/me",
			Router::new()
				.route("/", put(update_current_user))
				.route("/preferences", put(update_current_user_preferences))
				.route(
					"/keypair",
					get(get_current_user_keypair).put(set_current_user_keypair),
				)
				.route("/password", patch(change_current_user_password))
				.route(
					"/navigation-arrangement",
					get(get_navigation_arrangement).put(update_navigation_arrangement),
				),
		)
		.nest(
			"/users/{id}",
			Router::new()
				.route(
					"/",
					get(get_user_by_id)
						.put(update_user_handler)
						.delete(delete_user_by_id),
				)
				.route("/sessions", delete(delete_user_sessions))
				.route("/lock", put(update_user_lock_status))
				.route("/login-activity", get(get_user_login_activity_by_id))
				.route(
					"/preferences",
					get(get_user_preferences).put(update_user_preferences),
				)
				.route(
					"/avatar",
					get(get_user_avatar).post(upload_user_avatar).layer(
						DefaultBodyLimit::max(app_state.config.max_image_upload_size),
					),
				),
		)
		.layer(middleware::from_fn_with_state(app_state, auth_middleware))
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Arc;

	use axum::{extract::State, Extension};
	use stump_core::{
		config::StumpConfig,
		db::{entity::User as CoreUser, migration::run_migrations},
		prisma::{user, PrismaClient},
		Ctx,
	};

	use crate::{config::state::AppState, middleware::auth::RequestContext};

	async fn setup_test_user(
		client: &PrismaClient,
		config: &StumpConfig,
		username: &str,
		password: &str,
	) -> user::Data {
		// Ensure idempotency across tests sharing the same test.db
		client
			.user()
			.delete_many(vec![user::username::equals(username.to_string())])
			.exec()
			.await
			.expect("failed to clean up test user");

		let hash = crate::utils::argon2_auth::hash_password(password, config)
			.expect("failed to hash password");

		client
			.user()
			.create(username.to_string(), hash, vec![])
			.exec()
			.await
			.expect("failed to create test user")
	}

	#[tokio::test]
	async fn change_current_user_password_updates_hash_and_keypair_fields() {
		let ctx = Ctx::integration_test_mock().await;
		let client: &PrismaClient = ctx.db.as_ref();
		run_migrations(client)
			.await
			.expect("Failed to run migrations for change_password tests");

		let config = ctx.config.clone();
		let db_user =
			setup_test_user(client, &config, "cp-user-ok", "old-password").await;
		let user_id = db_user.id.clone();
		let username = db_user.username.clone();

		let core_user = CoreUser {
			id: user_id.clone(),
			username,
			..Default::default()
		};
		let app_state = AppState::new(Arc::new(ctx));
		let req_ctx = RequestContext::new_for_tests(core_user, None, None);

		let payload = ChangePasswordPayload {
			current_password: "old-password".to_string(),
			new_password: "new-password".to_string(),
			encrypted_private: "ct-new".to_string(),
			nonce: "nonce-new".to_string(),
			salt: "salt-new".to_string(),
		};

		let result = change_current_user_password(
			Extension(req_ctx),
			State(app_state.clone()),
			Json(payload),
		)
		.await;

		assert!(
			result.is_ok(),
			"expected Ok from change_current_user_password"
		);

		let client_after: &PrismaClient = app_state.db.as_ref();
		let updated = client_after
			.user()
			.find_unique(user::id::equals(user_id.clone()))
			.exec()
			.await
			.expect("failed to reload user")
			.expect("user should exist after password change");

		// Hash should verify with new password and fail with old password
		let ok_new = crate::utils::argon2_auth::verify_password(
			&updated.hashed_password,
			"new-password",
		)
		.expect("verify new password");
		assert!(ok_new, "new password should verify");
		let ok_old = crate::utils::argon2_auth::verify_password(
			&updated.hashed_password,
			"old-password",
		)
		.expect("verify old password");
		assert!(!ok_old, "old password should no longer verify");

		assert_eq!(updated.encrypted_x_25519_private.as_deref(), Some("ct-new"),);
		assert_eq!(updated.x_25519_private_nonce.as_deref(), Some("nonce-new"),);
		assert_eq!(updated.x_25519_password_salt.as_deref(), Some("salt-new"),);
	}

	#[tokio::test]
	async fn change_current_user_password_rejects_wrong_current_password() {
		let ctx = Ctx::integration_test_mock().await;
		let client_arc = ctx.db.clone();
		let client: &PrismaClient = client_arc.as_ref();
		run_migrations(client).await.expect(
			"Failed to run migrations for change_password tests (wrong password)",
		);

		let config = ctx.config.clone();
		let db_user =
			setup_test_user(client, &config, "cp-user-wrong", "correct-password").await;

		let core_user = CoreUser {
			id: db_user.id.clone(),
			username: db_user.username.clone(),
			..Default::default()
		};
		let app_state = AppState::new(Arc::new(ctx));
		let req_ctx = RequestContext::new_for_tests(core_user, None, None);

		let payload = ChangePasswordPayload {
			current_password: "wrong-password".to_string(),
			new_password: "new-password".to_string(),
			encrypted_private: "ct-new".to_string(),
			nonce: "nonce-new".to_string(),
			salt: "salt-new".to_string(),
		};

		let result = change_current_user_password(
			Extension(req_ctx),
			State(app_state.clone()),
			Json(payload),
		)
		.await;

		match result {
			Err(APIError::Unauthorized) => {},
			other => panic!("expected Unauthorized, got: {:?}", other),
		}

		let updated = client
			.user()
			.find_unique(user::id::equals(db_user.id.clone()))
			.exec()
			.await
			.expect("failed to reload user after failed password change")
			.expect("user should exist after failed password change");

		// Password hash should still verify with the original password
		let ok_original = crate::utils::argon2_auth::verify_password(
			&updated.hashed_password,
			"correct-password",
		)
		.expect("verify original password");
		assert!(ok_original, "original password should still verify");
	}

	#[tokio::test]
	async fn keypair_get_returns_404_when_missing() {
		let ctx = Ctx::integration_test_mock().await;
		let client: &PrismaClient = ctx.db.as_ref();
		run_migrations(client)
			.await
			.expect("Failed to run migrations for keypair tests");

		// Ensure idempotency: clean up any existing user with this username, then
		// create a user with no keypair fields set.
		client
			.user()
			.delete_many(vec![user::username::equals("kp-missing".to_string())])
			.exec()
			.await
			.expect("failed to clean up keypair test user");
		let db_user = client
			.user()
			.create("kp-missing".to_string(), "hashed".to_string(), vec![])
			.exec()
			.await
			.expect("failed to create keypair test user");

		let core_user = CoreUser {
			id: db_user.id.clone(),
			username: db_user.username.clone(),
			..Default::default()
		};
		let app_state = AppState::new(Arc::new(ctx));
		let req_ctx = RequestContext::new_for_tests(core_user, None, None);

		let result = get_current_user_keypair(Extension(req_ctx), State(app_state)).await;

		match result {
			Err(APIError::NotFound(_)) => {},
			other => panic!("expected NotFound for missing keypair, got: {:?}", other),
		}
	}

	#[tokio::test]
	async fn keypair_roundtrip_after_set_succeeds() {
		let ctx = Ctx::integration_test_mock().await;
		let client: &PrismaClient = ctx.db.as_ref();
		run_migrations(client)
			.await
			.expect("Failed to run migrations for keypair roundtrip test");

		// Ensure idempotency: clean up any existing user with this username, then
		// create a user with no keypair fields set.
		client
			.user()
			.delete_many(vec![user::username::equals("kp-roundtrip".to_string())])
			.exec()
			.await
			.expect("failed to clean up keypair roundtrip user");
		let db_user = client
			.user()
			.create("kp-roundtrip".to_string(), "hashed".to_string(), vec![])
			.exec()
			.await
			.expect("failed to create keypair roundtrip user");

		let core_user = CoreUser {
			id: db_user.id.clone(),
			username: db_user.username.clone(),
			..Default::default()
		};
		let app_state = AppState::new(Arc::new(ctx));
		let req_ctx = RequestContext::new_for_tests(core_user.clone(), None, None);

		// Set keypair with valid base64 fields
		let public_bytes = [1u8; 32];
		let encrypted_bytes = vec![2u8; 48];
		let nonce_bytes = [3u8; 12];
		let salt_bytes = [4u8; 16];

		let public_key_b64 = BASE64.encode(public_bytes);
		let encrypted_private_b64 = BASE64.encode(encrypted_bytes);
		let nonce_b64 = BASE64.encode(nonce_bytes);
		let salt_b64 = BASE64.encode(salt_bytes);

		let set_payload = SetKeypairPayload {
			public_key: public_key_b64.clone(),
			encrypted_private: encrypted_private_b64.clone(),
			nonce: nonce_b64.clone(),
			salt: salt_b64.clone(),
		};
		let _ = set_current_user_keypair(
			Extension(req_ctx),
			State(app_state.clone()),
			Json(set_payload),
		)
		.await
		.expect("expected Ok from set_current_user_keypair");

		// Now fetch via GET and verify values
		let req_ctx_get = RequestContext::new_for_tests(core_user, None, None);
		let Json(resp) =
			get_current_user_keypair(Extension(req_ctx_get), State(app_state))
				.await
				.expect("expected Ok from get_current_user_keypair");

		assert_eq!(resp.public_key, public_key_b64);
		assert_eq!(resp.encrypted_private, encrypted_private_b64);
		assert_eq!(resp.nonce, nonce_b64);
		assert_eq!(resp.salt, salt_b64);
	}

	#[tokio::test]
	async fn keypair_created_at_is_set_on_first_set() {
		let ctx = Ctx::integration_test_mock().await;
		let client: &PrismaClient = ctx.db.as_ref();
		run_migrations(client)
			.await
			.expect("Failed to run migrations for keypair_created_at test");

		client
			.user()
			.delete_many(vec![user::username::equals("kp-created-at".to_string())])
			.exec()
			.await
			.expect("failed to clean up kp-created-at user");

		let db_user = client
			.user()
			.create("kp-created-at".to_string(), "hashed".to_string(), vec![])
			.exec()
			.await
			.expect("failed to create kp-created-at user");

		let core_user = CoreUser {
			id: db_user.id.clone(),
			username: db_user.username.clone(),
			..Default::default()
		};
		let app_state = AppState::new(Arc::new(ctx));
		let req_ctx = RequestContext::new_for_tests(core_user, None, None);
		let client_after: &PrismaClient = app_state.db.as_ref();

		let before = client_after
			.user()
			.find_unique(user::id::equals(db_user.id.clone()))
			.exec()
			.await
			.expect("failed to reload user before set")
			.expect("user should exist before set");
		assert!(
			before.keypair_created_at.is_none(),
			"keypair_created_at should be None before first set",
		);

		let public_bytes = [9u8; 32];
		let encrypted_bytes = vec![8u8; 48];
		let nonce_bytes = [7u8; 12];
		let salt_bytes = [6u8; 16];

		let set_payload = SetKeypairPayload {
			public_key: BASE64.encode(public_bytes),
			encrypted_private: BASE64.encode(encrypted_bytes),
			nonce: BASE64.encode(nonce_bytes),
			salt: BASE64.encode(salt_bytes),
		};
		let _ = set_current_user_keypair(
			Extension(req_ctx),
			State(app_state.clone()),
			Json(set_payload),
		)
		.await
		.expect("expected Ok from set_current_user_keypair");

		let after = client_after
			.user()
			.find_unique(user::id::equals(db_user.id.clone()))
			.exec()
			.await
			.expect("failed to reload user after set")
			.expect("user should exist after set");
		assert!(
			after.keypair_created_at.is_some(),
			"keypair_created_at should be set after first set",
		);
	}

	async fn extract_status_and_error(err: APIError) -> (StatusCode, serde_json::Value) {
		match err {
			APIError::Custom(response) => {
				let status = response.status();
				let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
					.await
					.expect("failed to read response body");
				let json: serde_json::Value =
					serde_json::from_slice(&bytes).expect("failed to parse JSON body");
				(status, json)
			},
			other => panic!("expected APIError::Custom, got: {:?}", other),
		}
	}

	#[tokio::test]
	async fn set_current_user_keypair_rejects_invalid_base64() {
		let ctx = Ctx::integration_test_mock().await;
		let client: &PrismaClient = ctx.db.as_ref();
		run_migrations(client)
			.await
			.expect("Failed to run migrations for invalid keypair format test");

		let config = ctx.config.clone();
		let db_user =
			setup_test_user(client, &config, "kp-invalid-format", "password").await;

		let core_user = CoreUser {
			id: db_user.id.clone(),
			username: db_user.username.clone(),
			..Default::default()
		};
		let app_state = AppState::new(Arc::new(ctx));
		let req_ctx = RequestContext::new_for_tests(core_user, None, None);

		let payload = SetKeypairPayload {
			public_key: "not-base64".to_string(),
			encrypted_private: "also-not-base64".to_string(),
			nonce: "bad-nonce".to_string(),
			salt: "bad-salt".to_string(),
		};

		let result =
			set_current_user_keypair(Extension(req_ctx), State(app_state), Json(payload))
				.await;

		match result {
			Err(err) => {
				let (status, body) = extract_status_and_error(err).await;
				assert_eq!(status, StatusCode::BAD_REQUEST);
				assert_eq!(body["code"], "invalid_keypair_format");
			},
			Ok(_) => panic!("expected error for invalid keypair format"),
		}
	}
}

// ...

#[derive(Debug, Deserialize, Type, ToSchema)]
pub struct SetKeypairPayload {
	pub public_key: String,
	pub encrypted_private: String,
	pub nonce: String,
	pub salt: String,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub struct SetKeypairResponse {
	pub message: String,
	pub keypair_created_at: String,
}

fn invalid_keypair_format(message: String) -> APIError {
	let body = json!({
		"code": "invalid_keypair_format",
		"message": message,
	});
	let response = (StatusCode::BAD_REQUEST, Json(body)).into_response();
	APIError::Custom(response)
}

fn validate_user_keypair_payload(input: &SetKeypairPayload) -> APIResult<()> {
	// public_key: base64-encoded 32-byte X25519 public key
	let public_bytes = BASE64.decode(&input.public_key).map_err(|_| {
		invalid_keypair_format("public_key must be valid base64".to_string())
	})?;
	if public_bytes.len() != 32 {
		return Err(invalid_keypair_format(
			"public_key must decode to 32 bytes".to_string(),
		));
	}

	// encrypted_private: base64-encoded ChaCha20-Poly1305 ciphertext (must include 16-byte tag)
	let encrypted_bytes = BASE64.decode(&input.encrypted_private).map_err(|_| {
		invalid_keypair_format("encrypted_private must be valid base64".to_string())
	})?;
	if encrypted_bytes.len() < 16 {
		return Err(invalid_keypair_format(
			"encrypted_private must be at least 16 bytes".to_string(),
		));
	}

	// nonce: base64-encoded 12-byte nonce
	let nonce_bytes = BASE64
		.decode(&input.nonce)
		.map_err(|_| invalid_keypair_format("nonce must be valid base64".to_string()))?;
	if nonce_bytes.len() != 12 {
		return Err(invalid_keypair_format(
			"nonce must decode to 12 bytes".to_string(),
		));
	}

	// salt: base64-encoded 16-byte Argon2id salt
	let salt_bytes = BASE64
		.decode(&input.salt)
		.map_err(|_| invalid_keypair_format("salt must be valid base64".to_string()))?;
	if salt_bytes.len() != 16 {
		return Err(invalid_keypair_format(
			"salt must decode to 16 bytes".to_string(),
		));
	}

	Ok(())
}

/// Stores user's X25519 keypair metadata on the server
#[utoipa::path(
	put,
	path = "/api/v1/users/me/keypair",
	tag = "user",
    request_body = SetKeypairPayload,
    responses(
        (status = 200, description = "Stored user keypair", body = SetKeypairResponse),
        		(status = 400, description = "Invalid keypair format"),
		(status = 401, description = "Unauthorized"),
		(status = 500, description = "Internal server error"),
	),
)]
async fn set_current_user_keypair(
	Extension(req): Extension<RequestContext>,
	State(ctx): State<AppState>,
	Json(input): Json<SetKeypairPayload>,
) -> APIResult<Json<SetKeypairResponse>> {
	let db = &ctx.db;
	let user = req.user();

	// Validate base64 encoding and expected sizes before persisting.
	validate_user_keypair_payload(&input)?;

	let updated = db
		.user()
		.update(
			user::id::equals(user.id.clone()),
			vec![
				user::x_25519_public_key::set(Some(input.public_key.clone())),
				user::encrypted_x_25519_private::set(Some(
					input.encrypted_private.clone(),
				)),
				user::x_25519_private_nonce::set(Some(input.nonce.clone())),
				user::x_25519_password_salt::set(Some(input.salt.clone())),
				user::keypair_created_at::set(Some(Utc::now().into())),
			],
		)
		.with(user::user_preferences::fetch())
		.with(user::age_restriction::fetch())
		.exec()
		.await?;

	// Audit log
	db.crypto_audit_log()
		.create(
			"KEYPAIR_GENERATED".to_string(),
			user.id.clone(),
			vec![
				crypto_audit_log::target_type::set(Some("USER".to_string())),
				crypto_audit_log::target_id::set(Some(user.id.clone())),
			],
		)
		.exec()
		.await
		.ok();

	let created_at = updated
		.keypair_created_at
		.map(|dt| dt.to_rfc3339())
		.unwrap_or_else(|| Utc::now().to_rfc3339());

	Ok(Json(SetKeypairResponse {
		message: "Keypair updated".to_string(),
		keypair_created_at: created_at,
	}))
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub struct GetKeypairResponse {
	pub public_key: String,
	pub encrypted_private: String,
	pub nonce: String,
	pub salt: String,
}

/// Returns the current user's encrypted keypair materials for client-side restore
#[utoipa::path(
    get,
    path = "/api/v1/users/me/keypair",
    tag = "user",
    responses(
        (status = 200, description = "Encrypted keypair for current user", body = GetKeypairResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Keypair not found"),
        (status = 500, description = "Internal server error"),
    )
)]
async fn get_current_user_keypair(
	Extension(req): Extension<RequestContext>,
	State(ctx): State<AppState>,
) -> APIResult<Json<GetKeypairResponse>> {
	let db = &ctx.db;
	let user = req.user();

	let db_user = db
		.user()
		.find_unique(user::id::equals(user.id.clone()))
		.exec()
		.await?
		.ok_or(APIError::Unauthorized)?;

	let public_key = db_user
		.x_25519_public_key
		.ok_or(APIError::NotFound("Keypair not found".to_string()))?;
	let encrypted_private = db_user
		.encrypted_x_25519_private
		.ok_or(APIError::NotFound("Keypair not found".to_string()))?;
	let nonce = db_user
		.x_25519_private_nonce
		.ok_or(APIError::NotFound("Keypair not found".to_string()))?;
	let salt = db_user
		.x_25519_password_salt
		.ok_or(APIError::NotFound("Keypair not found".to_string()))?;

	Ok(Json(GetKeypairResponse {
		public_key,
		encrypted_private,
		nonce,
		salt,
	}))
}

#[derive(Debug, Clone, Deserialize, Type, ToSchema)]
pub struct UpdateUserPreferences {
	pub id: String,
	pub locale: String,
	pub preferred_layout_mode: String,
	pub primary_navigation_mode: String,
	pub layout_max_width_px: Option<i32>,
	pub app_theme: String,
	pub enable_gradients: bool,
	pub app_font: SupportedFont,
	pub show_query_indicator: bool,
	pub enable_live_refetch: bool,
	pub enable_discord_presence: bool,
	pub enable_compact_display: bool,
	pub enable_double_sidebar: bool,
	pub enable_replace_primary_sidebar: bool,
	pub enable_hide_scrollbar: bool,
	pub enable_job_overlay: bool,
	pub prefer_accent_color: bool,
	pub show_thumbnails_in_headers: bool,
}

#[utoipa::path(
    put,
    path = "/api/v1/users/me/preferences",
    tag = "user",
    request_body = UpdateUserPreferences,
    responses(
        (status = 200, description = "Successfully updated user preferences", body = UserPreferences),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error"),
    )
)]
/// Updates a user's preferences.
async fn update_current_user_preferences(
	Extension(req): Extension<RequestContext>,
	session: Session,
	State(ctx): State<AppState>,
	Json(input): Json<UpdateUserPreferences>,
) -> APIResult<Json<UserPreferences>> {
	let db = &ctx.db;

	let user = req.user();
	let user_preferences = user.user_preferences.clone().unwrap_or_default();

	trace!(user_id = ?user.id, ?user_preferences, updates = ?input, "Updating viewer's preferences");

	let updated_preferences = update_preferences(db, user_preferences.id, input).await?;
	debug!(?updated_preferences, "Updated user preferences");

	if get_session_user(&session).await?.is_some() {
		session
			.insert(
				SESSION_USER_KEY,
				User {
					user_preferences: Some(updated_preferences.clone()),
					..user.clone()
				},
			)
			.await?;
	}

	Ok(Json(updated_preferences))
}

#[derive(Debug, Deserialize, Type, ToSchema)]
pub struct ChangePasswordPayload {
	pub current_password: String,
	pub new_password: String,
	pub encrypted_private: String,
	pub nonce: String,
	pub salt: String,
}

/// Change current user's password and replace encrypted private key
#[utoipa::path(
    patch,
    path = "/api/v1/users/me/password",
    tag = "user",
    request_body = ChangePasswordPayload,
    responses((status = 200, description = "Password changed"))
)]
async fn change_current_user_password(
	Extension(req): Extension<RequestContext>,
	State(ctx): State<AppState>,
	Json(input): Json<ChangePasswordPayload>,
) -> APIResult<Json<()>> {
	let db = &ctx.db;
	let user = req.user();

	// Verify current password
	let db_user = db
		.user()
		.find_unique(user::id::equals(user.id.clone()))
		.exec()
		.await?
		.ok_or(APIError::Unauthorized)?;

	let matches = crate::utils::argon2_auth::verify_password(
		&db_user.hashed_password,
		&input.current_password,
	)?;
	if !matches {
		return Err(APIError::Unauthorized);
	}

	// Hash new password
	let new_hash =
		crate::utils::argon2_auth::hash_password(&input.new_password, &ctx.config)
			.map_err(|e| {
				APIError::InternalServerError(format!("Password hashing failed: {}", e))
			})?;

	// Update user
	db.user()
		.update(
			user::id::equals(user.id.clone()),
			vec![
				user::hashed_password::set(new_hash),
				user::encrypted_x_25519_private::set(Some(
					input.encrypted_private.clone(),
				)),
				user::x_25519_private_nonce::set(Some(input.nonce.clone())),
				user::x_25519_password_salt::set(Some(input.salt.clone())),
			],
		)
		.exec()
		.await?;

	// Delete all sessions for this user
	db.session()
		.delete_many(vec![session::user_id::equals(user.id.clone())])
		.exec()
		.await?;

	// Audit log
	db.crypto_audit_log()
		.create(
			"PASSWORD_CHANGED".to_string(),
			user.id.clone(),
			vec![
				crypto_audit_log::target_type::set(Some("USER".to_string())),
				crypto_audit_log::target_id::set(Some(user.id.clone())),
			],
		)
		.exec()
		.await
		.ok();

	Ok(Json(()))
}

#[utoipa::path(
    get,
    path = "/api/v1/users/me/navigation-arrangement",
    tag = "user",
    responses(
        (status = 200, description = "Successfully fetched user navigation arrangement"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error"),
    )
)]
async fn get_navigation_arrangement(
	Extension(req): Extension<RequestContext>,
	State(ctx): State<AppState>,
) -> APIResult<Json<Arrangement<NavigationItem>>> {
	let user = req.user();
	let db = &ctx.db;

	let prefs_data = match db
		.user_preferences()
		.find_first(vec![user_preferences::user::is(vec![user::id::equals(
			user.id.clone(),
		)])])
		.exec()
		.await?
	{
		Some(p) => p,
		None => {
			db.user_preferences()
				.create(vec![
					user_preferences::user::connect(user::id::equals(user.id.clone())),
					user_preferences::user_id::set(Some(user.id.clone())),
				])
				.exec()
				.await?
		},
	};
	let user_preferences = UserPreferences::from(prefs_data);

	Ok(Json(user_preferences.navigation_arrangement))
}

#[utoipa::path(
	put,
	path = "/api/v1/users/me/navigation-arrangement",
	tag = "user",
	request_body = Arrangement<NavigationItem>,
	responses(
		(status = 200, description = "Successfully updated user navigation arrangement", body = Arrangement<NavigationItem>),
		(status = 401, description = "Unauthorized"),
		(status = 403, description = "Forbidden"),
		(status = 500, description = "Internal server error"),
	)
)]
async fn update_navigation_arrangement(
	Extension(req): Extension<RequestContext>,
	State(ctx): State<AppState>,
	Json(input): Json<Arrangement<NavigationItem>>,
) -> APIResult<Json<Arrangement<NavigationItem>>> {
	let user = req.user();
	let db = &ctx.db;

	let prefs_data = match db
		.user_preferences()
		// TODO: Really old accounts potentially have users with preferences missing a `user_id`
		// assignment. This should be more properly fixed in the future, e.g. by a migration.
		.find_first(vec![user_preferences::user::is(vec![user::id::equals(
			user.id.clone(),
		)])])
		.exec()
		.await?
	{
		Some(p) => p,
		None => {
			db.user_preferences()
				.create(vec![
					user_preferences::user::connect(user::id::equals(user.id.clone())),
					user_preferences::user_id::set(Some(user.id.clone())),
				])
				.exec()
				.await?
		},
	};
	let user_preferences = UserPreferences::from(prefs_data);

	let _updated_preferences = db
		.user_preferences()
		.update(
			user_preferences::id::equals(user_preferences.id.clone()),
			vec![user_preferences::navigation_arrangement::set(Some(
				serde_json::to_vec(&input).map_err(|e| {
					APIError::InternalServerError(format!(
						"Failed to serialize navigation arrangement: {e}"
					))
				})?,
			))],
		)
		.exec()
		.await?;

	Ok(Json(input))
}

#[derive(Deserialize, Type, ToSchema)]
pub struct DeleteUser {
	pub hard_delete: Option<bool>,
}

#[utoipa::path(
	delete,
	path = "/api/v1/users/{id}",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's id.", example = "1ab2c3d4")
	),
	responses(
		(status = 200, description = "Successfully deleted user", body = User),
		(status = 401, description = "Unauthorized"),
		(status = 403, description = "Forbidden"),
		(status = 404, description = "User not found"),
		(status = 500, description = "Internal server error"),
	)
)]
/// Deletes a user by ID.
async fn delete_user_by_id(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	Json(input): Json<DeleteUser>,
) -> APIResult<Json<User>> {
	let db = &ctx.db;
	let user = req.server_owner_user()?;

	if user.id == id {
		return Err(APIError::BadRequest(
			"You cannot delete your own account.".into(),
		));
	}

	let hard_delete = input.hard_delete.unwrap_or(false);

	let deleted_user = if hard_delete {
		db.user().delete(user::id::equals(id.clone())).exec().await
	} else {
		db.user()
			.update(
				user::id::equals(id.clone()),
				vec![user::deleted_at::set(Some(Utc::now().into()))],
			)
			.exec()
			.await
	}?;

	debug!(?deleted_user, "Deleted user");

	Ok(Json(User::from(deleted_user)))
}

#[utoipa::path(
	get,
	path = "/api/v1/users/{id}",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's ID.", example = "1ab2c3d4")
	),
	responses(
		(status = 200, description = "Successfully fetched user", body = User),
		(status = 401, description = "Unauthorized"),
		(status = 403, description = "Forbidden"),
		(status = 404, description = "User not found"),
		(status = 500, description = "Internal server error"),
	)
)]
/// Gets a user by ID.
async fn get_user_by_id(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<User>> {
	req.enforce_server_owner()?;
	let db = &ctx.db;
	let fetched_user = db
		.user()
		.find_unique(user::id::equals(id.clone()))
		.with(user::age_restriction::fetch())
		.exec()
		.await?
		.ok_or(APIError::NotFound(format!("User with id {id} not found")))?;

	Ok(Json(User::from(fetched_user)))
}

// TODO: pagination!
#[utoipa::path(
	get,
	path = "/api/v1/users/{id}/login-activity",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's ID.", example = "1ab2c3d4")
	),
	responses(
		(status = 200, description = "Successfully fetched user", body = Vec<LoginActivity>),
		(status = 401, description = "Unauthorized"),
		(status = 403, description = "Forbidden"),
		(status = 404, description = "User not found"),
		(status = 500, description = "Internal server error"),
	)
)]
async fn get_user_login_activity_by_id(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<Vec<LoginActivity>>> {
	let user = req.user();

	let client = &ctx.db;

	if user.id != id && !user.is_server_owner {
		return Err(APIError::Forbidden(String::from(
			"You cannot access this resource",
		)));
	}

	let user_activity = client
		.user_login_activity()
		.find_many(vec![user_login_activity::user_id::equals(id)])
		.order_by(user_login_activity::timestamp::order(Direction::Desc))
		.exec()
		.await?;

	Ok(Json(
		user_activity.into_iter().map(LoginActivity::from).collect(),
	))
}

#[utoipa::path(
	put,
	path = "/api/v1/users/{id}",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's ID.", example = "1ab2c3d4")
	),
	request_body = UpdateUser,
	responses(
		(status = 200, description = "Successfully updated user", body = User),
		(status = 401, description = "Unauthorized"),
		(status = 403, description = "Forbidden"),
		(status = 500, description = "Internal server error"),
	)
)]
/// Updates a user by ID.
async fn update_user_handler(
	Extension(req): Extension<RequestContext>,
	session: Session,
	State(ctx): State<AppState>,
	Path(id): Path<String>,
	Json(input): Json<UpdateUser>,
) -> APIResult<Json<User>> {
	let db = &ctx.db;
	let user = req.user();

	if user.id != id && !user.is_server_owner {
		return Err(APIError::forbidden_discreet());
	}

	let updated_user =
		update_user(user.clone(), db, id.clone(), input, &ctx.config).await?;
	debug!(?updated_user, "Updated user");

	if user.id == id && get_session_user(&session).await?.is_some() {
		session
			.insert(SESSION_USER_KEY, updated_user.clone())
			.await?;
	} else {
		// When a server owner updates another user, we need to delete all sessions for that user
		// because the user's permissions may have changed. This is a bit lazy but it works.
		db.session()
			.delete_many(vec![session::user_id::equals(id)])
			.exec()
			.await?;
	}

	Ok(Json(updated_user))
}

#[utoipa::path(
	delete,
	path = "/api/v1/users/{id}/sessions",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's ID.", example = "1ab2c3d4")
	),
	responses(
		(status = 200, description = "Successfully deleted user sessions"),
		(status = 401, description = "Unauthorized"),
		(status = 403, description = "Forbidden"),
		(status = 500, description = "Internal server error"),
	)
)]
async fn delete_user_sessions(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<()> {
	req.enforce_server_owner()?;

	let client = &ctx.db;
	let removed_sessions = client
		.session()
		.delete_many(vec![session::user_id::equals(id)])
		.exec()
		.await?;
	tracing::trace!(?removed_sessions, "Removed sessions for user");

	Ok(())
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateAccountLock {
	lock: bool,
}

#[utoipa::path(
	put,
	path = "/api/v1/users/{id}/lock",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's ID.", example = "1ab2c3d4")
	),
	request_body = UpdateAccountLock,
	responses(
		(status = 200, description = "Successfully updated user lock status", body = User),
		(status = 400, description = "You cannot lock your own account"),
		(status = 401, description = "Unauthorized"),
		(status = 403, description = "Forbidden"),
		(status = 500, description = "Internal server error"),
	)
)]
async fn update_user_lock_status(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	Json(input): Json<UpdateAccountLock>,
) -> APIResult<Json<User>> {
	let user = req.server_owner_user()?;
	if user.id == id {
		return Err(APIError::BadRequest(
			"You cannot lock your own account.".into(),
		));
	}

	let db = &ctx.db;
	let updated_user = db
		.user()
		.update(
			user::id::equals(id.clone()),
			vec![user::is_locked::set(input.lock)],
		)
		.exec()
		.await?;

	if input.lock {
		// Delete all sessions for this user if they are being locked
		let removed_sessions = db
			.session()
			.delete_many(vec![session::user_id::equals(id)])
			.exec()
			.await?;
		tracing::trace!(?removed_sessions, "Removed sessions for locked user");
	}

	Ok(Json(User::from(updated_user)))
}

#[utoipa::path(
	get,
	path = "/api/v1/users/{id}/preferences",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's ID.", example = "1ab2c3d4")
	),
	responses(
		(status = 200, description = "Successfully fetched user preferences", body = UserPreferences),
		(status = 401, description = "Unauthorized"),
		(status = 403, description = "Forbidden"),
		(status = 404, description = "User preferences not found"),
		(status = 500, description = "Internal server error"),
	)
)]
/// Gets the user's preferences.
async fn get_user_preferences(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<UserPreferences>> {
	let db = &ctx.db;
	let user = req.user();

	if id != user.id {
		return Err(APIError::forbidden_discreet());
	}

	let user_preferences = db
		.user_preferences()
		.find_unique(user_preferences::user_id::equals(id.clone()))
		.exec()
		.await?;
	debug!(id, ?user_preferences, "Fetched user preferences");

	if user_preferences.is_none() {
		return Err(APIError::NotFound(format!(
			"User preferences with id {id} not found"
		)));
	}

	Ok(Json(UserPreferences::from(user_preferences.unwrap())))
}

// TODO: this is now a duplicate, do I need it? I think to remain RESTful, yes...
#[utoipa::path(
	put,
	path = "/api/v1/users/{id}/preferences",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's ID.", example = "1ab2c3d4")
	),
	request_body = UpdateUserPreferences,
	responses(
		(status = 200, description = "Successfully updated user preferences", body = UserPreferences),
		(status = 401, description = "Unauthorized"),
		(status = 403, description = "Forbidden"),
		(status = 500, description = "Internal server error"),
	)
)]
/// Updates a user's preferences.
async fn update_user_preferences(
	Extension(req): Extension<RequestContext>,
	session: Session,
	State(ctx): State<AppState>,
	Path(id): Path<String>,
	Json(input): Json<UpdateUserPreferences>,
) -> APIResult<Json<UserPreferences>> {
	trace!(?id, ?input, "Updating user preferences");
	let db = &ctx.db;

	let user = req.user();
	let user_preferences = user.user_preferences.clone().unwrap_or_default();

	if user_preferences.id != input.id {
		return Err(APIError::forbidden_discreet());
	}

	let updated_preferences = update_preferences(db, user_preferences.id, input).await?;
	debug!(?updated_preferences, "Updated user preferences");

	if get_session_user(&session).await?.is_some() {
		session
			.insert(
				SESSION_USER_KEY,
				User {
					user_preferences: Some(updated_preferences.clone()),
					..user.clone()
				},
			)
			.await?;
	}

	Ok(Json(updated_preferences))
}

#[utoipa::path(
	get,
	path = "/api/v1/users/{id}/avatar",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's ID.", example = "1ab2c3d4"),
	),
	responses(
		(status = 200, description = "Successfully fetched user avatar"),
		(status = 401, description = "Unauthorized"),
		(status = 404, description = "User avatar not found"),
		(status = 500, description = "Internal server error"),
	)
)]
async fn get_user_avatar(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
) -> APIResult<ImageResponse> {
	let client = &ctx.db;

	let user = client
		.user()
		.find_unique(user::id::equals(id))
		.exec()
		.await?
		.ok_or(APIError::NotFound("User not found".to_string()))?;

	match user.avatar_url {
		Some(url) if url.starts_with("/api/v1/") => {
			let avatars_dir = ctx.config.get_avatars_dir();
			let base_path = avatars_dir.join(user.username.as_str());
			if let Some(local_file) = get_unknown_image(base_path) {
				let FileParts { extension, .. } = local_file.file_parts();
				let content_type = ContentType::from_extension(extension.as_str());
				let bytes = fs::read(local_file).await?;
				Ok(ImageResponse::new(content_type, bytes))
			} else {
				Err(APIError::NotFound("User avatar not found".to_string()))
			}
		},
		Some(url) => {
			let bytes = reqwest::get(&url).await?.bytes().await?;
			let mut magic_bytes = [0; 5];
			magic_bytes.copy_from_slice(&bytes[0..5]);
			let content_type = ContentType::from_bytes(&magic_bytes);
			Ok(ImageResponse::new(content_type, bytes.to_vec()))
		},
		None => Err(APIError::NotFound("User avatar not found".to_string())),
	}
}

#[utoipa::path(
	post,
	path = "/api/v1/users/{id}/avatar",
	tag = "user",
	params(
		("id" = String, Path, description = "The user's ID.", example = "1ab2c3d4")
	),
	responses(
		(status = 200, description = "Successfully uploaded user avatar", body = User),
		(status = 400, description = "Invalid request"),
		(status = 401, description = "Unauthorized"),
		(status = 404, description = "User not found"),
		(status = 500, description = "Internal server error"),
	)
)]
async fn upload_user_avatar(
	Path(id): Path<String>,
	State(ctx): State<AppState>,
	Extension(req): Extension<RequestContext>,
	mut upload: Multipart,
) -> APIResult<ImageResponse> {
	let by_user = req.user_and_enforce_permissions(&[UserPermission::UploadFile])?;
	let client = &ctx.db;

	if by_user.id != id && !by_user.is_server_owner {
		return Err(APIError::forbidden_discreet());
	}

	tracing::trace!(?id, ?upload, "Replacing user avatar");

	let user = client
		.user()
		.find_unique(user::id::equals(id.clone()))
		.exec()
		.await?
		.ok_or(APIError::NotFound("User not found".to_string()))?;

	let upload_data =
		validate_and_load_image(&mut upload, Some(ctx.config.max_image_upload_size))
			.await?;

	let ext = upload_data.content_type.extension();
	let username = user.username.clone();

	let base_path = ctx.config.get_avatars_dir().join(username.as_str());
	let existing_avatar = get_unknown_image(base_path.clone());
	if let Some(existing_avatar) = existing_avatar {
		std::fs::remove_file(existing_avatar)?;
	}

	let file_name = format!("{username}.{ext}");
	let file_path = ctx.config.get_avatars_dir().join(file_name.as_str());
	let mut file = File::create(file_path.clone())?;
	file.write_all(&upload_data.bytes)?;

	let updated_user = client
		.user()
		.update(
			user::id::equals(id.clone()),
			vec![user::avatar_url::set(Some(format!(
				"/api/v1/users/{id}/avatar"
			)))],
		)
		.exec()
		.await?;

	tracing::trace!(?updated_user, "Updated user");

	Ok(ImageResponse::new(
		upload_data.content_type,
		upload_data.bytes,
	))
}
