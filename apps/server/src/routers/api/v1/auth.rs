use axum::{
	extract::{ConnectInfo, Query, State},
	http::{header, HeaderMap, StatusCode},
	middleware,
	response::{IntoResponse, Response},
	routing::{get, post},
	Extension, Json, Router,
};
use axum_extra::{headers::UserAgent, TypedHeader};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, FixedOffset, Utc};
use prisma_client_rust::{raw, Direction, PrismaValue};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use specta::Type;
use stump_core::{
	db::entity::User,
	prisma::{session, user, user_login_activity, user_preferences, PrismaClient},
};
use tower_sessions::Session;
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
	config::{
		jwt::CreatedToken,
		jwt_manager::JWT_MANAGER,
		session::{delete_cookie_header, ABSOLUTE_SESSION_TTL_DAYS, SESSION_USER_KEY},
		state::AppState,
	},
	errors::{api_error_message, APIError, APIResult},
	http_server::StumpRequestInfo,
	middleware::auth::{auth_middleware, RequestContext},
	secure::audit as secure_audit,
	utils::{default_true, get_session_user, hash_password, verify_password},
};

const REFRESH_COOKIE_NAME: &str = "stump_refresh";
const REFRESH_COOKIE_PATH: &str = "/api/v1/auth/refresh";
const REFRESH_TOKEN_TTL_SECS: i64 = 60 * 60 * 24 * 7;

fn should_use_secure_cookies(state: &AppState) -> bool {
	!state.config.is_debug()
}

fn set_refresh_cookie_header(token: &str, secure: bool) -> (String, String) {
	let mut value = format!(
		"{}={}; HttpOnly; SameSite=Strict; Path={}; Max-Age={}",
		REFRESH_COOKIE_NAME, token, REFRESH_COOKIE_PATH, REFRESH_TOKEN_TTL_SECS
	);
	if secure {
		value.push_str("; Secure");
	}
	("Set-Cookie".to_string(), value)
}

fn delete_refresh_cookie_header(secure: bool) -> (String, String) {
	let mut value = format!(
		"{}={}; HttpOnly; SameSite=Strict; Path={}; Max-Age=0",
		REFRESH_COOKIE_NAME, "", REFRESH_COOKIE_PATH
	);
	if secure {
		value.push_str("; Secure");
	}
	("Set-Cookie".to_string(), value)
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
	let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
	for part in cookie.split(';') {
		let part = part.trim();
		let Some((k, v)) = part.split_once('=') else {
			continue;
		};
		if k == name {
			return Some(v.to_string());
		}
	}
	None
}

fn generate_refresh_token() -> String {
	let mut bytes = [0u8; 32];
	OsRng.fill_bytes(&mut bytes);
	general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_refresh_token(token: &str) -> String {
	let mut hasher = Sha256::new();
	hasher.update(token.as_bytes());
	let digest = hasher.finalize();
	general_purpose::STANDARD_NO_PAD.encode(digest)
}

pub(crate) fn mount(app_state: AppState) -> Router<AppState> {
	// Public auth endpoints (no session required)
	let public = Router::new()
		.route("/auth/login", post(login))
		.route("/auth/refresh", post(refresh))
		.route("/auth/login-opds", post(login_opds))
		.route("/auth/logout", post(logout))
		.route("/auth/register", post(register))
		.with_state(app_state.clone());

	// Protected auth endpoint: requires valid session
	let protected = Router::new()
		.route("/auth/me", get(viewer))
		.route("/session/heartbeat", post(session_heartbeat))
		.layer(middleware::from_fn_with_state(
			app_state.clone(),
			auth_middleware,
		))
		.with_state(app_state);

	public.merge(protected)
}

pub async fn enforce_max_sessions(
	for_user: &user::Data,
	db: &PrismaClient,
) -> APIResult<()> {
	let existing_sessions = for_user
		.sessions()
		.cloned()
		.unwrap_or_else(|error| {
			tracing::error!(?error, "Failed to load user's existing session(s)");
			Vec::default()
		})
		.clone();
	let existing_login_sessions_count = existing_sessions.len() as i32;

	match (for_user.max_sessions_allowed, existing_login_sessions_count) {
		(Some(max_login_sessions), count) if count >= max_login_sessions => {
			let oldest_session_id = existing_sessions
				.iter()
				.min_by_key(|session| session.expiry_time)
				.map(|session| session.id.clone());
			handle_remove_earliest_session(db, for_user.id.clone(), oldest_session_id)
				.await?;
		},
		_ => (),
	}

	Ok(())
}

#[derive(Deserialize, Type, ToSchema)]
pub struct LoginOrRegisterArgs {
	pub username: String,
	pub password: String,
}

#[derive(Debug, Deserialize, Type, ToSchema)]
pub struct AuthenticationOptions {
	#[serde(default)]
	generate_token: bool,
	#[serde(default = "default_true")]
	create_session: bool,
}

#[utoipa::path(
	get,
	path = "/api/v1/auth/me",
	tag = "auth",
	responses(
		(status = 200, description = "Returns the currently logged in user from the session.", body = User),
		(status = 401, description = "No user is logged in (unauthorized).")
	)
)]
/// Returns the currently logged in user from the session. If no user is logged in, returns an
/// unauthorized error.
async fn viewer(
	State(state): State<AppState>,
	session: Session,
	Extension(req): Extension<RequestContext>,
) -> APIResult<Json<User>> {
	let mut user = req.user().clone();

	if user.secure_library_access.is_none() {
		let accessible_ids =
			stump_core::db::query::secure_library_access::get_user_accessible_libraries(
				state.db.as_ref(),
				&user.id,
			)
			.await
			.map_err(|e| APIError::InternalServerError(e.to_string()))?;

		user.secure_library_access = Some(accessible_ids);

		if get_session_user(&session).await?.is_some() {
			session.insert(SESSION_USER_KEY, user.clone()).await?;
		}
	}

	Ok(Json(user))
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub struct HeartbeatResponse {
	ok: bool,
}

#[utoipa::path(
	post,
	path = "/api/v1/session/heartbeat",
	tag = "auth",
	responses(
		(status = 200, description = "Session heartbeat successful", body = HeartbeatResponse),
		(status = 401, description = "Unauthorized"),
	)
)]
/// Lightweight session heartbeat used by web clients to keep sessions active
/// during long-running reading sessions. This endpoint intentionally avoids
/// heavy database queries and only refreshes the session inactivity timeout
/// when a session exists.
async fn session_heartbeat(
	Extension(req): Extension<RequestContext>,
	session: Session,
) -> APIResult<Json<HeartbeatResponse>> {
	// If there is an existing session, rewrite the user payload to refresh
	// the inactivity timeout. For bearer-token-only contexts, there may be no
	// session, in which case we simply return ok.
	if get_session_user(&session).await?.is_some() {
		session.insert(SESSION_USER_KEY, req.user().clone()).await?;
	}

	Ok(Json(HeartbeatResponse { ok: true }))
}

async fn handle_login_attempt(
	client: &PrismaClient,
	for_user: user::Data,
	user_agent: UserAgent,
	request_info: StumpRequestInfo,
	success: bool,
) -> APIResult<user_login_activity::Data> {
	let login_activity = client
		.user_login_activity()
		.create(
			request_info.ip_addr.to_string(),
			user_agent.to_string(),
			success,
			user::id::equals(for_user.id),
			vec![],
		)
		.exec()
		.await?;
	Ok(login_activity)
}

async fn handle_remove_earliest_session(
	client: &PrismaClient,
	for_user_id: String,
	session_id: Option<String>,
) -> APIResult<i32> {
	if let Some(oldest_session_id) = session_id {
		let deleted_session = client
			.session()
			.delete(session::id::equals(oldest_session_id))
			.exec()
			.await?;
		tracing::trace!(?deleted_session, "Removed oldest session for user");
		Ok(1)
	} else {
		tracing::warn!("No existing session ID was provided for enforcing the maximum number of sessions. Deleting all sessions for user instead.");
		let deleted_sessions_count = client
			.session()
			.delete_many(vec![session::user_id::equals(for_user_id)])
			.exec()
			.await?;
		Ok(deleted_sessions_count as i32)
	}
}

#[derive(Debug, Serialize, Type, ToSchema)]
#[serde(untagged)]
pub enum LoginResponse {
	User(User),
	AccessToken { for_user: User, token: CreatedToken },
}

#[utoipa::path(
	post,
	path = "/api/v1/auth/login",
	tag = "auth",
	request_body = LoginOrRegisterArgs,
	responses(
		(status = 200, description = "Authenticates the user and returns the user object.", body = User),
		(status = 401, description = "Invalid username or password."),
		(status = 500, description = "An internal server error occurred.")
	)
)]
/// Authenticates the user and returns the user object. If the user is already logged in, returns the
/// user object from the session.
async fn login(
	TypedHeader(user_agent): TypedHeader<UserAgent>,
	ConnectInfo(request_info): ConnectInfo<StumpRequestInfo>,
	session: Session,
	State(state): State<AppState>,
	Query(AuthenticationOptions {
		generate_token,
		create_session,
	}): Query<AuthenticationOptions>,
	Json(input): Json<LoginOrRegisterArgs>,
) -> APIResult<Response> {
	// Check rate limit before processing login
	use crate::middleware::rate_limit::check_login_rate_limit;
	if let Err(response) = check_login_rate_limit(
		&state.rate_limiter,
		&input.username,
		&request_info.ip_addr.to_string(),
	)
	.await
	{
		return Err(APIError::Custom(response));
	}
	match get_session_user(&session).await? {
		Some(user) if user.username == input.username => {
			// TODO: should this be tracked?
			// TODO: should this be permission gated?
			if generate_token {
				secure_audit::log_login(state.db.as_ref(), &user.id).await;
				let token = JWT_MANAGER
					.create_token(&user.id, &state.config, &state.db, None)
					.await?;
				let refresh_token = generate_refresh_token();
				let refresh_hash = hash_refresh_token(&refresh_token);
				let now: DateTime<FixedOffset> = Utc::now().into();
				let expires_at = now + Duration::seconds(REFRESH_TOKEN_TTL_SECS);
				let refresh_id = Uuid::new_v4().to_string();
				let family_id = Uuid::new_v4().to_string();
				state
					.db
					._execute_raw(raw!(
						"INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at) VALUES ({}, {}, {}, {}, {})",
						PrismaValue::String(refresh_id),
						PrismaValue::String(user.id.clone()),
						PrismaValue::String(family_id),
						PrismaValue::String(refresh_hash),
						PrismaValue::DateTime(expires_at)
					))
					.exec()
					.await?;
				let compat_token = CreatedToken {
					access_token: token.access_token,
					expires_at: token.expires_at,
				};
				let secure = should_use_secure_cookies(&state);
				let (cookie_name, cookie_value) =
					set_refresh_cookie_header(&refresh_token, secure);
				let base = Json(LoginResponse::AccessToken {
					for_user: user,
					token: compat_token,
				})
				.into_response();
				let mut builder = Response::builder().status(StatusCode::OK);
				builder = builder.header("Content-Type", "application/json");
				builder = builder.header(cookie_name, cookie_value);
				return Ok(builder.body(base.into_body()).unwrap_or_else(|error| {
					tracing::error!(?error, "Failed to build response");
					(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
				}));
			}

			let mut user = user;
			if user.secure_library_access.is_none() {
				let accessible_ids =
					stump_core::db::query::secure_library_access::get_user_accessible_libraries(
						state.db.as_ref(),
						&user.id,
					)
					.await
					.map_err(|e| APIError::InternalServerError(e.to_string()))?;
				user.secure_library_access = Some(accessible_ids);
				if create_session {
					session.insert(SESSION_USER_KEY, user.clone()).await?;
				}
			}

			secure_audit::log_login(state.db.as_ref(), &user.id).await;
			return Ok(Json(LoginResponse::User(user)).into_response());
		},
		_ => {},
	}

	let client = state.db.clone();
	let today: DateTime<FixedOffset> = Utc::now().into();
	// TODO: make this configurable via environment variable so knowledgeable attackers can't bypass this
	let twenty_four_hours_ago = today - Duration::hours(24);
	let absolute_session_cutoff = today - Duration::days(ABSOLUTE_SESSION_TTL_DAYS);

	let fetch_result = client
		.user()
		.find_first(vec![
			user::username::equals(input.username.to_owned()),
			user::deleted_at::equals(None),
		])
		.with(user::user_preferences::fetch())
		.with(user::age_restriction::fetch())
		.with(
			user::login_activity::fetch(vec![
				user_login_activity::timestamp::gte(twenty_four_hours_ago),
				user_login_activity::timestamp::lte(today),
			])
			.order_by(user_login_activity::timestamp::order(Direction::Desc))
			.take(10),
		)
		.with(user::sessions::fetch(vec![
			session::expiry_time::gt(today),
			session::created_at::gt(absolute_session_cutoff),
		]))
		.exec()
		.await?;

	match fetch_result {
		Some(db_user)
			if db_user.is_locked
				&& verify_password(&db_user.hashed_password, &input.password)? =>
		{
			Err(APIError::Forbidden(
				api_error_message::LOCKED_ACCOUNT.to_string(),
			))
		},
		Some(db_user) if !db_user.is_locked => {
			let user_id = db_user.id.clone();
			let matches = verify_password(&db_user.hashed_password, &input.password)?;
			if !matches {
				// TODO: make this configurable via environment variable so knowledgeable attackers can't bypass this
				let should_lock_account = db_user
					.login_activity
					.as_ref()
					// If there are 9 or more failed login attempts _in a row_, within a 24 hour period, lock the account
					.map(|activity| {
						!activity
							.iter()
							.any(|activity| activity.authentication_successful)
							&& activity.len() >= 9
					})
					.unwrap_or(false);

				handle_login_attempt(&client, db_user, user_agent, request_info, false)
					.await?;

				if should_lock_account {
					let _locked_user = client
						.user()
						.update(
							user::id::equals(user_id.clone()),
							vec![user::is_locked::set(true)],
						)
						.exec()
						.await?;

					let removed_sessions_count = client
						.session()
						.delete_many(vec![session::user_id::equals(user_id.clone())])
						.exec()
						.await?;
					tracing::debug!(
						?removed_sessions_count,
						?user_id,
						"Locked user account and removed all associated sessions"
					)
				}

				return Err(APIError::Unauthorized);
			}

			enforce_max_sessions(&db_user, &client).await?;

			let updated_user = state
				.db
				.user()
				.update(
					user::id::equals(db_user.id.clone()),
					vec![user::last_login::set(Some(Utc::now().into()))],
				)
				.with(user::user_preferences::fetch())
				.with(user::age_restriction::fetch())
				.exec()
				.await
				.unwrap_or_else(|err| {
					error!(error = ?err, "Failed to update user last login!");
					user::Data {
						last_login: Some(Utc::now().into()),
						..db_user
					}
				});

			let login_track_result = handle_login_attempt(
				&state.db,
				updated_user.clone(),
				user_agent,
				request_info.clone(),
				true,
			)
			.await;
			// I don't want to kill the login here, so not bubbling up the error
			if let Err(err) = login_track_result {
				error!(error = ?err, "Failed to track login attempt!");
			}

			let mut user = User::from(updated_user);
			if !generate_token {
				let accessible_ids =
					stump_core::db::query::secure_library_access::get_user_accessible_libraries(
						state.db.as_ref(),
						&user.id,
					)
					.await
					.map_err(|e| APIError::InternalServerError(e.to_string()))?;
				user.secure_library_access = Some(accessible_ids);
			}
			secure_audit::log_login(state.db.as_ref(), &user.id).await;

			if create_session {
				session.insert(SESSION_USER_KEY, user.clone()).await?;
			}

			// TODO: should this be permission gated?
			if generate_token {
				let token = JWT_MANAGER
					.create_token(&user.id, &state.config, &state.db, None)
					.await?;
				let refresh_token = generate_refresh_token();
				let refresh_hash = hash_refresh_token(&refresh_token);
				let now: DateTime<FixedOffset> = Utc::now().into();
				let expires_at = now + Duration::seconds(REFRESH_TOKEN_TTL_SECS);
				let refresh_id = Uuid::new_v4().to_string();
				let family_id = Uuid::new_v4().to_string();
				state
					.db
					._execute_raw(raw!(
						"INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at) VALUES ({}, {}, {}, {}, {})",
						PrismaValue::String(refresh_id),
						PrismaValue::String(user.id.clone()),
						PrismaValue::String(family_id),
						PrismaValue::String(refresh_hash),
						PrismaValue::DateTime(expires_at)
					))
					.exec()
					.await?;
				let compat_token = CreatedToken {
					access_token: token.access_token,
					expires_at: token.expires_at,
				};
				let secure = should_use_secure_cookies(&state);
				let (cookie_name, cookie_value) =
					set_refresh_cookie_header(&refresh_token, secure);
				let base = Json(LoginResponse::AccessToken {
					for_user: user,
					token: compat_token,
				})
				.into_response();
				let mut builder = Response::builder().status(StatusCode::OK);
				builder = builder.header("Content-Type", "application/json");
				builder = builder.header(cookie_name, cookie_value);
				Ok(builder.body(base.into_body()).unwrap_or_else(|error| {
					tracing::error!(?error, "Failed to build response");
					(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
				}))
			} else {
				// Clear rate limit on successful login
				use crate::middleware::rate_limit::clear_login_rate_limit;
				clear_login_rate_limit(
					&state.rate_limiter,
					&input.username,
					&request_info.ip_addr.to_string(),
				)
				.await;

				Ok(Json(LoginResponse::User(user)).into_response())
			}
		},
		_ => Err(APIError::Unauthorized),
	}
}

#[derive(Deserialize)]
struct RefreshTokenRow {
	id: String,
	user_id: String,
	family_id: String,
	expires_at: DateTime<FixedOffset>,
	rotated_at: Option<DateTime<FixedOffset>>,
	revoked_at: Option<DateTime<FixedOffset>>,
	replaced_by: Option<String>,
}

async fn refresh(
	State(state): State<AppState>,
	headers: HeaderMap,
) -> APIResult<Response> {
	let Some(raw_token) = read_cookie(&headers, REFRESH_COOKIE_NAME) else {
		return Err(APIError::Unauthorized);
	};

	let token_hash = hash_refresh_token(&raw_token);
	let now: DateTime<FixedOffset> = Utc::now().into();
	let new_expires_at = now + Duration::seconds(REFRESH_TOKEN_TTL_SECS);

	let secure = should_use_secure_cookies(&state);

	let result: APIResult<(String, String)> = state
		.db
		._transaction()
		.run(|client| async move {
			let mut found: Vec<RefreshTokenRow> = client
				._query_raw(raw!(
					"SELECT id, user_id, family_id, expires_at, rotated_at, revoked_at, replaced_by FROM refresh_tokens WHERE token_hash={} LIMIT 1",
					PrismaValue::String(token_hash)
				))
				.exec()
				.await?;

			let Some(row) = found.pop() else {
				return Err(APIError::Unauthorized);
			};

			if row.revoked_at.is_some() || row.expires_at < now {
				return Err(APIError::Unauthorized);
			}

			if row.rotated_at.is_some() || row.replaced_by.is_some() {
				client
					._execute_raw(raw!(
						"UPDATE refresh_tokens SET revoked_at={} WHERE family_id={} AND revoked_at IS NULL",
						PrismaValue::DateTime(now),
						PrismaValue::String(row.family_id)
					))
					.exec()
					.await?;
				return Ok((row.user_id, String::new()));
			}

			let new_token = generate_refresh_token();
			let new_hash = hash_refresh_token(&new_token);
			let new_id = Uuid::new_v4().to_string();

			client
				._execute_raw(raw!(
					"INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at) VALUES ({}, {}, {}, {}, {})",
					PrismaValue::String(new_id.clone()),
					PrismaValue::String(row.user_id.clone()),
					PrismaValue::String(row.family_id.clone()),
					PrismaValue::String(new_hash),
					PrismaValue::DateTime(new_expires_at)
				))
				.exec()
				.await?;

			client
				._execute_raw(raw!(
					"UPDATE refresh_tokens SET rotated_at={}, replaced_by={} WHERE id={} AND rotated_at IS NULL AND revoked_at IS NULL",
					PrismaValue::DateTime(now),
					PrismaValue::String(new_id),
					PrismaValue::String(row.id)
				))
				.exec()
				.await?;

			Ok((row.user_id, new_token))
		})
		.await;

	let (user_id, new_refresh_token) = result?;
	if new_refresh_token.is_empty() {
		return Err(APIError::Unauthorized);
	}

	let token = JWT_MANAGER
		.create_token(&user_id, &state.config, &state.db, None)
		.await?;
	let compat_token = CreatedToken {
		access_token: token.access_token,
		expires_at: token.expires_at,
	};

	let (cookie_name, cookie_value) =
		set_refresh_cookie_header(&new_refresh_token, secure);
	let base = Json(compat_token).into_response();
	let mut builder = Response::builder().status(StatusCode::OK);
	builder = builder.header("Content-Type", "application/json");
	builder = builder.header(cookie_name, cookie_value);
	Ok(builder.body(base.into_body()).unwrap_or_else(|error| {
		tracing::error!(?error, "Failed to build response");
		(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
	}))
}

#[utoipa::path(
	post,
	path = "/api/v1/auth/logout",
	tag = "auth",
	responses(
		(status = 200, description = "Destroys the session and logs the user out."),
		(status = 500, description = "Failed to destroy session.")
	)
)]
/// Destroys the session and logs the user out.
async fn logout(
	State(state): State<AppState>,
	session: Session,
) -> APIResult<impl IntoResponse> {
	session.delete().await?;

	let body = serde_json::json!({
		"status": 200,
		"message": "OK",
	});

	let base_response = Json(body).into_response();

	let (name, value) = delete_cookie_header();
	let secure = should_use_secure_cookies(&state);
	let (refresh_name, refresh_value) = delete_refresh_cookie_header(secure);
	let builder = Response::builder()
		.status(200)
		.header("Content-Type", "application/json")
		.header(name, value)
		.header(refresh_name, refresh_value);

	Ok(builder
		.body(base_response.into_body())
		.unwrap_or_else(|error| {
			tracing::error!(?error, "Failed to build response");
			(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
		}))
}

#[utoipa::path(
	post,
	path = "/api/v1/auth/register",
	tag = "auth",
	request_body = LoginOrRegisterArgs,
	responses(
		(status = 200, description = "Successfully registered new user.", body = User),
		(status = 403, description = "Must be server owner to register member accounts."),
		(status = 500, description = "An internal server error occurred.")
	)
)]
/// Attempts to register a new user. If no users exist in the database, the user is registered as a server owner.
/// Otherwise, the registration is rejected by all users except the server owner.
pub async fn register(
	session: Session,
	State(ctx): State<AppState>,
	Json(input): Json<LoginOrRegisterArgs>,
) -> APIResult<Json<User>> {
	let db = &ctx.db;

	let has_users = db.user().find_first(vec![]).exec().await?.is_some();

	let mut is_server_owner = false;

	let session_user = get_session_user(&session).await?;

	// TODO: move nested if to if let once stable
	if let Some(user) = session_user {
		if !user.is_server_owner {
			return Err(APIError::Forbidden(String::from(
				"You do not have permission to access this resource.",
			)));
		}
	} else if session_user.is_none() && has_users {
		// if users exist, a valid session is required to register a new user
		return Err(APIError::Unauthorized);
	} else if !has_users {
		// if no users present, the user is automatically a server owner
		is_server_owner = true;
	}

	let hashed_password = hash_password(&input.password, &ctx.config)?;

	let created_user = db
		.user()
		.create(
			input.username.clone(),
			hashed_password,
			vec![user::is_server_owner::set(is_server_owner)],
		)
		.exec()
		.await?;

	// TODO(prisma-nested-create): Refactor once nested create is supported
	let _user_preferences = db
		.user_preferences()
		.create(vec![
			user_preferences::user::connect(user::id::equals(created_user.id.clone())),
			user_preferences::user_id::set(Some(created_user.id.clone())),
		])
		.exec()
		.await?;

	let user = db
		.user()
		.find_unique(user::id::equals(created_user.id))
		.with(user::user_preferences::fetch())
		.with(user::age_restriction::fetch())
		.exec()
		.await
		.map_err(|_e| {
			APIError::InternalServerError(
				"Failed to fetch user after registration".to_string(),
			)
		})?;

	let user = user.ok_or(APIError::InternalServerError(
		"User not found after registration".to_string(),
	))?;

	Ok(Json(user.into()))
}

#[derive(Debug, Deserialize, Type, ToSchema)]
pub struct OpdsLoginRequest {
	pub username: String,
	pub password: String,
}

#[derive(Debug, Serialize, Type, ToSchema)]
pub struct OpdsLoginResponse {
	pub access_token: String,
	pub token_type: String,
	pub expires_in: i64,
	pub expires_at: DateTime<FixedOffset>,
}

#[utoipa::path(
	post,
	path = "/api/v1/auth/login-opds",
	tag = "auth",
	request_body = OpdsLoginRequest,
	responses(
		(status = 200, description = "OPDS authentication successful", body = OpdsLoginResponse),
		(status = 401, description = "Invalid credentials"),
	)
)]
/// OPDS client authentication endpoint
///
/// This endpoint authenticates OPDS clients and returns a JWT with:
/// - token_type: "opds"
/// - TTL: 1 hour (for better reader app compatibility)
/// - secure_library_access: always empty array (OPDS cannot access secure libraries)
///
/// OPDS tokens can only access non-secure libraries. Any attempt to access
/// secure library endpoints will result in 404 Not Found.
async fn login_opds(
	ConnectInfo(request_info): ConnectInfo<StumpRequestInfo>,
	State(state): State<AppState>,
	Json(input): Json<OpdsLoginRequest>,
) -> APIResult<Json<OpdsLoginResponse>> {
	// Check rate limit before processing login
	use crate::middleware::rate_limit::check_login_rate_limit;
	if let Err(response) = check_login_rate_limit(
		&state.rate_limiter,
		&input.username,
		&request_info.ip_addr.to_string(),
	)
	.await
	{
		return Err(APIError::Custom(response));
	}

	let client = state.db.clone();

	// Fetch user
	let db_user = client
		.user()
		.find_first(vec![
			user::username::equals(input.username.clone()),
			user::deleted_at::equals(None),
		])
		.exec()
		.await?
		.ok_or(APIError::Unauthorized)?;

	// Check if account is locked
	if db_user.is_locked {
		return Err(APIError::Forbidden(
			api_error_message::LOCKED_ACCOUNT.to_string(),
		));
	}

	// Verify password
	let matches = verify_password(&db_user.hashed_password, &input.password)?;
	if !matches {
		return Err(APIError::Unauthorized);
	}

	// Create OPDS token with 1-hour TTL
	let mut opds_config = (*state.config).clone();
	opds_config.access_token_ttl = 3600; // 1 hour in seconds

	// Generate token with token_type="opds"
	let token = JWT_MANAGER
		.create_token(&db_user.id, &opds_config, &state.db, Some("opds"))
		.await?;

	// Clear rate limit on successful login
	use crate::middleware::rate_limit::clear_login_rate_limit;
	clear_login_rate_limit(
		&state.rate_limiter,
		&input.username,
		&request_info.ip_addr.to_string(),
	)
	.await;

	secure_audit::log_login(state.db.as_ref(), &db_user.id).await;

	Ok(Json(OpdsLoginResponse {
		access_token: token.access_token,
		token_type: "Bearer".to_string(),
		expires_in: 3600,
		expires_at: token.expires_at,
	}))
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::body::to_bytes;
	use axum::http::HeaderValue;
	use axum::Extension;
	use std::sync::Arc;
	use stump_core::db::entity::User as CoreUser;
	use stump_core::db::migration::run_migrations;
	use stump_core::Ctx;
	use tower_sessions::{MemoryStore, Session};

	#[tokio::test]
	async fn session_heartbeat_refreshes_existing_session_user() {
		let store = Arc::new(MemoryStore::default());
		let session = Session::new(None, store, None);

		let original_user = CoreUser {
			id: "session-user".to_string(),
			username: "session-user".to_string(),
			..Default::default()
		};

		// Seed the session with an existing user
		session
			.insert(SESSION_USER_KEY, original_user.clone())
			.await
			.expect("failed to insert original user into session");

		let ctx_user = CoreUser {
			id: "ctx-user".to_string(),
			username: "ctx-user".to_string(),
			..Default::default()
		};
		let req_ctx = RequestContext::new_for_tests(ctx_user.clone(), None, None);

		let Json(resp) = session_heartbeat(Extension(req_ctx), session.clone())
			.await
			.expect("expected heartbeat to succeed");
		assert!(resp.ok);

		let stored: Option<CoreUser> = session
			.get(SESSION_USER_KEY)
			.await
			.expect("failed to load user from session after heartbeat");
		let stored = stored.expect("expected user to remain in session after heartbeat");
		assert_eq!(stored.id, ctx_user.id);
	}

	#[tokio::test]
	async fn session_heartbeat_does_not_create_session_when_absent() {
		let store = Arc::new(MemoryStore::default());
		let session = Session::new(None, store, None);

		// Ensure no session user is present initially
		let before: Option<CoreUser> = session
			.get(SESSION_USER_KEY)
			.await
			.expect("failed to load user from empty session");
		assert!(before.is_none(), "session should start without a user");

		let ctx_user = CoreUser {
			id: "ctx-user-no-session".to_string(),
			username: "ctx-user-no-session".to_string(),
			..Default::default()
		};
		let req_ctx = RequestContext::new_for_tests(ctx_user, None, None);

		let Json(resp) = session_heartbeat(Extension(req_ctx), session.clone())
			.await
			.expect("expected heartbeat to succeed for bearer-only context");
		assert!(resp.ok);

		let after: Option<CoreUser> = session
			.get(SESSION_USER_KEY)
			.await
			.expect("failed to load user from session after heartbeat");
		assert!(
			after.is_none(),
			"heartbeat should not create a new session user when none existed",
		);
	}

	#[tokio::test]
	async fn refresh_rotates_and_reuse_revokes_family() {
		JWT_MANAGER
			.initialize()
			.await
			.expect("initialize JWT manager");

		let ctx = Ctx::integration_test_mock().await;
		let db: &PrismaClient = ctx.db.as_ref();
		run_migrations(db)
			.await
			.expect("run migrations for refresh token test");
		let app_state = AppState::new(Arc::new(ctx));

		let hashed = hash_password("rt-password", &app_state.config)
			.expect("hash password for refresh test user");
		let created = app_state
			.db
			.user()
			.create("rt-user".to_string(), hashed, vec![])
			.exec()
			.await
			.expect("create test user");
		let user_id = created.id;

		let refresh_token = generate_refresh_token();
		let refresh_hash = hash_refresh_token(&refresh_token);
		let refresh_id = Uuid::new_v4().to_string();
		let family_id = Uuid::new_v4().to_string();
		let now: DateTime<FixedOffset> = Utc::now().into();
		let expires_at = now + Duration::seconds(REFRESH_TOKEN_TTL_SECS);

		app_state
			.db
			._execute_raw(raw!(
				"INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at) VALUES ({}, {}, {}, {}, {})",
				PrismaValue::String(refresh_id.clone()),
				PrismaValue::String(user_id.clone()),
				PrismaValue::String(family_id.clone()),
				PrismaValue::String(refresh_hash),
				PrismaValue::DateTime(expires_at)
			))
			.exec()
			.await
			.expect("insert refresh token");

		let mut headers = HeaderMap::new();
		headers.insert(
			header::COOKIE,
			HeaderValue::from_str(&format!("{}={}", REFRESH_COOKIE_NAME, refresh_token))
				.expect("cookie header value"),
		);
		let resp = refresh(State(app_state.clone()), headers)
			.await
			.expect("refresh should succeed");
		assert_eq!(resp.status(), StatusCode::OK);

		let set_cookie = resp
			.headers()
			.get("Set-Cookie")
			.expect("Set-Cookie present")
			.to_str()
			.expect("Set-Cookie is utf8");
		let cookie_kv = set_cookie
			.split(';')
			.next()
			.expect("Set-Cookie has kv pair");
		let (_, new_refresh_token) = cookie_kv
			.split_once('=')
			.expect("Set-Cookie has name=value");
		assert!(!new_refresh_token.is_empty());
		assert_ne!(new_refresh_token, refresh_token);

		let body = to_bytes(resp.into_body(), usize::MAX)
			.await
			.expect("read refresh response body");
		let value: serde_json::Value =
			serde_json::from_slice(&body).expect("refresh response is json");
		assert!(
			value.get("access_token").and_then(|v| v.as_str()).is_some(),
			"refresh response must include access_token"
		);

		#[derive(Deserialize)]
		struct TokenRowMeta {
			rotated_at: Option<DateTime<FixedOffset>>,
			revoked_at: Option<DateTime<FixedOffset>>,
			replaced_by: Option<String>,
		}
		let mut original: Vec<TokenRowMeta> = app_state
			.db
			._query_raw(raw!(
				"SELECT rotated_at, revoked_at, replaced_by FROM refresh_tokens WHERE id={} LIMIT 1",
				PrismaValue::String(refresh_id.clone())
			))
			.exec()
			.await
			.expect("load original refresh row");
		let original = original.pop().expect("original refresh row exists");
		assert!(original.rotated_at.is_some());
		assert!(original.replaced_by.is_some());
		assert!(original.revoked_at.is_none());

		let mut headers = HeaderMap::new();
		headers.insert(
			header::COOKIE,
			HeaderValue::from_str(&format!("{}={}", REFRESH_COOKIE_NAME, refresh_token))
				.expect("cookie header value"),
		);
		let res = refresh(State(app_state.clone()), headers).await;
		assert!(matches!(res, Err(APIError::Unauthorized)));

		#[derive(Deserialize)]
		struct FamilyRow {
			revoked_at: Option<DateTime<FixedOffset>>,
		}
		let rows: Vec<FamilyRow> = app_state
			.db
			._query_raw(raw!(
				"SELECT revoked_at FROM refresh_tokens WHERE family_id={}",
				PrismaValue::String(family_id)
			))
			.exec()
			.await
			.expect("load family refresh rows");
		assert!(!rows.is_empty());
		assert!(rows.iter().all(|r| r.revoked_at.is_some()));
	}
}
