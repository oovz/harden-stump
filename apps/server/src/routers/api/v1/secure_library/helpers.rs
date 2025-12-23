//! Helper functions for secure library endpoints
//!
//! - SMK/LMK extraction from headers
//! - Error construction helpers
//! - Middleware for blocking API key and OPDS access

use axum::{
	body::Body,
	http::{HeaderValue, StatusCode},
	middleware::Next,
	response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use stump_core::crypto::{smk::SystemMasterKey, LibraryMasterKey};

use crate::{
	errors::{secure_error_codes, APIError, APIResult},
	middleware::auth::RequestContext,
};

/// CSP header value for secure content responses
pub(crate) const SECURE_CONTENT_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'";

/// Construct a structured API error for secure library endpoints
pub(crate) fn secure_api_error(
	status: StatusCode,
	code: &'static str,
	message: String,
) -> APIError {
	let body = json!({
		"error": code,
		"code": code,
		"message": message,
	});
	APIError::Custom(
		Response::builder()
			.status(status)
			.header("Content-Type", HeaderValue::from_static("application/json"))
			.body(Body::from(body.to_string()))
			.unwrap_or_else(|e| {
				(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
			}),
	)
}

/// Extract Library Master Key (LMK) from X-LMK header
pub(crate) fn extract_lmk(
	headers: &axum::http::HeaderMap,
) -> APIResult<LibraryMasterKey> {
	let header = headers.get("X-LMK").ok_or_else(|| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			"Library Master Key required in X-LMK header".to_string(),
		)
	})?;

	let lmk_str = header.to_str().map_err(|_| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			"Invalid LMK header format".to_string(),
		)
	})?;

	let lmk_bytes = BASE64.decode(lmk_str).map_err(|_| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			"X-LMK header must be base64".to_string(),
		)
	})?;

	LibraryMasterKey::from_slice(&lmk_bytes).map_err(|e| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_LMK,
			format!("Invalid LMK: {}", e),
		)
	})
}

/// Extract System Master Key (SMK) from X-SMK header
pub(crate) fn extract_smk(headers: &axum::http::HeaderMap) -> APIResult<SystemMasterKey> {
	let header = headers.get("X-SMK").ok_or_else(|| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_SMK_FORMAT,
			"System Master Key required in X-SMK header".to_string(),
		)
	})?;

	let smk_str = header.to_str().map_err(|_| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_SMK_FORMAT,
			"Invalid SMK header format".to_string(),
		)
	})?;

	SystemMasterKey::from_base64(smk_str).map_err(|e| {
		secure_api_error(
			StatusCode::BAD_REQUEST,
			secure_error_codes::INVALID_SMK_FORMAT,
			format!("Invalid SMK: {}", e),
		)
	})
}

/// Middleware to block API key and OPDS token access to secure routes
///
/// Secure libraries require session-based authentication with keypair,
/// so API keys and OPDS tokens are not allowed.
pub(crate) async fn block_api_key_and_opds_for_secure_routes(
	req: axum::extract::Request<Body>,
	next: Next,
) -> Response {
	if let Some(ctx) = req.extensions().get::<RequestContext>() {
		if ctx.api_key().is_some() || matches!(ctx.token_type().as_deref(), Some("opds"))
		{
			let body = json!({
				"error": "forbidden",
				"message": "Secure library routes are not accessible via API key or OPDS token"
			});
			return Response::builder()
				.status(StatusCode::FORBIDDEN)
				.header("Content-Type", HeaderValue::from_static("application/json"))
				.body(Body::from(body.to_string()))
				.unwrap_or_else(|e| {
					(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
				});
		}
	}
	next.run(req).await
}
