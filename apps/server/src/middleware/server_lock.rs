use axum::{
	extract::{Request, State},
	middleware::Next,
	response::Response,
};

use crate::{config::state::AppState, errors::APIError};

/// Middleware to enforce server lock state
pub async fn server_lock_middleware(
	State(ctx): State<AppState>,
	request: Request,
	next: Next,
) -> Result<Response, APIError> {
	let path = request.uri().path();

	// Allow certain routes when server is locked
	let allowed_when_locked = [
		"/api/v1/ping",
		"/api/v1/version", 
		"/api/v1/claim",
		"/api/v1/check-for-update",
		"/api/v1/server/unlock",
	];

	// Allow all static assets and SPA routes when locked (for unlock UI)
	let is_static_or_spa = path.starts_with("/assets/") 
		|| path.starts_with("/static/")
		|| path == "/"
		|| !path.starts_with("/api/");

	// Check if server is locked and path is not allowed
	if !ctx.is_server_unlocked() 
		&& !allowed_when_locked.iter().any(|&allowed| path.starts_with(allowed)) 
		&& !is_static_or_spa 
	{
		return Err(APIError::ServiceUnavailable(
			"Server is locked. Please unlock the server first.".to_string(),
		));
	}

	Ok(next.run(request).await)
}
