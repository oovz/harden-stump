use std::str::FromStr;

use axum::http::{
	header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
	HeaderName, HeaderValue, Method,
};
use local_ip_address::local_ip;
use stump_core::config::StumpConfig;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::middleware::auth::STUMP_SAVE_BASIC_SESSION_HEADER;

const DEFAULT_ALLOWED_ORIGINS: &[&str] = &[
	"tauri://localhost",
	"https://tauri.localhost",
	"http://tauri.localhost",
];
const DEBUG_ALLOWED_ORIGINS: &[&str] = &[
	"tauri://localhost",
	"https://tauri.localhost",
	"http://tauri.localhost",
	"http://localhost:3000",
	"http://127.0.0.1:3000",
	"https://127.0.0.1:3000",
	"http://0.0.0.0:3000",
];

fn merge_origins(origins: &[&str], local_origins: Vec<String>) -> Vec<HeaderValue> {
	origins
		.iter()
		.map(|origin| origin.to_string())
		.chain(local_origins)
		.map(|origin| origin.parse())
		.filter_map(Result::ok)
		.collect::<Vec<HeaderValue>>()
}

pub fn get_cors_layer(config: StumpConfig) -> CorsLayer {
	let is_debug = config.is_debug();

	// Create CORS layer
	let mut cors_layer = CorsLayer::new();
	cors_layer = cors_layer
		.allow_methods([
			Method::GET,
			Method::PUT,
			Method::POST,
			Method::PATCH,
			Method::DELETE,
			Method::OPTIONS,
			Method::CONNECT,
		])
		// TODO: support custom header configurations
		.allow_headers([
			ACCEPT,
			AUTHORIZATION,
			CONTENT_TYPE,
			HeaderName::from_str(STUMP_SAVE_BASIC_SESSION_HEADER)
				.expect("Failed to parse header name"),
			HeaderName::from_str("X-SMK").expect("Failed to parse header name"),
			HeaderName::from_str("X-LMK").expect("Failed to parse header name"),
		])
		// Expose crypto headers required by the web client for client-side decryption
		.expose_headers([
			HeaderName::from_str("X-Nonce").expect("Failed to parse header name"),
			HeaderName::from_str("X-Tag").expect("Failed to parse header name"),
			HeaderName::from_str("X-Plaintext-Size")
				.expect("Failed to parse header name"),
			HeaderName::from_str("X-Original-Size").expect("Failed to parse header name"),
		])
		.allow_credentials(true);

	// If allowed origins include the general wildcard ("*") then we can return a permissive CORS layer and exit early.
	if config.allowed_origins.contains(&"*".to_string()) {
		cors_layer = cors_layer.allow_origin(AllowOrigin::any());

		#[cfg(debug_assertions)]
		tracing::trace!(
			?cors_layer,
			"Cors configuration completed (allowing any origin)"
		);

		return cors_layer;
	}

	// Convert allowed origins from config into `HeaderValue`s for CORS layer.
	let allowed_origins: Vec<_> = config
		.allowed_origins
		.into_iter()
		.filter_map(|origin| match origin.parse::<HeaderValue>() {
			Ok(val) => Some(val),
			Err(e) => {
				tracing::error!("Failed to parse allowed origin: {origin:?}: {e}");
				None
			},
		})
		.collect();

	let local_ip = local_ip()
		.map_err(|e| {
			tracing::error!("Failed to get local ip: {:?}", e);
			e
		})
		.map(|ip| ip.to_string())
		.unwrap_or_default();

	// Format the local IP with both http and https, and the port. If is_debug is true,
	// then also add port 3000.
	let local_origins = if local_ip.is_empty() {
		vec![]
	} else {
		let port = config.port;
		let mut base = vec![
			format!("http://{local_ip}:{port}"),
			format!("https://{local_ip}:{port}"),
		];

		if is_debug {
			base.append(&mut vec![
				format!("http://{local_ip}:3000"),
				format!("https://{local_ip}:3000"),
			]);
		}

		base
	};

	let defaults = if is_debug {
		DEBUG_ALLOWED_ORIGINS
	} else {
		DEFAULT_ALLOWED_ORIGINS
	};
	let default_allowlist = merge_origins(defaults, local_origins);

	// TODO: add new config option for fully overriding the default allowlist versus appending to it
	cors_layer = cors_layer.allow_origin(AllowOrigin::list(
		default_allowlist
			.into_iter()
			.chain(allowed_origins)
			.collect::<Vec<HeaderValue>>(),
	));

	#[cfg(debug_assertions)]
	tracing::trace!(?cors_layer, "Cors configuration complete");

	cors_layer
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::{routing::get, Router};
	use axum_test::TestServer;
	use stump_core::config::StumpConfig;

	#[tokio::test]
	async fn cors_exposes_crypto_headers() {
		let config = StumpConfig::debug();
		let cors_layer = get_cors_layer(config);

		let app = Router::new()
			.route("/test", get(|| async { "ok" }))
			.layer(cors_layer);

		let server = TestServer::new(app).expect("failed to create test server");

		let response = server
			.get("/test")
			.add_header(
				HeaderName::from_static("origin"),
				HeaderValue::from_static("http://localhost:3000"),
			)
			.await;

		let expose = response
			.headers()
			.get(HeaderName::from_static("access-control-expose-headers"))
			.expect("missing Access-Control-Expose-Headers")
			.to_str()
			.expect("invalid Access-Control-Expose-Headers value");
		let expose_lower = expose.to_ascii_lowercase();

		for header in ["x-nonce", "x-tag", "x-plaintext-size"] {
			assert!(
				expose_lower.contains(header),
				"Access-Control-Expose-Headers should contain {header}, got: {expose}",
			);
		}
	}

	#[tokio::test]
	async fn cors_allows_x_lmk_request_header() {
		let config = StumpConfig::debug();
		let cors_layer = get_cors_layer(config);

		let app = Router::new()
			.route("/test", get(|| async { "ok" }))
			.layer(cors_layer);

		let server = TestServer::new(app).expect("failed to create test server");

		let response = server
			.method(Method::OPTIONS, "/test")
			.add_header(
				HeaderName::from_static("origin"),
				HeaderValue::from_static("http://localhost:3000"),
			)
			.add_header(
				HeaderName::from_static("access-control-request-method"),
				HeaderValue::from_static("DELETE"),
			)
			.add_header(
				HeaderName::from_static("access-control-request-headers"),
				HeaderValue::from_static("x-lmk"),
			)
			.await;

		let allow_headers = response
			.headers()
			.get(HeaderName::from_static("access-control-allow-headers"))
			.expect("missing Access-Control-Allow-Headers")
			.to_str()
			.expect("invalid Access-Control-Allow-Headers value");

		assert!(
			allow_headers.to_ascii_lowercase().contains("x-lmk"),
			"Access-Control-Allow-Headers should contain x-lmk, got: {allow_headers}",
		);
	}
}
