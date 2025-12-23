//! Rate limiting middleware for authentication endpoints
//!
//! Prevents brute force attacks by limiting login attempts per username/IP combination.
//!
//! Configuration:
//! - 5 attempts per 15 minutes per username
//! - Uses in-memory storage (sufficient for MVP)
//! - Automatic cleanup of old entries
//!
//! For production scale, consider:
//! - Redis backend for distributed rate limiting
//! - Per-IP global limits
//! - Exponential backoff

use axum::{
	body::Body,
	extract::{ConnectInfo, Request, State},
	http::StatusCode,
	middleware::Next,
	response::{IntoResponse, Response},
	Json,
};
use serde::Serialize;
use std::{
	collections::HashMap,
	sync::Arc,
	time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::{config::state::AppState, http_server::StumpRequestInfo};

/// Rate limit configuration
const MAX_ATTEMPTS: usize = 5;
const WINDOW_DURATION: Duration = Duration::from_secs(15 * 60); // 15 minutes

/// Tracks login attempts for a specific identifier
#[derive(Debug, Clone)]
struct AttemptRecord {
	attempts: Vec<Instant>,
}

impl AttemptRecord {
	fn new() -> Self {
		Self {
			attempts: Vec::new(),
		}
	}

	/// Add a new attempt and clean up old ones
	fn record_attempt(&mut self, now: Instant) {
		// Remove attempts outside the window
		self.attempts
			.retain(|&attempt| now.duration_since(attempt) < WINDOW_DURATION);

		// Add new attempt
		self.attempts.push(now);
	}

	/// Check if rate limit is exceeded
	fn is_rate_limited(&self, now: Instant) -> bool {
		// Count attempts within the window
		let recent_attempts = self
			.attempts
			.iter()
			.filter(|&&attempt| now.duration_since(attempt) < WINDOW_DURATION)
			.count();

		recent_attempts >= MAX_ATTEMPTS
	}

	/// Get time until rate limit resets
	fn time_until_reset(&self, now: Instant) -> Option<Duration> {
		if self.attempts.is_empty() {
			return None;
		}

		// Find oldest attempt within window
		let oldest_in_window = self
			.attempts
			.iter()
			.filter(|&&attempt| now.duration_since(attempt) < WINDOW_DURATION)
			.min()?;

		let elapsed = now.duration_since(*oldest_in_window);
		Some(WINDOW_DURATION.saturating_sub(elapsed))
	}
}

/// In-memory rate limiter storage
#[derive(Clone)]
pub struct RateLimiter {
	store: Arc<RwLock<HashMap<String, AttemptRecord>>>,
}

impl RateLimiter {
	/// Create a new rate limiter
	pub fn new() -> Self {
		let limiter = Self {
			store: Arc::new(RwLock::new(HashMap::new())),
		};

		// Spawn background cleanup task
		let store_clone = Arc::clone(&limiter.store);
		tokio::spawn(async move {
			cleanup_task(store_clone).await;
		});

		limiter
	}

	/// Check if a request is rate limited
	pub async fn check_rate_limit(&self, identifier: &str) -> RateLimitResult {
		let now = Instant::now();
		let mut store = self.store.write().await;

		let record = store
			.entry(identifier.to_string())
			.or_insert_with(AttemptRecord::new);

		if record.is_rate_limited(now) {
			let retry_after = record.time_until_reset(now).unwrap_or(WINDOW_DURATION);

			RateLimitResult::Limited {
				retry_after_seconds: retry_after.as_secs(),
			}
		} else {
			record.record_attempt(now);
			RateLimitResult::Allowed
		}
	}

	/// Manually clear rate limit for a user (e.g., after successful login)
	pub async fn clear_rate_limit(&self, identifier: &str) {
		let mut store = self.store.write().await;
		store.remove(identifier);
	}
}

impl Default for RateLimiter {
	fn default() -> Self {
		Self::new()
	}
}

/// Result of rate limit check
pub enum RateLimitResult {
	Allowed,
	Limited { retry_after_seconds: u64 },
}

/// Background task to clean up old entries
async fn cleanup_task(store: Arc<RwLock<HashMap<String, AttemptRecord>>>) {
	let mut interval = tokio::time::interval(Duration::from_secs(5 * 60)); // Clean every 5 minutes

	loop {
		interval.tick().await;

		let now = Instant::now();
		let mut store = store.write().await;

		// Remove entries with no recent attempts
		store.retain(|_, record| {
			!record.attempts.is_empty()
				&& record
					.attempts
					.iter()
					.any(|&attempt| now.duration_since(attempt) < WINDOW_DURATION)
		});

		tracing::debug!(
			remaining_entries = store.len(),
			"Rate limiter cleanup completed"
		);
	}
}

#[derive(Serialize)]
struct RateLimitErrorResponse {
	error: String,
	message: String,
	retry_after_seconds: u64,
}

/// Extract username from login request body
#[allow(dead_code)]
async fn extract_username_from_body(_request: &Request<Body>) -> Option<String> {
	// For login requests, we need to peek at the body to get the username
	// This is a simplified approach - in production you might use a more robust method

	// Try to parse common login body formats
	// Note: This consumes the body, so we'd need to reconstruct it
	// For now, we'll use IP-based rate limiting as a simpler approach
	None
}

/// Rate limiting middleware for login endpoints
#[allow(dead_code)]
pub async fn login_rate_limit_middleware(
	State(_state): State<AppState>,
	ConnectInfo(request_info): ConnectInfo<StumpRequestInfo>,
	request: Request<Body>,
	next: Next,
) -> Response {
	// For simplicity, use IP address as the rate limit key
	// In production, you'd want to combine IP + username
	let _identifier = request_info.ip_addr.to_string();

	// Get or create rate limiter from app state
	// Note: Rate limiter should be stored in AppState
	// For this implementation, we'll use a simple in-memory approach

	// Check rate limit
	// This is a simplified version - the actual implementation should
	// integrate with AppState to access the shared RateLimiter

	// For now, pass through - the actual rate limiting will be
	// implemented at the handler level with username information
	next.run(request).await
}

/// Helper function to check rate limit with username and IP
pub async fn check_login_rate_limit(
	rate_limiter: &RateLimiter,
	username: &str,
	ip_addr: &str,
) -> Result<(), Response> {
	// Combine username and IP for rate limit key
	let identifier = format!("{}:{}", username, ip_addr);

	match rate_limiter.check_rate_limit(&identifier).await {
		RateLimitResult::Allowed => Ok(()),
		RateLimitResult::Limited {
			retry_after_seconds,
		} => {
			let error_response = RateLimitErrorResponse {
				error: "rate_limit_exceeded".to_string(),
				message: format!(
					"Too many login attempts. Please try again in {} seconds.",
					retry_after_seconds
				),
				retry_after_seconds,
			};

			let response = (
				StatusCode::TOO_MANY_REQUESTS,
				[("Retry-After", retry_after_seconds.to_string())],
				Json(error_response),
			)
				.into_response();

			Err(response)
		},
	}
}

/// Clear rate limit after successful login
pub async fn clear_login_rate_limit(
	rate_limiter: &RateLimiter,
	username: &str,
	ip_addr: &str,
) {
	let identifier = format!("{}:{}", username, ip_addr);
	rate_limiter.clear_rate_limit(&identifier).await;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn test_rate_limiter_basic() {
		let limiter = RateLimiter::new();
		let identifier = "test_user:127.0.0.1";

		// First 5 attempts should succeed
		for i in 0..5 {
			match limiter.check_rate_limit(identifier).await {
				RateLimitResult::Allowed => {},
				RateLimitResult::Limited { .. } => {
					panic!("Should not be rate limited on attempt {}", i + 1);
				},
			}
		}

		// 6th attempt should be rate limited
		match limiter.check_rate_limit(identifier).await {
			RateLimitResult::Allowed => {
				panic!("Should be rate limited after 5 attempts");
			},
			RateLimitResult::Limited {
				retry_after_seconds,
			} => {
				assert!(retry_after_seconds > 0);
			},
		}
	}

	#[tokio::test]
	async fn test_rate_limiter_clear() {
		let limiter = RateLimiter::new();
		let identifier = "test_user:127.0.0.1";

		// Make 5 attempts
		for _ in 0..5 {
			limiter.check_rate_limit(identifier).await;
		}

		// Should be rate limited
		assert!(matches!(
			limiter.check_rate_limit(identifier).await,
			RateLimitResult::Limited { .. }
		));

		// Clear the rate limit
		limiter.clear_rate_limit(identifier).await;

		// Should be allowed again
		assert!(matches!(
			limiter.check_rate_limit(identifier).await,
			RateLimitResult::Allowed
		));
	}

	#[tokio::test]
	async fn test_rate_limiter_different_users() {
		let limiter = RateLimiter::new();
		let user1 = "user1:127.0.0.1";
		let user2 = "user2:127.0.0.1";

		// Make 5 attempts for user1
		for _ in 0..5 {
			limiter.check_rate_limit(user1).await;
		}

		// user1 should be rate limited
		assert!(matches!(
			limiter.check_rate_limit(user1).await,
			RateLimitResult::Limited { .. }
		));

		// user2 should still be allowed
		assert!(matches!(
			limiter.check_rate_limit(user2).await,
			RateLimitResult::Allowed
		));
	}
}
