use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use crate::middleware::rate_limit::RateLimiter;
use stump_core::Ctx;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Application state that wraps the core Ctx with additional server-specific state
#[derive(Clone)]
pub struct AppState {
	pub ctx: Arc<Ctx>,
	pub rate_limiter: RateLimiter,
	secure_library_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl AppState {
	/// Create a new AppState from a Ctx
	pub fn new(ctx: Arc<Ctx>) -> Self {
		Self {
			ctx,
			rate_limiter: RateLimiter::new(),
			secure_library_locks: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	pub async fn lock_secure_library(&self, library_id: &str) -> OwnedMutexGuard<()> {
		let lock = {
			let mut locks = self.secure_library_locks.lock().await;
			locks
				.entry(library_id.to_string())
				.or_insert_with(|| Arc::new(Mutex::new(())))
				.clone()
		};
		lock.lock_owned().await
	}
}

// Implement Deref to allow transparent access to Ctx fields
// This maintains backward compatibility with existing code
impl Deref for AppState {
	type Target = Ctx;

	fn deref(&self) -> &Self::Target {
		&self.ctx
	}
}
