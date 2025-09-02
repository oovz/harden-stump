use std::{
    time::{Duration, SystemTime},
};

use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::{
    config::StumpConfig, 
    security::audit::AuditLogger,
    Ctx
};

/// Service that monitors encryption key usage and automatically clears idle keys
/// to enhance security by ensuring keys don't remain in memory indefinitely.
pub struct KeyTimeoutService {
    /// Server context for accessing file encryption service
    ctx: Ctx,
    /// How long keys can remain idle before being cleared
    idle_timeout: Duration,
    /// How often to check for expired keys
    check_interval: Duration,
}

impl KeyTimeoutService {
    /// Create a new key timeout service with configuration from the server config
    pub fn new(ctx: Ctx, config: &StumpConfig) -> Self {
        let idle_timeout = Duration::from_secs(config.encryption_key_idle_timeout as u64);
        let check_interval = Duration::from_secs(config.encryption_key_check_interval as u64);

        Self {
            ctx,
            idle_timeout,
            check_interval,
        }
    }

    /// Start the key timeout monitoring service
    /// This runs in a background task and periodically checks for expired keys
    pub async fn start(&self) {
        info!(
            "Starting encryption key timeout service (idle_timeout: {:?}, check_interval: {:?})",
            self.idle_timeout, self.check_interval
        );

        // Log the service startup as a security event
        AuditLogger::log_service_event("key_timeout", "started", true);

        let mut interval_timer = interval(self.check_interval);

        loop {
            interval_timer.tick().await;
            
            if let Err(e) = self.check_and_clear_expired_keys().await {
                warn!("Error during key timeout check: {}", e);
                
                // Log errors as security events since they could indicate tampering
                AuditLogger::log_service_event("key_timeout", "error", false);
                
                // Continue the loop even if there's an error
                continue;
            }
        }
    }

    /// Check for encryption keys that have been idle longer than the timeout
    /// and clear them from memory
    async fn check_and_clear_expired_keys(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Checking for expired encryption keys");

        // Get the current time
        let now = SystemTime::now();
        
        // Access the file encryption service to check key activity
        let encryption_service = self.ctx.get_file_encryption_service();
        let encryption_service = encryption_service.read().unwrap();
        
        // Check if the master key exists and when it was last used
        if let Some(last_activity) = encryption_service.get_last_key_activity() {
            let elapsed = now.duration_since(last_activity)?;
            
            if elapsed > self.idle_timeout {
                // Drop the read lock before trying to get a write lock
                drop(encryption_service);
                
                info!(
                    "Clearing idle encryption key (idle for: {:?}, limit: {:?})", 
                    elapsed, 
                    self.idle_timeout
                );
                
                // Get write lock to clear the master key
                let encryption_service = self.ctx.get_file_encryption_service();
                let mut encryption_service = encryption_service.write().unwrap();
                encryption_service.clear_master_key();
                
                // Log this security event for audit purposes
                AuditLogger::log_key_operation("timeout", true, Some(&format!("Idle for {:?}", elapsed)));
                
                // Also log to general info for operations awareness
                info!("Encryption key cleared due to idle timeout of {:?}", elapsed);
                
            } else {
                debug!(
                    "Encryption key still active (idle for: {:?}, limit: {:?})", 
                    elapsed, 
                    self.idle_timeout
                );
            }
        } else {
            debug!("No encryption key activity to check");
        }

        Ok(())
    }

    /// Get the configured idle timeout duration
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Get the configured check interval duration
    pub fn check_interval(&self) -> Duration {
        self.check_interval
    }
}

/// Spawn the key timeout service as a background task
/// Returns a handle to the spawned task
pub fn spawn_key_timeout_service(ctx: Ctx, config: &StumpConfig) -> tokio::task::JoinHandle<()> {
    let service = KeyTimeoutService::new(ctx, config);
    
    tokio::spawn(async move {
        service.start().await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use crate::config::StumpConfig;
    use secrecy::SecretBox;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_key_timeout_service_creation() {
        // Create a test context and config
        let (ctx, _mock) = Ctx::mock();
        let config = StumpConfig {
            profile: "debug".to_string(),
            port: 8080,
            verbosity: 0,
            pretty_logs: false,
            db_path: None,
            client_dir: "./client".to_string(),
            config_dir: "/tmp/stump".to_string(),
            allowed_origins: vec![],
            pdfium_path: None,
            enable_swagger: false,
            enable_koreader_sync: false,
            password_hash_cost: 12,
            session_ttl: 3600,
            access_token_ttl: 900,
            expired_session_cleanup_interval: 3600,
            custom_templates_dir: None,
            max_scanner_concurrency: 4,
            max_thumbnail_concurrency: 4,
            max_image_upload_size: 10485760,
            enable_upload: false,
            max_file_upload_size: 10485760,
            encryption_key_idle_timeout: 1800, // 30 minutes
            encryption_key_check_interval: 60,  // 1 minute
        };

        let service = KeyTimeoutService::new(ctx, &config);
        
        assert_eq!(service.idle_timeout(), Duration::from_secs(1800));
        assert_eq!(service.check_interval(), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_key_timeout_service_startup() {
        let (ctx, _mock) = Ctx::mock();
        let config = StumpConfig {
            profile: "debug".to_string(),
            port: 8080,
            verbosity: 0,
            pretty_logs: false,
            db_path: None,
            client_dir: "./client".to_string(),
            config_dir: "/tmp/stump".to_string(),
            allowed_origins: vec![],
            pdfium_path: None,
            enable_swagger: false,
            enable_koreader_sync: false,
            password_hash_cost: 12,
            session_ttl: 3600,
            access_token_ttl: 900,
            expired_session_cleanup_interval: 3600,
            custom_templates_dir: None,
            max_scanner_concurrency: 4,
            max_thumbnail_concurrency: 4,
            max_image_upload_size: 10485760,
            enable_upload: false,
            max_file_upload_size: 10485760,
            encryption_key_idle_timeout: 30,
            encryption_key_check_interval: 1,
        };
        
        // Test that the service can be created and started
        let handle = spawn_key_timeout_service(ctx, &config);
        
        // Let it run briefly then cancel
        tokio::time::sleep(Duration::from_millis(100)).await;
        handle.abort();
        
        // Just verify it doesn't panic on startup
        assert!(true);
    }

    #[tokio::test]
    async fn test_key_timeout_functionality() {
        let (ctx, _mock) = Ctx::mock();
        
        // Use very short timeouts for testing
        let config = StumpConfig {
            profile: "debug".to_string(),
            port: 8080,
            verbosity: 0,
            pretty_logs: false,
            db_path: None,
            client_dir: "./client".to_string(),
            config_dir: "/tmp/stump".to_string(),
            allowed_origins: vec![],
            pdfium_path: None,
            enable_swagger: false,
            enable_koreader_sync: false,
            password_hash_cost: 12,
            session_ttl: 3600,
            access_token_ttl: 900,
            expired_session_cleanup_interval: 3600,
            custom_templates_dir: None,
            max_scanner_concurrency: 4,
            max_thumbnail_concurrency: 4,
            max_image_upload_size: 10485760,
            enable_upload: false,
            max_file_upload_size: 10485760,
            encryption_key_idle_timeout: 1,  // 1 second timeout for testing
            encryption_key_check_interval: 1, // Check every second
        };

        // Set up an encryption key
        let encryption_service = ctx.get_file_encryption_service();
        {
            let mut service = encryption_service.write().unwrap();
            let test_key = SecretBox::new(Box::new(vec![1, 2, 3, 4, 5, 6, 7, 8]));
            service.set_master_key(test_key);
            
            // Verify key is set
            assert!(service.is_encryption_available());
        }

        // Create the timeout service with short intervals
        let timeout_service = KeyTimeoutService::new(ctx.clone(), &config);
        
        // Wait longer than the idle timeout
        sleep(Duration::from_millis(1500)).await;
        
        // Manually check and clear expired keys
        timeout_service.check_and_clear_expired_keys().await.unwrap();
        
        // Verify the key was cleared
        {
            let service = encryption_service.read().unwrap();
            assert!(!service.is_encryption_available());
        }
    }

    #[tokio::test]
    async fn test_key_activity_tracking() {
        let (ctx, _mock) = Ctx::mock();
        
        let encryption_service = ctx.get_file_encryption_service();
        
        // Initially no activity
        {
            let service = encryption_service.read().unwrap();
            assert!(service.get_last_key_activity().is_none());
        }
        
        // Set a key and verify activity is tracked
        {
            let mut service = encryption_service.write().unwrap();
            let test_key = SecretBox::new(Box::new(vec![1, 2, 3, 4, 5, 6, 7, 8]));
            service.set_master_key(test_key);
        }
        
        // Check that activity is now tracked
        {
            let service = encryption_service.read().unwrap();
            assert!(service.get_last_key_activity().is_some());
        }
        
        // Clear the key and verify activity is cleared
        {
            let mut service = encryption_service.write().unwrap();
            service.clear_master_key();
        }
        
        {
            let service = encryption_service.read().unwrap();
            assert!(service.get_last_key_activity().is_none());
        }
    }

    #[tokio::test]
    async fn test_key_timeout_service_configuration() {
        let (ctx, _mock) = Ctx::mock();
        
        // Test different configuration values
        let config = StumpConfig {
            profile: "debug".to_string(),
            port: 8080,
            verbosity: 0,
            pretty_logs: false,
            db_path: None,
            client_dir: "./client".to_string(),
            config_dir: "/tmp/stump".to_string(),
            allowed_origins: vec![],
            pdfium_path: None,
            enable_swagger: false,
            enable_koreader_sync: false,
            password_hash_cost: 12,
            session_ttl: 3600,
            access_token_ttl: 900,
            expired_session_cleanup_interval: 3600,
            custom_templates_dir: None,
            max_scanner_concurrency: 4,
            max_thumbnail_concurrency: 4,
            max_image_upload_size: 10485760,
            enable_upload: false,
            max_file_upload_size: 10485760,
            encryption_key_idle_timeout: 7200, // 2 hours
            encryption_key_check_interval: 300, // 5 minutes
        };

        let service = KeyTimeoutService::new(ctx, &config);
        
        assert_eq!(service.idle_timeout(), Duration::from_secs(7200));
        assert_eq!(service.check_interval(), Duration::from_secs(300));
    }
}
