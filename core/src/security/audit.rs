use std::time::SystemTime;
use serde::{Deserialize, Serialize};

/// Security audit event types for comprehensive logging of encryption operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    // Authentication and Authorization
    AuthenticationAttempt,
    AuthenticationSuccess, 
    AuthenticationFailure,
    AuthorizationSuccess,
    AuthorizationFailure,
    
    // Server Management
    ServerUnlock,
    ServerLock,
    ServerStatusCheck,
    
    // Key Management
    EncryptionKeyGenerated,
    EncryptionKeyLoaded,
    EncryptionKeyCleared,
    EncryptionKeyTimeout,
    
    // File Operations
    FileEncrypted,
    FileDecrypted,
    FileEncryptionFailure,
    FileDecryptionFailure,
    FileMigrationStarted,
    FileMigrationCompleted,
    FileMigrationFailure,
    
    // Backup Operations
    BackupOperationSuccess,
    BackupOperationFailure,
    
    // Database Operations
    DatabaseEncrypted,
    DatabaseDecrypted,
    DatabaseMigrationStarted,
    DatabaseMigrationCompleted,
    DatabaseMigrationFailure,
    
    // Configuration Changes
    ConfigurationChanged,
    SecuritySettingsChanged,
    
    // Security Events
    SecurityViolation,
    UnauthorizedAccess,
    SuspiciousActivity,
    
    // System Events
    ServiceStarted,
    ServiceStopped,
    ServiceError,
}

/// Audit event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Comprehensive audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Timestamp when the event occurred
    pub timestamp: SystemTime,
    /// Type of audit event
    pub event_type: AuditEventType,
    /// Severity level
    pub severity: AuditSeverity,
    /// Unique event identifier
    pub event_id: String,
    /// User or system that triggered the event
    pub actor: Option<String>,
    /// IP address if applicable
    pub ip_address: Option<String>,
    /// File path for file operations
    pub file_path: Option<String>,
    /// Operation status (success/failure)
    pub status: AuditStatus,
    /// Human-readable description
    pub description: String,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
    /// Error message if applicable
    pub error: Option<String>,
}

/// Audit event status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditStatus {
    Success,
    Failure,
    InProgress,
    Cancelled,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(
        event_type: AuditEventType,
        severity: AuditSeverity,
        description: String,
    ) -> Self {
        Self {
            timestamp: SystemTime::now(),
            event_type,
            severity,
            event_id: uuid::Uuid::new_v4().to_string(),
            actor: None,
            ip_address: None,
            file_path: None,
            status: AuditStatus::Success,
            description,
            metadata: std::collections::HashMap::new(),
            error: None,
        }
    }

    /// Add actor information
    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Add IP address
    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Add file path
    pub fn with_file_path(mut self, path: String) -> Self {
        self.file_path = Some(path);
        self
    }

    /// Set status
    pub fn with_status(mut self, status: AuditStatus) -> Self {
        self.status = status;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Add error information
    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self.status = AuditStatus::Failure;
        self
    }

    /// Log the audit event using tracing
    pub fn log(&self) {
        match self.severity {
            AuditSeverity::Info => {
                tracing::info!(
                    target: "stump::security::audit",
                    event_id = %self.event_id,
                    event_type = ?self.event_type,
                    severity = ?self.severity,
                    timestamp = ?self.timestamp,
                    actor = ?self.actor,
                    ip_address = ?self.ip_address,
                    file_path = ?self.file_path,
                    status = ?self.status,
                    error = ?self.error,
                    metadata = ?self.metadata,
                    "{}",
                    self.description
                );
            },
            AuditSeverity::Warning => {
                tracing::warn!(
                    target: "stump::security::audit",
                    event_id = %self.event_id,
                    event_type = ?self.event_type,
                    severity = ?self.severity,
                    timestamp = ?self.timestamp,
                    actor = ?self.actor,
                    ip_address = ?self.ip_address,
                    file_path = ?self.file_path,
                    status = ?self.status,
                    error = ?self.error,
                    metadata = ?self.metadata,
                    "{}",
                    self.description
                );
            },
            AuditSeverity::Error | AuditSeverity::Critical => {
                tracing::error!(
                    target: "stump::security::audit",
                    event_id = %self.event_id,
                    event_type = ?self.event_type,
                    severity = ?self.severity,
                    timestamp = ?self.timestamp,
                    actor = ?self.actor,
                    ip_address = ?self.ip_address,
                    file_path = ?self.file_path,
                    status = ?self.status,
                    error = ?self.error,
                    metadata = ?self.metadata,
                    "{}",
                    self.description
                );
            },
        }
    }
}

/// Audit logger for security events
pub struct AuditLogger;

impl AuditLogger {
    /// Log authentication attempt
    pub fn log_auth_attempt(username: &str, ip: Option<&str>, success: bool) {
        let event = if success {
            AuditEvent::new(
                AuditEventType::AuthenticationSuccess,
                AuditSeverity::Info,
                format!("User '{}' authenticated successfully", username),
            )
        } else {
            AuditEvent::new(
                AuditEventType::AuthenticationFailure,
                AuditSeverity::Warning,
                format!("Authentication failed for user '{}'", username),
            )
        };

        let event = event.with_actor(username.to_string());
        let event = if let Some(ip) = ip {
            event.with_ip(ip.to_string())
        } else {
            event
        };

        event.log();
    }

    /// Log server unlock/lock events
    pub fn log_server_operation(operation: &str, actor: Option<&str>, success: bool) {
        let (event_type, severity, description) = match (operation, success) {
            ("unlock", true) => (
                AuditEventType::ServerUnlock,
                AuditSeverity::Info,
                "Server unlocked successfully".to_string(),
            ),
            ("unlock", false) => (
                AuditEventType::ServerUnlock,
                AuditSeverity::Warning,
                "Server unlock failed".to_string(),
            ),
            ("lock", true) => (
                AuditEventType::ServerLock,
                AuditSeverity::Info,
                "Server locked successfully".to_string(),
            ),
            ("lock", false) => (
                AuditEventType::ServerLock,
                AuditSeverity::Warning,
                "Server lock failed".to_string(),
            ),
            _ => (
                AuditEventType::ServerStatusCheck,
                AuditSeverity::Info,
                format!("Server operation: {}", operation),
            ),
        };

        let mut event = AuditEvent::new(event_type, severity, description);
        if let Some(actor) = actor {
            event = event.with_actor(actor.to_string());
        }
        if !success {
            event = event.with_status(AuditStatus::Failure);
        }

        event.log();
    }

    /// Log key management events
    pub fn log_key_operation(operation: &str, success: bool, additional_info: Option<&str>) {
        let (event_type, severity, description) = match (operation, success) {
            ("generated", true) => (
                AuditEventType::EncryptionKeyGenerated,
                AuditSeverity::Info,
                "New encryption key generated".to_string(),
            ),
            ("loaded", true) => (
                AuditEventType::EncryptionKeyLoaded,
                AuditSeverity::Info,
                "Encryption key loaded into memory".to_string(),
            ),
            ("cleared", true) => (
                AuditEventType::EncryptionKeyCleared,
                AuditSeverity::Info,
                "Encryption key cleared from memory".to_string(),
            ),
            ("timeout", true) => (
                AuditEventType::EncryptionKeyTimeout,
                AuditSeverity::Warning,
                "Encryption key cleared due to timeout".to_string(),
            ),
            _ => (
                AuditEventType::EncryptionKeyCleared,
                AuditSeverity::Error,
                format!("Key operation '{}' failed", operation),
            ),
        };

        let mut event = AuditEvent::new(event_type, severity, description);
        if !success {
            event = event.with_status(AuditStatus::Failure);
        }
        if let Some(info) = additional_info {
            event = event.with_metadata("details".to_string(), info.to_string());
        }

        event.log();
    }

    /// Log file encryption/decryption events
    pub fn log_file_operation(
        operation: &str,
        file_path: &str,
        success: bool,
        error: Option<&str>,
    ) {
        let (event_type, severity, description) = match (operation, success) {
            ("encrypt", true) => (
                AuditEventType::FileEncrypted,
                AuditSeverity::Info,
                format!("File encrypted successfully: {}", file_path),
            ),
            ("encrypt", false) => (
                AuditEventType::FileEncryptionFailure,
                AuditSeverity::Error,
                format!("File encryption failed: {}", file_path),
            ),
            ("decrypt", true) => (
                AuditEventType::FileDecrypted,
                AuditSeverity::Info,
                format!("File decrypted successfully: {}", file_path),
            ),
            ("decrypt", false) => (
                AuditEventType::FileDecryptionFailure,
                AuditSeverity::Error,
                format!("File decryption failed: {}", file_path),
            ),
            _ => (
                AuditEventType::FileEncryptionFailure,
                AuditSeverity::Error,
                format!("Unknown file operation '{}' on: {}", operation, file_path),
            ),
        };

        let mut event = AuditEvent::new(event_type, severity, description)
            .with_file_path(file_path.to_string());

        if !success {
            event = event.with_status(AuditStatus::Failure);
        }
        if let Some(error) = error {
            event = event.with_error(error.to_string());
        }

        event.log();
    }

    /// Log service lifecycle events
    pub fn log_service_event(service: &str, operation: &str, success: bool) {
        let (event_type, severity, description) = match (operation, success) {
            ("started", true) => (
                AuditEventType::ServiceStarted,
                AuditSeverity::Info,
                format!("{} service started successfully", service),
            ),
            ("stopped", true) => (
                AuditEventType::ServiceStopped,
                AuditSeverity::Info,
                format!("{} service stopped successfully", service),
            ),
            ("error", false) => (
                AuditEventType::ServiceError,
                AuditSeverity::Error,
                format!("{} service encountered an error", service),
            ),
            _ => (
                AuditEventType::ServiceError,
                AuditSeverity::Warning,
                format!("{} service operation: {}", service, operation),
            ),
        };

        let mut event = AuditEvent::new(event_type, severity, description)
            .with_metadata("service".to_string(), service.to_string());

        if !success {
            event = event.with_status(AuditStatus::Failure);
        }

        event.log();
    }

    /// Log security violations
    pub fn log_security_violation(
        violation_type: &str,
        description: &str,
        actor: Option<&str>,
        ip: Option<&str>,
    ) {
        let mut event = AuditEvent::new(
            AuditEventType::SecurityViolation,
            AuditSeverity::Critical,
            format!("Security violation - {}: {}", violation_type, description),
        )
        .with_metadata("violation_type".to_string(), violation_type.to_string());

        if let Some(actor) = actor {
            event = event.with_actor(actor.to_string());
        }
        if let Some(ip) = ip {
            event = event.with_ip(ip.to_string());
        }

        event.log();
    }

    /// Log backup operations
    pub fn log_backup_operation(operation: &str, backup_id: &str, success: bool, details: Option<&str>) {
        let event_type = if success {
            AuditEventType::BackupOperationSuccess
        } else {
            AuditEventType::BackupOperationFailure
        };

        let description = match details {
            Some(detail) => format!("Backup operation '{}' for backup '{}': {}", operation, backup_id, detail),
            None => format!("Backup operation '{}' for backup '{}'", operation, backup_id),
        };

        let mut event = AuditEvent::new(
            event_type,
            if success { AuditSeverity::Info } else { AuditSeverity::Warning },
            description,
        );

        event.metadata.insert("operation".to_string(), operation.to_string());
        event.metadata.insert("backup_id".to_string(), backup_id.to_string());
        if let Some(detail) = details {
            event.metadata.insert("details".to_string(), detail.to_string());
        }

        event.log();
    }
}

/// Convenience macros for audit logging
#[macro_export]
macro_rules! audit_info {
    ($event_type:expr, $description:literal $(, $key:expr => $value:expr)*) => {
        {
            let mut event = crate::security::audit::AuditEvent::new(
                $event_type,
                crate::security::audit::AuditSeverity::Info,
                $description.to_string(),
            );
            $(
                event = event.with_metadata($key.to_string(), $value.to_string());
            )*
            event.log();
        }
    };
}

#[macro_export]
macro_rules! audit_warn {
    ($event_type:expr, $description:literal $(, $key:expr => $value:expr)*) => {
        {
            let mut event = crate::security::audit::AuditEvent::new(
                $event_type,
                crate::security::audit::AuditSeverity::Warning,
                $description.to_string(),
            );
            $(
                event = event.with_metadata($key.to_string(), $value.to_string());
            )*
            event.log();
        }
    };
}

#[macro_export]
macro_rules! audit_error {
    ($event_type:expr, $description:literal $(, $key:expr => $value:expr)*) => {
        {
            let mut event = crate::security::audit::AuditEvent::new(
                $event_type,
                crate::security::audit::AuditSeverity::Error,
                $description.to_string(),
            );
            $(
                event = event.with_metadata($key.to_string(), $value.to_string());
            )*
            event.log();
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            AuditEventType::AuthenticationSuccess,
            AuditSeverity::Info,
            "Test authentication".to_string(),
        )
        .with_actor("test_user".to_string())
        .with_ip("127.0.0.1".to_string());

        assert_eq!(event.actor, Some("test_user".to_string()));
        assert_eq!(event.ip_address, Some("127.0.0.1".to_string()));
        assert_eq!(event.description, "Test authentication");
    }

    #[test]
    fn test_audit_logger_auth() {
        // This test just ensures the logging doesn't panic
        AuditLogger::log_auth_attempt("test_user", Some("127.0.0.1"), true);
        AuditLogger::log_auth_attempt("bad_user", None, false);
    }

    #[test]
    fn test_audit_logger_server_ops() {
        AuditLogger::log_server_operation("unlock", Some("admin"), true);
        AuditLogger::log_server_operation("lock", None, false);
    }

    #[test]
    fn test_audit_logger_key_ops() {
        AuditLogger::log_key_operation("generated", true, Some("Initial setup"));
        AuditLogger::log_key_operation("cleared", true, None);
    }

    #[test]
    fn test_audit_logger_file_ops() {
        AuditLogger::log_file_operation("encrypt", "/test/file.txt", true, None);
        AuditLogger::log_file_operation("decrypt", "/test/file.txt", false, Some("Invalid key"));
    }
}
