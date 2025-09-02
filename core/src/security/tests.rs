use crate::security::audit::{AuditEvent, AuditEventType, AuditLogger, AuditSeverity};

#[tokio::test]
async fn test_comprehensive_audit_logging() {
    // Initialize test logging
    let _ = tracing_subscriber::fmt::try_init();

    // Test authentication audit logging
    AuditLogger::log_auth_attempt("test_user", Some("127.0.0.1"), true);
    AuditLogger::log_auth_attempt("bad_user", None, false);

    // Test server operation audit logging
    AuditLogger::log_server_operation("unlock", Some("admin"), true);
    AuditLogger::log_server_operation("lock", None, false);

    // Test key management audit logging
    AuditLogger::log_key_operation("generated", true, Some("Initial setup"));
    AuditLogger::log_key_operation("timeout", true, Some("Idle for 30 minutes"));

    // Test file operation audit logging
    AuditLogger::log_file_operation("encrypt", "/test/file.txt", true, None);
    AuditLogger::log_file_operation("decrypt", "/test/file.txt", false, Some("Invalid key"));

    // Test service event audit logging
    AuditLogger::log_service_event("key_timeout", "started", true);
    AuditLogger::log_service_event("encryption", "error", false);

    // Test security violation audit logging
    AuditLogger::log_security_violation(
        "unauthorized_access",
        "Attempt to access encrypted files without proper authorization",
        Some("anonymous"),
        Some("192.168.1.100"),
    );

    // Test manual audit event creation
    let event = AuditEvent::new(
        AuditEventType::ConfigurationChanged,
        AuditSeverity::Info,
        "Security configuration updated".to_string(),
    )
    .with_actor("admin".to_string())
    .with_metadata("section".to_string(), "encryption".to_string());

    event.log();

    println!("✅ All audit logging tests completed successfully");
}

#[test]
fn test_audit_event_serialization() {
    let event = AuditEvent::new(
        AuditEventType::FileEncrypted,
        AuditSeverity::Info,
        "Test file encrypted".to_string(),
    )
    .with_file_path("/test/path.txt".to_string())
    .with_metadata("size".to_string(), "1024".to_string());

    // Test JSON serialization
    let json = serde_json::to_string(&event).expect("Should serialize to JSON");
    let deserialized: AuditEvent = serde_json::from_str(&json).expect("Should deserialize from JSON");

    assert_eq!(event.description, deserialized.description);
    assert_eq!(event.file_path, deserialized.file_path);
    assert_eq!(event.metadata.get("size"), deserialized.metadata.get("size"));

    println!("✅ Audit event serialization test completed successfully");
}

#[test]
fn test_audit_macros() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test audit macros
    crate::audit_info!(
        AuditEventType::ServiceStarted,
        "Test service started successfully",
        "service" => "test_service",
        "version" => "1.0.0"
    );

    crate::audit_warn!(
        AuditEventType::SecurityViolation,
        "Security warning detected",
        "threat_level" => "medium"
    );

    crate::audit_error!(
        AuditEventType::ServiceError,
        "Service encountered an error",
        "error_code" => "500",
        "component" => "encryption_service"
    );

    println!("✅ Audit macro tests completed successfully");
}
