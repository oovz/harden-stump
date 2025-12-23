//! High-level cryptographic services
//!
//! This module provides service-layer abstractions for managing secure libraries,
//! user keypairs, access control, and audit logging.

pub mod access_control;
pub mod audit;
pub mod encryption_task;
pub mod key_management;
pub mod secure_library;
pub mod user_keypair;

pub use access_control::AccessControlService;
pub use audit::AuditService;
pub use key_management::KeyManagementService;
pub use secure_library::SecureLibraryService;
pub use user_keypair::UserKeypairService;
