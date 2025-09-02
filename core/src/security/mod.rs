//! Security module for comprehensive audit logging and security event management
//! 
//! This module provides structured audit logging for all security-related operations
//! including authentication, encryption, file operations, and system events.

pub mod audit;

#[cfg(test)]
mod tests;

pub use audit::{
    AuditEvent, AuditEventType, AuditLogger, AuditSeverity, AuditStatus,
};
