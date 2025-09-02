//! Backup system for creating encrypted backups of comics, metadata, and database content
//! 
//! This module provides comprehensive backup capabilities including:
//! - Full and incremental backups
//! - Encrypted backup storage with separate key management
//! - Backup verification and integrity checking
//! - Backup restoration and recovery
//! - Automated backup scheduling and retention policies

pub mod encryption;
pub mod manifest;
pub mod service;
pub mod restore;

pub use encryption::BackupEncryption;
pub use manifest::{BackupManifest, BackupType, ManifestEntry};
pub use service::{BackupService, BackupConfig, BackupRequest, BackupScheduleConfig};
pub use restore::{RestoreJob, RestoreRequest, RestoreTask};
