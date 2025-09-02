// TODO: remove pubs, expose only what is needed

pub mod archive;
mod common;
mod content_type;
pub mod decryption_cache;
#[cfg(test)]
mod decryption_integration_tests;
pub mod decryption_middleware;
mod directory_listing;
pub mod encrypted_file;
pub(crate) mod error;
pub mod file_migration_job;
mod hash;
pub mod image;
pub mod key_timeout_service;
pub mod media;
pub mod scanner;

pub use common::*;
pub use content_type::ContentType;
pub use decryption_cache::{
	get_file_mtime, CacheKey, CacheStats, DecryptionCache, DecryptionCacheConfig,
};
pub use decryption_middleware::DecryptionMiddleware;
pub use directory_listing::{
	DirectoryListing, DirectoryListingFile, DirectoryListingIgnoreParams,
	DirectoryListingInput,
};
pub use encrypted_file::FileEncryptionService;
pub use error::FileError;
pub use file_migration_job::{FileMigrationJob, FileMigrationOutput};
pub use key_timeout_service::{spawn_key_timeout_service, KeyTimeoutService};
pub use media::*;
