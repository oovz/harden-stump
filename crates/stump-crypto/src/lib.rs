//! Stump Crypto Library
//!
//! This crate provides cryptographic utilities for the Stump comic server,
//! including master key derivation, file encryption/decryption, and secure
//! storage of encrypted comic archives.

pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod key;

pub use decrypt::{decrypt_comic_archive, decrypt_comic_page, DecryptionParams};
pub use encrypt::{encrypt_comic_archive, EncryptionParams};
pub use error::{CryptoError, CryptoResult};
pub use key::{derive_master_key, KeyDerivationParams, MasterKey};

/// AES-256-GCM key size in bytes
pub const KEY_SIZE: usize = 32;

/// AES-GCM nonce size in bytes  
pub const NONCE_SIZE: usize = 12;

/// Argon2 salt size in bytes
pub const SALT_SIZE: usize = 32;

/// File extension for encrypted comic archives
pub const ENCRYPTED_EXTENSION: &str = ".stumpenc";
