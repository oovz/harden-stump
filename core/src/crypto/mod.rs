//! # Cryptography Module
//!
//! This module provides the core cryptographic functionality for secure library management
//! in the Stump manga server. It implements an owner-held master key (SMK) architecture
//! with client-side decryption.
//!
//! ## Architecture Overview
//!
//! - **SMK (System Master Key)**: 256-bit key held by the server owner, never stored on server
//! - **LMK (Library Master Key)**: Derived per-library from SMK using HKDF-SHA256
//! - **DEK (Data Encryption Key)**: Derived per-file from LMK for encrypting file contents
//!
//! ## Key Technologies
//!
//! - AES-256-GCM with AEAD for file encryption
//! - X25519-ECDH + AES-256-GCM for LMK wrapping
//! - ChaCha20-Poly1305 for user private key encryption (with KEK from Argon2id)
//! - HKDF-SHA256 for key derivation
//! - Argon2id for password hashing and KEK derivation
//! - `zeroize` and `secrecy` crates for memory safety

pub mod encrypt;
pub mod errors;
pub mod keys;
pub mod services;
pub mod smk;
pub mod types;
pub mod user_keys;

pub use errors::{CryptoError, CryptoResult};
pub use smk::{SMKDisplay, SystemMasterKey};
pub use types::{DataEncryptionKey, KeyEncryptionKey, LibraryMasterKey};

// Re-export commonly used crypto primitives
pub use secrecy::{ExposeSecret, Secret, SecretVec};
pub use zeroize::{Zeroize, Zeroizing};

/// Size constants for cryptographic keys and nonces
pub mod sizes {
	/// AES-256-GCM key size (32 bytes)
	pub const AES_256_KEY_SIZE: usize = 32;

	/// AES-256-GCM nonce size (12 bytes)
	pub const AES_GCM_NONCE_SIZE: usize = 12;

	/// AES-256-GCM tag size (16 bytes)
	pub const AES_GCM_TAG_SIZE: usize = 16;

	/// X25519 key size (32 bytes)
	pub const X25519_KEY_SIZE: usize = 32;

	/// ChaCha20-Poly1305 key size (32 bytes)
	pub const CHACHA20_KEY_SIZE: usize = 32;

	/// ChaCha20-Poly1305 nonce size (12 bytes)
	pub const CHACHA20_NONCE_SIZE: usize = 12;

	/// Argon2id salt size (16 bytes)
	pub const ARGON2_SALT_SIZE: usize = 16;

	/// File padding boundary (1MB)
	pub const FILE_PADDING_BOUNDARY: usize = 1_048_576;
}

/// Domain separation strings for HKDF key derivation
pub mod domains {
	/// Domain for Library Master Key derivation
	pub const LMK_DOMAIN: &[u8] = b"library-master-key-v1";

	/// Domain prefix for file DEK derivation
	pub const DEK_DOMAIN: &[u8] = b"file-dek-v1";

	/// Domain for LMK wrapping key derivation
	pub const LMK_WRAP_DOMAIN: &[u8] = b"lmk-wrap";

	/// Domain for user KEK derivation from password
	pub const USER_KEK_DOMAIN: &[u8] = b"user-kek-v1";
}

/// Version constants for cryptographic operations
pub mod versions {
	/// Current crypto implementation version
	pub const CRYPTO_VERSION: u32 = 1;

	/// Argon2id parameters
	pub mod argon2 {
		/// Memory cost in KiB (256 MiB)
		pub const MEMORY_COST: u32 = 256 * 1024;

		/// Time cost (iterations)
		pub const TIME_COST: u32 = 3;

		/// Parallelism (number of lanes)
		pub const PARALLELISM: u32 = 4;

		/// Output length (32 bytes for AES-256 keys)
		pub const OUTPUT_LEN: usize = 32;
	}
}
