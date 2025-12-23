//! Cryptography error types

use thiserror::Error;

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Errors that can occur during cryptographic operations
#[derive(Debug, Error)]
pub enum CryptoError {
	/// Invalid key size
	#[error("Invalid key size: expected {expected}, got {actual}")]
	InvalidKeySize { expected: usize, actual: usize },

	/// Invalid nonce size
	#[error("Invalid nonce size: expected {expected}, got {actual}")]
	InvalidNonceSize { expected: usize, actual: usize },

	/// Encryption failed
	#[error("Encryption failed: {0}")]
	EncryptionFailed(String),

	/// Decryption failed
	#[error("Decryption failed: {0}")]
	DecryptionFailed(String),

	/// Key derivation failed
	#[error("Key derivation failed: {0}")]
	KeyDerivationFailed(String),

	/// Invalid key format
	#[error("Invalid key format: {0}")]
	InvalidKeyFormat(String),

	/// Password hashing failed
	#[error("Password hashing failed: {0}")]
	PasswordHashFailed(String),

	/// Password verification failed
	#[error("Password verification failed: {0}")]
	PasswordVerificationFailed(String),

	/// Key exchange failed
	#[error("Key exchange failed: {0}")]
	KeyExchangeFailed(String),

	/// Invalid file size
	#[error("Invalid file size: {0}")]
	InvalidFileSize(String),

	/// I/O error during crypto operations
	#[error("I/O error: {0}")]
	Io(#[from] std::io::Error),

	/// Library not found
	#[error("Library not found: {0}")]
	LibraryNotFound(String),

	/// Database error
	#[error("Database error: {0}")]
	DatabaseError(String),

	/// Invalid operation
	#[error("Invalid operation: {0}")]
	InvalidOperation(String),

	/// Invalid encrypted data
	#[error("Invalid encrypted data: {0}")]
	InvalidEncryptedData(String),

	/// Invalid key
	#[error("Invalid key: {0}")]
	InvalidKey(String),

	/// Generic crypto error
	#[error("Crypto error: {0}")]
	Generic(String),
}

// Note: We don't implement automatic From conversions for AEAD errors
// because aes_gcm, aes_siv, and chacha20poly1305 all use overlapping error types
// which causes conflicting trait implementations. Instead, we use manual
// .map_err() conversions at call sites for better clarity and control.

impl From<argon2::Error> for CryptoError {
	fn from(err: argon2::Error) -> Self {
		CryptoError::PasswordHashFailed(err.to_string())
	}
}

impl From<argon2::password_hash::Error> for CryptoError {
	fn from(err: argon2::password_hash::Error) -> Self {
		CryptoError::PasswordVerificationFailed(err.to_string())
	}
}
