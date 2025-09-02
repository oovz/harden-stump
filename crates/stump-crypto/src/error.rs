//! Error types for the Stump crypto library

use thiserror::Error;

/// Main error type for cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
	#[error("Key derivation failed: {0}")]
	KeyDerivation(String),

	#[error("Encryption failed: {0}")]
	Encryption(String),

	#[error("Decryption failed: {0}")]
	Decryption(String),

	#[error("Archive error: {0}")]
	Archive(String),

	#[error("I/O error: {0}")]
	Io(#[from] std::io::Error),

	#[error("Zip error: {0}")]
	Zip(#[from] zip::result::ZipError),

	#[error("Invalid key or corrupted data: {0}")]
	InvalidData(String),

	#[error("Page not found: {0}")]
	PageNotFound(String),

	#[error("Invalid parameters: {0}")]
	InvalidParams(String),

	#[error("Hex decode error: {0}")]
	HexDecode(#[from] hex::FromHexError),
}

/// Convenience result type for crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;
