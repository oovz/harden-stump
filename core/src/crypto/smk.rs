use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bip39::Mnemonic;
use hkdf::Hkdf;
use qrcode::{render::unicode, QrCode};
/// System Master Key (SMK) generation and handling
///
/// The SMK is a 256-bit key that is:
/// - Generated once during system setup
/// - NEVER stored on the server
/// - Only held by the server owner
/// - Required for all secure library operations
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;

use crate::{CoreError, CoreResult};

/// System Master Key wrapper with automatic zeroization
/// Note: Secret<T> already implements Drop and zeroizes on drop
#[derive(Clone)]
pub struct SystemMasterKey {
	key: Secret<[u8; 32]>,
}

impl SystemMasterKey {
	/// Generate a new random SMK using OS CSPRNG
	pub fn generate() -> Self {
		let mut key = [0u8; 32];
		rand::thread_rng().fill_bytes(&mut key);

		Self {
			key: Secret::new(key),
		}
	}

	/// Create SMK from base64-encoded string
	pub fn from_base64(encoded: &str) -> CoreResult<Self> {
		let decoded = BASE64
			.decode(encoded)
			.map_err(|e| CoreError::BadRequest(format!("Invalid base64: {}", e)))?;

		if decoded.len() != 32 {
			return Err(CoreError::BadRequest(format!(
				"SMK must be exactly 32 bytes, got {}",
				decoded.len()
			)));
		}

		let mut key = [0u8; 32];
		key.copy_from_slice(&decoded);

		Ok(Self {
			key: Secret::new(key),
		})
	}

	/// Export SMK as base64 string
	pub fn to_base64(&self) -> String {
		BASE64.encode(self.key.expose_secret())
	}

	/// Export SMK as BIP-39 mnemonic (24 words)
	pub fn to_mnemonic(&self) -> CoreResult<String> {
		// BIP-39 requires entropy in specific bit lengths
		// 256 bits = 24 words
		let mnemonic = Mnemonic::from_entropy(self.key.expose_secret()).map_err(|e| {
			CoreError::InternalError(format!("Failed to create mnemonic: {}", e))
		})?;

		Ok(mnemonic.to_string())
	}

	/// Generate QR code for the SMK (as base64)
	pub fn to_qr_code(&self) -> CoreResult<String> {
		let base64 = self.to_base64();
		let code = QrCode::new(&base64).map_err(|e| {
			CoreError::InternalError(format!("Failed to generate QR code: {}", e))
		})?;

		let image = code
			.render::<unicode::Dense1x2>()
			.dark_color(unicode::Dense1x2::Light)
			.light_color(unicode::Dense1x2::Dark)
			.build();

		Ok(image)
	}

	/// Expose the secret key material
	pub fn expose_secret(&self) -> &[u8; 32] {
		self.key.expose_secret()
	}

	/// Derive a Library Master Key (LMK) from the SMK
	pub fn derive_library_key(&self, library_id: &str) -> CoreResult<[u8; 32]> {
		let salt = format!("stump-library-{}", library_id);
		let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), self.key.expose_secret());

		let mut lmk = [0u8; 32];
		hkdf.expand(b"library-master-key", &mut lmk).map_err(|e| {
			CoreError::InternalError(format!("Failed to derive LMK: {}", e))
		})?;

		Ok(lmk)
	}

	/// Validate SMK has sufficient entropy (for setup validation)
	pub fn validate_entropy(&self) -> CoreResult<()> {
		let key = self.key.expose_secret();

		// Check for obvious weak patterns
		if key.iter().all(|&b| b == 0) {
			return Err(CoreError::BadRequest(
				"SMK appears to be all zeros - this is not secure!".to_string(),
			));
		}

		if key.iter().all(|&b| b == 0xFF) {
			return Err(CoreError::BadRequest(
				"SMK appears to be all ones - this is not secure!".to_string(),
			));
		}

		// Check for repeating patterns
		let unique_bytes: std::collections::HashSet<_> = key.iter().collect();
		if unique_bytes.len() < 16 {
			return Err(CoreError::BadRequest(
				"SMK has low entropy - too many repeating bytes".to_string(),
			));
		}

		Ok(())
	}

	/// Constant-time comparison with another SMK
	pub fn ct_eq(&self, other: &Self) -> bool {
		use subtle::ConstantTimeEq;
		self.key
			.expose_secret()
			.ct_eq(other.key.expose_secret())
			.into()
	}
}

/// Display formats for the SMK during setup
pub struct SMKDisplay {
	pub base64: String,
	pub mnemonic: String,
	pub qr_code: String,
}

impl SMKDisplay {
	/// Generate all display formats for a given SMK
	pub fn from_smk(smk: &SystemMasterKey) -> CoreResult<Self> {
		Ok(Self {
			base64: smk.to_base64(),
			mnemonic: smk.to_mnemonic()?,
			qr_code: smk.to_qr_code()?,
		})
	}

	/// Display the SMK with security warnings
	pub fn display_with_warnings(&self) {
		println!("\n{}", "=".repeat(80));
		println!("🔐 SYSTEM MASTER KEY GENERATED");
		println!("{}", "=".repeat(80));

		println!("\n⚠️  CRITICAL SECURITY WARNING ⚠️");
		println!("This key will NEVER be shown again!");
		println!("Save it immediately in a password manager or secure location.");
		println!("Without this key, encrypted libraries CANNOT be recovered!");

		println!("\n📋 BASE64 FORMAT (for password managers):");
		println!("{}", "─".repeat(60));
		println!("{}", self.base64);

		println!("\n📝 BIP-39 MNEMONIC (24 words):");
		println!("{}", "─".repeat(60));
		// Format mnemonic as 4 rows of 6 words for readability
		let words: Vec<&str> = self.mnemonic.split_whitespace().collect();
		for chunk in words.chunks(6) {
			println!("  {}", chunk.join("  "));
		}

		println!("\n📱 QR CODE (for mobile apps):");
		println!("{}", "─".repeat(60));
		println!("{}", self.qr_code);

		println!("\n{}", "=".repeat(80));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_smk_generation() {
		let smk = SystemMasterKey::generate();
		assert_eq!(smk.expose_secret().len(), 32);

		// Ensure entropy validation passes
		smk.validate_entropy().unwrap();
	}

	#[test]
	fn test_smk_base64_roundtrip() {
		let smk1 = SystemMasterKey::generate();
		let base64 = smk1.to_base64();

		let smk2 = SystemMasterKey::from_base64(&base64).unwrap();
		assert!(smk1.ct_eq(&smk2));
	}

	#[test]
	fn test_weak_key_detection() {
		let weak_key = SystemMasterKey {
			key: Secret::new([0u8; 32]),
		};

		assert!(weak_key.validate_entropy().is_err());
	}

	#[test]
	fn test_library_key_derivation() {
		let smk = SystemMasterKey::generate();
		let lmk1 = smk.derive_library_key("library-1").unwrap();
		let lmk2 = smk.derive_library_key("library-2").unwrap();

		// Different libraries should have different keys
		assert_ne!(lmk1, lmk2);

		// Same library should always derive same key
		let lmk1_again = smk.derive_library_key("library-1").unwrap();
		assert_eq!(lmk1, lmk1_again);
	}

	#[test]
	fn test_mnemonic_generation() {
		let smk = SystemMasterKey::generate();
		let mnemonic = smk.to_mnemonic().unwrap();

		// BIP-39 24-word mnemonic
		let word_count = mnemonic.split_whitespace().count();
		assert_eq!(word_count, 24);
	}
}
