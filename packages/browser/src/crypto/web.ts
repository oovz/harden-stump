// Web-only KEK derivation (PBKDF2 fallback) + ChaCha20-Poly1305 encrypt
// Note: This is an MVP fallback to avoid WASM bundling issues. Do not persist keys.

const textEncoder = new TextEncoder()

function toB64(bytes: Uint8Array): string {
	if (typeof btoa === 'function') {
		let bin = ''
		for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
		return btoa(bin)
	}
	return Buffer.from(bytes).toString('base64')
}

async function pbkdf2(
	password: string,
	salt: Uint8Array,
	iterations = 200_000,
): Promise<Uint8Array> {
	const pw = textEncoder.encode(password)
	const pwAb = pw.buffer.slice(pw.byteOffset, pw.byteOffset + pw.byteLength)
	const keyMaterial = await crypto.subtle.importKey('raw', pwAb, { name: 'PBKDF2' }, false, [
		'deriveBits',
	])
	const bits = await crypto.subtle.deriveBits(
		{ name: 'PBKDF2', salt: new Uint8Array(salt), iterations, hash: 'SHA-256' },
		keyMaterial,
		256,
	)
	return new Uint8Array(bits)
}

export async function encryptPrivateKeyWithPasswordWeb(
	privateKey: Uint8Array,
	password: string,
): Promise<{ encrypted_private: string; nonce: string; salt: string }> {
	const { chacha20poly1305 } = await import('@noble/ciphers/chacha.js')
	const salt = new Uint8Array(16)
	crypto.getRandomValues(salt)
	const kek = await pbkdf2(password, salt)
	const nonce = new Uint8Array(12)
	crypto.getRandomValues(nonce)
	const cipher = chacha20poly1305(kek, nonce)
	const ciphertext = cipher.encrypt(privateKey)
	return { encrypted_private: toB64(ciphertext), nonce: toB64(nonce), salt: toB64(salt) }
}
