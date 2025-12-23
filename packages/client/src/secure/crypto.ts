/* Web-only MVP crypto utilities for client-side decryption (Option A)
 * - HKDF-SHA256 derivations matching Rust core
 * - AES-256-GCM decrypt for catalog/media (padding trimmed via original_size)
 */

// Domain separation constants (must match Rust)
const LMK_DOMAIN = new TextEncoder().encode('library-master-key-v1')
const DEK_DOMAIN = new TextEncoder().encode('file-dek-v1')
// No FEK/MEK used for catalog-only decryption

function textToBytes(s: string): Uint8Array {
	return new TextEncoder().encode(s)
}

export async function decryptPrivateKeyWithPassword(
	encrypted_private_b64: string,
	nonce_b64: string,
	salt_b64: string,
	password: string,
): Promise<Uint8Array> {
	const { chacha20poly1305 } = await import('@noble/ciphers/chacha.js')
	type Argon2Like = {
		hash: (opts: Record<string, unknown>) => Promise<{ hash: Uint8Array }>
		ArgonType: { Argon2id: number }
	}
	const mod = (await import('argon2-browser/dist/argon2-bundled.min.js')) as unknown
	const argon2 = (mod as { default?: Argon2Like }).default ?? (mod as Argon2Like)

	const salt = b64ToBytes(salt_b64)
	const nonce = b64ToBytes(nonce_b64)
	const ciphertext = b64ToBytes(encrypted_private_b64)

	const derive = async (memKiB: number) =>
		argon2.hash({
			pass: password,
			salt,
			type: argon2.ArgonType.Argon2id,
			mem: memKiB,
			time: 3,
			parallelism: 4,
			hashLen: 32,
		})

	let kek: Uint8Array
	try {
		kek = (await derive(262144)).hash // 256 MiB
	} catch {
		kek = (await derive(65536)).hash // 64 MiB fallback
	}

	const cipher = chacha20poly1305(kek, nonce)
	const plaintext = cipher.decrypt(ciphertext)
	if (plaintext.length !== 32) {
		throw new Error('Invalid private key size')
	}
	return plaintext
}

// =========== User keypair generation and private key encryption (web-only MVP) ==========

export async function generateX25519Keypair(): Promise<{
	publicKey: Uint8Array
	privateKey: Uint8Array
	publicKeyB64: string
}> {
	const curves = await import('@noble/curves/ed25519.js')
	const priv = curves.x25519.utils.randomSecretKey()
	const pub = curves.x25519.getPublicKey(priv)
	return { publicKey: pub, privateKey: priv, publicKeyB64: bytesToB64(pub) }
}

export async function encryptPrivateKeyWithPassword(
	privateKey: Uint8Array,
	password: string,
): Promise<{ encrypted_private: string; nonce: string; salt: string }> {
	const { chacha20poly1305 } = await import('@noble/ciphers/chacha.js')
	type Argon2Like = {
		hash: (opts: Record<string, unknown>) => Promise<{ hash: Uint8Array }>
		ArgonType: { Argon2id: number }
	}
	// NOTE: Argon2 WASM + Vite:
	// We import the argon2-browser bundled build to avoid Vite's lack of support for the
	// ESM Wasm integration proposal. The bundled file embeds the Wasm, requiring no special
	// loader configuration and working reliably across environments.
	// Rationale and references:
	// - Upstream docs provide a bundled entry: dist/argon2-bundled(.min).js
	// - Related discussion: https://github.com/antelle/argon2-browser/issues/92
	// - We intentionally avoid PBKDF2 fallbacks; Argon2id is required for KEK derivation.
	// - TS shim lives at packages/client/src/types/argon2-browser-bundled.d.ts
	const mod = (await import('argon2-browser/dist/argon2-bundled.min.js')) as unknown
	const argon2 = (mod as { default?: Argon2Like }).default ?? (mod as Argon2Like)

	// 16-byte salt
	const salt = new Uint8Array(16)
	crypto.getRandomValues(salt)

	// Derive 32-byte KEK with Argon2id; try server-like params, fallback on OOM
	const derive = async (memKiB: number) =>
		argon2.hash({
			pass: password,
			salt,
			type: argon2.ArgonType.Argon2id,
			mem: memKiB, // KiB
			time: 3,
			parallelism: 4,
			hashLen: 32,
		})

	let kek: Uint8Array
	// Some browsers may fail to allocate 256 MiB for Argon2. In that case, fall back to 64 MiB
	// to preserve usability while maintaining Argon2id. This mirrors the server's recommended
	// browser fallback and keeps KEK size/strength consistent.
	try {
		kek = (await derive(262144)).hash // 256 MiB
	} catch {
		kek = (await derive(65536)).hash // 64 MiB fallback for browsers
	}

	const nonce = new Uint8Array(12)
	crypto.getRandomValues(nonce)
	const cipher = chacha20poly1305(kek, nonce)
	const ciphertext = cipher.encrypt(privateKey)

	return {
		encrypted_private: bytesToB64(ciphertext),
		nonce: bytesToB64(nonce),
		salt: bytesToB64(salt),
	}
}

// =========== X25519 + ChaCha20-Poly1305 LMK unwrap (matches Rust core) ==========

export type WrappedLmk = {
	encrypted_lmk: string // base64
	ephemeral_public: string // base64 (32 bytes)
	nonce: string // base64 (12 bytes)
}

export async function unwrapLmkX25519ChaCha(
	wrapped: WrappedLmk,
	privateKey: Uint8Array,
): Promise<Uint8Array> {
	const { x25519 } = await import('@noble/curves/ed25519.js')
	const { chacha20poly1305 } = await import('@noble/ciphers/chacha.js')

	const ephPub = b64ToBytes(wrapped.ephemeral_public)
	const shared = x25519.getSharedSecret(privateKey, ephPub)

	const LMK_WRAP = new TextEncoder().encode('lmk-wrap')
	const wrappingKey = await hkdfExpand(shared, new Uint8Array(0), LMK_WRAP, 32)

	const nonce = b64ToBytes(wrapped.nonce)
	const ciphertext = b64ToBytes(wrapped.encrypted_lmk)

	const cipher = chacha20poly1305(wrappingKey, nonce)
	const plaintext = cipher.decrypt(ciphertext)

	if (plaintext.length !== 32) {
		throw new Error('Invalid LMK size')
	}
	return plaintext
}

export const base64 = { toBytes: b64ToBytes, fromBytes: bytesToB64 }

function b64ToBytes(b64: string): Uint8Array {
	if (typeof atob === 'function') {
		const bin = atob(b64)
		const bytes = new Uint8Array(bin.length)
		for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
		return bytes
	}
	// Node fallback if needed during SSR/build
	return Uint8Array.from(Buffer.from(b64, 'base64'))
}

function bytesToB64(bytes: Uint8Array): string {
	if (typeof btoa === 'function') {
		let bin = ''
		for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
		return btoa(bin)
	}
	return Buffer.from(bytes).toString('base64')
}

async function hkdfExpand(
	ikm: Uint8Array,
	salt: Uint8Array,
	info: Uint8Array,
	length: number,
): Promise<Uint8Array> {
	// Copy into fresh typed arrays backed by ArrayBuffer (avoids SharedArrayBuffer union types)
	const ikmCopy = new Uint8Array(ikm)
	const saltCopy = new Uint8Array(salt)
	const infoCopy = new Uint8Array(info)
	const baseKey = await crypto.subtle.importKey('raw', ikmCopy.buffer, 'HKDF', false, [
		'deriveBits',
	])
	const bits = await crypto.subtle.deriveBits(
		{ name: 'HKDF', hash: 'SHA-256', salt: saltCopy, info: infoCopy },
		baseKey,
		length * 8,
	)
	return new Uint8Array(bits)
}

// Derive LMK from SMK
export async function deriveLMKFromSMK(smk: Uint8Array, libraryId: string): Promise<Uint8Array> {
	// Rust: HKDF(salt=LMK_DOMAIN, ikm=SMK).expand(info="library:{id}", len=32)
	return hkdfExpand(smk, LMK_DOMAIN, textToBytes(`library:${libraryId}`), 32)
}

// Derive DEK from LMK for a specific file or catalog
export async function deriveDEK(lmk: Uint8Array, fileLabel: string): Promise<Uint8Array> {
	// Rust: HKDF(salt=LMK, ikm=DEK_DOMAIN).expand(info="file:{label}", len=32)
	return hkdfExpand(DEK_DOMAIN, lmk, textToBytes(`file:${fileLabel}`), 32)
}

// Derive MEK from LMK (deterministic metadata encryption)
// No MEK/FEK required for the catalog JSON flow

// AES-256-GCM decrypt where ciphertext is padded, tag provided separately, and original_size is known
export async function decryptAesGcm(
	key: Uint8Array,
	nonceB64: string,
	tagB64: string,
	paddedCiphertext: Uint8Array,
	originalSize: number,
): Promise<Uint8Array> {
	// Reconstruct ciphertext_with_tag (original_size bytes: ct || tag)
	if (originalSize < 16) throw new Error('Invalid originalSize for GCM')
	const ctLen = originalSize - 16
	const ct = paddedCiphertext.slice(0, ctLen)
	const tag = b64ToBytes(tagB64)
	if (tag.length !== 16) throw new Error('Invalid GCM tag')
	const combined = new Uint8Array(ctLen + 16)
	combined.set(ct, 0)
	combined.set(tag, ctLen)

	const nonce = b64ToBytes(nonceB64)
	if (nonce.length !== 12) throw new Error('Invalid GCM nonce')

	const keyCopy = new Uint8Array(key)
	const cryptoKey = await crypto.subtle.importKey(
		'raw',
		keyCopy.buffer,
		{ name: 'AES-GCM' },
		false,
		['decrypt'],
	)
	// Use Uint8Array views to satisfy BufferSource typing (avoid SharedArrayBuffer unions)
	const ivView = new Uint8Array(nonce)
	const dataView = new Uint8Array(combined)
	const plaintext = await crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv: ivView },
		cryptoKey,
		dataView,
	)
	return new Uint8Array(plaintext)
}

// AES-256-SIV decrypt of deterministic metadata (base64 input -> bytes -> open)
// No SIV decryption required

export type EncryptedCatalog = {
	version: number
	total_series: number
	total_media: number
	series: {
		id: string
		name: string
		cover_media_id: string | null
		sort_order: number
		volume: number | null
		updated_at: string
	}[]
	media: {
		id: string
		series_id: string | null
		name: string
		pages: number
		extension: string
		size: number
		sort_order: number
		number: number | null
		volume: number | null
		updated_at: string
	}[]
	updated_at: string
	library_id: string
}

export type DecryptedCatalog = {
	version: number
	totalSeries: number
	totalMedia: number
	libraryId: string
	updatedAt: string
	series: {
		id: string
		name: string
		coverMediaId: string | null
		sortOrder: number
		volume: number | null
		updatedAt: string
	}[]
	media: {
		id: string
		seriesId: string | null
		name: string
		pages: number
		extension: string
		size: number
		sortOrder: number
		number: number | null
		volume: number | null
		updatedAt: string
	}[]
}

// High-level helper: decrypt catalog JSON payload
export async function decryptCatalogJSON(
	lmk: Uint8Array,
	raw: Uint8Array,
	nonceB64: string,
	tagB64: string,
	originalSize: number,
): Promise<DecryptedCatalog> {
	const dek = await deriveDEK(lmk, 'catalog')
	const jsonBytes = await decryptAesGcm(dek, nonceB64, tagB64, raw, originalSize)
	const enc: EncryptedCatalog = JSON.parse(new TextDecoder().decode(jsonBytes))
	return {
		version: enc.version,
		totalSeries: enc.total_series,
		totalMedia: enc.total_media,
		libraryId: enc.library_id,
		updatedAt: enc.updated_at,
		series: enc.series.map((s) => ({
			id: s.id,
			name: s.name,
			coverMediaId: s.cover_media_id ?? null,
			sortOrder: s.sort_order,
			volume: s.volume ?? null,
			updatedAt: s.updated_at,
		})),
		media: enc.media.map((m) => ({
			id: m.id,
			seriesId: m.series_id ?? null,
			name: m.name,
			pages: m.pages,
			extension: m.extension,
			size: m.size,
			sortOrder: m.sort_order,
			number: m.number ?? null,
			volume: m.volume ?? null,
			updatedAt: m.updated_at,
		})),
	}
}
