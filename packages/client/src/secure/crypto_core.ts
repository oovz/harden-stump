/* Web-only-safe crypto utilities (no WASM):
 * - HKDF-SHA256 (WebCrypto) for LMK/DEK derivation (matches Rust core domains)
 * - AES-256-GCM decrypt (WebCrypto)
 * - X25519 keypair + LMK unwrap (noble)
 */

// Domain separation constants (must match Rust)
const LMK_DOMAIN = new TextEncoder().encode('library-master-key-v1')
const DEK_DOMAIN = new TextEncoder().encode('file-dek-v1')

function textToBytes(s: string): Uint8Array {
	return new TextEncoder().encode(s)
}

// AES-256-GCM unwrap of LMK (matches server MVP implementation)
export async function unwrapLmkX25519AesGcm(
	wrapped: WrappedLmk,
	privateKey: Uint8Array,
): Promise<Uint8Array> {
	const { x25519 } = await import('@noble/curves/ed25519.js')

	const ephPub = b64ToBytes(wrapped.ephemeral_public)
	const shared = x25519.getSharedSecret(privateKey, ephPub)

	const LMK_WRAP = new TextEncoder().encode('lmk-wrap')
	const wrappingKey = await hkdfExpand(shared, new Uint8Array(0), LMK_WRAP, 32)

	const nonce = b64ToBytes(wrapped.nonce)
	const ciphertext = b64ToBytes(wrapped.encrypted_lmk)

	if (nonce.length !== 12) throw new Error('Invalid GCM nonce')

	const keyCopy = new Uint8Array(wrappingKey)
	const cryptoKey = await crypto.subtle.importKey(
		'raw',
		keyCopy.buffer,
		{ name: 'AES-GCM' },
		false,
		['decrypt'],
	)
	const dataView = new Uint8Array(ciphertext)
	const ivView = new Uint8Array(nonce)
	const plaintext = await crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv: ivView },
		cryptoKey,
		dataView,
	)
	if ((plaintext as ArrayBuffer).byteLength !== 32) throw new Error('Invalid LMK size')
	return new Uint8Array(plaintext)
}

// (Removed duplicate unwrapLmkX25519ChaCha; see single implementation below)

export type WrappedLmk = {
	encrypted_lmk: string // base64
	ephemeral_public: string // base64 (32 bytes)
	nonce: string // base64 (12 bytes)
}

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

	if (plaintext.length !== 32) throw new Error('Invalid LMK size')
	return plaintext
}

export function b64ToBytes(b64: string): Uint8Array {
	if (typeof atob === 'function') {
		const bin = atob(b64)
		const bytes = new Uint8Array(bin.length)
		for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
		return bytes
	}
	return Uint8Array.from(Buffer.from(b64, 'base64'))
}

export function bytesToB64(bytes: Uint8Array): string {
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

export async function deriveLMKFromSMK(smk: Uint8Array, libraryId: string): Promise<Uint8Array> {
	return hkdfExpand(smk, LMK_DOMAIN, textToBytes(`library:${libraryId}`), 32)
}

export async function deriveDEK(lmk: Uint8Array, fileLabel: string): Promise<Uint8Array> {
	return hkdfExpand(DEK_DOMAIN, lmk, textToBytes(`file:${fileLabel}`), 32)
}

export async function deriveThumbnailKey(lmk: Uint8Array, mediaId: string): Promise<Uint8Array> {
	return hkdfExpand(DEK_DOMAIN, lmk, textToBytes(`thumb:${mediaId}`), 32)
}

export async function decryptAesGcm(
	key: Uint8Array,
	nonceB64: string,
	tagB64: string,
	paddedCiphertext: Uint8Array,
	originalSize: number,
): Promise<Uint8Array> {
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
	const combinedView = new Uint8Array(combined)
	const nonceView = new Uint8Array(nonce)
	const plaintext = await crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv: nonceView },
		cryptoKey,
		combinedView,
	)
	return new Uint8Array(plaintext)
}

export type EncryptedCatalogSeriesV1 = {
	id: string
	name: string
	cover_media_id: string | null
	sort_order: number
	volume: number | null
	updated_at: string
}

export type EncryptedCatalogMediaV1 = {
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
}

export type EncryptedCatalogV1 = {
	version: number
	total_series: number
	total_media: number
	series: EncryptedCatalogSeriesV1[]
	media: EncryptedCatalogMediaV1[]
	updated_at: string
	library_id: string
}

export type EncryptedCatalog = EncryptedCatalogV1

export type DecryptedCatalogSeries = {
	id: string
	name: string
	coverMediaId: string | null
	sortOrder: number
	volume: number | null
	updatedAt: string
}

export type DecryptedCatalogMedia = {
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
}

export type DecryptedCatalog = {
	version: number
	totalSeries: number
	totalMedia: number
	series: DecryptedCatalogSeries[]
	media: DecryptedCatalogMedia[]
	updatedAt: string
	libraryId: string
}

export async function decryptCatalogJSON(
	lmk: Uint8Array,
	raw: Uint8Array,
	nonceB64: string,
	tagB64: string,
	originalSize: number,
): Promise<DecryptedCatalog> {
	const dek = await deriveDEK(lmk, 'catalog')
	const jsonBytes = await decryptAesGcm(dek, nonceB64, tagB64, raw, originalSize)
	const value: unknown = JSON.parse(new TextDecoder().decode(jsonBytes))

	// v1 schema (current)
	if (
		value &&
		typeof value === 'object' &&
		'total_series' in value &&
		'total_media' in value &&
		'library_id' in value
	) {
		const enc = value as EncryptedCatalogV1
		return {
			version: enc.version,
			totalSeries: enc.total_series,
			totalMedia: enc.total_media,
			libraryId: enc.library_id,
			updatedAt: enc.updated_at,
			series: (enc.series || []).map((s) => ({
				id: s.id,
				name: s.name,
				coverMediaId: s.cover_media_id ?? null,
				sortOrder: s.sort_order,
				volume: s.volume ?? null,
				updatedAt: s.updated_at,
			})),
			media: (enc.media || []).map((m) => ({
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

	// legacy schema (pre-v1 contract alignment)
	if (value && typeof value === 'object' && 'library_name' in value) {
		const legacy = value as {
			version: number
			library_id: string
			library_name: string
			generated_at?: string
			series?: { id: string; name: string }[]
			media?: { id: string; series_id?: string | null; title: string }[]
		}
		const series = legacy.series ?? []
		const media = legacy.media ?? []
		const updatedAt = legacy.generated_at ?? new Date().toISOString()
		return {
			version: legacy.version,
			totalSeries: series.length,
			totalMedia: media.length,
			libraryId: legacy.library_id,
			updatedAt,
			series: series.map((s) => ({
				id: s.id,
				name: s.name,
				coverMediaId: null,
				sortOrder: 0,
				volume: null,
				updatedAt,
			})),
			media: media.map((m) => ({
				id: m.id,
				seriesId: m.series_id ?? null,
				name: m.title,
				pages: 0,
				extension: 'cbz',
				size: 0,
				sortOrder: 0,
				number: null,
				volume: null,
				updatedAt,
			})),
		}
	}

	throw new Error('Unsupported secure catalog schema')
}
