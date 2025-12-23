import nodeCrypto from 'node:crypto'

import {
	decryptAesGcm,
	decryptCatalogJSON,
	deriveDEK,
	deriveLMKFromSMK,
	unwrapLmkX25519AesGcm,
	WrappedLmk,
} from '@stump/client'

import { encryptPrivateKeyWithPasswordWeb } from '@/crypto/web'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function toB64(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString('base64')
}

async function encryptAesGcm(
	key: Uint8Array,
	nonce: Uint8Array,
	plaintext: Uint8Array,
): Promise<{ raw: Uint8Array; nonceB64: string; tagB64: string; originalSize: number }> {
	const cipher = nodeCrypto.createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce))
	const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()])
	const tag = cipher.getAuthTag()
	const combined = new Uint8Array(ct.length + tag.length)
	combined.set(ct, 0)
	combined.set(tag, ct.length)
	return {
		raw: combined,
		nonceB64: toB64(nonce),
		tagB64: toB64(new Uint8Array(tag)),
		originalSize: combined.length,
	}
}

describe('WebCrypto HKDF wrappers', () => {
	test('deriveLMKFromSMK is deterministic and library-specific', async () => {
		const smk = new Uint8Array(32).fill(7)

		const lmk1 = await deriveLMKFromSMK(smk, 'lib-1')
		const lmk2 = await deriveLMKFromSMK(smk, 'lib-1')
		const lmk3 = await deriveLMKFromSMK(smk, 'lib-2')

		expect(Buffer.from(lmk1)).toEqual(Buffer.from(lmk2))
		expect(Buffer.from(lmk1)).not.toEqual(Buffer.from(lmk3))
	})

	test('deriveDEK is deterministic and file-specific', async () => {
		const smk = new Uint8Array(32).map((_, i) => i)
		const lmk = await deriveLMKFromSMK(smk, 'lib-derive-dek')

		const dek1 = await deriveDEK(lmk, 'file-a')
		const dek2 = await deriveDEK(lmk, 'file-a')
		const dek3 = await deriveDEK(lmk, 'file-b')

		expect(Buffer.from(dek1)).toEqual(Buffer.from(dek2))
		expect(Buffer.from(dek1)).not.toEqual(Buffer.from(dek3))
	})
})

describe('decryptAesGcm', () => {
	test('round-trips AES-GCM ciphertext', async () => {
		const key = new Uint8Array(32).map((_, i) => (i * 7) & 0xff)
		const nonce = new Uint8Array(12).map((_, i) => i & 0xff)
		const plaintext = encoder.encode('hello secure world')

		const { raw, nonceB64, tagB64, originalSize } = await encryptAesGcm(key, nonce, plaintext)

		const decrypted = await decryptAesGcm(key, nonceB64, tagB64, raw, originalSize)
		expect(decoder.decode(decrypted)).toBe('hello secure world')
	})

	test('rejects when originalSize is too small', async () => {
		const key = new Uint8Array(32).fill(1)
		const nonceB64 = toB64(new Uint8Array(12))
		const tagB64 = toB64(new Uint8Array(16))
		await expect(decryptAesGcm(key, nonceB64, tagB64, new Uint8Array(0), 8)).rejects.toThrow(
			'Invalid originalSize for GCM',
		)
	})

	test('rejects when tag length is invalid', async () => {
		const key = new Uint8Array(32).fill(2)
		const nonceB64 = toB64(new Uint8Array(12))
		const badTagB64 = toB64(new Uint8Array(8))
		await expect(decryptAesGcm(key, nonceB64, badTagB64, new Uint8Array(16), 16)).rejects.toThrow(
			'Invalid GCM tag',
		)
	})

	test('rejects when nonce length is invalid', async () => {
		const key = new Uint8Array(32).fill(3)
		const badNonceB64 = toB64(new Uint8Array(8))
		const tagB64 = toB64(new Uint8Array(16))
		await expect(decryptAesGcm(key, badNonceB64, tagB64, new Uint8Array(16), 16)).rejects.toThrow(
			'Invalid GCM nonce',
		)
	})
})

describe('decryptCatalogJSON', () => {
	test('decrypts catalog JSON produced with matching HKDF/AES-GCM parameters', async () => {
		const smk = new Uint8Array(32).map((_, i) => (i * 13) & 0xff)
		const lmk = await deriveLMKFromSMK(smk, 'lib-catalog')
		const dek = await deriveDEK(lmk, 'catalog')

		const enc = {
			version: 1,
			total_series: 1,
			total_media: 1,
			series: [
				{
					id: 's1',
					name: 'Series 1',
					cover_media_id: 'm1',
					sort_order: 0,
					volume: null,
					updated_at: new Date().toISOString(),
				},
			],
			media: [
				{
					id: 'm1',
					series_id: 's1',
					name: 'Book 1',
					pages: 10,
					extension: 'cbz',
					size: 123,
					sort_order: 0,
					number: null,
					volume: null,
					updated_at: new Date().toISOString(),
				},
			],
			updated_at: new Date().toISOString(),
			library_id: 'lib-catalog',
		}
		const plaintext = encoder.encode(JSON.stringify(enc))
		const nonce = new Uint8Array(12).map((_, i) => (i * 5) & 0xff)
		const { raw, nonceB64, tagB64, originalSize } = await encryptAesGcm(dek, nonce, plaintext)

		const result = await decryptCatalogJSON(lmk, raw, nonceB64, tagB64, originalSize)

		expect(result.version).toBe(1)
		expect(result.libraryId).toBe('lib-catalog')
		expect(result.totalSeries).toBe(1)
		expect(result.totalMedia).toBe(1)
		expect(result.series[0]?.id).toBe('s1')
		expect(result.media[0]?.id).toBe('m1')
		expect(result.media[0]?.name).toBe('Book 1')
	})
})

describe('encryptPrivateKeyWithPasswordWeb', () => {
	test('produces nonce/salt of correct length and non-empty ciphertext', async () => {
		const priv = new Uint8Array(32).map((_, i) => (255 - i) & 0xff)
		const { encrypted_private, nonce, salt } = await encryptPrivateKeyWithPasswordWeb(
			priv,
			'password-123',
		)

		expect(typeof encrypted_private).toBe('string')
		expect(encrypted_private.length).toBeGreaterThan(0)

		const nonceBytes = Buffer.from(nonce, 'base64')
		const saltBytes = Buffer.from(salt, 'base64')

		expect(nonceBytes).toHaveLength(12)
		expect(saltBytes).toHaveLength(16)
	})
})

describe('unwrapLmkX25519AesGcm', () => {
	test('rejects when wrapped LMK has invalid GCM nonce length', async () => {
		const privateKey = new Uint8Array(32).fill(11)
		const wrapped: WrappedLmk = {
			// Minimum-length, zeroed test values; unwrap will fail before decryption
			encrypted_lmk: toB64(new Uint8Array(32)),
			ephemeral_public: toB64(new Uint8Array(32)),
			nonce: toB64(new Uint8Array(8)), // invalid length; should be 12
		}

		await expect(unwrapLmkX25519AesGcm(wrapped, privateKey)).rejects.toThrow('Invalid GCM nonce')
	})
})
