import '@testing-library/jest-dom'
import 'cross-fetch/polyfill'

import crypto from 'node:crypto'

import { TextDecoder, TextEncoder } from 'util'

if (!('TextEncoder' in globalThis)) {
	Object.assign(globalThis, { TextEncoder })
}
if (!('TextDecoder' in globalThis)) {
	Object.assign(globalThis, { TextDecoder })
}

interface DeriveAlgorithm {
	name: string
	salt?: ArrayBuffer | ArrayBufferView
	info?: ArrayBuffer | ArrayBufferView
	iterations?: number
	hash?: string | { name: string }
}

interface DerivedKey {
	algoName: string
	keyData: Buffer
}

interface SubtleCryptoLike {
	importKey(
		format: string,
		keyData: ArrayBuffer | ArrayBufferView,
		algorithm: DeriveAlgorithm | string,
	): Promise<DerivedKey>
	deriveBits(algorithm: DeriveAlgorithm, baseKey: DerivedKey, length: number): Promise<ArrayBuffer>
}

interface CryptoLike {
	getRandomValues?(array: Uint8Array): Uint8Array
	subtle?: SubtleCryptoLike
}

interface GlobalWithCrypto {
	crypto?: CryptoLike
}

interface NodeWebCrypto {
	subtle?: SubtleCryptoLike
}

interface NodeCryptoWithExtras {
	webcrypto?: NodeWebCrypto
	hkdfSync?(hash: string, ikm: Buffer, salt: Buffer, info: Buffer, keylen: number): Buffer
}

const anyGlobal = globalThis as GlobalWithCrypto

if (!anyGlobal.crypto) {
	anyGlobal.crypto = {} as CryptoLike
}

const c = anyGlobal.crypto as CryptoLike

const nodeCrypto = crypto as unknown as NodeCryptoWithExtras

if (typeof c.getRandomValues !== 'function') {
	c.getRandomValues = (array: Uint8Array) => {
		return crypto.randomFillSync(array)
	}
}

if (!c.subtle) {
	const nodeWebcrypto = nodeCrypto.webcrypto
	if (nodeWebcrypto && nodeWebcrypto.subtle) {
		c.subtle = nodeWebcrypto.subtle
	} else {
		c.subtle = {
			async importKey(
				format: string,
				keyData: ArrayBuffer | ArrayBufferView,
				algorithm: DeriveAlgorithm | string,
			): Promise<DerivedKey> {
				if (format !== 'raw') {
					throw new Error('Only raw keys are supported in test subtle polyfill')
				}
				const algoName = typeof algorithm === 'string' ? algorithm : algorithm.name
				const view =
					keyData instanceof ArrayBuffer
						? new Uint8Array(keyData)
						: new Uint8Array(
								(keyData as ArrayBufferView).buffer,
								(keyData as ArrayBufferView).byteOffset,
								(keyData as ArrayBufferView).byteLength,
							)
				return {
					algoName,
					keyData: Buffer.from(view),
				}
			},
			async deriveBits(
				algorithm: DeriveAlgorithm,
				baseKey: DerivedKey,
				length: number,
			): Promise<ArrayBuffer> {
				const algoName = algorithm.name
				if (algoName === 'PBKDF2') {
					const saltSource = algorithm.salt ?? new Uint8Array()
					const saltView =
						saltSource instanceof ArrayBuffer
							? new Uint8Array(saltSource)
							: new Uint8Array((saltSource as ArrayBufferView).buffer)
					const salt = Buffer.from(saltView)
					const iterations = algorithm.iterations ?? 1
					const hashSource = algorithm.hash ?? 'SHA-256'
					const hashName = typeof hashSource === 'string' ? hashSource : hashSource.name
					const keyMaterial = baseKey.keyData
					const outLen = length / 8
					const dk = crypto.pbkdf2Sync(
						keyMaterial,
						salt,
						iterations,
						outLen,
						hashName.replace('-', '').toLowerCase(),
					)
					return dk.buffer.slice(dk.byteOffset, dk.byteOffset + dk.byteLength)
				}
				if (algoName === 'HKDF') {
					const saltSource = algorithm.salt ?? new Uint8Array()
					const saltView =
						saltSource instanceof ArrayBuffer
							? new Uint8Array(saltSource)
							: new Uint8Array((saltSource as ArrayBufferView).buffer)
					const salt = Buffer.from(saltView)
					const infoSource = algorithm.info ?? new Uint8Array()
					const infoView =
						infoSource instanceof ArrayBuffer
							? new Uint8Array(infoSource)
							: new Uint8Array((infoSource as ArrayBufferView).buffer)
					const info = Buffer.from(infoView)
					const hashSource = algorithm.hash ?? 'SHA-256'
					const hashName = typeof hashSource === 'string' ? hashSource : hashSource.name
					const ikm = baseKey.keyData
					const outLen = length / 8
					const hkdf = nodeCrypto.hkdfSync
					if (typeof hkdf !== 'function') {
						throw new Error('Node crypto hkdfSync is not available in test environment')
					}
					const dk = hkdf(hashName.replace('-', '').toLowerCase(), ikm, salt, info, outLen)
					return dk.buffer.slice(dk.byteOffset, dk.byteOffset + dk.byteLength)
				}
				throw new Error(`Unsupported algorithm in test subtle polyfill: ${algoName}`)
			},
		}
	}
}

if (!('IntersectionObserver' in globalThis)) {
	class MockIntersectionObserver {
		constructor() {}
		observe() {}
		unobserve() {}
		disconnect() {}
	}
	// @ts-expect-error jsdom test shim
	globalThis.IntersectionObserver = MockIntersectionObserver
}

if (typeof Element !== 'undefined' && !Element.prototype.scrollIntoView) {
	Element.prototype.scrollIntoView = () => {}
}

if (typeof window !== 'undefined' && !window.matchMedia) {
	// Minimal matchMedia shim for tests; always reports no matches.
	// @ts-expect-error jsdom test shim
	window.matchMedia = () => ({
		matches: false,
		media: '',
		onchange: null,
		addListener: () => {},
		removeListener: () => {},
		addEventListener: () => {},
		removeEventListener: () => {},
		dispatchEvent: () => false,
	})
}
