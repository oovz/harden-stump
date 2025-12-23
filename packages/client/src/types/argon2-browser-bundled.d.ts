// Type shim for argon2-browser bundled build used with Vite.
// Rationale: we import 'argon2-browser/dist/argon2-bundled.min.js' to embed Wasm
// and avoid ESM Wasm loader issues. This file provides minimal typings for that
// specific entry point. See crypto.ts for the import and comments.
declare module 'argon2-browser/dist/argon2-bundled.min.js' {
	type Argon2HashInput = {
		pass: string | Uint8Array
		salt?: string | Uint8Array
		time?: number
		mem?: number
		parallelism?: number
		hashLen?: number
		secret?: Uint8Array
		ad?: Uint8Array
		type?: { Argon2id: number } | number
	}
	type Argon2HashOutput = { hash: Uint8Array; hashHex: string; encoded: string }
	const Argon2: {
		ArgonType: { Argon2id: number }
		hash: (input: Argon2HashInput) => Promise<Argon2HashOutput>
		verify: (input: { pass: string | Uint8Array; encoded: string }) => Promise<Argon2HashOutput>
	}
	export default Argon2
}
