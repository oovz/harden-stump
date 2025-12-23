// Stub shim for argon2-browser to avoid WASM in web build
export default {
	ArgonType: { Argon2id: 2 },
	hash: async () => ({ hash: new Uint8Array(32) }),
}
