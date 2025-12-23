export const chacha20poly1305 = (key: Uint8Array, nonce: Uint8Array) => {
	void key
	void nonce

	return {
		encrypt(plaintext: Uint8Array): Uint8Array {
			return plaintext
		},
		decrypt(ciphertext: Uint8Array): Uint8Array {
			return ciphertext
		},
	}
}

export const x25519 = {
	utils: {
		randomSecretKey(): Uint8Array {
			return new Uint8Array(32)
		},
	},
	getPublicKey(privateKey: Uint8Array): Uint8Array {
		void privateKey
		return new Uint8Array(32)
	},
	getSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
		void privateKey
		void publicKey
		return new Uint8Array(32)
	},
}

export default {}
