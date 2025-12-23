import { create } from 'zustand'

// In-memory LMK store for MVP. Never persist.
export type LmkStore = {
	lmks: Record<string, Uint8Array>
	setLMK: (libraryId: string, lmk: Uint8Array) => void
	getLMK: (libraryId: string) => Uint8Array | undefined
	clearLMK: (libraryId?: string) => void
	// Web-only MVP: hold user keypair in memory (never persist)
	privateKey?: Uint8Array | null
	publicKey?: Uint8Array | null
	setPrivateKey: (key: Uint8Array | null) => void
	setPublicKey: (key: Uint8Array | null) => void
	clearKeypair: () => void
}

export const useLmkStore = create<LmkStore>((set, get) => ({
	lmks: {},
	setLMK: (libraryId, lmk) => set((s) => ({ lmks: { ...s.lmks, [libraryId]: lmk } })),
	getLMK: (libraryId) => get().lmks[libraryId],
	clearLMK: (libraryId) =>
		set((s) => {
			if (!libraryId) return { lmks: {} }
			const copy = { ...s.lmks }
			delete copy[libraryId]
			return { lmks: copy }
		}),
	privateKey: null,
	publicKey: null,
	setPrivateKey: (key) => set(() => ({ privateKey: key })),
	setPublicKey: (key) => set(() => ({ publicKey: key })),
	clearKeypair: () => set(() => ({ privateKey: null, publicKey: null })),
}))
