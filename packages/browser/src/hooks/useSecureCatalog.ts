import type { DecryptedCatalog } from '@stump/client'
import { decryptCatalogJSON, useQuery, useSDK } from '@stump/client'

function bytesToB64(bytes: Uint8Array): string {
	if (typeof btoa === 'function') {
		let bin = ''
		for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
		return btoa(bin)
	}
	// Node fallback (not expected in browser build)
	// eslint-disable-next-line @typescript-eslint/ban-ts-comment
	// @ts-ignore
	return Buffer.from(bytes).toString('base64')
}

export function useSecureCatalog(
	libraryId: string,
	getLMK: () => Promise<Uint8Array>,
	options?: { enabled?: boolean },
) {
	const { sdk } = useSDK()

	return useQuery<DecryptedCatalog | null>(
		['secureCatalog', libraryId],
		async () => {
			const url = `${sdk.serviceURL}/secure/libraries/${libraryId}/catalog`
			const headers: Record<string, string> = {}
			if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`

			const resp = await fetch(url, {
				method: 'GET',
				credentials: 'include',
				headers,
			})
			if (!resp.ok) {
				if (resp.status === 404) {
					// Backend masks missing grants and some not-yet-ready states as 404.
					// Treat as unlocked-but-empty per CP8-OVERLAY-003.
					// Revocation is enforced via /access-status (404) which clears LMK.
					return null
				}
				let message = `Failed to fetch encrypted catalog (${resp.status})`
				try {
					const data = await resp.json()
					if (data && typeof data.message === 'string') {
						message = data.message
					}
				} catch {
					// ignore JSON parse errors and fall back to generic message
				}
				throw new Error(message)
			}
			const buf = new Uint8Array(await resp.arrayBuffer())
			const nonce = resp.headers.get('X-Nonce') || ''
			const sizeHeader =
				resp.headers.get('X-Plaintext-Size') || resp.headers.get('X-Original-Size') || '0'
			const originalSize = parseInt(sizeHeader, 10)
			// If nonce or size are missing/invalid, treat as not-ready
			if (!nonce || !Number.isFinite(originalSize) || originalSize < 1) {
				return null
			}
			// Prefer header tag; if missing (e.g., CORS not exposing), derive from body segment [originalSize-16, originalSize)
			let tag = resp.headers.get('X-Tag') || ''
			if (!tag && buf.length >= originalSize && originalSize >= 16) {
				const tagBytes = buf.slice(originalSize - 16, originalSize)
				tag = bytesToB64(tagBytes)
			}
			if (!tag) {
				return null
			}
			const lmk = await getLMK()
			return await decryptCatalogJSON(lmk, buf, nonce, tag, originalSize)
		},
		{ staleTime: 60_000, enabled: options?.enabled ?? true },
	)
}
