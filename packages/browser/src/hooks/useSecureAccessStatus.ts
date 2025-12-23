import { useQuery, useSDK } from '@stump/client'

import { useLmkStore } from '@/stores'

export function useSecureAccessStatus(libraryId?: string) {
	const { sdk } = useSDK()

	return useQuery<{ has_access: boolean }>(
		['secureAccessStatus', libraryId],
		async () => {
			if (!libraryId) throw new Error('Missing libraryId')
			const url = `${sdk.serviceURL}/secure/libraries/${libraryId}/access-status`
			const headers: Record<string, string> = {}
			if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
			const resp = await fetch(url, { method: 'GET', credentials: 'include', headers })
			if (resp.status === 404) {
				// Backend masks missing grants and revoked access as 404; clear any cached LMK
				// for this library and treat as no access for current user.
				const { clearLMK } = useLmkStore.getState()
				clearLMK(libraryId)
				return { has_access: false }
			}
			if (!resp.ok) {
				throw new Error(`Failed to fetch access (${resp.status})`)
			}
			// If we successfully fetched wrapped LMK metadata, the user has access.
			// We intentionally ignore the ciphertext here; SecureUnlockGate will fetch
			// and unwrap LMK when needed.
			await resp.json()
			return { has_access: true }
		},
		{ enabled: !!libraryId },
	)
}
