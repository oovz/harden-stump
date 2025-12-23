import { useQuery, useSDK } from '@stump/client'

export type SecureLibrarySummary = {
	id: string
	name: string
	is_secure: boolean
	encryption_status: string
}

export function useAccessibleSecureLibraries() {
	const { sdk } = useSDK()

	return useQuery<SecureLibrarySummary[]>(['secureLibraries'], async () => {
		const url = `${sdk.serviceURL}/secure/libraries`
		const headers: Record<string, string> = {}
		if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
		const resp = await fetch(url, { method: 'GET', credentials: 'include', headers })
		if (!resp.ok) throw new Error(`Failed to fetch secure libraries (${resp.status})`)
		return (await resp.json()) as SecureLibrarySummary[]
	})
}
