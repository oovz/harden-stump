export type JwtPayload = {
	sub?: string
	jti?: string
	iat?: number
	exp?: number
	secure_library_access?: string[]
	token_type?: string
}

function base64UrlToUtf8(input: string): string {
	let b64 = input.replace(/-/g, '+').replace(/_/g, '/')
	const pad = b64.length % 4
	if (pad) b64 += '='.repeat(4 - pad)

	try {
		// Browser
		return decodeURIComponent(escape(window.atob(b64)))
	} catch {
		try {
			// Node / non-browser
			return Buffer.from(b64, 'base64').toString('utf-8')
		} catch {
			return ''
		}
	}
}

export function parseJwtSecureAccess(token: string): JwtPayload | null {
	if (!token || typeof token !== 'string') return null
	const parts = token.split('.')
	if (parts.length < 2) return null
	const payload = parts[1] || ''
	if (!payload) return null
	const json = base64UrlToUtf8(payload)
	if (!json) return null
	try {
		const parsed = JSON.parse(json)
		return parsed as JwtPayload
	} catch {
		return null
	}
}
