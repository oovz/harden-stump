export type SecureErrorPayload = {
	error?: string
	message?: string
}

function parseSecureErrorBody(raw: string): SecureErrorPayload {
	try {
		return JSON.parse(raw) as SecureErrorPayload
	} catch {
		return {}
	}
}

export async function formatSecureAdminError(
	action: 'create' | 'scan',
	resp: Response,
): Promise<string> {
	const status = resp.status
	let raw = ''
	try {
		raw = await resp.text()
	} catch {
		// If we cannot read the body, fall back to a generic message
		return action === 'create'
			? `Failed to create secure library (${status})`
			: `Failed to start secure scan (${status})`
	}

	const { error, message } = parseSecureErrorBody(raw)

	const base =
		action === 'create' ? 'Failed to create secure library' : 'Failed to start secure scan'

	const fallback = message || `${base} (${status})`

	if (!error) {
		return fallback
	}

	switch (error) {
		case 'secure_dir_present':
			return 'This path already has a secure library configured (secure_dir_present).'
		case 'path_not_found':
			return 'The selected library path does not exist on the server (path_not_found).'
		case 'invalid_smk_format':
			return 'The System Master Key (SMK) format is invalid (invalid_smk_format).'
		case 'invalid_smk':
			return 'The System Master Key (SMK) is incorrect for this library (invalid_smk).'
		case 'forbidden':
			return 'You do not have permission to perform this secure library action (forbidden).'
		case 'missing_user_keypair':
			return 'You must generate a secure keypair for your account before creating a secure library (missing_user_keypair).'
		case 'user_not_found':
			return 'The server could not find your user while auto-granting access (user_not_found).'
		case 'job_already_running':
			return 'A background job is already running. Wait for it to finish before starting a secure library scan (job_already_running).'
		default:
			return fallback
	}
}
