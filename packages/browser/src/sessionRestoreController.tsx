import { useState } from 'react'

import SessionRestoreModal from '@/components/SessionRestoreModal'
import { clearSecureReaderCache } from '@/secure/readerCache'
import { useLmkStore, useUserStore } from '@/stores'

export const LAST_AUTH_KEY = 'stump:last_full_auth_at'

function safeGetLastAuth(): number | null {
	try {
		const raw = window.localStorage.getItem(LAST_AUTH_KEY)
		if (!raw) {
			return null
		}
		const value = Number.parseInt(raw, 10)
		if (!Number.isFinite(value)) {
			return null
		}
		return value
	} catch {
		return null
	}
}

function safeSetLastAuth(timestamp: number) {
	try {
		window.localStorage.setItem(LAST_AUTH_KEY, timestamp.toString())
	} catch {
		return
	}
}

function safeClearLastAuth() {
	try {
		window.localStorage.removeItem(LAST_AUTH_KEY)
	} catch {
		return
	}
}

type Params = {
	onExternalUnauthenticated?: (redirectUrl?: string, data?: unknown) => void
	handleRedirect: (url: string) => void
}

export function useSessionRestoreController({ onExternalUnauthenticated, handleRedirect }: Params) {
	const [isSessionRestoreOpen, setIsSessionRestoreOpen] = useState(false)
	const { setUser, user } = useUserStore((store) => ({
		setUser: store.setUser,
		user: store.user,
	}))

	const handleUnauthenticatedResponse = (redirectUrl?: string) => {
		const { clearLMK, clearKeypair } = useLmkStore.getState()
		clearLMK()
		clearKeypair()
		clearSecureReaderCache()

		const lastAuth = safeGetLastAuth()
		const now = Date.now()
		const sevenDaysMs = 7 * 24 * 60 * 60 * 1000
		const withinWindow = lastAuth !== null && now - lastAuth <= sevenDaysMs

		if (user && withinWindow) {
			setIsSessionRestoreOpen(true)
			return
		}

		onExternalUnauthenticated?.(redirectUrl)
		setUser(null)
		if (redirectUrl) {
			handleRedirect(redirectUrl)
		}
	}

	const modal = (
		<SessionRestoreModal
			isOpen={isSessionRestoreOpen}
			onDone={() => {
				safeSetLastAuth(Date.now())
				setIsSessionRestoreOpen(false)
			}}
			onForceLogout={() => {
				safeClearLastAuth()
				setIsSessionRestoreOpen(false)
				setUser(null)
				handleRedirect('/auth')
			}}
		/>
	)

	return { handleUnauthenticatedResponse, modal }
}
