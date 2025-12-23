import { useEffect } from 'react'
import { StumpWebClient } from '@stump/browser'

const getDebugUrl = () => {
	const { hostname } = window.location
	return `http://${hostname}:10801`
}

export const baseUrl = import.meta.env.PROD ? window.location.origin : getDebugUrl()

function useSessionHeartbeat() {
	useEffect(() => {
		let intervalId: number | null = null
		let lastVisibilityChange = Date.now()

		const ping = async () => {
			if (document.visibilityState !== 'visible') {
				return
			}

			try {
				await fetch(`${baseUrl}/api/v1/session/heartbeat`, {
					method: 'POST',
					credentials: 'include',
					headers: { 'Content-Type': 'application/json' },
				})
			} catch {
				return
			}
		}

		const start = () => {
			if (intervalId === null) {
				intervalId = window.setInterval(ping, 5 * 60 * 1000)
			}
		}

		const stop = () => {
			if (intervalId !== null) {
				window.clearInterval(intervalId)
				intervalId = null
			}
		}

		const handleVisibilityChange = () => {
			const now = Date.now()
			if (document.visibilityState === 'visible') {
				const elapsed = now - lastVisibilityChange
				lastVisibilityChange = now
				if (elapsed <= 30 * 60 * 1000) {
					void ping()
				}
				start()
			} else {
				lastVisibilityChange = now
				stop()
			}
		}

		document.addEventListener('visibilitychange', handleVisibilityChange)
		handleVisibilityChange()

		return () => {
			document.removeEventListener('visibilitychange', handleVisibilityChange)
			stop()
		}
	}, [])
}

export default function App() {
	useSessionHeartbeat()
	return <StumpWebClient platform={'browser'} baseUrl={baseUrl} />
}
