import { queryClient, useSDK } from '@stump/client'
import { Button, Input, Label, Text } from '@stump/components'
import { useEffect, useState } from 'react'
import { toast } from 'react-hot-toast'

import { SceneContainer } from '@/components/container'
import { useUserStore } from '@/stores'

import { useLibraryContext } from '../../../context'
import { formatSecureAdminError } from '../../../secureErrorHelpers'

export default function SecureScanSettingsScene() {
	const { library } = useLibraryContext()
	const { sdk } = useSDK()
	const isOwner = useUserStore((s) => !!s.user?.is_server_owner)

	const [smk, setSmk] = useState('')
	const [isScanning, setIsScanning] = useState(false)
	const [status, setStatus] = useState<{
		library_id: string
		encryption_status: string
		encrypted_files: number
		total_files: number
		progress: number
		error?: string | null
	} | null>(null)
	const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
	const isBroken = status?.encryption_status === 'ENCRYPTION_BROKEN'
	const isEncrypting = status?.encryption_status === 'ENCRYPTING'
	const isFailed = status?.encryption_status === 'ENCRYPTION_FAILED'
	const canScan = isOwner && !isBroken
	const isRunningOrQueued = status?.encryption_status === 'ENCRYPTING'

	useEffect(() => {
		if (!isOwner || !sdk.serviceURL || !library?.id) return

		let mounted = true
		const fetchStatus = async () => {
			try {
				const headers: Record<string, string> = {}
				if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
				const resp = await fetch(`${sdk.serviceURL}/admin/secure/libraries/${library.id}/status`, {
					method: 'GET',
					credentials: 'include',
					headers,
				})
				if (!resp.ok) return
				const data = (await resp.json()) as {
					library_id: string
					encryption_status: string
					encrypted_files: number
					total_files: number
					progress: number
					error?: string | null
				}
				if (mounted) {
					setStatus(data)
					setLastUpdated(new Date())
				}
			} catch {
				// ignore polling errors
			}
		}

		// initial fetch + interval polling
		fetchStatus()
		const id = window.setInterval(fetchStatus, 3000)
		return () => {
			mounted = false
			window.clearInterval(id)
		}
	}, [isOwner, sdk.serviceURL, sdk.token, library?.id])

	const handleScan = async () => {
		if (!isOwner) {
			toast.error('Only the server owner can scan secure libraries')
			return
		}
		if (isBroken) {
			toast.error(
				'Cannot scan while encryption is broken. Restore secure storage on the server first.',
			)
			return
		}
		if (!smk.trim()) {
			toast.error('Enter the System Master Key (SMK)')
			return
		}
		if (!sdk.serviceURL) {
			toast.error('Missing service URL')
			return
		}
		if (isRunningOrQueued) {
			toast('A secure scan is already running for this library.')
			return
		}
		try {
			setIsScanning(true)
			const headers: Record<string, string> = {
				'Content-Type': 'application/json',
				'X-SMK': smk.trim(),
			}
			if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
			const resp = await fetch(`${sdk.serviceURL}/admin/secure/libraries/${library.id}/scan`, {
				method: 'POST',
				credentials: 'include',
				headers,
			})
			if (!resp.ok) {
				const friendly = await formatSecureAdminError('scan', resp)
				throw new Error(friendly)
			}
			toast.custom((t) => (
				<div className="flex items-center gap-3 rounded-md border border-edge bg-background px-3 py-2 shadow">
					<div className="text-sm">Scan started. Click to refresh when complete.</div>
					<Button
						size="xs"
						variant="secondary"
						onClick={() => {
							queryClient.invalidateQueries(['secureCatalog', library.id])
							toast.dismiss(t.id)
						}}
					>
						Refresh
					</Button>
				</div>
			))
			// Force a status refresh soon; polling will keep it fresh.
			setTimeout(() => {
				setLastUpdated(new Date())
			}, 250)
		} catch (e) {
			console.error(e)
			toast.error(e instanceof Error ? e.message : 'Failed to start secure scan')
		} finally {
			setIsScanning(false)
		}
	}

	return (
		<SceneContainer>
			<div className="relative flex max-w-xl flex-col gap-4 p-2">
				{isOwner && isEncrypting ? (
					<div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 bg-background/80">
						<Text size="sm" className="font-medium">
							Secure library encryption in progress
						</Text>
						<Text size="sm" variant="muted">
							This page is temporarily locked while files are being encrypted.
						</Text>
						{status ? (
							<Text size="sm" variant="muted" data-testid="secure-encryption-overlay-progress">
								{Math.round(status.progress)}% • {status.encrypted_files} / {status.total_files}{' '}
								files
							</Text>
						) : null}
					</div>
				) : null}
				<div className="flex flex-col gap-1">
					<Label>System Master Key (SMK)</Label>
					<Input
						value={smk}
						onChange={(e) => setSmk(e.target.value)}
						type="password"
						placeholder="Enter SMK to start a secure scan"
					/>
				</div>
				<div className="flex items-center gap-2">
					<Button onClick={handleScan} isLoading={isScanning} disabled={!canScan}>
						Scan Secure Library
					</Button>
					{!isOwner ? (
						<Text size="sm" variant="muted">
							Only the server owner can perform a secure scan.
						</Text>
					) : null}
				</div>
				{isOwner && status ? (
					<div className="mt-2 flex flex-col gap-1">
						<Label>Encryption Status</Label>
						{isBroken ? (
							<Text size="sm">
								Secure library is currently broken. Restore the secure storage on the server and run
								a new secure scan with the System Master Key.
							</Text>
						) : null}
						{!isBroken && isFailed ? (
							<Text size="sm">
								Last encryption run failed. Fix the underlying error and click Scan Secure Library
								to retry.
								{status.error ? ` Error: ${status.error}` : ''}
							</Text>
						) : null}
						<Text size="sm">
							Status: {status.encryption_status}
							{status.error ? ` — ${status.error}` : ''}
						</Text>
						<Text size="sm">
							Progress: {Math.round(status.progress)}% • {status.encrypted_files} /{' '}
							{status.total_files} files
						</Text>
						{lastUpdated ? (
							<Text size="xs" variant="muted">
								Last updated: {lastUpdated.toLocaleTimeString()}
							</Text>
						) : null}
					</div>
				) : null}
				<Text size="sm" variant="muted">
					Secure libraries do not support automatic scanning. Start a manual scan by providing the
					SMK.
				</Text>
			</div>
		</SceneContainer>
	)
}
