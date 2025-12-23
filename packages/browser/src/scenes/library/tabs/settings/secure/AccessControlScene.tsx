import { useSDK, useUsersQuery } from '@stump/client'
import { Button, Input, Label, Text } from '@stump/components'
import { useEffect, useMemo, useState } from 'react'

import { SceneContainer } from '@/components/container'
import { useUserStore } from '@/stores'

import { useLibraryContext } from '../../../context'

type AccessListUser = {
	user_id: string
	username: string
	granted_at: string
	is_revoked: boolean
}

type AccessListWire = {
	users: AccessListUser[]
}

type AccessListResponse = {
	users: AccessListUser[]
}

export default function AccessControlScene() {
	const { library } = useLibraryContext()
	const { sdk } = useSDK()
	const isOwner = useUserStore((s) => !!s.user?.is_server_owner)
	const myUserId = useUserStore((s) => s.user?.id)
	const { users: allUsers } = useUsersQuery({ page: 0, page_size: 100 })

	const [list, setList] = useState<AccessListResponse | null>(null)
	const [loadingList, setLoadingList] = useState(false)
	const [userId, setUserId] = useState('')
	const [smk, setSmk] = useState('')
	const [isGranting, setIsGranting] = useState(false)
	const [isRevoking, setIsRevoking] = useState(false)

	const headersWithAuth = useMemo(() => {
		const headers: Record<string, string> = { 'Content-Type': 'application/json' }
		if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
		return headers
	}, [sdk.token])

	const fetchList = async () => {
		if (!sdk.serviceURL || !library?.id) return
		try {
			setLoadingList(true)
			const resp = await fetch(`${sdk.serviceURL}/admin/secure/libraries/${library.id}/access`, {
				method: 'GET',
				credentials: 'include',
				headers: headersWithAuth,
			})
			if (!resp.ok) return
			const data = (await resp.json()) as AccessListWire
			setList({
				users: data.users ?? [],
			})
		} catch {
			// ignore
		} finally {
			setLoadingList(false)
		}
	}

	useEffect(() => {
		fetchList()
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [sdk.serviceURL, sdk.token, library?.id])

	const b64ToBytes = (b64: string): Uint8Array => {
		const bin = typeof atob === 'function' ? atob(b64) : ''
		const bytes = new Uint8Array(bin.length)
		for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
		return bytes
	}

	const handleGrant = async () => {
		if (!isOwner) return
		if (!sdk.serviceURL) return
		if (!userId.trim()) {
			alert('Enter a user ID')
			return
		}
		if (!smk.trim()) {
			alert('Enter the System Master Key (SMK)')
			return
		}
		const smkBytes = b64ToBytes(smk.trim())
		if (smkBytes.length !== 32) {
			alert('SMK must be a base64-encoded 32-byte key')
			return
		}
		try {
			setIsGranting(true)
			const headers: Record<string, string> = { ...headersWithAuth, 'X-SMK': smk.trim() }
			const resp = await fetch(
				`${sdk.serviceURL}/admin/secure/libraries/${library.id}/grant-access`,
				{
					method: 'POST',
					credentials: 'include',
					headers,
					body: JSON.stringify({ user_id: userId.trim() }),
				},
			)
			if (!resp.ok) {
				let msg = `Failed to grant access (${resp.status})`
				try {
					const data = (await resp.json()) as { error?: unknown; message?: unknown }
					if (data && typeof data === 'object') {
						if (data.error === 'missing_user_keypair') {
							msg = 'User must log in once to generate a keypair before access can be granted.'
						} else if (typeof data.message === 'string') {
							msg = data.message
						}
					}
				} catch {
					try {
						const raw = await resp.text()
						if (raw) msg = `Failed to grant access (${resp.status}): ${raw}`
					} catch {
						// no-op
					}
				}
				throw new Error(msg)
			}
			setSmk('')
			setUserId('')
			await fetchList()
		} catch (e) {
			console.error(e)
			alert(e instanceof Error ? e.message : 'Failed to grant access')
		} finally {
			setIsGranting(false)
		}
	}

	const handleRevoke = async () => {
		if (!isOwner) return
		if (!sdk.serviceURL) return
		if (!userId.trim()) {
			alert('Enter a user ID')
			return
		}
		if (!window.confirm('Are you sure you want to revoke access for this user?')) {
			return
		}
		try {
			setIsRevoking(true)
			const resp = await fetch(
				`${sdk.serviceURL}/admin/secure/libraries/${library.id}/revoke-access`,
				{
					method: 'POST',
					credentials: 'include',
					headers: headersWithAuth,
					body: JSON.stringify({ user_id: userId.trim() }),
				},
			)
			if (!resp.ok) {
				const msg = await resp.text()
				throw new Error(`Failed to revoke access (${resp.status}): ${msg}`)
			}
			setUserId('')
			await fetchList()
		} catch (e) {
			console.error(e)
			alert(e instanceof Error ? e.message : 'Failed to revoke access')
		} finally {
			setIsRevoking(false)
		}
	}

	return (
		<SceneContainer>
			<div className="flex max-w-3xl flex-col gap-4 p-2">
				<div className="flex flex-col gap-2 md:max-w-sm">
					<Label>User</Label>
					{allUsers && allUsers.length > 0 ? (
						<select
							className="rounded-md border border-edge bg-background px-2 py-1 text-sm"
							value={userId}
							onChange={(e) => setUserId(e.target.value)}
						>
							<option value="">Select a user</option>
							{allUsers.map((u) => (
								<option key={u.id} value={u.id}>
									{u.username} ({u.id})
								</option>
							))}
						</select>
					) : (
						<Text size="xs" variant="muted">
							No users loaded; enter a user ID manually.
						</Text>
					)}
					<Input
						value={userId}
						onChange={(e) => setUserId(e.target.value)}
						placeholder="Target user ID"
					/>
					<div className="flex items-center gap-2 pt-1">
						<Button
							size="xs"
							variant="secondary"
							onClick={() => myUserId && setUserId(myUserId)}
							disabled={!myUserId}
						>
							Use my ID
						</Button>
						{myUserId ? (
							<Text size="xs" variant="muted">
								Your ID: <span className="font-mono">{myUserId}</span>
							</Text>
						) : null}
					</div>
				</div>
				<div className="flex flex-col gap-1 md:max-w-sm">
					<Label>System Master Key (base64)</Label>
					<Input
						value={smk}
						onChange={(e) => setSmk(e.target.value)}
						placeholder="Required for grant access"
						type="password"
					/>
					<Text size="xs" variant="muted">
						SMK is only required for grant access
					</Text>
				</div>
				<div className="flex items-center gap-2">
					<Button onClick={handleGrant} isLoading={isGranting} disabled={!isOwner}>
						Grant access
					</Button>
					<Button
						variant="secondary"
						onClick={handleRevoke}
						isLoading={isRevoking}
						disabled={!isOwner}
					>
						Revoke access
					</Button>
					{!isOwner ? (
						<Text size="sm" variant="muted">
							Only the server owner can manage secure access.
						</Text>
					) : null}
				</div>

				<div className="mt-4">
					<Label>Access grants</Label>
					{loadingList ? (
						<Text size="sm" variant="muted">
							Loading access list...
						</Text>
					) : list && list.users.length > 0 ? (
						<div className="flex flex-col divide-y divide-edge-subtle rounded-md border border-edge">
							{list.users.map((g) => (
								<div key={g.user_id} className="flex items-center justify-between p-3">
									<div className="flex flex-col text-sm">
										<div>
											<span className="font-semibold">{g.username}</span>{' '}
											<span className="font-mono text-xs text-foreground-muted">({g.user_id})</span>
											{g.is_revoked ? (
												<Text size="xs" variant="muted">
													Revoked
												</Text>
											) : null}
										</div>
										<Text size="xs" variant="muted">
											Granted: {new Date(g.granted_at).toLocaleString()}
										</Text>
									</div>
									<div className="flex items-center gap-2">
										<Button
											size="sm"
											variant="secondary"
											disabled={!isOwner || g.is_revoked}
											onClick={async () => {
												setUserId(g.user_id)
												await handleRevoke()
											}}
										>
											Revoke
										</Button>
									</div>
								</div>
							))}
						</div>
					) : (
						<Text size="sm" variant="muted">
							No access grants found.
						</Text>
					)}
				</div>
			</div>
		</SceneContainer>
	)
}
