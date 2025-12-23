import {
	decryptPrivateKeyWithPassword,
	encryptPrivateKeyWithPassword,
	generateX25519Keypair,
	useLoginOrRegister,
	useSDK,
} from '@stump/client'
import { Button, Dialog, Input, Text } from '@stump/components'
import { FormEvent, useCallback, useState } from 'react'
import toast from 'react-hot-toast'

import { useLmkStore, useUserStore } from '@/stores'

interface Props {
	isOpen: boolean
	onDone: () => void
	onForceLogout: () => void
}

export default function SessionRestoreModal({ isOpen, onDone, onForceLogout }: Props) {
	const { user, setUser } = useUserStore((store) => ({
		setUser: store.setUser,
		user: store.user,
	}))
	const { sdk } = useSDK()

	const [password, setPassword] = useState('')
	const [submitError, setSubmitError] = useState<string | null>(null)

	const restoreKeypairWithPassword = useCallback(
		async (pwd: string) => {
			try {
				if (!sdk.serviceURL) {
					return
				}
				if (!pwd.trim()) {
					return
				}
				const url = `${sdk.serviceURL}/users/me/keypair`
				const headers: Record<string, string> = {}
				if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
				const resp = await fetch(url, { method: 'GET', credentials: 'include', headers })
				if (resp.ok) {
					const { public_key, encrypted_private, nonce, salt } = (await resp.json()) as {
						public_key: string
						encrypted_private: string
						nonce: string
						salt: string
					}
					const priv = await decryptPrivateKeyWithPassword(encrypted_private, nonce, salt, pwd)
					const bin = typeof atob === 'function' ? atob(public_key) : ''
					const pubBytes = new Uint8Array(bin.length)
					for (let i = 0; i < bin.length; i++) {
						pubBytes[i] = bin.charCodeAt(i)
					}
					const { setPrivateKey, setPublicKey } = useLmkStore.getState()
					setPrivateKey(priv)
					setPublicKey(pubBytes)
					return
				}
				if (resp.status !== 404) {
					return
				}
				const toastId = toast.loading('Generating secure keypair...')
				try {
					const { publicKey: pub, privateKey: priv, publicKeyB64 } = await generateX25519Keypair()
					const { encrypted_private, nonce, salt } = await encryptPrivateKeyWithPassword(priv, pwd)
					const putHeaders: Record<string, string> = { 'Content-Type': 'application/json' }
					if (sdk.token) putHeaders['Authorization'] = `Bearer ${sdk.token}`
					const putResp = await fetch(url, {
						method: 'PUT',
						credentials: 'include',
						headers: putHeaders,
						body: JSON.stringify({ public_key: publicKeyB64, encrypted_private, nonce, salt }),
					})
					if (!putResp.ok) {
						throw new Error(`Failed to upload keypair (${putResp.status})`)
					}
					const { setPrivateKey, setPublicKey } = useLmkStore.getState()
					setPrivateKey(priv)
					setPublicKey(pub)
					toast.success('Secure keypair generated', { id: toastId })
				} catch (error) {
					console.error('Error generating keypair after session restore:', error)
					toast.error('Failed to set up secure keypair. You can try again later.', {
						id: toastId,
					})
				}
			} catch (error) {
				console.error('Error restoring keypair during session restore:', error)
			}
		},
		[sdk.serviceURL, sdk.token],
	)

	const { isLoggingIn, loginUser } = useLoginOrRegister({
		onSuccess: async (loggedInUser) => {
			if (!loggedInUser) {
				return
			}
			setUser(loggedInUser)
			if (password.trim()) {
				await restoreKeypairWithPassword(password)
			}
			setPassword('')
			setSubmitError(null)
			onDone()
		},
		onError: (err) => {
			console.error('Error during session restoration login:', err)
			setSubmitError('Re-authentication failed. You can try again or go to the login screen.')
		},
		refetchClaimed: false,
	})

	const handleSubmit = useCallback(
		async (event: FormEvent<HTMLFormElement>) => {
			event.preventDefault()
			if (!user || !user.username) {
				onForceLogout()
				return
			}
			if (!password.trim()) {
				setSubmitError('Password is required to restore your session.')
				return
			}
			setSubmitError(null)
			await loginUser({ username: user.username, password })
		},
		[loginUser, onForceLogout, password, user],
	)

	const handleOpenChange = (nowOpen: boolean) => {
		if (!nowOpen) {
			onForceLogout()
		}
	}

	return (
		<Dialog open={isOpen} onOpenChange={handleOpenChange}>
			<Dialog.Content size="sm">
				<Dialog.Header>
					<Dialog.Title>Session expired</Dialog.Title>
					<Dialog.Description>
						<Text size="sm">
							Re-enter your password to continue as <strong>{user?.username}</strong>. Your current
							view will be restored after successful re-authentication.
						</Text>
					</Dialog.Description>
					<Dialog.Close onClick={onForceLogout} />
				</Dialog.Header>

				<form className="flex flex-col gap-4" onSubmit={handleSubmit}>
					<Input
						id="session-restore-password"
						label="Password"
						variant="primary"
						type="password"
						autoComplete="current-password"
						value={password}
						onChange={(event) => setPassword(event.target.value)}
						fullWidth
					/>
					{submitError ? (
						<Text size="sm" className="text-red-500">
							{submitError}
						</Text>
					) : null}

					<Dialog.Footer className="flex w-full flex-col-reverse gap-2 sm:flex-row sm:justify-end sm:gap-3">
						<Button type="button" variant="ghost" onClick={onForceLogout}>
							Go to login
						</Button>
						<Button type="submit" variant="primary" isLoading={isLoggingIn}>
							Re-authenticate
						</Button>
					</Dialog.Footer>
				</form>
			</Dialog.Content>
		</Dialog>
	)
}
