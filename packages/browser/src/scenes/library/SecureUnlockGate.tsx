import {
	decryptPrivateKeyWithPassword,
	encryptPrivateKeyWithPassword,
	generateX25519Keypair,
	unwrapLmkX25519AesGcm,
	useSDK,
} from '@stump/client'
import { Button, Input, Text } from '@stump/components'
import { useEffect, useState } from 'react'
import { toast } from 'react-hot-toast'

import Spinner from '@/components/Spinner'
import { useSecureCatalog } from '@/hooks/useSecureCatalog'
import { useSecureLibrary } from '@/hooks/useSecureLibrary'
import { useLmkStore } from '@/stores'

import { useLibraryContext } from './context'

function b64ToBytes(b64: string): Uint8Array {
	if (typeof atob === 'function') {
		const bin = atob(b64)
		const bytes = new Uint8Array(bin.length)
		for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
		return bytes
	}
	return Uint8Array.from([])
}

export default function SecureUnlockGate() {
	const { sdk } = useSDK()
	const { library } = useLibraryContext()

	const handleGoBack = () => {
		try {
			if (typeof window !== 'undefined' && window.history.length > 1) {
				window.history.back()
				return
			}
		} catch (e) {
			void e
		}
		window.location.assign('/libraries')
	}
	const { isSecure, isNotEncrypted, access, hasAccess, lmk, getLMKForCatalog } = useSecureLibrary({
		libraryId: library.id,
		isSecure: Boolean((library as Record<string, unknown>)['is_secure']),
		encryptionStatus: (library as Record<string, unknown>)['encryption_status'] as
			| string
			| undefined,
	})
	const [notifiedNoAccess, setNotifiedNoAccess] = useState(false)

	const { privateKey, setPrivateKey, setPublicKey, setLMK } = useLmkStore((s) => ({
		privateKey: s.privateKey,
		setPrivateKey: s.setPrivateKey,
		setPublicKey: s.setPublicKey,
		setLMK: s.setLMK,
	}))

	const [password, setPassword] = useState('')
	const [isWorking, setIsWorking] = useState(false)
	const [showAdvanced, setShowAdvanced] = useState(false)
	const [unlockError, setUnlockError] = useState<string | null>(null)
	const [progressStep, setProgressStep] = useState<string | null>(null)

	const { isLoading: isDecrypting, refetch } = useSecureCatalog(library.id, getLMKForCatalog, {
		enabled: isSecure && hasAccess && !!lmk && !isNotEncrypted,
	})

	useEffect(() => {
		if (isSecure && access && access.has_access === false && !notifiedNoAccess) {
			toast.error('Access to this secure library has been revoked or is not available.', {
				id: 'no-access',
			})
			setNotifiedNoAccess(true)
		}
	}, [isSecure, access, notifiedNoAccess])

	useEffect(() => {
		// If we just set LMK, refetch catalog (but only once encryption has actually run)
		if (isSecure && hasAccess && lmk && !isNotEncrypted) {
			void refetch()
		}
	}, [isSecure, hasAccess, lmk, isNotEncrypted, refetch])

	useEffect(() => {
		if (isSecure && hasAccess && privateKey && !lmk && !unlockError) {
			void handleFetchAndUnwrapLMK(privateKey)
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [isSecure, hasAccess, privateKey, lmk, unlockError])

	const handleRestoreKeypair = async (pwd: string): Promise<Uint8Array | null> => {
		try {
			if (!sdk.serviceURL) throw new Error('Missing serviceURL')
			if (!pwd.trim()) throw new Error('Enter password')
			setProgressStep('Deriving KEK')
			const url = `${sdk.serviceURL}/users/me/keypair`
			const headers: Record<string, string> = {}
			if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
			const resp = await fetch(url, { method: 'GET', credentials: 'include', headers })
			if (resp.status === 404) {
				throw new Error('No secure keypair found for your account.')
			}
			if (!resp.ok) throw new Error(`Failed to fetch keypair (${resp.status})`)
			const { public_key, encrypted_private, nonce, salt } = await resp.json()
			const priv = await decryptPrivateKeyWithPassword(encrypted_private, nonce, salt, pwd)
			const pub = b64ToBytes(public_key)
			setPrivateKey(priv)
			setPublicKey(pub)
			setPassword('')
			setUnlockError(null)
			return priv
		} catch (e) {
			console.error(e)
			const msg = e instanceof Error ? e.message : 'Failed to restore your secure keypair.'
			setUnlockError(msg)
			toast.error(msg)
			return null
		} finally {
			// no-op
		}
	}

	const handleGenerateAndUploadKeypair = async (pwd: string): Promise<Uint8Array | null> => {
		try {
			if (!sdk.serviceURL) throw new Error('Missing serviceURL')
			if (!pwd.trim()) throw new Error('Enter password')
			setProgressStep('Deriving KEK')
			const { publicKey: pub, privateKey: priv, publicKeyB64 } = await generateX25519Keypair()
			const { encrypted_private, nonce, salt } = await encryptPrivateKeyWithPassword(priv, pwd)
			const url = `${sdk.serviceURL}/users/me/keypair`
			const headers: Record<string, string> = { 'Content-Type': 'application/json' }
			if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
			const resp = await fetch(url, {
				method: 'PUT',
				credentials: 'include',
				headers,
				body: JSON.stringify({ public_key: publicKeyB64, encrypted_private, nonce, salt }),
			})
			if (!resp.ok) throw new Error(`Failed to upload keypair (${resp.status})`)
			setPrivateKey(priv)
			setPublicKey(pub)
			setPassword('')
			setUnlockError(null)
			toast.success('Secure keypair generated and saved to your account.')
			return priv
		} catch (e) {
			console.error(e)
			const msg = e instanceof Error ? e.message : 'Failed to generate your secure keypair.'
			setUnlockError(msg)
			toast.error(msg)
			return null
		} finally {
			// no-op
		}
	}

	const handleFetchAndUnwrapLMK = async (key: Uint8Array) => {
		try {
			if (!sdk.serviceURL) throw new Error('Missing serviceURL')
			setIsWorking(true)
			setProgressStep('Unwrapping LMK')
			const url = `${sdk.serviceURL}/secure/libraries/${library.id}/access`
			const headers: Record<string, string> = {}
			if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
			const resp = await fetch(url, { method: 'GET', credentials: 'include', headers })
			if (!resp.ok) throw new Error(`Failed to fetch wrapped LMK (${resp.status})`)
			const wrappedJson = (await resp.json()) as {
				encrypted_lmk: string
				lmk_ephemeral_public: string
				lmk_nonce: string
			}
			const wrapped = {
				encrypted_lmk: wrappedJson.encrypted_lmk,
				ephemeral_public: wrappedJson.lmk_ephemeral_public,
				nonce: wrappedJson.lmk_nonce,
			}
			const lmkBytes = await unwrapLmkX25519AesGcm(wrapped, key)
			setLMK(library.id, lmkBytes)
			setUnlockError(null)
			setProgressStep('Decrypting catalog')
			await refetch()
		} catch (e) {
			console.error(e)
			const msg =
				e instanceof Error
					? e.message
					: 'Failed to unlock this secure library. Your keypair may be out of date or access has been revoked.'
			setUnlockError(msg)
			toast.error(
				'Failed to unlock this secure library. If this persists, ask the library owner to re-grant access and try again.',
			)
		} finally {
			setIsWorking(false)
			setProgressStep(null)
		}
	}

	const handleUnlock = async () => {
		if (isWorking) return
		try {
			setUnlockError(null)
			setIsWorking(true)
			let key = privateKey
			if (!key) {
				if (!password.trim()) {
					toast.error('Enter your password to unlock')
					return
				}
				key = await handleRestoreKeypair(password)
			}
			if (!key) {
				setShowAdvanced(true)
				return
			}
			await handleFetchAndUnwrapLMK(key)
		} finally {
			setIsWorking(false)
			setProgressStep(null)
		}
	}

	const handleGenerateNewKeypairAndUnlock = async () => {
		if (isWorking) return
		try {
			setUnlockError(null)
			setIsWorking(true)
			if (!password.trim()) {
				toast.error('Enter your password to generate a keypair')
				return
			}
			const key = await handleGenerateAndUploadKeypair(password)
			if (!key) return
			await handleFetchAndUnwrapLMK(key)
		} finally {
			setIsWorking(false)
		}
	}

	if (!isSecure) return null
	if (!hasAccess) {
		return (
			<div className="absolute inset-0 z-20 flex items-center justify-center bg-black/60 backdrop-blur-sm">
				<div className="w-full max-w-md rounded-lg border border-edge bg-background p-4 shadow-xl">
					<Text size="sm" className="font-medium">
						Secure library unavailable
					</Text>
					<Text size="sm" variant="muted" className="mt-1">
						Access to this secure library has been revoked or is not available.
					</Text>
					<div className="mt-3 flex">
						<Button size="sm" variant="secondary" onClick={handleGoBack}>
							Go back
						</Button>
					</div>
				</div>
			</div>
		)
	}

	// If LMK missing, prompt for password to restore or generate keypair, then unwrap LMK
	if (!lmk) {
		const shouldAutoUnlock = !!privateKey && !unlockError
		return (
			<div className="absolute inset-0 z-20 flex items-center justify-center bg-black/60 backdrop-blur-sm">
				<div className="w-full max-w-md rounded-lg border border-edge bg-background p-4 shadow-xl">
					<Text size="sm" className="font-medium">
						Unlock secure library
					</Text>
					<Text size="sm" variant="muted" className="mt-1">
						We use your account keypair to decrypt the library key. Your keys are stored in memory
						only.
					</Text>

					{unlockError ? (
						<Text size="sm" className="mt-2" variant="danger">
							{unlockError}
						</Text>
					) : null}

					{shouldAutoUnlock ? (
						<div className="mt-3 flex items-center gap-2 text-sm text-foreground-muted">
							<div className="h-4 w-4">
								<Spinner />
							</div>
							{progressStep || 'Unlocking…'}
						</div>
					) : (
						<>
							<div className="mt-3">
								<Input
									value={password}
									type="password"
									placeholder="Account password"
									onChange={(e) => setPassword(e.target.value)}
								/>
								<Text size="xs" variant="muted" className="mt-1">
									Used to restore your encrypted private key from your account, or to encrypt a new
									one.
								</Text>
							</div>

							<div className="mt-3 flex items-center justify-between">
								<Button size="sm" variant="secondary" onClick={handleGoBack} disabled={isWorking}>
									Cancel
								</Button>
								<div className="flex items-center gap-2">
									<Button
										size="sm"
										variant="ghost"
										onClick={() => setShowAdvanced((v) => !v)}
										disabled={isWorking}
									>
										Advanced
									</Button>
									<Button size="sm" variant="primary" onClick={handleUnlock} disabled={isWorking}>
										Unlock
									</Button>
								</div>
							</div>
							{showAdvanced ? (
								<div className="mt-3 flex flex-col gap-2 rounded-md border border-edge-subtle bg-background-surface p-3">
									<Text size="sm" className="font-medium">
										Keypair options
									</Text>
									<Text size="xs" variant="muted">
										Generating a new keypair can require the library owner to re-grant access.
									</Text>
									<div className="flex flex-wrap items-center gap-2">
										<Button
											size="sm"
											variant="secondary"
											onClick={async () => {
												if (isWorking) return
												try {
													setIsWorking(true)
													if (!password.trim()) {
														toast.error('Enter your password to restore your keypair')
														return
													}
													const key = await handleRestoreKeypair(password)
													if (!key) return
													await handleFetchAndUnwrapLMK(key)
												} finally {
													setIsWorking(false)
												}
											}}
											disabled={isWorking}
										>
											Restore keypair
										</Button>
										<Button
											size="sm"
											variant="secondary"
											onClick={handleGenerateNewKeypairAndUnlock}
											disabled={isWorking}
										>
											Generate new keypair
										</Button>
									</div>
								</div>
							) : null}
						</>
					)}
				</div>
			</div>
		)
	}

	// LMK present: while catalog is being fetched/decrypted, block with spinner
	if (isDecrypting) {
		return (
			<div className="absolute inset-0 z-20 flex items-center justify-center bg-black/60 backdrop-blur-sm">
				<div className="flex items-center gap-2 rounded-lg border border-edge bg-background px-4 py-2 text-sm shadow-xl">
					<div className="h-4 w-4">
						<Spinner />
					</div>
					Decrypting library...
				</div>
			</div>
		)
	}

	// LMK present but catalog is null (e.g., 404 / not yet generated):
	// treat as unlocked but empty; do not block the underlying UI.
	return null
}
