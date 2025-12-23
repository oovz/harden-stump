import {
	decryptAesGcm,
	decryptPrivateKeyWithPassword,
	deriveDEK,
	encryptPrivateKeyWithPassword,
	generateX25519Keypair,
	unwrapLmkX25519AesGcm,
	useSDK,
} from '@stump/client'
import { Button, Input, Text } from '@stump/components'
import type { Media } from '@stump/sdk'
import { unzipSync } from 'fflate'
import { useEffect, useState } from 'react'
import { Helmet } from 'react-helmet'
import { toast } from 'react-hot-toast'

import { ImageBasedReader } from '@/components/readers/imageBased'
import { useSecureAccessStatus } from '@/hooks/useSecureAccessStatus'
import { useSecureCatalog } from '@/hooks/useSecureCatalog'
import { getCachedSecurePages, putCachedSecurePages } from '@/secure/readerCache'
import { useLmkStore, useUserStore } from '@/stores'

import { useLibraryContext } from '../../context'
import { formatSecureAdminError } from '../../secureErrorHelpers'

function b64ToBytes(b64: string): Uint8Array {
	if (typeof atob === 'function') {
		const bin = atob(b64)
		const bytes = new Uint8Array(bin.length)
		for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
		return bytes
	}
	return Uint8Array.from([])
}

function bytesToB64(bytes: Uint8Array): string {
	if (typeof btoa === 'function') {
		let bin = ''
		for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
		return btoa(bin)
	}
	return ''
}

export default function SecureLibraryScene() {
	const { library } = useLibraryContext()
	const { data: access } = useSecureAccessStatus(library.id)
	const hasAccess = access?.has_access === true
	const [notifiedNoAccess, setNotifiedNoAccess] = useState(false)

	useEffect(() => {
		if (access && access.has_access === false && !notifiedNoAccess) {
			toast.error('Access to this secure library has been revoked or is not available.', {
				id: 'no-access',
			})
			setNotifiedNoAccess(true)
		}
	}, [access, access?.has_access, notifiedNoAccess])

	const { getLMK, setLMK, clearLMK, privateKey, publicKey, setPrivateKey, setPublicKey } =
		useLmkStore((s) => ({
			getLMK: s.getLMK,
			setLMK: s.setLMK,
			clearLMK: s.clearLMK,
			privateKey: s.privateKey,
			publicKey: s.publicKey,
			setPrivateKey: s.setPrivateKey,
			setPublicKey: s.setPublicKey,
		}))
	const [lmkB64, setLmkB64] = useState('')
	const [password, setPassword] = useState('')

	const lmk = getLMK(library.id)

	const getLMKAsync = async () => {
		const key = getLMK(library.id)
		if (!key) throw new Error('LMK not set')
		return key
	}

	const handleRestoreKeypair = async () => {
		if (!sdk.serviceURL) throw new Error('Missing serviceURL')
		if (!password.trim()) {
			alert('Enter your password to restore your private key')
			return
		}
		const url = `${sdk.serviceURL}/users/me/keypair`
		const headers: Record<string, string> = {}
		if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
		const resp = await fetch(url, {
			method: 'GET',
			credentials: 'include',
			headers,
		})
		if (resp.status === 404) {
			alert('No stored keypair found for your account')
			return
		}
		if (!resp.ok) {
			alert(`Failed to fetch keypair (${resp.status})`)
			return
		}
		const { public_key, encrypted_private, nonce, salt } = await resp.json()
		const priv = await decryptPrivateKeyWithPassword(encrypted_private, nonce, salt, password)
		const pub = b64ToBytes(public_key)
		setPrivateKey(priv)
		setPublicKey(pub)
		setPassword('')
		alert('Private key restored to memory')
	}

	const handleGenerateAndUploadKeypair = async () => {
		if (!sdk.serviceURL) throw new Error('Missing serviceURL')
		if (!password.trim()) {
			alert('Enter a password to protect your private key')
			return
		}
		const { publicKey: pub, privateKey: priv, publicKeyB64 } = await generateX25519Keypair()
		const { encrypted_private, nonce, salt } = await encryptPrivateKeyWithPassword(priv, password)
		const url = `${sdk.serviceURL}/users/me/keypair`
		const headers: Record<string, string> = { 'Content-Type': 'application/json' }
		if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
		const resp = await fetch(url, {
			method: 'PUT',
			credentials: 'include',
			headers,
			body: JSON.stringify({ public_key: publicKeyB64, encrypted_private, nonce, salt }),
		})
		if (!resp.ok) {
			alert(`Failed to upload keypair (${resp.status})`)
			return
		}
		setPrivateKey(priv)
		setPublicKey(pub)
		setPassword('')
		alert('Keypair uploaded')
	}

	const handleUnlockFromServer = async () => {
		if (!sdk.serviceURL) throw new Error('Missing serviceURL')
		if (!privateKey) {
			alert('No private key in memory. Generate & upload your keypair first.')
			return
		}
		const url = `${sdk.serviceURL}/secure/libraries/${library.id}/lmk`
		const headers: Record<string, string> = {}
		if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
		const resp = await fetch(url, {
			method: 'GET',
			credentials: 'include',
			headers,
		})
		if (!resp.ok) {
			alert(`Failed to fetch wrapped LMK (${resp.status})`)
			return
		}
		const wrappedJson = (await resp.json()) as {
			encrypted_lmk: string
			ephemeral_public: string
			nonce: string
		}
		const wrapped = {
			encrypted_lmk: wrappedJson.encrypted_lmk,
			ephemeral_public: wrappedJson.ephemeral_public,
			nonce: wrappedJson.nonce,
		}
		const lmkBytes = await unwrapLmkX25519AesGcm(wrapped, privateKey)
		setLMK(library.id, lmkBytes)
		refetch()
	}

	const { sdk } = useSDK()
	const { refetch } = useSecureCatalog(library.id, getLMKAsync, { enabled: !!lmk })
	const isOwner = useUserStore((s) => !!s.user?.is_server_owner)
	const [smkForScan, setSmkForScan] = useState('')
	const [isScanning, setIsScanning] = useState(false)

	const handleManualScan = async () => {
		try {
			if (!isOwner) return
			if (!sdk.serviceURL) throw new Error('Missing serviceURL')
			if (!smkForScan.trim()) {
				alert('Enter the System Master Key (SMK) to scan')
				return
			}
			setIsScanning(true)
			const headers: Record<string, string> = {
				'Content-Type': 'application/json',
				'X-SMK': smkForScan.trim(),
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
			alert('Secure library scan started')
		} catch (e) {
			console.error(e)
			alert(e instanceof Error ? e.message : 'Failed to start secure scan')
		} finally {
			setIsScanning(false)
		}
	}

	const handleSetLMK = () => {
		try {
			const bytes = b64ToBytes(lmkB64.trim())
			if (!bytes || bytes.length === 0) throw new Error('Invalid LMK base64')
			setLMK(library.id, bytes)
			setLmkB64('')
			refetch()
		} catch (e) {
			console.error(e)
			alert('Invalid LMK, please paste a base64-encoded 32-byte key')
		}
	}

	return (
		<div className="flex flex-1 flex-col gap-4 p-4">
			<Helmet>
				<title>Secure • {library.name}</title>
			</Helmet>

			<div className="flex items-center justify-between">
				<h2 className="text-xl font-semibold">Secure Library</h2>
				<div className="text-sm text-foreground-muted">{library.name}</div>
			</div>

			{access?.has_access === false ? (
				<div className="text-sm text-foreground-muted">
					Access to this secure library has been revoked or is not available.
				</div>
			) : null}

			<div className="flex items-center gap-2">
				<Input
					value={lmkB64}
					placeholder={lmk ? 'LMK is set (in-memory)' : 'Paste base64 LMK'}
					onChange={(e) => setLmkB64(e.target.value)}
				/>
				<Button onClick={handleSetLMK} disabled={!lmkB64.trim() || !hasAccess}>
					Set LMK
				</Button>
				<Button
					variant="secondary"
					onClick={handleUnlockFromServer}
					disabled={!hasAccess || !privateKey}
				>
					Unlock
				</Button>
				{lmk ? (
					<Button variant="ghost" onClick={() => clearLMK(library.id)}>
						Clear LMK
					</Button>
				) : null}
			</div>

			{isOwner ? (
				<div className="flex items-center gap-2">
					<Input
						value={smkForScan}
						type="password"
						placeholder="System Master Key (SMK)"
						onChange={(e) => setSmkForScan(e.target.value)}
					/>
					<Button variant="secondary" onClick={handleManualScan} isLoading={isScanning}>
						Scan Secure Library
					</Button>
				</div>
			) : null}

			<div className="flex items-center gap-2">
				<Input
					value={password}
					type="password"
					placeholder={
						publicKey ? 'Keypair present (in-memory)' : 'Enter password to protect/restore keypair'
					}
					onChange={(e) => setPassword(e.target.value)}
				/>
				<Button onClick={handleGenerateAndUploadKeypair}>Generate & Upload Keypair</Button>
				<Button variant="secondary" onClick={handleRestoreKeypair}>
					Restore Keypair
				</Button>
			</div>

			<SecureCatalogList />
		</div>
	)
}

function SecureCatalogList() {
	const { library } = useLibraryContext()
	const { sdk } = useSDK()
	const { getLMK } = useLmkStore((s) => ({ getLMK: s.getLMK }))

	const getLMKAsync = async () => {
		const key = getLMK(library.id)
		if (!key) throw new Error('LMK not set')
		return key
	}
	const lmk = getLMK(library.id)
	const { data: catalog, error } = useSecureCatalog(library.id, getLMKAsync, { enabled: !!lmk })

	const [active, setActive] = useState<{
		mediaId: string
		title: string
		kind: 'cbz' | 'pdf'
		pages?: string[]
		pdfUrl?: string
	} | null>(null)

	const handleRead = async (mediaId: string, title: string, extension: string) => {
		if (!sdk.serviceURL) throw new Error('Missing serviceURL')
		const ext = extension.toLowerCase()
		if (ext !== 'pdf') {
			const cached = getCachedSecurePages(library.id, mediaId)
			if (cached && cached.length > 0) {
				setActive((prev) => {
					if (prev?.kind === 'pdf' && prev.pdfUrl) {
						try {
							URL.revokeObjectURL(prev.pdfUrl)
						} catch (e) {
							void e
						}
					}
					return { mediaId, title, kind: 'cbz', pages: cached }
				})
				return
			}
		}
		const url = `${sdk.serviceURL}/secure/libraries/${library.id}/media/${mediaId}/file`
		const headers: Record<string, string> = {}
		if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`

		const resp = await fetch(url, {
			method: 'GET',
			credentials: 'include',
			headers,
		})
		if (!resp.ok) {
			alert('Failed to fetch encrypted media')
			return
		}
		const encBytes = new Uint8Array(await resp.arrayBuffer())
		const nonce = resp.headers.get('X-Nonce') || ''
		const originalSize = parseInt(
			resp.headers.get('X-Plaintext-Size') || resp.headers.get('X-Original-Size') || '0',
			10,
		)
		let tag = resp.headers.get('X-Tag') || ''
		if (!tag && encBytes.length >= originalSize && originalSize >= 16) {
			const tagBytes = encBytes.slice(originalSize - 16, originalSize)
			tag = bytesToB64(tagBytes)
		}
		const lmk = getLMK(library.id)
		if (!lmk) {
			alert('LMK not set')
			return
		}
		const dek = await deriveDEK(lmk, mediaId)
		let plain: Uint8Array
		try {
			plain = await decryptAesGcm(dek, nonce, tag, encBytes, originalSize)
		} catch (e) {
			// Fallback: try to locate the tag boundary within the padded ciphertext
			const tagBytes = b64ToBytes(tag)
			let found = -1
			for (let i = Math.max(16, encBytes.length - 16); i >= 16; i--) {
				let match = true
				for (let j = 0; j < 16; j++) {
					if (encBytes[i - 16 + j] !== tagBytes[j]) {
						match = false
						break
					}
				}
				if (match) {
					found = i
					break
				}
			}
			if (found > 0) {
				plain = await decryptAesGcm(dek, nonce, tag, encBytes, found)
			} else {
				console.error(e)
				toast.error(
					'Failed to decrypt this secure book. Contact the server owner or try again later.',
				)
				return
			}
		}

		if (ext === 'pdf') {
			const ab = plain.buffer.slice(
				plain.byteOffset,
				plain.byteOffset + plain.byteLength,
			) as ArrayBuffer
			const pdfUrl = URL.createObjectURL(new Blob([ab], { type: 'application/pdf' }))
			setActive((prev) => {
				if (prev?.kind === 'pdf' && prev.pdfUrl) {
					try {
						URL.revokeObjectURL(prev.pdfUrl)
					} catch (e) {
						void e
					}
				}
				return { mediaId, title, kind: 'pdf', pdfUrl }
			})
			return
		}

		let files: Record<string, Uint8Array>
		try {
			files = unzipSync(plain)
		} catch (e) {
			console.error(e)
			alert('Unsupported media format. Only CBZ (zip) and PDF are supported in MVP.')
			return
		}
		const images: { name: string; bytes: Uint8Array }[] = []
		for (const [name, data] of Object.entries(files)) {
			const lower = name.toLowerCase()
			if (
				lower.endsWith('.png') ||
				lower.endsWith('.jpg') ||
				lower.endsWith('.jpeg') ||
				lower.endsWith('.webp') ||
				lower.endsWith('.gif') ||
				lower.endsWith('.avif')
			) {
				images.push({ name, bytes: data as unknown as Uint8Array })
			}
		}
		images.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }))
		let totalBytes = 0
		const pages = images.map((img) => {
			const mime = guessMime(img.name)
			const ab = img.bytes.buffer.slice(0) as ArrayBuffer
			totalBytes += img.bytes.byteLength
			const blob = new Blob([ab], { type: mime })
			const url = URL.createObjectURL(blob)
			return url
		})

		const cachedPages = putCachedSecurePages(library.id, mediaId, pages, totalBytes)
		setActive((prev) => {
			if (prev?.kind === 'pdf' && prev.pdfUrl) {
				try {
					URL.revokeObjectURL(prev.pdfUrl)
				} catch (e) {
					void e
				}
			}
			return { mediaId, title, kind: 'cbz', pages: cachedPages }
		})
	}

	const handleCloseReader = () => {
		setActive((prev) => {
			if (prev?.kind === 'pdf' && prev.pdfUrl) {
				try {
					URL.revokeObjectURL(prev.pdfUrl)
				} catch (e) {
					void e
				}
			}
			return null
		})
	}

	if (error instanceof Error) {
		return <div className="text-sm text-foreground-muted">{error.message}</div>
	}

	if (!catalog) {
		return <div className="text-sm text-foreground-muted">No catalog loaded.</div>
	}

	if (active) {
		const syntheticMedia: Media = {
			id: active.mediaId,
			name: active.title,
			size: 0,
			extension: active.kind,
			pages: active.kind === 'cbz' ? active.pages?.length ?? 0 : 0,
			updated_at: new Date().toISOString(),
			created_at: new Date().toISOString(),
			modified_at: null,
			hash: null,
			koreader_hash: null,
			path: '',
			status: 'READY',
			series_id: '',
			metadata: null,
			series: null,
			active_reading_session: null,
			finished_reading_sessions: null,
			current_page: null,
			current_epubcfi: null,
			is_completed: null,
			tags: null,
			bookmarks: null,
		}

		return (
			<div className="flex h-full w-full flex-1 flex-col">
				<div className="flex items-center justify-between p-2">
					<div className="text-sm text-foreground-muted">{active.title}</div>
					<Button size="sm" onClick={handleCloseReader}>
						Close
					</Button>
				</div>
				<div className="flex min-h-0 flex-1">
					{active.kind === 'pdf' ? (
						<object data={active.pdfUrl} type="application/pdf" width="100%" height="100%">
							<Text>PDF failed to load.</Text>
						</object>
					) : (
						<ImageBasedReader
							media={syntheticMedia}
							isAnimated={false}
							isIncognito
							initialPage={1}
							getPageUrl={(page: number) => {
								const pages = active.pages ?? []
								const idx = Math.max(0, Math.min(pages.length - 1, page - 1))
								return pages[idx] ?? ''
							}}
						/>
					)}
				</div>
			</div>
		)
	}

	return (
		<div className="flex flex-col gap-4">
			{catalog.series.length > 0 ? (
				<div className="text-xs text-foreground-muted">{catalog.series.length} series</div>
			) : null}
			<div className="flex flex-col divide-y divide-edge-subtle rounded-md border border-edge">
				{catalog.media.map((m) => (
					<div key={m.id} className="flex items-center justify-between p-3">
						<div className="text-sm">{m.name}</div>
						<Button size="sm" onClick={() => handleRead(m.id, m.name, m.extension)}>
							Read
						</Button>
					</div>
				))}
			</div>
		</div>
	)
}

function guessMime(name: string): string {
	const lower = name.toLowerCase()
	if (lower.endsWith('.png')) return 'image/png'
	if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg'
	if (lower.endsWith('.webp')) return 'image/webp'
	if (lower.endsWith('.gif')) return 'image/gif'
	if (lower.endsWith('.avif')) return 'image/avif'
	return 'application/octet-stream'
}
