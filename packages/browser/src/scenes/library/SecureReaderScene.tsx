import { decryptAesGcm, deriveDEK, useLibraryByID, useSDK } from '@stump/client'
import { Button, Text } from '@stump/components'
import type { FileStatus, Media } from '@stump/sdk'
import { unzipSync } from 'fflate'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Helmet } from 'react-helmet'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'

import { ImageBasedReader } from '@/components/readers/imageBased'
import Spinner from '@/components/Spinner'
import { useSecureCatalog } from '@/hooks/useSecureCatalog'
import paths from '@/paths'
import { getCachedSecurePages, putCachedSecurePages } from '@/secure/readerCache'
import { useLmkStore } from '@/stores'

import { LibraryContext } from './context'
import SecureUnlockGate from './SecureUnlockGate'

function bytesToB64(bytes: Uint8Array): string {
	if (typeof btoa === 'function') {
		let bin = ''
		for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
		return btoa(bin)
	}
	return ''
}

type PageItem = {
	url: string
}

export default function SecureReaderScene() {
	const navigate = useNavigate()
	const { sdk } = useSDK()
	const params = useParams()
	const [search, setSearch] = useSearchParams()

	const libraryId = params.id || ''
	const mediaId = params.mediaId || ''

	const { library, isLoading } = useLibraryByID(libraryId)

	const { getLMK } = useLmkStore((s) => ({ getLMK: s.getLMK }))
	const lmk = getLMK(libraryId)
	const getLMKAsync = async () => {
		const key = getLMK(libraryId)
		if (!key) throw new Error('LMK not set')
		return key
	}

	const { data: secureCatalog } = useSecureCatalog(libraryId, getLMKAsync, {
		enabled: Boolean(lmk),
	})

	const catalogMedia = useMemo(() => {
		if (!secureCatalog) return undefined
		return secureCatalog.media.find((m) => m.id === mediaId)
	}, [secureCatalog, mediaId])

	const ext = (search.get('ext') || catalogMedia?.extension || 'cbz').toLowerCase()

	useEffect(() => {
		if (search.get('incognito') !== 'true') {
			search.set('incognito', 'true')
			setSearch(search, { replace: true })
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [])

	const [isBusy, setIsBusy] = useState(false)
	const [readerError, setReaderError] = useState<string | null>(null)
	const [pdfUrl, setPdfUrl] = useState<string | null>(null)
	const [pages, setPages] = useState<PageItem[] | null>(null)

	useEffect(() => {
		return () => {
			if (pdfUrl) {
				try {
					URL.revokeObjectURL(pdfUrl)
				} catch {
					// ignore
				}
			}
		}
	}, [pdfUrl])

	const getPageUrl = useCallback(
		(pageNumber: number) => {
			const idx = pageNumber - 1
			if (!pages || idx < 0 || idx >= pages.length) return ''
			const item = pages[idx]
			return item?.url || ''
		},
		[pages],
	)

	useEffect(() => {
		async function run() {
			if (!sdk.serviceURL) return
			if (!libraryId || !mediaId) return
			const lmkBytes = getLMK(libraryId)
			if (!lmkBytes) return

			if (ext !== 'pdf') {
				const cached = getCachedSecurePages(libraryId, mediaId)
				if (cached && cached.length > 0) {
					setReaderError(null)
					setPdfUrl(null)
					setPages(cached.map((url) => ({ url })))
					return
				}
			}

			setIsBusy(true)
			setReaderError(null)
			setPdfUrl(null)
			setPages(null)

			const url = `${sdk.serviceURL}/secure/libraries/${libraryId}/media/${mediaId}/file`
			const headers: Record<string, string> = {}
			if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
			const resp = await fetch(url, { method: 'GET', credentials: 'include', headers })
			if (!resp.ok) {
				setReaderError('Failed to fetch encrypted media')
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

			try {
				const dek = await deriveDEK(lmkBytes, mediaId)
				const plain = await decryptAesGcm(dek, nonce, tag, encBytes, originalSize)

				if (ext === 'pdf') {
					const ab = plain.buffer.slice(0) as ArrayBuffer
					setPdfUrl(URL.createObjectURL(new Blob([ab], { type: 'application/pdf' })))
					return
				}

				let files: Record<string, Uint8Array>
				try {
					files = unzipSync(plain)
				} catch {
					setReaderError('Unsupported media format. Only CBZ (zip) and PDF are supported in MVP.')
					return
				}

				const images: { name: string; bytes: Uint8Array; mime: string }[] = []
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
						const mime = lower.endsWith('.png')
							? 'image/png'
							: lower.endsWith('.webp')
								? 'image/webp'
								: lower.endsWith('.gif')
									? 'image/gif'
									: lower.endsWith('.avif')
										? 'image/avif'
										: 'image/jpeg'
						images.push({ name, bytes: data as unknown as Uint8Array, mime })
					}
				}
				images.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }))
				let totalBytes = 0
				const pageUrls = images.map((img) => {
					totalBytes += img.bytes.byteLength
					const ab = img.bytes.buffer.slice(0) as ArrayBuffer
					return URL.createObjectURL(new Blob([ab], { type: img.mime }))
				})
				const cachedPages = putCachedSecurePages(libraryId, mediaId, pageUrls, totalBytes)
				setPages(cachedPages.map((url) => ({ url })))
			} catch (e) {
				console.error(e)
				setReaderError(
					'Failed to decrypt this secure book. Contact the server owner or try again later.',
				)
			}
		}

		run().finally(() => setIsBusy(false))
	}, [sdk.serviceURL, sdk.token, libraryId, mediaId, getLMK, ext, lmk])

	if (isLoading || !library) return null

	if (!libraryId || !mediaId) {
		return null
	}

	const pageCount = pages?.length || catalogMedia?.pages || 0
	const minimalMedia = {
		id: mediaId,
		name: catalogMedia?.name || '',
		size: BigInt(catalogMedia?.size || 0),
		extension: ext,
		pages: pageCount,
		updated_at: new Date().toISOString(),
		created_at: new Date().toISOString(),
		modified_at: null,
		hash: null,
		koreader_hash: null,
		path: '',
		status: 'READY' as FileStatus,
		series_id: catalogMedia?.seriesId || '',
		metadata: null,
		series: null,
		active_reading_session: null,
		finished_reading_sessions: null,
		current_page: null,
		current_epubcfi: null,
		is_completed: null,
		tags: null,
		bookmarks: null,
	} as unknown as Media

	const body = (
		<div className="relative flex flex-1 flex-col bg-black">
			<Helmet>
				<title>Stump | Secure Reader</title>
			</Helmet>

			<LibraryContext.Provider value={{ library }}>
				<SecureUnlockGate />
			</LibraryContext.Provider>

			{readerError ? (
				<div className="m-auto flex max-w-md flex-col gap-3 px-4 text-center">
					<Text size="sm" variant="muted">
						{readerError}
					</Text>
					<div className="flex items-center justify-center gap-2">
						<Button
							size="sm"
							variant="secondary"
							onClick={() => navigate(paths.libraryBooks(libraryId))}
						>
							Back to books
						</Button>
						<Button
							size="sm"
							variant="secondary"
							onClick={() => navigate(`/books/secure/${libraryId}/${mediaId}`)}
						>
							Book info
						</Button>
					</div>
				</div>
			) : isBusy ? (
				<div className="m-auto flex items-center gap-2 rounded-lg border border-edge bg-background px-4 py-2 text-sm shadow-xl">
					<div className="h-4 w-4">
						<Spinner />
					</div>
					Decrypting...
				</div>
			) : pdfUrl ? (
				<div className="flex min-h-0 flex-1 overflow-hidden">
					<object data={pdfUrl} type="application/pdf" width="100%" height="100%">
						<div className="m-auto max-w-md px-4 text-center text-sm text-foreground-muted">
							PDF failed to load.
						</div>
					</object>
				</div>
			) : pages ? (
				<ImageBasedReader
					media={minimalMedia}
					isAnimated={false}
					isIncognito
					initialPage={1}
					getPageUrl={getPageUrl}
				/>
			) : (
				<div className="m-auto flex items-center gap-2 rounded-lg border border-edge bg-background px-4 py-2 text-sm shadow-xl">
					<div className="h-4 w-4">
						<Spinner />
					</div>
					Preparing...
				</div>
			)}
		</div>
	)

	return body
}
