import { decryptAesGcm, deriveThumbnailKey, queryClient, useSDK } from '@stump/client'
import { ConfirmationModal, DropdownMenu, IconButton, Text } from '@stump/components'
import { Series } from '@stump/sdk'
import { MoreVertical, Trash2 } from 'lucide-react'
import {
	type MouseEvent as ReactMouseEvent,
	useCallback,
	useEffect,
	useMemo,
	useRef,
	useState,
} from 'react'
import toast from 'react-hot-toast'

import { useAppContext } from '@/context'
import useIsInView from '@/hooks/useIsInView'
import paths from '@/paths'
import { useLmkStore } from '@/stores'

import pluralizeStat from '../../utils/pluralize'
import { EntityCard } from '../entity'

type Props = {
	series: Series
	fullWidth?: boolean
	variant?: 'cover' | 'default'
	libraryId: string
	mediaIdForThumbnail?: string
}

const BLANK_IMG = 'data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs='

function bytesToB64(bytes: Uint8Array): string {
	if (typeof btoa !== 'function') {
		throw new Error('No base64 encoder available')
	}
	let bin = ''
	for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
	return btoa(bin)
}

export default function SecureSeriesCard({
	series,
	fullWidth,
	variant = 'default',
	libraryId,
	mediaIdForThumbnail,
}: Props) {
	const { sdk } = useSDK()
	const { isServerOwner } = useAppContext()
	const isCoverOnly = variant === 'cover'

	const bookCount = Number(series.media ? series.media.length : series.media_count ?? 0)
	const booksUnread = series.unread_media_count

	function getProgress() {
		if (isCoverOnly || booksUnread == null) {
			return undefined
		}

		const percent = Math.round((1 - Number(booksUnread) / bookCount) * 100)
		if (percent > 100) {
			return 100
		}

		return percent
	}

	const getSubtitle = (series: Series) => {
		if (isCoverOnly) {
			return null
		}

		const isMissing = series.status === 'MISSING'
		if (isMissing) {
			return (
				<Text size="xs" className="uppercase text-amber-500">
					Series Missing
				</Text>
			)
		}

		return (
			<div className="flex items-center justify-between">
				<Text size="xs" variant="muted">
					{pluralizeStat('book', Number(bookCount))}
				</Text>
			</div>
		)
	}

	const overrides = isCoverOnly
		? {
				className: 'flex-shrink',
				href: undefined,
				progress: undefined,
				subtitle: undefined,
				title: undefined,
			}
		: {}

	const href = useMemo(() => {
		const base = paths.libraryBooks(libraryId)
		const sp = new URLSearchParams()
		sp.set('secure_series_id', series.id)
		return `${base}?${sp.toString()}`
	}, [libraryId, series.id])

	const defaultImageUrl = useMemo(() => sdk.series.thumbnailURL(series.id), [sdk, series.id])
	const [resolvedImageUrl, setResolvedImageUrl] = useState<string>(BLANK_IMG)
	const objectUrlRef = useRef<string | null>(null)
	const { getLMK } = useLmkStore((s) => ({ getLMK: s.getLMK }))
	const [isDeleting, setIsDeleting] = useState(false)
	const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false)
	const [thumbRef, isThumbInView] = useIsInView<HTMLDivElement>('200px')
	const [shouldLoadSecureThumb, setShouldLoadSecureThumb] = useState(true)

	const canShowSecureDeleteMenu = Boolean(isServerOwner)
	const handleConfirmSecureDelete = useCallback(async () => {
		try {
			if (!sdk.serviceURL) throw new Error('Missing serviceURL')
			const lmk = getLMK(libraryId)
			if (!lmk || lmk.length !== 32) {
				throw new Error('Unlock this secure library before deleting items.')
			}
			setIsDeleting(true)
			const url = `${sdk.serviceURL}/secure/libraries/${libraryId}/series/${series.id}`
			const headers: Record<string, string> = {
				'X-LMK': bytesToB64(lmk),
			}
			if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
			const resp = await fetch(url, { method: 'DELETE', credentials: 'include', headers })
			if (!resp.ok) {
				let msg = `Failed to delete (${resp.status})`
				try {
					const data: unknown = await resp.json()
					if (
						data &&
						typeof data === 'object' &&
						'message' in data &&
						typeof (data as { message?: unknown }).message === 'string'
					) {
						msg = (data as { message: string }).message
					}
				} catch {
					// no-op
				}
				throw new Error(msg)
			}
			await queryClient.invalidateQueries(['secureCatalog', libraryId])
			setShowDeleteConfirmation(false)
			toast.success('Series deleted')
		} catch (e) {
			toast.error(e instanceof Error ? e.message : 'Failed to delete series')
		} finally {
			setIsDeleting(false)
		}
	}, [getLMK, libraryId, sdk.serviceURL, sdk.token, series.id])

	useEffect(() => {
		if (isThumbInView) {
			setShouldLoadSecureThumb(true)
		}
	}, [isThumbInView])

	useEffect(() => {
		let cancelled = false
		async function run() {
			if (objectUrlRef.current) {
				URL.revokeObjectURL(objectUrlRef.current)
				objectUrlRef.current = null
			}

			if (!shouldLoadSecureThumb) {
				setResolvedImageUrl(BLANK_IMG)
				return
			}

			if (!mediaIdForThumbnail) {
				setResolvedImageUrl(BLANK_IMG)
				return
			}

			try {
				const lmk = getLMK(libraryId)
				if (!lmk) {
					setResolvedImageUrl(BLANK_IMG)
					return
				}
				const url = `${sdk.serviceURL}/secure/libraries/${libraryId}/media/${mediaIdForThumbnail}/thumbnail`
				const headers: Record<string, string> = {}
				if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
				const resp = await fetch(url, { method: 'GET', credentials: 'include', headers })
				if (!resp.ok) {
					setResolvedImageUrl(BLANK_IMG)
					return
				}
				const encBytes = new Uint8Array(await resp.arrayBuffer())
				const nonce = resp.headers.get('X-Nonce') || ''
				const originalSize = parseInt(
					resp.headers.get('X-Plaintext-Size') || resp.headers.get('X-Original-Size') || '0',
					10,
				)
				const tag = resp.headers.get('X-Tag') || ''
				if (!nonce || !tag || !originalSize || originalSize < 16) {
					setResolvedImageUrl(BLANK_IMG)
					return
				}
				const dek = await deriveThumbnailKey(lmk, mediaIdForThumbnail)
				const plain = await decryptAesGcm(dek, nonce, tag, encBytes, originalSize)
				const blob = new Blob([plain.buffer.slice(0) as ArrayBuffer], { type: 'image/jpeg' })
				const objUrl = URL.createObjectURL(blob)
				objectUrlRef.current = objUrl
				if (!cancelled) {
					setResolvedImageUrl(objUrl)
				}
			} catch {
				if (!cancelled) {
					setResolvedImageUrl(BLANK_IMG)
				}
			}
		}
		run()
		return () => {
			cancelled = true
			if (objectUrlRef.current) {
				URL.revokeObjectURL(objectUrlRef.current)
				objectUrlRef.current = null
			}
		}
	}, [
		defaultImageUrl,
		getLMK,
		libraryId,
		mediaIdForThumbnail,
		sdk.serviceURL,
		sdk.token,
		shouldLoadSecureThumb,
	])

	return (
		<div ref={thumbRef} className="relative block" data-testid={`secure-series-card-${series.id}`}>
			{canShowSecureDeleteMenu && (
				<>
					<ConfirmationModal
						title="Delete series"
						description={`Are you sure you want to delete “${series.name}”? This will delete ${bookCount} book${bookCount === 1 ? '' : 's'}.`}
						confirmText="Delete"
						confirmVariant="danger"
						isOpen={showDeleteConfirmation}
						onClose={() => setShowDeleteConfirmation(false)}
						onConfirm={handleConfirmSecureDelete}
						confirmIsLoading={isDeleting}
						trigger={null}
					/>
					<div className="absolute right-2 top-2 z-10">
						<DropdownMenu
							align="end"
							trigger={
								<IconButton
									size="xs"
									variant="ghost"
									data-testid={`secure-series-menu-${series.id}`}
									aria-label="Series options"
									onClick={(e: ReactMouseEvent<HTMLButtonElement>) => e.stopPropagation()}
								>
									<MoreVertical className="h-4 w-4" />
								</IconButton>
							}
							groups={[
								{
									items: [
										{
											label: 'Delete',
											leftIcon: <Trash2 className="mr-2 h-4 w-4" />,
											onClick: (e: ReactMouseEvent<HTMLDivElement>) => {
												e.stopPropagation()
												setShowDeleteConfirmation(true)
											},
										},
									],
								},
							]}
						/>
					</div>
				</>
			)}
			<EntityCard
				key={series.id}
				title={series.name}
				href={href}
				imageUrl={resolvedImageUrl}
				progress={getProgress()}
				subtitle={getSubtitle(series)}
				fullWidth={fullWidth}
				isCover={isCoverOnly}
				{...overrides}
			/>
		</div>
	)
}
