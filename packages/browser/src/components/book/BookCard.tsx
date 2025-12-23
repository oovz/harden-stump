import {
	decryptAesGcm,
	deriveThumbnailKey,
	queryClient,
	usePrefetchMediaByID,
	useSDK,
} from '@stump/client'
import { ConfirmationModal, DropdownMenu, IconButton, Text } from '@stump/components'
import type { Media } from '@stump/sdk'
import { MoreVertical, Trash2 } from 'lucide-react'
import pluralize from 'pluralize'
import {
	type ComponentPropsWithoutRef,
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
import { formatBookName, formatBytes } from '@/utils/format'
import { prefetchMediaPage } from '@/utils/prefetch'

import { EntityCard } from '../entity'

const BLANK_IMG = 'data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs='

function bytesToB64(bytes: Uint8Array): string {
	if (typeof btoa !== 'function') {
		throw new Error('No base64 encoder available')
	}
	let bin = ''
	for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
	return btoa(bin)
}

export type BookCardProps = {
	media: Media
	readingLink?: boolean
	fullWidth?: boolean
	variant?: 'cover' | 'default'
	onSelect?: (media: Media) => void
	/** If provided, will render secure thumbnail by decrypting from secure endpoint */
	libraryId?: string
}

type EntityCardProps = ComponentPropsWithoutRef<typeof EntityCard>

export default function BookCard({
	media,
	readingLink,
	fullWidth,
	variant = 'default',
	onSelect,
	libraryId,
}: BookCardProps) {
	const { sdk } = useSDK()
	const { isServerOwner } = useAppContext()
	const { prefetch } = usePrefetchMediaByID(media.id)
	const { getLMK } = useLmkStore((s) => ({ getLMK: s.getLMK }))
	const [isDeleting, setIsDeleting] = useState(false)
	const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false)

	const isCoverOnly = variant === 'cover'

	const handleHover = () => {
		if (!readingLink && !onSelect && !libraryId) {
			prefetch()
		}

		const currentPage = media.current_page || -1
		if (!onSelect && !libraryId && currentPage > 0) {
			prefetchMediaPage(sdk, media.id, currentPage)
		}
	}

	const getSubtitle = (media: Media) => {
		if (isCoverOnly) {
			return null
		}

		const isMissing = media.status === 'MISSING'
		if (isMissing) {
			return (
				<Text size="xs" className="uppercase text-amber-500">
					File Missing
				</Text>
			)
		}

		const percentageComplete = getProgress()
		if (percentageComplete != null) {
			const isEpubProgress = !!media.current_epubcfi
			const pagesLeft = media.pages - (media.current_page || 0)

			return (
				<div className="flex items-center justify-between">
					<Text size="xs" variant="muted">
						{percentageComplete}%
					</Text>
					{!isEpubProgress && percentageComplete < 100 && (
						<Text size="xs" variant="muted">
							{pagesLeft} {pluralize('page', pagesLeft)} left
						</Text>
					)}
				</div>
			)
		}

		if (libraryId) {
			return null
		}

		return (
			<div className="flex items-center justify-between">
				<Text size="xs" variant="muted">
					{formatBytes(media.size.valueOf())}
				</Text>
			</div>
		)
	}

	const getProgress = useCallback(() => {
		const { active_reading_session, finished_reading_sessions } = media

		if (isCoverOnly || (!active_reading_session && !finished_reading_sessions)) {
			return null
		} else if (active_reading_session) {
			const { epubcfi, percentage_completed, page } = active_reading_session

			if (epubcfi && percentage_completed) {
				return Math.round(percentage_completed * 100)
			} else if (page) {
				const pages = media.pages

				const percent = Math.round((page / pages) * 100)
				return Math.min(Math.max(percent, 0), 100) // Clamp between 0 and 100
			}
		} else if (finished_reading_sessions?.length) {
			return 100
		}

		return null
	}, [isCoverOnly, media])

	const canShowSecureDeleteMenu = Boolean(libraryId && isServerOwner)
	const handleConfirmSecureDelete = useCallback(async () => {
		if (!libraryId) return
		try {
			if (!sdk.serviceURL) throw new Error('Missing serviceURL')
			const lmk = getLMK(libraryId)
			if (!lmk || lmk.length !== 32) {
				throw new Error('Unlock this secure library before deleting items.')
			}
			setIsDeleting(true)
			const url = `${sdk.serviceURL}/secure/libraries/${libraryId}/media/${media.id}`
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
					// ignore JSON parse errors
				}
				throw new Error(msg)
			}
			await queryClient.invalidateQueries(['secureCatalog', libraryId])
			setShowDeleteConfirmation(false)
			toast.success('Book deleted')
		} catch (e) {
			toast.error(e instanceof Error ? e.message : 'Failed to delete book')
		} finally {
			setIsDeleting(false)
		}
	}, [libraryId, sdk.serviceURL, sdk.token, getLMK, media.id])

	const href = useMemo(() => {
		if (onSelect) {
			return undefined
		}

		return readingLink
			? paths.bookReader(media.id, {
					epubcfi: media.current_epubcfi,
					page: media.current_page || undefined,
				})
			: paths.bookOverview(media.id)
	}, [readingLink, media.id, media.current_epubcfi, media.current_page, onSelect])

	// Resolve image URL (secure or standard)
	const defaultImageUrl = useMemo(() => sdk.media.thumbnailURL(media.id), [sdk, media.id])
	const [resolvedImageUrl, setResolvedImageUrl] = useState<string>(
		libraryId ? BLANK_IMG : defaultImageUrl,
	)
	const objectUrlRef = useRef<string | null>(null)
	const [thumbRef, isThumbInView] = useIsInView<HTMLDivElement>('200px')
	const [shouldLoadSecureThumb, setShouldLoadSecureThumb] = useState(!libraryId)

	useEffect(() => {
		if (libraryId && isThumbInView) {
			setShouldLoadSecureThumb(true)
		}
	}, [libraryId, isThumbInView])

	useEffect(() => {
		let cancelled = false
		async function run() {
			// Cleanup previous object URL
			if (objectUrlRef.current) {
				URL.revokeObjectURL(objectUrlRef.current)
				objectUrlRef.current = null
			}
			if (!libraryId) {
				// Non-secure library: use standard thumbnail URL
				setResolvedImageUrl(defaultImageUrl)
				return
			}
			if (!shouldLoadSecureThumb) {
				setResolvedImageUrl(BLANK_IMG)
				return
			}
			try {
				const lmk = getLMK(libraryId)
				if (!lmk) {
					// Secure library but LMK missing: show no thumbnail (no plaintext fallback)
					setResolvedImageUrl(BLANK_IMG)
					return
				}
				const url = `${sdk.serviceURL}/secure/libraries/${libraryId}/media/${media.id}/thumbnail`
				const headers: Record<string, string> = {}
				if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
				const resp = await fetch(url, { method: 'GET', credentials: 'include', headers })
				if (!resp.ok) {
					// Secure thumbnail fetch failed: show no thumbnail
					setResolvedImageUrl(BLANK_IMG)
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
					const b64 = (bytes: Uint8Array) => {
						if (typeof btoa === 'function') {
							let bin = ''
							for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
							return btoa(bin)
						}
						// eslint-disable-next-line @typescript-eslint/ban-ts-comment
						// @ts-ignore
						return Buffer.from(bytes).toString('base64')
					}
					tag = b64(tagBytes)
				}
				if (!nonce || !tag || !originalSize || originalSize < 16) {
					// Missing crypto headers: show no thumbnail
					setResolvedImageUrl(BLANK_IMG)
					return
				}
				const dek = await deriveThumbnailKey(lmk, media.id)
				const plain = await decryptAesGcm(dek, nonce, tag, encBytes, originalSize)
				// Assume JPEG for MVP
				const blob = new Blob([plain.buffer.slice(0) as ArrayBuffer], { type: 'image/jpeg' })
				const objUrl = URL.createObjectURL(blob)
				objectUrlRef.current = objUrl
				if (!cancelled) {
					setResolvedImageUrl(objUrl)
				}
			} catch {
				if (!cancelled) {
					// Decryption failed: show no thumbnail
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
		libraryId,
		shouldLoadSecureThumb,
		media.id,
		sdk.serviceURL,
		sdk.token,
		defaultImageUrl,
		getLMK,
	])

	const propsOverrides = useMemo(() => {
		let overrides = (
			isCoverOnly
				? {
						className: 'flex-shrink-0 flex-auto',
						href: undefined,
						progress: undefined,
						subtitle: undefined,
						title: undefined,
					}
				: {}
		) as Partial<EntityCardProps>

		if (onSelect) {
			overrides = {
				...overrides,
				onClick: () => onSelect(media),
			}
		}

		return overrides
	}, [onSelect, isCoverOnly, media])

	return (
		<div
			ref={thumbRef}
			className="relative block"
			data-testid={libraryId ? `secure-book-card-${media.id}` : undefined}
		>
			{canShowSecureDeleteMenu && (
				<>
					<ConfirmationModal
						title="Delete book"
						description={`Are you sure you want to delete “${formatBookName(media)}”? This cannot be undone.`}
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
									data-testid={`secure-book-menu-${media.id}`}
									aria-label="Book options"
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
				key={media.id}
				title={formatBookName(media)}
				href={href}
				fullWidth={fullWidth}
				imageUrl={resolvedImageUrl}
				progress={getProgress()}
				subtitle={getSubtitle(media)}
				onMouseEnter={handleHover}
				isCover={isCoverOnly}
				{...propsOverrides}
			/>
		</div>
	)
}
