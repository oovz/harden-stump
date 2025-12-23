import { useLibraryByID, useSDK } from '@stump/client'
import { Button, Text } from '@stump/components'
import { useMemo } from 'react'
import { Helmet } from 'react-helmet'
import { useNavigate, useParams } from 'react-router-dom'

import GenericEmptyState from '@/components/GenericEmptyState'
import { useSecureCatalog } from '@/hooks/useSecureCatalog'
import paths from '@/paths'
import { useLmkStore } from '@/stores'

export default function SecureBookOverviewScene() {
	const navigate = useNavigate()
	const { sdk } = useSDK()
	const params = useParams()

	const libraryId = params.libraryId || ''
	const mediaId = params.mediaId || ''

	const { library, isLoading } = useLibraryByID(libraryId)
	const { getLMK } = useLmkStore((s) => ({ getLMK: s.getLMK }))
	const lmk = getLMK(libraryId)
	const getLMKAsync = async () => {
		const key = getLMK(libraryId)
		if (!key) throw new Error('LMK not set')
		return key
	}

	const { data: secureCatalog, error } = useSecureCatalog(libraryId, getLMKAsync, {
		enabled: Boolean(lmk),
	})

	const media = useMemo(() => {
		if (!secureCatalog) return undefined
		return secureCatalog.media.find((m) => m.id === mediaId)
	}, [secureCatalog, mediaId])

	if (!libraryId || !mediaId) return null

	if (isLoading) {
		return null
	}

	if (!lmk) {
		return (
			<div className="flex flex-1 items-center justify-center px-4">
				<div className="flex flex-col items-center gap-3">
					<GenericEmptyState
						title="Unlock required"
						subtitle="Unlock the secure library first, then come back to view secure book info."
					/>
					<Button size="sm" onClick={() => navigate(paths.librarySeries(libraryId))}>
						Go to library
					</Button>
				</div>
			</div>
		)
	}

	if (!secureCatalog || error || !media) {
		return (
			<div className="flex flex-1 items-center justify-center px-4">
				<div className="flex flex-col items-center gap-3">
					<GenericEmptyState
						title="Secure book not found"
						subtitle="This secure book may not exist in the catalog yet. Try running a secure scan and refreshing."
					/>
					<Button
						size="sm"
						variant="secondary"
						onClick={() => navigate(paths.librarySeries(libraryId))}
					>
						Back to library
					</Button>
				</div>
			</div>
		)
	}

	const ext = (media.extension || '').toLowerCase()

	return (
		<div className="flex flex-1 flex-col gap-4 p-4">
			<Helmet>
				<title>Stump | {media.name}</title>
			</Helmet>

			<div className="flex flex-col gap-1">
				<Text size="lg" className="font-semibold">
					{media.name}
				</Text>
				<Text size="sm" variant="muted">
					Secure library: {library?.name || libraryId}
				</Text>
			</div>

			<div className="grid max-w-xl grid-cols-2 gap-2 text-sm">
				<div className="text-foreground-muted">Pages</div>
				<div>{media.pages}</div>
				<div className="text-foreground-muted">Extension</div>
				<div>{media.extension}</div>
				<div className="text-foreground-muted">Size</div>
				<div>{media.size} bytes</div>
				<div className="text-foreground-muted">Series</div>
				<div>{media.seriesId || '—'}</div>
				<div className="text-foreground-muted">Volume</div>
				<div>{media.volume ?? '—'}</div>
				<div className="text-foreground-muted">Number</div>
				<div>{media.number ?? '—'}</div>
			</div>

			<div className="flex flex-wrap items-center gap-2 pt-2">
				<Button
					size="sm"
					variant="primary"
					onClick={() =>
						navigate(
							`/libraries/${libraryId}/secure-reader/${mediaId}?incognito=true&ext=${encodeURIComponent(ext)}`,
						)
					}
				>
					Read
				</Button>
				<Button
					size="sm"
					variant="secondary"
					onClick={() => navigate(paths.libraryBooks(libraryId))}
				>
					Back to books
				</Button>
			</div>

			{sdk ? null : null}
		</div>
	)
}
