import { useLibraryByID, usePagedSeriesQuery, usePrefetchPagedSeries } from '@stump/client'
import { usePrevious, usePreviousIsDifferent } from '@stump/components'
import { useCallback, useEffect, useMemo } from 'react'
import { Helmet } from 'react-helmet'
import { useParams } from 'react-router'

import {
	FilterContext,
	FilterHeader,
	FilterProvider,
	URLFilterContainer,
	URLFilterDrawer,
	URLOrdering,
	useFilterScene,
} from '@/components/filters'
import GenericEmptyState from '@/components/GenericEmptyState'
import { SeriesTable } from '@/components/series'
import SeriesGrid from '@/components/series/SeriesGrid'
import TableOrGridLayout from '@/components/TableOrGridLayout'
import useIsInView from '@/hooks/useIsInView'
import { useSecureCatalog } from '@/hooks/useSecureCatalog'
import { useLmkStore } from '@/stores'
import { useSeriesLayout } from '@/stores/layout'

export default function LibrarySeriesSceneWrapper() {
	return (
		<FilterProvider>
			<LibrarySeriesScene />
		</FilterProvider>
	)
}

function LibrarySeriesScene() {
	const { id } = useParams()

	const [containerRef, isInView] = useIsInView<HTMLDivElement>()

	if (!id) {
		throw new Error('Library id is required')
	}

	const { layoutMode, setLayout } = useSeriesLayout((state) => ({
		layoutMode: state.layout,
		setLayout: state.setLayout,
	}))
	const { isLoading, library } = useLibraryByID(id)
	const {
		filters,
		ordering,
		pagination: { page, page_size },
		setPage,
		...rest
	} = useFilterScene()
	const { prefetch } = usePrefetchPagedSeries()

	const params = useMemo(
		() => ({
			page,
			page_size,
			params: {
				...filters,
				...ordering,
				count_media: true,
				library: {
					id: [id],
				},
			},
		}),
		[page, page_size, filters, ordering, id],
	)
	const {
		isLoading: isLoadingSeries,
		isRefetching: isRefetchingSeries,
		series,
		pageData,
	} = usePagedSeriesQuery(params)

	// Secure catalog bridge
	const isSecure = Boolean((library as unknown as Record<string, unknown>)?.['is_secure'])
	const encryptionStatus = (library as unknown as Record<string, unknown>)?.[
		'encryption_status'
	] as string | undefined
	const isNotEncrypted = isSecure && encryptionStatus === 'NOT_ENCRYPTED'
	const isBroken = isSecure && encryptionStatus === 'ENCRYPTION_BROKEN'
	const { getLMK } = useLmkStore((s) => ({ getLMK: s.getLMK }))
	const lmk = getLMK(id)
	const getLMKAsync = async () => {
		const key = getLMK(id)
		if (!key) throw new Error('LMK not set')
		return key
	}
	const { data: secureCatalog, error: secureError } = useSecureCatalog(id, getLMKAsync, {
		enabled: isSecure && !!lmk && !isNotEncrypted,
	})
	const secureSeries = useMemo(() => {
		if (!isSecure || !secureCatalog) return undefined
		const counts: Record<string, number> = {}
		for (const m of secureCatalog.media) {
			if (!m.seriesId) continue
			counts[m.seriesId] = (counts[m.seriesId] || 0) + 1
		}
		return secureCatalog.series.map((s) => ({
			id: s.id,
			name: s.name,
			media_count: counts[s.id] ?? 0,
		})) as unknown as typeof series
	}, [isSecure, secureCatalog])
	const secureFirstMediaIds = useMemo(() => {
		if (!isSecure || !secureCatalog) return undefined as undefined | Record<string, string>
		const map: Record<string, string> = {}
		for (const m of secureCatalog.media) {
			const sid = m.seriesId || undefined
			if (sid && !map[sid]) {
				map[sid] = m.id
			}
		}
		return map
	}, [isSecure, secureCatalog])
	const { current_page, total_pages } = pageData || {}

	const differentSearch = usePreviousIsDifferent(filters?.search as string)
	useEffect(() => {
		if (differentSearch) {
			setPage(1)
		}
	}, [differentSearch, setPage])

	const handlePrefetchPage = useCallback(
		(page: number) => {
			prefetch({
				...params,
				page,
			})
		},
		[params, prefetch],
	)

	const previousPage = usePrevious(current_page)
	const shouldScroll = !!previousPage && previousPage !== current_page
	useEffect(
		() => {
			if (!isInView && shouldScroll) {
				containerRef.current?.scrollIntoView({
					behavior: 'smooth',
					block: 'nearest',
					inline: 'start',
				})
			}
		},
		// eslint-disable-next-line react-hooks/exhaustive-deps
		[isInView, shouldScroll],
	)

	if (isLoading) {
		return null
	} else if (!library) {
		throw new Error('Library not found')
	}

	const renderContent = () => {
		if (isSecure && isBroken) {
			return (
				<div className="flex flex-1 px-4 pb-2 pt-4 md:pb-4">
					<GenericEmptyState
						title="Secure library is currently broken"
						subtitle="Contact the server owner to restore from backup and run a new secure scan, then try again."
					/>
				</div>
			)
		}

		if (isSecure && isNotEncrypted) {
			return (
				<div className="flex flex-1 px-4 pb-2 pt-4 md:pb-4">
					<GenericEmptyState
						title="Secure library has not been encrypted yet"
						subtitle="Run an initial secure scan from the admin UI to populate this secure library, then refresh."
					/>
				</div>
			)
		}

		if (isSecure && secureError instanceof Error) {
			return (
				<div className="flex flex-1 px-4 pb-2 pt-4 md:pb-4">
					<GenericEmptyState
						title="Secure library error"
						subtitle={`${secureError.message} Contact the server owner or try again later.`}
					/>
				</div>
			)
		}

		if (layoutMode === 'GRID') {
			return (
				<URLFilterContainer
					currentPage={current_page || 1}
					pages={total_pages || 1}
					onChangePage={setPage}
					onPrefetchPage={handlePrefetchPage}
				>
					<div className="flex flex-1 px-4 pb-2 pt-4 md:pb-4">
						<SeriesGrid
							isLoading={isSecure ? false : isLoadingSeries}
							series={isSecure ? secureSeries : series}
							hasFilters={Object.keys(filters || {}).length > 0}
							libraryId={isSecure ? id : undefined}
							secureFirstMediaIds={isSecure ? secureFirstMediaIds : undefined}
						/>
					</div>
				</URLFilterContainer>
			)
		} else {
			return (
				<SeriesTable
					items={(isSecure ? secureSeries : series) || []}
					render={(props) => (
						<URLFilterContainer
							currentPage={current_page || 1}
							pages={total_pages || 1}
							onChangePage={setPage}
							onPrefetchPage={handlePrefetchPage}
							// tableControls={<BookTableColumnConfiguration />}
							{...props}
						/>
					)}
				/>
			)
		}
	}

	return (
		<FilterContext.Provider
			value={{
				filters,
				ordering,
				pagination: { page, page_size },
				setPage,
				...rest,
			}}
		>
			<div className="flex flex-1 flex-col pb-4 md:pb-0">
				<Helmet>
					<title>Stump | {library.name}</title>
				</Helmet>

				<section ref={containerRef} id="grid-top-indicator" className="h-0" />

				<FilterHeader
					isSearching={isRefetchingSeries}
					layoutControls={<TableOrGridLayout layout={layoutMode} setLayout={setLayout} />}
					orderControls={<URLOrdering entity="series" />}
					filterControls={<URLFilterDrawer entity="series" />}
					navOffset
				/>

				{renderContent()}
			</div>
		</FilterContext.Provider>
	)
}
