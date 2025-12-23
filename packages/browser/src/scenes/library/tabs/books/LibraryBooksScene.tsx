import { usePagedMediaQuery, usePrefetchMediaPaged } from '@stump/client'
import { usePreviousIsDifferent } from '@stump/components'
import type { FileStatus, Media } from '@stump/sdk'
import { useCallback, useEffect, useMemo } from 'react'
import { Helmet } from 'react-helmet'
import { useNavigate } from 'react-router-dom'

import { BookTable } from '@/components/book'
import BookGrid from '@/components/book/BookGrid'
import { defaultBookColumnSort } from '@/components/book/table'
import {
	FilterContext,
	FilterHeader,
	URLFilterContainer,
	URLFilterDrawer,
	URLOrdering,
	useFilterScene,
} from '@/components/filters'
import GenericEmptyState from '@/components/GenericEmptyState'
import { EntityTableColumnConfiguration } from '@/components/table'
import TableOrGridLayout from '@/components/TableOrGridLayout'
import useIsInView from '@/hooks/useIsInView'
import { useSecureCatalog } from '@/hooks/useSecureCatalog'
import { useLmkStore } from '@/stores'
import { useBooksLayout } from '@/stores/layout'

import { useLibraryContext } from '../../context'

export default function LibraryBooksScene() {
	const navigate = useNavigate()
	const [containerRef, isInView] = useIsInView<HTMLDivElement>()

	const { prefetch } = usePrefetchMediaPaged()
	const { library } = useLibraryContext()
	const { layoutMode, setLayout, columns, setColumns } = useBooksLayout((state) => ({
		columns: state.columns,
		layoutMode: state.layout,
		setColumns: state.setColumns,
		setLayout: state.setLayout,
	}))
	const {
		filters,
		ordering,
		pagination: { page, page_size },
		setPage,
		...rest
	} = useFilterScene()
	const params = useMemo(
		() => ({
			page,
			page_size,
			params: {
				...filters,
				...ordering,
				series: {
					library: {
						id: [library.id],
					},
				},
			},
		}),
		[page, page_size, ordering, filters, library.id],
	)
	const {
		isLoading: isLoadingMedia,
		isRefetching: isRefetchingMedia,
		media,
		pageData,
	} = usePagedMediaQuery(params)

	// Secure catalog bridge
	const isSecure = Boolean((library as unknown as Record<string, unknown>)?.['is_secure'])
	const encryptionStatus = (library as unknown as Record<string, unknown>)?.[
		'encryption_status'
	] as string | undefined
	const isNotEncrypted = isSecure && encryptionStatus === 'NOT_ENCRYPTED'
	const isBroken = isSecure && encryptionStatus === 'ENCRYPTION_BROKEN'
	const { getLMK } = useLmkStore((s) => ({ getLMK: s.getLMK }))
	const lmk = getLMK(library.id)
	const getLMKAsync = async () => {
		const key = getLMK(library.id)
		if (!key) throw new Error('LMK not set')
		return key
	}
	const { data: secureCatalog, error: secureError } = useSecureCatalog(library.id, getLMKAsync, {
		enabled: isSecure && !!lmk && !isNotEncrypted,
	})
	const secureCatalogMissing = isSecure && !!lmk && secureCatalog === null
	const secureBooks = useMemo<Media[] | undefined>(() => {
		if (!isSecure || !secureCatalog) return undefined
		const seriesFilter = (filters as Record<string, unknown>)['secure_series_id']
		const media =
			typeof seriesFilter === 'string'
				? secureCatalog.media.filter((m) => (m.seriesId || '') === seriesFilter)
				: secureCatalog.media
		// Minimal Media shape
		return media.map((m) => ({
			id: m.id,
			name: m.name,
			size: m.size,
			extension: m.extension,
			pages: m.pages,
			updated_at: m.updatedAt,
			created_at: m.updatedAt,
			modified_at: null,
			hash: null,
			koreader_hash: null,
			path: '',
			status: 'READY' as FileStatus,
			series_id: m.seriesId ?? '',
			metadata: null,
			series: null,
			active_reading_session: null,
			finished_reading_sessions: null,
			current_page: null,
			current_epubcfi: null,
			is_completed: null,
			tags: null,
			bookmarks: null,
		})) as Media[]
	}, [isSecure, secureCatalog, filters])
	const { current_page, total_pages } = pageData || {}

	const differentSearch = usePreviousIsDifferent(filters?.search as string)
	useEffect(() => {
		if (differentSearch) {
			setPage(1)
		}
	}, [differentSearch, setPage])

	// Force GRID layout for secure libraries (table not supported for secure)
	useEffect(() => {
		if (isSecure && layoutMode !== 'GRID') {
			setLayout('GRID')
		}
	}, [isSecure, layoutMode, setLayout])

	const handlePrefetchPage = useCallback(
		(page: number) => {
			prefetch({
				...params,
				page,
			})
		},
		[params, prefetch],
	)

	const shouldScroll = usePreviousIsDifferent(current_page)
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

	const renderContent = () => {
		if (layoutMode === 'GRID' || isSecure) {
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

			if (isSecure && secureCatalogMissing) {
				return (
					<div className="flex flex-1 px-4 pb-2 pt-4 md:pb-4">
						<GenericEmptyState
							title="Secure library is empty or not yet scanned"
							subtitle="Run a secure scan from the admin UI to populate this secure library, then refresh."
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

			return (
				<URLFilterContainer
					currentPage={current_page || 1}
					pages={total_pages || 1}
					onChangePage={setPage}
					onPrefetchPage={handlePrefetchPage}
				>
					<div className="flex flex-1 px-4 pb-2 pt-4 md:pb-4">
						<BookGrid
							isLoading={isSecure ? false : isLoadingMedia}
							books={isSecure ? secureBooks : media}
							onSelect={
								isSecure ? (m) => navigate(`/books/secure/${library.id}/${m.id}`) : undefined
							}
							libraryId={isSecure ? library.id : undefined}
							hasFilters={Object.keys(filters || {}).length > 0}
						/>
					</div>
				</URLFilterContainer>
			)
		} else {
			return (
				<BookTable
					items={media || []}
					render={(props) => (
						<URLFilterContainer
							currentPage={current_page || 1}
							pages={total_pages || 1}
							onChangePage={setPage}
							onPrefetchPage={handlePrefetchPage}
							tableControls={
								<EntityTableColumnConfiguration
									entity="media"
									configuration={columns || defaultBookColumnSort}
									onSave={setColumns}
								/>
							}
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
					<title>Stump | {library.name || ''}</title>
				</Helmet>

				<section ref={containerRef} id="grid-top-indicator" className="h-0" />

				<FilterHeader
					isSearching={isRefetchingMedia}
					layoutControls={<TableOrGridLayout layout={layoutMode} setLayout={setLayout} />}
					orderControls={<URLOrdering entity="media" />}
					filterControls={<URLFilterDrawer entity="media" />}
					navOffset
				/>

				{renderContent()}
			</div>
		</FilterContext.Provider>
	)
}
