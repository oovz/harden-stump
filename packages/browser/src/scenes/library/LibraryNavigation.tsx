import {
	usePrefetchLibraryBooks,
	usePrefetchLibraryFiles,
	usePrefetchLibrarySeries,
} from '@stump/client'
import { cn, Link, useSticky } from '@stump/components'
import { useMemo } from 'react'
import { useLocation } from 'react-router'
import { useMediaMatch } from 'rooks'

import { useAppContext } from '@/context'
import { usePreferences } from '@/hooks'
import paths from '@/paths'

import { useLibraryContext } from './context'

export default function LibraryNavigation() {
	const location = useLocation()
	const isMobile = useMediaMatch('(max-width: 768px)')
	const {
		preferences: { primary_navigation_mode, layout_max_width_px },
	} = usePreferences()
	const { library } = useLibraryContext()
	const { id, path } = library
	const { checkPermission, isServerOwner } = useAppContext()
	const { prefetch: prefetchBooks } = usePrefetchLibraryBooks({ id })
	const { prefetch: prefetchFiles } = usePrefetchLibraryFiles({
		path,
		fetchConfig: checkPermission('file:upload'),
	})
	const { prefetch: prefetchSeries } = usePrefetchLibrarySeries({ id })

	const { ref, isSticky } = useSticky<HTMLDivElement>({
		extraOffset: isMobile || primary_navigation_mode === 'TOPBAR' ? 56 : 0,
	})

	const isSecure = Boolean((library as Record<string, unknown>)['is_secure'])
	const canAccessFiles = checkPermission('file:explorer') && (!isSecure || isServerOwner)
	const tabs = useMemo(() => {
		const base = paths.librarySeries(id) // e.g. /libraries/:id
		return [
			{
				isActive: location.pathname === base || location.pathname.startsWith(`${base}/series`),
				label: 'Series',
				onHover: () => prefetchSeries(),
				to: paths.librarySeries(id),
			},
			{
				isActive: location.pathname.startsWith(`${base}/books`),
				label: 'Books',
				onHover: () => prefetchBooks(),
				to: paths.libraryBooks(id),
			},
			...(canAccessFiles
				? [
						{
							isActive: location.pathname.startsWith(`${base}/files`),
							label: 'Files',
							onHover: () => prefetchFiles(),
							to: paths.libraryFileExplorer(id),
						},
					]
				: []),
			{
				isActive: location.pathname.startsWith(`${base}/settings`),
				label: 'Settings',
				to: paths.libraryManage(id),
			},
		]
	}, [id, location.pathname, canAccessFiles, prefetchBooks, prefetchFiles, prefetchSeries])

	const preferTopBar = primary_navigation_mode === 'TOPBAR'

	return (
		<div
			ref={ref}
			className={cn(
				'sticky top-0 z-10 h-12 w-full border-b border-edge bg-transparent md:relative md:top-[unset] md:z-[unset]',
				{ 'bg-background': isSticky },
			)}
		>
			<nav
				className={cn(
					'-mb-px flex h-12 gap-x-6 overflow-x-scroll px-3 scrollbar-hide md:overflow-x-hidden',
					{
						'mx-auto': preferTopBar && !!layout_max_width_px,
					},
				)}
				style={{ maxWidth: preferTopBar ? layout_max_width_px || undefined : undefined }}
			>
				{tabs.map((tab) => (
					<Link
						to={tab.to}
						key={tab.to}
						underline={false}
						onMouseEnter={tab.onHover}
						className={cn('whitespace-nowrap border-b-2 px-1 py-3 text-sm font-medium', {
							'border-edge-brand text-foreground-brand': tab.isActive,
							'border-transparent text-foreground-muted hover:border-edge': !tab.isActive,
						})}
					>
						{tab.label}
					</Link>
				))}
			</nav>
		</div>
	)
}
