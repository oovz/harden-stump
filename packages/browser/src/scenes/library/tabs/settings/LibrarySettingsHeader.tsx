import { cn, Heading, Text } from '@stump/components'
import { useLocaleContext } from '@stump/i18n'
import { useMemo } from 'react'
import { useLocation } from 'react-router'
import { useMediaMatch } from 'rooks'

import { usePreferences } from '@/hooks/usePreferences'

import { useLibraryContext } from '../../context'
import LibrarySettingsSelectNavigation from './LibrarySettingsSelectNavigation'
import { LibraryPatternDisplay } from './options/scanner'
import { buildLibrarySettingsRouteGroups } from './routes'

export default function LibrarySettingsHeader() {
	const location = useLocation()
	const {
		preferences: { primary_navigation_mode, layout_max_width_px, enable_double_sidebar },
	} = usePreferences()
	const { t } = useLocaleContext()
	const { library } = useLibraryContext()

	const isMobile = useMediaMatch('(max-width: 768px)')
	const preferTopBar = primary_navigation_mode === 'TOPBAR'
	const displayingSideBar = !!enable_double_sidebar && !isMobile

	/**
	 * The active route based on the current location
	 */
	const activeRouteGroup = useMemo(() => {
		const isSecure = Boolean((library as Record<string, unknown>)['is_secure'])
		const groups = buildLibrarySettingsRouteGroups(isSecure)
		return groups
			.flatMap((group) => group.items)
			.find((page) => location.pathname.endsWith(page.to))
	}, [library, location.pathname])

	/**
	 * The active route's locale key, which is used to pull the title and description. If
	 * the active route has sub-items, we'll have to check the provided matchers to see
	 * if/which sub-item is active
	 */
	const activeRouteKey = useMemo(() => {
		if (!activeRouteGroup) {
			return null
		}

		const matchedSubItemKey = activeRouteGroup.subItems?.find((subItem) =>
			subItem.matcher(location.pathname),
		)?.localeKey

		return matchedSubItemKey || activeRouteGroup?.localeKey
	}, [activeRouteGroup, location.pathname])

	const translatedHeader = activeRouteKey
		? t(`librarySettingsScene.${activeRouteKey}.title`)
		: t('librarySettingsScene.heading')
	const translatedDescription = activeRouteKey
		? t(`librarySettingsScene.${activeRouteKey}.description`)
		: t('librarySettingsScene.subtitle')

	const isScannerSettings = activeRouteKey === 'options/scanning'

	return (
		<header
			className={cn(
				'flex w-full flex-col items-start justify-between gap-4 border-b border-b-edge p-4 lg:flex-row lg:gap-0',
				{
					// Note: We make the border transparent because the width constraint when using a top bar
					'mx-auto border-b-transparent': preferTopBar && !!layout_max_width_px,
					'pl-52': displayingSideBar,
				},
			)}
			style={{
				maxWidth: preferTopBar ? layout_max_width_px || undefined : undefined,
			}}
		>
			<div className="flex flex-col space-y-4">
				<div>
					<Heading size="lg" className="font-bold">
						{translatedHeader}
					</Heading>

					<Text variant="muted" className="mt-1.5" size="sm">
						{translatedDescription}
					</Text>
				</div>
			</div>

			{isScannerSettings && <LibraryPatternDisplay />}

			{isMobile && <LibrarySettingsSelectNavigation />}
		</header>
	)
}
