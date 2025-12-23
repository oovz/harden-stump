import { useDirectoryListing, useSDK } from '@stump/client'
import { DirectoryListingFile } from '@stump/sdk'
import { useCallback, useState } from 'react'
import toast from 'react-hot-toast'
import { useNavigate } from 'react-router'

import paths from '@/paths'

import { ExplorerContext, ExplorerLayout, IExplorerContext } from './context'
import FileExplorer from './FileExplorer'
import FileExplorerFooter, { FOOTER_HEIGHT } from './FileExplorerFooter'
import FileExplorerHeader from './FileExplorerHeader'
import { getBook } from './FileThumbnail'

type Props = Pick<IExplorerContext, 'libraryID' | 'rootPath' | 'uploadConfig' | 'isSecureLibrary'>

// TODO: refactor to match other explore scenes, e.g. sticky header + fixed footer + window scrolling

export default function FileExplorerProvider({ rootPath, isSecureLibrary, ...ctx }: Props) {
	const navigate = useNavigate()
	const { sdk } = useSDK()

	const [layout, setLayout] = useState<ExplorerLayout>(() => getDefaultLayout())

	// TODO: I need to store location.state somewhere so that when the user uses native navigation,
	// their history, or at the very least where they left off, is persisted.
	const {
		entries,
		setPath,
		path,
		goForward,
		goBack,
		canGoBack,
		canGoForward,
		refetch,
		canLoadMore,
		loadMore,
	} = useDirectoryListing({
		enabled: !!rootPath,
		enforcedRoot: rootPath,
		initialPath: rootPath,
	})

	const handleSelect = async (entry: DirectoryListingFile) => {
		if (entry.is_directory) {
			setPath(entry.path)
		} else {
			if (isSecureLibrary && isSecureLibraryMediaFile(entry.name)) {
				toast('Secure libraries do not open media files from the Files tab.', {
					id: 'secure-files-tab-disabled',
				})
				return
			}
			try {
				const entity = await getBook(entry.path, sdk)
				if (entity) {
					navigate(paths.bookOverview(entity.id), {
						state: {
							forward_path: path,
						},
					})
				} else {
					toast.error('No associated DB entry found for this file')
				}
			} catch (err) {
				console.error(err)
				toast.error('An unknown error occurred')
			}
		}
	}

	const changeLayout = (newLayout: 'grid' | 'table') => {
		setDefaultLayout(newLayout)
		setLayout(newLayout)
	}

	const onLoadMore = useCallback(() => {
		if (canLoadMore) {
			loadMore()
		}
	}, [canLoadMore, loadMore])

	return (
		<ExplorerContext.Provider
			value={{
				canGoBack: canGoBack && path !== rootPath,
				canGoForward,
				currentPath: path,
				files: entries,
				isSecureLibrary,
				goBack,
				goForward,
				layout,
				onSelect: handleSelect,
				refetch,
				rootPath,
				setLayout: changeLayout,
				canLoadMore,
				loadMore: onLoadMore,
				...ctx,
			}}
		>
			<div className="flex h-full flex-1 flex-col">
				<FileExplorerHeader />
				<div
					className="flex-1"
					style={{
						marginBottom: FOOTER_HEIGHT,
					}}
				>
					<FileExplorer />
				</div>
				<FileExplorerFooter />
			</div>
		</ExplorerContext.Provider>
	)
}

const LOCAL_STORAGE_LAYOUT_KEY = 'stump-explorer-layout'
const getDefaultLayout = () => {
	const storedLayout = localStorage.getItem(LOCAL_STORAGE_LAYOUT_KEY)
	if (storedLayout === 'grid' || storedLayout === 'table') {
		return storedLayout
	}
	return 'grid'
}
const setDefaultLayout = (layout: ExplorerLayout) => {
	localStorage.setItem(LOCAL_STORAGE_LAYOUT_KEY, layout)
}

function isSecureLibraryMediaFile(name: string): boolean {
	const lower = (name || '').toLowerCase()
	return (
		lower.endsWith('.cbz') ||
		lower.endsWith('.cbr') ||
		lower.endsWith('.cb7') ||
		lower.endsWith('.pdf') ||
		lower.endsWith('.epub') ||
		lower.endsWith('.zip') ||
		lower.endsWith('.rar')
	)
}
