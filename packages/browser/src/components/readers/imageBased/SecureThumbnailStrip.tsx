import { cn, ProgressBar, Text } from '@stump/components'
import { motion } from 'framer-motion'
import { useCallback, useEffect, useMemo, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Virtuoso, VirtuosoHandle } from 'react-virtuoso'

import { EntityImage } from '@/components/entity'
import useIsInView from '@/hooks/useIsInView'
import { useBookPreferences } from '@/scenes/book/reader/useBookPreferences'

import { useImageBaseReaderContext } from './context'

const THUMB_WIDTH = 100
const THUMB_HEIGHT = 150
const THUMB_WIDTH_ACTIVE = 130
const THUMB_HEIGHT_ACTIVE = 195
const BLANK_IMG = 'data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs='

type ThumbProps = {
	index: number
	isCurrentSet: boolean
}

function SecureThumbnail({ index, isCurrentSet }: ThumbProps) {
	const { setCurrentPage, setDimensions, getPageUrl } = useImageBaseReaderContext()
	const [ref, inView] = useIsInView<HTMLDivElement>('200px')
	const dimensionsSetRef = useRef(false)

	const url = useMemo(() => {
		if (!inView) return BLANK_IMG
		return getPageUrl(index + 1)
	}, [getPageUrl, inView, index])

	const handleImageLoad = useCallback(
		({ height, width }: { height: number; width: number }) => {
			if (dimensionsSetRef.current) return
			dimensionsSetRef.current = true
			setDimensions((prev) => {
				if (prev[index]) return prev
				return {
					...prev,
					[index]: {
						height,
						width,
						ratio: width / height,
					},
				}
			})
		},
		[setDimensions, index],
	)

	const containerSize = isCurrentSet
		? { width: THUMB_WIDTH_ACTIVE, height: THUMB_HEIGHT_ACTIVE }
		: { width: THUMB_WIDTH, height: THUMB_HEIGHT }

	return (
		<div
			className="flex shrink-0 flex-col items-center justify-end gap-1 px-1"
			style={{ height: THUMB_HEIGHT_ACTIVE + 24 }}
		>
			<div
				ref={ref}
				onClick={() => setCurrentPage(index + 1)}
				className={cn(
					'flex cursor-pointer items-center justify-center overflow-hidden rounded-md border-2 border-solid border-transparent shadow-xl transition-all duration-200 hover:border-edge-brand',
					{
						'border-edge-brand': isCurrentSet,
					},
				)}
				style={containerSize}
			>
				<EntityImage src={url} className="h-full w-full object-contain" onLoad={handleImageLoad} />
			</div>
			{!isCurrentSet && <Text className="text-center text-xs text-[#898d94]">{index + 1}</Text>}
		</div>
	)
}

export default function SecureThumbnailStrip() {
	const { book, currentPage, pageSets } = useImageBaseReaderContext()
	const [search] = useSearchParams()
	const isIncognito = search.get('incognito') === 'true'
	const {
		settings: { showToolBar },
		bookPreferences: { readingDirection },
	} = useBookPreferences({ book })

	const virtuosoRef = useRef<VirtuosoHandle>(null)

	const currentPageSetIdx = useMemo(
		() => pageSets.findIndex((set) => set.includes(currentPage - 1)),
		[currentPage, pageSets],
	)

	useEffect(() => {
		if (showToolBar && currentPageSetIdx >= 0) {
			virtuosoRef.current?.scrollToIndex({
				align: 'center',
				behavior: 'smooth',
				index: currentPageSetIdx,
			})
		}
	}, [showToolBar, currentPageSetIdx])

	const stripHeight = THUMB_HEIGHT_ACTIVE + 24 + 8
	const footerHeight = 56

	return (
		<motion.nav
			initial={false}
			animate={showToolBar ? 'visible' : 'hidden'}
			variants={transition}
			transition={{ duration: 0.2, ease: 'easeInOut' }}
			className="fixed bottom-0 left-0 z-[100] flex w-full flex-col justify-end overflow-hidden bg-opacity-75 text-white shadow-lg"
			style={{
				height: stripHeight + footerHeight,
			}}
		>
			<Virtuoso
				ref={virtuosoRef}
				style={{ height: stripHeight, overflowY: 'hidden', overflowX: 'auto' }}
				horizontalDirection
				data={pageSets}
				itemContent={(idx, indexes) => (
					<div className="flex h-full items-end">
						{indexes.map((index) => (
							<SecureThumbnail key={index} index={index} isCurrentSet={currentPageSetIdx === idx} />
						))}
					</div>
				)}
				overscan={{ main: 3, reverse: 3 }}
				initialTopMostItemIndex={
					readingDirection === 'rtl' ? pageSets.length - currentPageSetIdx : currentPageSetIdx
				}
			/>

			<div className="flex w-full flex-col gap-2 px-4 py-2">
				<ProgressBar
					size="sm"
					value={currentPage}
					max={book.pages}
					className="bg-[#0c0c0c]"
					indicatorClassName="bg-[#898d94]"
					inverted={readingDirection === 'rtl'}
				/>

				<div className="flex flex-row justify-around">
					<Text className="text-sm text-[#898d94]">
						{currentPage} of {book.pages}
						{isIncognito ? ' • Private' : ''}
					</Text>
				</div>
			</div>
		</motion.nav>
	)
}

const transition = {
	hidden: {
		opacity: 0,
		transition: {
			duration: 0.2,
			ease: 'easeInOut',
		},
		y: '100%',
	},
	visible: {
		opacity: 1,
		transition: {
			duration: 0.2,
			ease: 'easeInOut',
		},
		y: 0,
	},
}
