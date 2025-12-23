import { motion } from 'framer-motion'
import { Fragment } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'

import { useBookPreferences } from '@/scenes/book/reader/useBookPreferences'

import { useImageBaseReaderContext } from '../context'
import SecureThumbnailStrip from '../SecureThumbnailStrip'
import ReaderFooter from './ReaderFooter'
import ReaderHeader from './ReaderHeader'

export default function ControlsOverlay() {
	const { book } = useImageBaseReaderContext()
	const params = useParams()
	const [search] = useSearchParams()
	const isIncognito = search.get('incognito') === 'true'
	const isSecureReaderRoute = Boolean(params.id && params.mediaId)
	const {
		settings: { showToolBar },
		setSettings,
		bookPreferences: { readingMode },
	} = useBookPreferences({ book })

	const showBottomToolbar = readingMode === 'paged'

	return (
		<Fragment>
			<ReaderHeader />

			<motion.div
				className="absolute inset-0 z-10 flex-1"
				style={{
					background:
						'linear-gradient(0deg, hsla(0, 0%, 0%, 0.95), hsla(0, 0%, 0%, 0.80), hsla(0, 0%, 0%, 0.5), hsla(0, 0%, 0%, 0.5), hsla(0, 0%, 0%, 0.5), hsla(0, 0%, 0%, 0.5), hsla(0, 0%, 0%, 0.80), hsla(0, 0%, 0%, 0.95))',
				}}
				initial={false}
				animate={showToolBar ? 'visible' : 'hidden'}
				variants={transition}
				transition={{ duration: 0.2, ease: 'easeInOut' }}
				onClick={() => setSettings({ showToolBar: !showToolBar })}
			/>

			{showBottomToolbar &&
				(isIncognito && isSecureReaderRoute ? <SecureThumbnailStrip /> : <ReaderFooter />)}
		</Fragment>
	)
}

const transition = {
	hidden: {
		opacity: 0,
		transition: {
			duration: 0.2,
			ease: 'easeInOut',
		},
		display: 'none',
	},
	visible: {
		opacity: 1,
		transition: {
			duration: 0.2,
			ease: 'easeInOut',
		},
		display: 'flex',
	},
}
