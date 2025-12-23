import { CardGrid } from '@stump/components'
import { type Series } from '@stump/sdk'

import GenericEmptyState from '../GenericEmptyState'
import SecureSeriesCard from './SecureSeriesCard'
import SeriesCard from './SeriesCard'

interface Props {
	isLoading: boolean
	series?: Series[]
	hasFilters?: boolean
	libraryId?: string
	secureFirstMediaIds?: Record<string, string>
}

export default function SeriesGrid({
	series,
	isLoading,
	hasFilters,
	libraryId,
	secureFirstMediaIds,
}: Props) {
	if (isLoading) {
		return null
	} else if (!series || !series.length) {
		return (
			<div className="grid flex-1 place-self-center">
				<GenericEmptyState
					title={
						hasFilters
							? 'No series match your search'
							: "It doesn't look like there are any series here"
					}
					subtitle={
						hasFilters
							? 'Try removing some filters to see more series'
							: 'Try adding some series to your library'
					}
				/>
			</div>
		)
	}

	return (
		<CardGrid>
			{series.map((s) =>
				libraryId ? (
					<SecureSeriesCard
						key={s.id}
						series={s}
						libraryId={libraryId}
						mediaIdForThumbnail={secureFirstMediaIds ? secureFirstMediaIds[s.id] : undefined}
					/>
				) : (
					<SeriesCard
						key={s.id}
						series={s}
						mediaIdForThumbnail={secureFirstMediaIds ? secureFirstMediaIds[s.id] : undefined}
					/>
				),
			)}
		</CardGrid>
	)
}
