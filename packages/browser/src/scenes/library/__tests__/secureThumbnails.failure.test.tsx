import { decryptAesGcm } from '@stump/client'
import type { Media, Series } from '@stump/sdk'
import { render, screen, waitFor } from '@testing-library/react'

import BookCard from '@/components/book/BookCard'
import SeriesCard from '@/components/series/SeriesCard'
import useIsInView from '@/hooks/useIsInView'
import { useLmkStore } from '@/stores'

// Expose imageUrl from EntityCard via data attribute so we can assert thumbnail behavior
jest.mock('@/components/entity', () => ({
	EntityCard: (props: any) => <div data-testid="entity-card" data-image-url={props.imageUrl} />,
}))

jest.mock('@stump/client', () => {
	const actual = jest.requireActual('@stump/client')
	return {
		...actual,
		useSDK: jest.fn(() => ({
			sdk: {
				serviceURL: 'http://localhost',
				token: 'token',
				media: {
					thumbnailURL: (id: string) => `DEFAULT_THUMB_${id}`,
				},
				series: {
					thumbnailURL: (id: string) => `DEFAULT_SERIES_THUMB_${id}`,
				},
			},
		})),
		decryptAesGcm: jest.fn(),
		deriveThumbnailKey: jest.fn(async () => new Uint8Array([1, 2, 3])),
		usePrefetchMediaByID: jest.fn(() => ({ prefetch: jest.fn() })),
		usePrefetchSeries: jest.fn(() => ({ prefetch: jest.fn() })),
	}
})

jest.mock('@/hooks/useIsInView', () => ({
	__esModule: true,
	default: jest.fn(() => [{ current: null }, true]),
}))

jest.mock('@/stores', () => {
	const actual = jest.requireActual('@/stores')
	return {
		...actual,
		useLmkStore: jest.fn(),
	}
})

const BLANK_PREFIX = 'data:image/gif;base64'

function buildMedia(partial: Partial<Media> = {}): Media {
	return {
		id: 'm1',
		name: 'Test Book',
		size: 123,
		pages: 10,
		updated_at: new Date().toISOString(),
		created_at: new Date().toISOString(),
		modified_at: null,
		extension: 'cbz',
		path: '/path',
		status: 'READY' as any,
		series_id: '',
		metadata: null,
		series: null as any,
		active_reading_session: null as any,
		finished_reading_sessions: null as any,
		current_page: null,
		current_epubcfi: null as any,
		is_completed: null as any,
		tags: null as any,
		bookmarks: null as any,
		koreader_hash: null as any,
		hash: null as any,
		...partial,
	}
}

function buildSeries(partial: Partial<Series> = {}): Series {
	return {
		id: 's1',
		name: 'Test Series',
		media: [],
		media_count: 0 as any,
		unread_media_count: 0 as any,
		status: 'READY' as any,
		created_at: new Date().toISOString(),
		updated_at: new Date().toISOString(),
		...partial,
	} as unknown as Series
}

describe('Secure thumbnails failure & LMK-missing behavior', () => {
	beforeAll(() => {
		if (!URL.createObjectURL) {
			const createObjectURLMock: () => number = () => 'blob:mock' as any
			// @ts-expect-error - JSDOM may not implement this
			URL.createObjectURL = createObjectURLMock
		}
		if (!URL.revokeObjectURL) {
			const revokeObjectURLMock: (input: number) => number = () => 0
			// @ts-expect-error - JSDOM may not implement this
			URL.revokeObjectURL = revokeObjectURLMock
		}
	})

	beforeEach(() => {
		jest.clearAllMocks()
		;(useIsInView as unknown as jest.Mock).mockReturnValue([{ current: null }, true])
	})

	it('BookCard uses blank thumbnail when LMK is missing (no non-secure fallback)', async () => {
		;(useLmkStore as unknown as jest.Mock).mockImplementation((selector: (state: any) => any) =>
			selector({
				getLMK: () => null,
				setLMK: jest.fn(),
				clearLMK: jest.fn(),
				privateKey: null,
				publicKey: null,
				setPrivateKey: jest.fn(),
				setPublicKey: jest.fn(),
			}),
		)

		const media = buildMedia()

		render(<BookCard media={media} libraryId="secure-lib" />)

		const el = await screen.findByTestId('entity-card')
		const url = el.getAttribute('data-image-url') || ''
		expect(url.startsWith(BLANK_PREFIX)).toBe(true)
		expect(url).not.toBe('DEFAULT_THUMB_m1')
	})

	it('BookCard falls back to blank thumbnail when decryption fails', async () => {
		;(useLmkStore as unknown as jest.Mock).mockImplementation((selector: (state: any) => any) =>
			selector({
				getLMK: () => new Uint8Array([1, 2, 3]),
				setLMK: jest.fn(),
				clearLMK: jest.fn(),
				privateKey: null,
				publicKey: null,
				setPrivateKey: jest.fn(),
				setPublicKey: jest.fn(),
			}),
		)
		;(decryptAesGcm as jest.Mock).mockRejectedValueOnce(new Error('bad decrypt'))

		jest.spyOn(global, 'fetch' as any).mockResolvedValueOnce({
			ok: true,
			arrayBuffer: async () => new Uint8Array(32).buffer,
			headers: {
				get: (name: string) => {
					if (name === 'X-Plaintext-Size') return '16'
					if (name === 'X-Tag') return 'tag-b64'
					if (name === 'X-Nonce') return 'nonce'
					return null
				},
			},
		} as any)

		const media = buildMedia()

		render(<BookCard media={media} libraryId="secure-lib" />)

		const el = await screen.findByTestId('entity-card')
		await waitFor(() => {
			const url = el.getAttribute('data-image-url') || ''
			expect(url.startsWith(BLANK_PREFIX)).toBe(true)
		})
	})

	it('BookCard uses X-Plaintext-Size when decrypting secure thumbnail payload', async () => {
		;(useLmkStore as unknown as jest.Mock).mockImplementation((selector: (state: any) => any) =>
			selector({
				getLMK: () => new Uint8Array([1, 2, 3]),
				setLMK: jest.fn(),
				clearLMK: jest.fn(),
				privateKey: null,
				publicKey: null,
				setPrivateKey: jest.fn(),
				setPublicKey: jest.fn(),
			}),
		)
		;(decryptAesGcm as jest.Mock).mockResolvedValueOnce(new Uint8Array(16))

		jest.spyOn(global, 'fetch' as any).mockResolvedValueOnce({
			ok: true,
			arrayBuffer: async () => new Uint8Array(32).buffer,
			headers: {
				get: (name: string) => {
					if (name === 'X-Plaintext-Size') return '16'
					if (name === 'X-Tag') return 'tag-b64'
					if (name === 'X-Nonce') return 'nonce'
					return null
				},
			},
		} as any)

		const media = buildMedia()

		render(<BookCard media={media} libraryId="secure-lib" />)

		await waitFor(() => {
			expect((decryptAesGcm as jest.Mock).mock.calls.length).toBeGreaterThan(0)
		})

		const call = (decryptAesGcm as jest.Mock).mock.calls[0]
		const sizeArg = call[4]
		expect(sizeArg).toBe(16)
	})

	it('SeriesCard uses blank thumbnail when LMK is missing (no non-secure fallback)', async () => {
		;(useLmkStore as unknown as jest.Mock).mockImplementation((selector: (state: any) => any) =>
			selector({
				getLMK: () => null,
				setLMK: jest.fn(),
				clearLMK: jest.fn(),
				privateKey: null,
				publicKey: null,
				setPrivateKey: jest.fn(),
				setPublicKey: jest.fn(),
			}),
		)

		const series = buildSeries()

		render(<SeriesCard series={series} libraryId="secure-lib" mediaIdForThumbnail="m1" />)

		const el = await screen.findByTestId('entity-card')
		const url = el.getAttribute('data-image-url') || ''
		expect(url.startsWith(BLANK_PREFIX)).toBe(true)
		expect(url).not.toBe('DEFAULT_SERIES_THUMB_s1')
	})
})
