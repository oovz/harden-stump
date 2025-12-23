import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { LibraryContext } from '../context'
import SecureReaderScene from '../SecureReaderScene'
import SecureUnlockGate from '../SecureUnlockGate'
import LibraryBooksScene from '../tabs/books/LibraryBooksScene'
import SecureLibraryScene from '../tabs/secure/SecureLibraryScene'
import LibrarySeriesSceneWrapper from '../tabs/series/LibrarySeriesScene'

jest.mock('@/components/book/BookGrid', () => ({
	__esModule: true,
	default: (props: any) => (
		<div
			data-testid="book-grid-mock"
			data-props={JSON.stringify({ libraryId: props.libraryId, books: props.books })}
		>
			{props.books?.map((b: any) => b.name).join(',') || 'no-books'}
			<button type="button" onClick={() => props.onSelect?.(props.books?.[0]?.id)}>
				Open secure book
			</button>
		</div>
	),
}))

jest.mock('@/components/series/SeriesGrid', () => ({
	__esModule: true,
	default: (props: any) => (
		<div
			data-testid="series-grid-mock"
			data-props={JSON.stringify({
				libraryId: props.libraryId,
				secureFirstMediaIds: props.secureFirstMediaIds,
				series: props.series,
			})}
		>
			{props.series?.map((s: any) => s.name).join(',') || 'no-series'}
		</div>
	),
}))

const mockSecureCatalog: jest.Mock<any, any[]> = jest.fn()
const mockSecureAccessStatus: jest.Mock<any, any[]> = jest.fn()

jest.mock('@/hooks/useSecureCatalog', () => ({
	useSecureCatalog: (...args: any[]) => mockSecureCatalog(...args),
}))

jest.mock('@/hooks/useSecureAccessStatus', () => ({
	useSecureAccessStatus: (...args: any[]) => mockSecureAccessStatus(...args),
}))

jest.mock('@stump/client', () => {
	const actual = jest.requireActual('@stump/client')
	return {
		...actual,
		deriveDEK: jest.fn(),
		decryptAesGcm: jest.fn(),
		useSDK: jest.fn(() => ({
			sdk: { serviceURL: 'http://localhost', token: 'token', auth: { keys: { me: ['me'] } } },
		})),
		usePagedMediaQuery: jest.fn(() => ({
			isLoading: false,
			isRefetching: false,
			media: [],
			pageData: { current_page: 1, total_pages: 1 },
		})),
		usePrefetchMediaPaged: jest.fn(() => ({ prefetch: jest.fn() })),
		useLibraryByID: jest.fn((id: string) => ({
			isLoading: false,
			library: {
				id,
				name: 'Secure Lib',
				is_secure: true,
				encryption_status: 'ENCRYPTED',
			},
		})),
		usePagedSeriesQuery: jest.fn(() => ({
			isLoading: false,
			isRefetching: false,
			series: [],
			pageData: { current_page: 1, total_pages: 1 },
		})),
		usePrefetchPagedSeries: jest.fn(() => ({ prefetch: jest.fn() })),
	}
})

jest.mock('@/stores', () => ({
	...jest.requireActual('@/stores'),
	useLmkStore: jest.fn((selector: (state: any) => any) =>
		selector({
			getLMK: () => null,
			setLMK: jest.fn(),
			clearLMK: jest.fn(),
			privateKey: null,
			publicKey: null,
			setPrivateKey: jest.fn(),
			setPublicKey: jest.fn(),
		}),
	),
}))

jest.mock('@/components/filters', () => ({
	FilterContext: {
		Provider: ({ children }: any) => children,
	},
	FilterProvider: ({ children }: any) => children,
	FilterHeader: () => null,
	URLFilterContainer: ({ children }: any) => children,
	URLFilterDrawer: () => null,
	URLOrdering: () => null,
	useFilterScene: jest.fn(() => ({
		filters: {},
		ordering: {},
		pagination: { page: 1, page_size: 24 },
		setPage: jest.fn(),
	})),
}))

jest.mock('@/components/ReadMore', () => () => null)
jest.mock('@/components/tags/TagList', () => () => null)

jest.mock('@/hooks/usePreferences', () => ({
	usePreferences: jest.fn(() => ({
		preferences: {
			primary_navigation_mode: 'SIDEBAR',
			layout_max_width_px: undefined,
		},
		update: jest.fn(),
	})),
}))

jest.mock('@/hooks', () => {
	const actual = jest.requireActual('@/hooks')
	return {
		...actual,
		usePreferences: jest.fn(() => ({
			preferences: {
				primary_navigation_mode: 'SIDEBAR',
				layout_max_width_px: undefined,
			},
			update: jest.fn(),
		})),
	}
})

jest.mock('rooks', () => ({
	useMediaMatch: jest.fn(() => false),
}))

describe('Secure libraries user flows', () => {
	beforeEach(() => {
		jest.clearAllMocks()
	})

	it('shows ENCRYPTION_BROKEN empty state in books tab for secure library', () => {
		const library: any = {
			id: 'secure-broken-books',
			name: 'Secure Broken Books',
			is_secure: true,
			encryption_status: 'ENCRYPTION_BROKEN',
			path: '/secure/broken-books',
			tags: [],
		}

		mockSecureCatalog.mockReturnValue({
			data: null,
			isLoading: false,
			refetch: jest.fn(),
		})

		render(
			<LibraryContext.Provider value={{ library }}>
				<MemoryRouter>
					<LibraryBooksScene />
				</MemoryRouter>
			</LibraryContext.Provider>,
		)

		expect(screen.getByText(/Secure library is currently broken/i)).toBeInTheDocument()
		expect(
			screen.getByText(
				/Contact the server owner to restore from backup and run a new secure scan, then try again\./i,
			),
		).toBeInTheDocument()
	})

	it('shows ENCRYPTION_BROKEN empty state in series tab for secure library', () => {
		const libraryId = 'secure-broken-series'
		const clientModule = jest.requireMock('@stump/client') as typeof import('@stump/client')
		const useLibraryByIDMock = clientModule.useLibraryByID as jest.Mock
		const defaultImpl = (id: string) => ({
			isLoading: false,
			library: {
				id,
				name: 'Secure Lib',
				is_secure: true,
				encryption_status: 'ENCRYPTED',
			},
		})

		useLibraryByIDMock.mockImplementation((id: string) =>
			id === libraryId
				? {
						isLoading: false,
						library: {
							id: libraryId,
							name: 'Secure Broken Series',
							is_secure: true,
							encryption_status: 'ENCRYPTION_BROKEN',
						},
					}
				: defaultImpl(id),
		)

		mockSecureCatalog.mockReturnValue({
			data: null,
			isLoading: false,
			refetch: jest.fn(),
		})

		try {
			render(
				<MemoryRouter initialEntries={[`/libraries/${libraryId}/series`]}>
					<Routes>
						<Route path="/libraries/:id/series" element={<LibrarySeriesSceneWrapper />} />
					</Routes>
				</MemoryRouter>,
			)

			expect(screen.getByText(/Secure library is currently broken/i)).toBeInTheDocument()
			expect(
				screen.getByText(
					/Contact the server owner to restore from backup and run a new secure scan, then try again\./i,
				),
			).toBeInTheDocument()
		} finally {
			useLibraryByIDMock.mockImplementation(defaultImpl as any)
		}
	})

	it('shows unlock overlay when user has access but LMK is missing', async () => {
		const library: any = {
			id: 'secure-1',
			name: 'Secure Lib',
			is_secure: true,
			encryption_status: 'ENCRYPTED',
			path: '/secure/path',
			tags: [],
		}

		mockSecureAccessStatus.mockReturnValue({ data: { has_access: true } })
		mockSecureCatalog.mockReturnValue({ data: null, isLoading: false, refetch: jest.fn() })

		render(
			<LibraryContext.Provider value={{ library }}>
				<SecureUnlockGate />
			</LibraryContext.Provider>,
		)

		expect(screen.getByText(/Unlock secure library/i)).toBeInTheDocument()
		expect(screen.getByPlaceholderText(/Account password/i)).toBeInTheDocument()
		expect(screen.getByRole('button', { name: /Advanced/i })).toBeInTheDocument()
		expect(screen.getByRole('button', { name: /Unlock/i })).toBeInTheDocument()

		// Keypair actions are in the advanced section
		expect(screen.queryByRole('button', { name: /Restore keypair/i })).not.toBeInTheDocument()
		expect(screen.queryByRole('button', { name: /Generate new keypair/i })).not.toBeInTheDocument()

		await userEvent.click(screen.getByRole('button', { name: /Advanced/i }))
		await waitFor(() => {
			expect(screen.getByRole('button', { name: /Restore keypair/i })).toBeInTheDocument()
			expect(screen.getByRole('button', { name: /Generate new keypair/i })).toBeInTheDocument()
		})
	})

	it('shows no-access overlay when user lacks secure access', () => {
		const library: any = {
			id: 'secure-2',
			name: 'Secure Lib',
			is_secure: true,
			encryption_status: 'ENCRYPTED',
			path: '/secure/path',
			tags: [],
		}

		mockSecureAccessStatus.mockReturnValue({ data: { has_access: false } })
		mockSecureCatalog.mockReturnValue({ data: null, isLoading: false, refetch: jest.fn() })

		render(
			<LibraryContext.Provider value={{ library }}>
				<SecureUnlockGate />
			</LibraryContext.Provider>,
		)

		expect(
			screen.getByText(/Access to this secure library has been revoked or is not available\./i),
		).toBeInTheDocument()
	})

	it('uses secure catalog for books and passes libraryId for secure thumbnails', () => {
		const library: any = {
			id: 'secure-books',
			name: 'Secure Books',
			is_secure: true,
			encryption_status: 'ENCRYPTED',
			path: '/secure/books',
			tags: [],
		}

		mockSecureAccessStatus.mockReturnValue({ data: { has_access: true } })
		mockSecureCatalog.mockReturnValue({
			data: {
				version: 1,
				totalSeries: 0,
				totalMedia: 1,
				libraryId: 'secure-books',
				updatedAt: new Date().toISOString(),
				series: [],
				media: [
					{
						id: 'm1',
						seriesId: null,
						name: 'Secure Book 1',
						pages: 10,
						extension: 'cbz',
						size: 123,
						sortOrder: 0,
						number: null,
						volume: null,
						updatedAt: new Date().toISOString(),
					},
				],
			},
			isLoading: false,
			refetch: jest.fn(),
		})

		render(
			<LibraryContext.Provider value={{ library }}>
				<MemoryRouter>
					<LibraryBooksScene />
				</MemoryRouter>
			</LibraryContext.Provider>,
		)

		const el = screen.getByTestId('book-grid-mock')
		const props = JSON.parse(el.getAttribute('data-props') || '{}') as any
		expect(props.libraryId).toBe('secure-books')
		expect(props.books).toHaveLength(1)
		expect(el.textContent).toContain('Secure Book 1')
	})

	it('uses secure catalog for series and passes libraryId and secureFirstMediaIds', async () => {
		const libraryId = 'secure-series'
		mockSecureAccessStatus.mockReturnValue({ data: { has_access: true } })
		mockSecureCatalog.mockReturnValue({
			data: {
				version: 1,
				totalSeries: 2,
				totalMedia: 3,
				libraryId,
				updatedAt: new Date().toISOString(),
				series: [
					{ id: 's1', name: 'Secure Series 1' },
					{ id: 's2', name: 'Secure Series 2' },
				],
				media: [
					{
						id: 'm1',
						name: 'First in S1',
						seriesId: 's1',
						pages: 10,
						extension: 'cbz',
						size: 123,
						sortOrder: 0,
						number: null,
						volume: null,
						updatedAt: new Date().toISOString(),
					},
					{
						id: 'm2',
						name: 'First in S2',
						seriesId: 's2',
						pages: 10,
						extension: 'cbz',
						size: 123,
						sortOrder: 0,
						number: null,
						volume: null,
						updatedAt: new Date().toISOString(),
					},
					{
						id: 'm3',
						name: 'Another in S1',
						seriesId: 's1',
						pages: 10,
						extension: 'cbz',
						size: 123,
						sortOrder: 0,
						number: null,
						volume: null,
						updatedAt: new Date().toISOString(),
					},
				],
			},
			isLoading: false,
			refetch: jest.fn(),
		})

		render(
			<MemoryRouter initialEntries={[`/libraries/${libraryId}/series`]}>
				<Routes>
					<Route path="/libraries/:id/series" element={<LibrarySeriesSceneWrapper />} />
				</Routes>
			</MemoryRouter>,
		)

		const el = screen.getByTestId('series-grid-mock')
		const props = JSON.parse(el.getAttribute('data-props') || '{}') as any
		expect(props.libraryId).toBe(libraryId)
		expect(Object.keys(props.secureFirstMediaIds || {})).toEqual(['s1', 's2'])
		expect(el.textContent).toContain('Secure Series 1')
	})

	it('shows no-access copy in secure tab when user lacks secure access', () => {
		const library: any = {
			id: 'secure-no-access',
			name: 'Secure Lib',
			is_secure: true,
			encryption_status: 'ENCRYPTED',
			path: '/secure/path',
			tags: [],
		}

		mockSecureAccessStatus.mockReturnValue({ data: { has_access: false } })
		mockSecureCatalog.mockReturnValue({ data: null, isLoading: false, refetch: jest.fn() })

		render(
			<LibraryContext.Provider value={{ library }}>
				<MemoryRouter>
					<SecureLibraryScene />
				</MemoryRouter>
			</LibraryContext.Provider>,
		)

		expect(
			screen.getByText(/Access to this secure library has been revoked or is not available\./i),
		).toBeInTheDocument()
	})

	it(
		'shows secure reader error overlay when media decryption fails',
		async () => {
			const library: any = {
				id: 'secure-reader-error',
				name: 'Secure Books',
				is_secure: true,
				encryption_status: 'ENCRYPTED',
				path: '/secure/books',
				tags: [],
			}

			mockSecureAccessStatus.mockReturnValue({ data: { has_access: true } })
			mockSecureCatalog.mockReturnValue({
				data: {
					version: 1,
					series: [],
					media: [
						{
							id: 'm1',
							title: 'Secure Book 1',
							seriesId: null,
						},
					],
					updated_at: new Date().toISOString(),
				},
				isLoading: false,
				refetch: jest.fn(),
			})

			const storesModule = jest.requireMock('@/stores') as typeof import('@/stores')
			const useLmkStoreMock = storesModule.useLmkStore as unknown as jest.Mock
			const originalUseLmkImpl = useLmkStoreMock.getMockImplementation()
			// Create a stable LMK reference to prevent re-renders
			const stableLmk = new Uint8Array(32).fill(7)
			const stableGetLMK = jest.fn((_id?: string) => stableLmk)
			const stableState = {
				getLMK: stableGetLMK,
				setLMK: jest.fn(),
				clearLMK: jest.fn(),
				privateKey: null,
				publicKey: null,
				setPrivateKey: jest.fn(),
				setPublicKey: jest.fn(),
			}
			useLmkStoreMock.mockImplementation((selector: (state: any) => any) => selector(stableState))

			const clientModule = jest.requireMock('@stump/client') as typeof import('@stump/client')
			// Mock deriveDEK to fail immediately so the error path is triggered
			;(clientModule.deriveDEK as unknown as jest.Mock).mockRejectedValue(
				new Error('decryption failure'),
			)

			const originalAtob = (global as any).atob
			;(global as any).atob = jest.fn(() => 'x'.repeat(16))

			const encBytes = new Uint8Array(32)
			const fetchMock = jest.spyOn(global, 'fetch' as any).mockResolvedValue({
				ok: true,
				arrayBuffer: async () => encBytes.buffer,
				headers: {
					get: (name: string) => {
						if (name === 'X-Nonce') return 'nonce'
						if (name === 'X-Plaintext-Size') return '32'
						if (name === 'X-Tag') return 'dummy-tag'
						return null
					},
				},
			} as any)

			try {
				render(
					<MemoryRouter initialEntries={[`/libraries/${library.id}/secure-reader/m1`]}>
						<Routes>
							<Route path="/libraries/:id/secure-reader/:mediaId" element={<SecureReaderScene />} />
						</Routes>
					</MemoryRouter>,
				)

				// Wait for the async decrypt to fail and show the error
				await waitFor(
					() => {
						expect(
							screen.getByText(
								/Failed to decrypt this secure book\. Contact the server owner or try again later\./i,
							),
						).toBeInTheDocument()
					},
					{ timeout: 5000 },
				)
			} finally {
				useLmkStoreMock.mockImplementation(originalUseLmkImpl as any)
				;(clientModule.deriveDEK as unknown as jest.Mock).mockReset()
				;(clientModule.decryptAesGcm as unknown as jest.Mock).mockReset()
				fetchMock.mockRestore()
				;(global as any).atob = originalAtob
			}
		},
		10000,
	)
})
