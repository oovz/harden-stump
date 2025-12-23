import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import { LibraryContext } from '../context'
import LibraryBooksScene from '../tabs/books/LibraryBooksScene'

// Avoid importing components that depend on import.meta.env when running this
// test in isolation.
jest.mock('@/components/ReadMore', () => () => null)
jest.mock('@/components/tags/TagList', () => () => null)

const mockUseSecureCatalog: jest.Mock<any, any[]> = jest.fn(() => ({
	data: undefined,
	isLoading: false,
	refetch: jest.fn(),
}))

jest.mock('@/hooks/useSecureCatalog', () => ({
	useSecureCatalog: (...args: any[]) => mockUseSecureCatalog(...args),
}))

jest.mock('@stump/client', () => {
	const actual = jest.requireActual('@stump/client')
	return {
		...actual,
		useSDK: jest.fn(() => ({
			sdk: { serviceURL: 'http://localhost', token: 'token' },
		})),
		usePagedMediaQuery: jest.fn(() => ({
			isLoading: false,
			isRefetching: false,
			media: [],
			pageData: { current_page: 1, total_pages: 1 },
		})),
		usePrefetchMediaPaged: jest.fn(() => ({ prefetch: jest.fn() })),
	}
})

jest.mock('@/stores', () => ({
	...jest.requireActual('@/stores'),
	useLmkStore: jest.fn((selector: (state: any) => any) =>
		selector({
			getLMK: () => new Uint8Array([1, 2, 3]),
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

describe('Secure libraries NOT_ENCRYPTED behavior', () => {
	beforeEach(() => {
		mockUseSecureCatalog.mockClear()
	})

	it('shows informational state and does not fetch secure catalog when encryption_status is NOT_ENCRYPTED', () => {
		const library: any = {
			id: 'secure-not-encrypted',
			name: 'Secure Lib',
			is_secure: true,
			encryption_status: 'NOT_ENCRYPTED',
			path: '/secure/path',
			tags: [],
		}

		render(
			<LibraryContext.Provider value={{ library }}>
				<MemoryRouter>
					<LibraryBooksScene />
				</MemoryRouter>
			</LibraryContext.Provider>,
		)

		expect(screen.getByText(/secure library has not been encrypted yet/i)).toBeInTheDocument()

		expect(mockUseSecureCatalog).toHaveBeenCalled()
		const call = (mockUseSecureCatalog.mock.calls[0] ?? []) as any[]
		const options = call[2] as any
		expect(options?.enabled).toBe(false)
	})
})
