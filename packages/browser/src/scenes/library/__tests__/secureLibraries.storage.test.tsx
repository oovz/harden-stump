import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import { useLmkStore } from '@/stores'

import { LibraryContext } from '../context'
import SecureUnlockGate from '../SecureUnlockGate'
import LibraryBooksScene from '../tabs/books/LibraryBooksScene'

const localStorageSetItem = jest.fn()
const indexedDbOpen = jest.fn()
const cachesOpen = jest.fn()

beforeEach(() => {
	Object.defineProperty(window, 'localStorage', {
		configurable: true,
		value: {
			getItem: jest.fn(),
			setItem: localStorageSetItem,
			removeItem: jest.fn(),
			clear: jest.fn(),
			key: jest.fn(),
			length: 0,
		},
	})
	;(global as any).indexedDB = {
		open: indexedDbOpen,
		deleteDatabase: jest.fn(),
	}
	;(global as any).caches = {
		open: cachesOpen,
		delete: jest.fn(),
		keys: jest.fn(async () => []),
	}

	if (!(global as any).URL) {
		;(global as any).URL = {} as any
	}
	;(global as any).URL.createObjectURL = jest.fn(() => 'blob://test-url')
	;(global as any).URL.revokeObjectURL = jest.fn()
})

jest.mock('@/hooks/useSecureAccessStatus', () => ({
	useSecureAccessStatus: jest.fn(() => ({ data: { has_access: true } })),
}))

const mockSecureCatalog: jest.Mock<any, any[]> = jest.fn()

jest.mock('@/hooks/useSecureCatalog', () => ({
	useSecureCatalog: (...args: any[]) => mockSecureCatalog(...args),
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
			},
		})),
		usePagedMediaQuery: jest.fn(() => ({
			isLoading: false,
			isRefetching: false,
			media: [],
			pageData: { current_page: 1, total_pages: 1 },
		})),
		usePrefetchMediaPaged: jest.fn(() => ({ prefetch: jest.fn() })),
		usePrefetchMediaByID: jest.fn(() => ({ prefetch: jest.fn() })),
		decryptAesGcm: jest.fn(async () => new Uint8Array(32)),
		deriveDEK: jest.fn(async () => new Uint8Array([1, 2, 3])),
	}
})

jest.mock('@/stores', () => {
	const actual = jest.requireActual('@/stores')
	return {
		...actual,
		useLmkStore: jest.fn(),
	}
})

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

jest.mock('@/components/ReadMore', () => () => null)
jest.mock('@/components/tags/TagList', () => () => null)

jest.mock('@/components/book/BookGrid', () => ({
	__esModule: true,
	default: (props: any) => {
		if (props.onSelect && props.books?.length) {
			props.onSelect(props.books[0])
		}
		return <div data-testid="book-grid-mock" />
	},
}))

jest.mock('fflate', () => ({
	unzipSync: jest.fn(() => ({
		'1.png': new Uint8Array([1, 2, 3]),
	})),
}))

describe('Secure Web storage behavior', () => {
	beforeEach(() => {
		jest.clearAllMocks()
	})

	it('unlock overlay does not write decrypted data to persistent storage', async () => {
		mockSecureCatalog.mockReturnValue({ data: null, isLoading: false, refetch: jest.fn() })
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

		const library: any = {
			id: 'secure-lib',
			name: 'Secure Lib',
			is_secure: true,
			encryption_status: 'ENCRYPTED',
			path: '/secure/path',
			tags: [],
		}

		render(
			<LibraryContext.Provider value={{ library }}>
				<SecureUnlockGate />
			</LibraryContext.Provider>,
		)

		await screen.findByText(/Unlock secure library/i)

		expect(localStorageSetItem).not.toHaveBeenCalled()
		expect(indexedDbOpen).not.toHaveBeenCalled()
		expect(cachesOpen).not.toHaveBeenCalled()
	})

	it('secure catalog, thumbnails, and reader flows do not write decrypted data to persistent storage', async () => {
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
		;(useLmkStore as unknown as jest.Mock).mockImplementation((selector: (state: any) => any) =>
			selector({
				getLMK: () => new Uint8Array([1, 2, 3]),
				setLMK: jest.fn(),
				clearLMK: jest.fn(),
				privateKey: new Uint8Array([9, 9, 9]),
				publicKey: new Uint8Array([8, 8, 8]),
				setPrivateKey: jest.fn(),
				setPublicKey: jest.fn(),
			}),
		)

		jest.spyOn(global as any, 'fetch').mockImplementation(async (input: any) => {
			const url = typeof input === 'string' ? input : input.toString()
			if (url.includes('/thumbnail')) {
				return {
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
				} as any
			}
			if (url.includes('/media/') && url.includes('/file')) {
				return {
					ok: true,
					arrayBuffer: async () => new Uint8Array(64).buffer,
					headers: {
						get: (name: string) => {
							if (name === 'X-Plaintext-Size') return '32'
							if (name === 'X-Tag') return 'tag-b64'
							if (name === 'X-Nonce') return 'nonce'
							return null
						},
					},
				} as any
			}
			return {
				ok: true,
				json: async () => ({}),
				arrayBuffer: async () => new ArrayBuffer(0),
				headers: {
					get: () => null,
				},
			} as any
		})

		const library: any = {
			id: 'secure-lib',
			name: 'Secure Lib',
			is_secure: true,
			encryption_status: 'ENCRYPTED',
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

		await waitFor(() => {
			expect(screen.getByTestId('book-grid-mock')).toBeInTheDocument()
		})

		expect(localStorageSetItem).not.toHaveBeenCalled()
		expect(indexedDbOpen).not.toHaveBeenCalled()
		expect(cachesOpen).not.toHaveBeenCalled()
	})
})
