import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import { LibraryContext } from '../context'
import LibraryNavigation from '../LibraryNavigation'

// Mock prefetch hooks used by LibraryNavigation
jest.mock('@stump/client', () => {
	const actual = jest.requireActual('@stump/client')
	return {
		...actual,
		usePrefetchLibraryBooks: jest.fn(() => ({ prefetch: jest.fn() })),
		usePrefetchLibraryFiles: jest.fn(() => ({ prefetch: jest.fn() })),
		usePrefetchLibrarySeries: jest.fn(() => ({ prefetch: jest.fn() })),
	}
})

// Mock rooks media query hook so tests do not depend on window.matchMedia
jest.mock('rooks', () => ({
	useMediaMatch: jest.fn(() => false),
}))

// Provide stable preferences for primary navigation layout
jest.mock('@/hooks', () => {
	const actual = jest.requireActual('@/hooks')
	return {
		...actual,
		usePreferences: jest.fn(() => ({
			preferences: {
				primary_navigation_mode: 'TOPBAR',
				layout_max_width_px: 1024,
			},
			update: jest.fn(),
		})),
	}
})

const mockCheckPermission = jest.fn()
let mockIsServerOwner = false

jest.mock('@/context', () => ({
	useAppContext: () => ({
		checkPermission: mockCheckPermission,
		isServerOwner: mockIsServerOwner,
	}),
}))

function renderWithLibrary(library: any, route = `/libraries/${library.id}`) {
	return render(
		<LibraryContext.Provider value={{ library }}>
			<MemoryRouter initialEntries={[route]}>
				<LibraryNavigation />
			</MemoryRouter>
		</LibraryContext.Provider>,
	)
}

describe('Secure library Files tab visibility', () => {
	beforeEach(() => {
		mockCheckPermission.mockReset()
		mockIsServerOwner = false
	})

	it('shows Files tab for non-secure libraries when user has file:explorer', () => {
		const library = {
			id: 'lib-non-secure',
			name: 'Non-secure Library',
			path: '/non-secure/path',
			is_secure: false,
		}

		mockCheckPermission.mockImplementation((perm: string) => perm === 'file:explorer')

		renderWithLibrary(library)

		expect(screen.getByText('Files')).toBeInTheDocument()
	})

	it('shows Files tab for secure libraries only when user is server owner with file:explorer', () => {
		const library = {
			id: 'lib-secure-owner',
			name: 'Secure Library',
			path: '/secure/path',
			is_secure: true,
		}

		mockIsServerOwner = true
		mockCheckPermission.mockImplementation((perm: string) => perm === 'file:explorer')

		renderWithLibrary(library)

		expect(screen.getByText('Files')).toBeInTheDocument()
	})

	it('hides Files tab for secure libraries when user is not server owner, even with file:explorer', () => {
		const library = {
			id: 'lib-secure-non-owner',
			name: 'Secure Library',
			path: '/secure/path',
			is_secure: true,
		}

		mockIsServerOwner = false
		mockCheckPermission.mockImplementation((perm: string) => perm === 'file:explorer')

		renderWithLibrary(library)

		expect(screen.queryByText('Files')).not.toBeInTheDocument()
	})
})
