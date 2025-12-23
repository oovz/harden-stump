import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import { LibraryContext } from '../context'
import BasicSettingsScene from '../tabs/settings/basics/BasicSettingsScene'
import { LibraryManagementContext } from '../tabs/settings/context'
import LibrarySettingsSidebar from '../tabs/settings/LibrarySettingsSidebar'
import SecureScanSettingsScene from '../tabs/settings/secure/SecureScanSettingsScene'

jest.mock('@stump/client', () => {
	const actual = jest.requireActual('@stump/client')
	return {
		...actual,
		useSDK: jest.fn(() => ({
			sdk: { serviceURL: 'http://localhost', token: 'token', auth: { keys: { me: ['me'] } } },
		})),
	}
})

jest.mock('@/stores', () => ({
	...jest.requireActual('@/stores'),
	useUserStore: jest.fn(() => ({ user: { is_server_owner: true } })),
}))

jest.mock('@/context', () => ({
	useAppContext: jest.fn(() => ({
		checkPermission: () => true,
	})),
}))

jest.mock('@/hooks/usePreferences', () => ({
	usePreferences: jest.fn(() => ({
		preferences: {
			enable_replace_primary_sidebar: false,
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

jest.mock('@/components/DirectoryPickerModal', () => () => null)
jest.mock('@/components/TagSelect', () => () => null)

const baseLibraryConfig = {
	convert_rar_to_zip: false,
	default_reading_dir: 'ltr',
	default_reading_image_scale_fit: 'height',
	default_reading_mode: 'paged',
	generate_file_hashes: false,
	generate_koreader_hashes: false,
	hard_delete_conversions: false,
	watch: true,
	ignore_rules: [],
	library_pattern: 'SERIES_BASED',
	process_metadata: true,
	thumbnail_config: {
		format: 'Webp',
		quality: undefined,
		resize_options: undefined,
	},
} as const

function renderWithProviders(
	ui: React.ReactElement,
	{ library, route = '/' }: { library: any; route?: string },
) {
	return render(
		<LibraryContext.Provider value={{ library }}>
			<LibraryManagementContext.Provider value={{ patch: jest.fn() }}>
				<MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
			</LibraryManagementContext.Provider>
		</LibraryContext.Provider>,
	)
}

describe('Secure library UI smoke tests', () => {
	beforeEach(() => {
		jest.clearAllMocks()
	})

	it('does not render a dedicated "Secure" sidebar link that routes to /libraries/:id/secure', () => {
		const library = {
			id: 'lib-1',
			name: 'Secure Lib',
			is_secure: true,
			tags: [],
			path: '/tmp/secure',
			config: baseLibraryConfig,
		}
		renderWithProviders(<LibrarySettingsSidebar />, {
			library,
			route: '/libraries/lib-1/settings/basics',
		})

		// Sidebar entries are driven by route groups; just assert we do not see a bare "Secure" tab label.
		expect(screen.queryByText('Secure')).not.toBeInTheDocument()
	})

	it('disables path editing for existing secure libraries in Basic settings', () => {
		const library = {
			id: 'secure-1',
			name: 'Secure Lib',
			is_secure: true,
			path: '/secure/path',
			tags: [],
			config: baseLibraryConfig,
		}
		renderWithProviders(<BasicSettingsScene />, {
			library,
			route: '/libraries/secure-1/settings/basics',
		})

		const pathInput = screen.getByPlaceholderText(
			'createOrUpdateLibraryForm.fields.path.placeholder',
		) as HTMLInputElement
		expect(pathInput).toBeDisabled()
	})

	it('disables Scan Secure Library button when encryption_status is ENCRYPTION_BROKEN', async () => {
		const library = {
			id: 'secure-2',
			name: 'Secure Lib',
			is_secure: true,
			path: '/secure/path',
			tags: [],
			config: baseLibraryConfig,
		}

		// Mock fetch status to return ENCRYPTION_BROKEN once
		jest.spyOn(global, 'fetch' as any).mockResolvedValueOnce({
			ok: true,
			json: async () => ({
				library_id: 'secure-2',
				encryption_status: 'ENCRYPTION_BROKEN',
				encrypted_files: 0,
				total_files: 0,
				progress: 0,
			}),
		} as any)

		renderWithProviders(<SecureScanSettingsScene />, {
			library,
			route: '/libraries/secure-2/settings/secure-scan',
		})

		const scanButton = await screen.findByRole('button', { name: /scan secure library/i })
		await waitFor(() => expect(scanButton).toBeDisabled())
	})

	it('renders blocking overlay while secure library is encrypting', async () => {
		const library = {
			id: 'secure-3',
			name: 'Secure Lib',
			is_secure: true,
			path: '/secure/path',
			tags: [],
			config: baseLibraryConfig,
		}

		jest.spyOn(global, 'fetch' as any).mockResolvedValueOnce({
			ok: true,
			json: async () => ({
				library_id: 'secure-3',
				encryption_status: 'ENCRYPTING',
				encrypted_files: 2,
				total_files: 10,
				progress: 20,
				error: null,
			}),
		} as any)

		renderWithProviders(<SecureScanSettingsScene />, {
			library,
			route: '/libraries/secure-3/settings/secure-scan',
		})

		const overlayText = await screen.findByText(/secure library encryption in progress/i)
		expect(overlayText).toBeInTheDocument()

		const overlayProgress = await screen.findByTestId('secure-encryption-overlay-progress')
		expect(overlayProgress.textContent).toContain('20%')
	})
})
