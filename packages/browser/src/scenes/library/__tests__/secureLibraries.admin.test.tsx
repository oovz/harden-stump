import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { toast } from 'react-hot-toast'
import { MemoryRouter } from 'react-router-dom'

import { SteppedFormContext } from '@/components/steppedForm'

import CreateLibraryForm from '../../createLibrary/CreateLibraryForm'
import { LibraryContext } from '../context'
import SecureScanSettingsScene from '../tabs/settings/secure/SecureScanSettingsScene'

jest.mock('react-hot-toast', () => ({
	toast: {
		error: jest.fn(),
		success: jest.fn(),
	},
}))

jest.mock('@stump/client', () => {
	const actual = jest.requireActual('@stump/client')
	return {
		...actual,
		useSDK: jest.fn(() => ({
			sdk: {
				serviceURL: 'http://localhost',
				token: 'token',
				auth: {
					me: jest.fn().mockResolvedValue({ id: 'owner-1', is_server_owner: true }),
					keys: { me: ['me'] },
				},
				library: { keys: { get: ['libraries'], getLastVisited: ['lastVisited'] } },
			},
		})),
		queryClient: {
			invalidateQueries: jest.fn(),
		},
	}
})

jest.mock('@/components/DirectoryPickerModal', () => () => null)
jest.mock('@/components/TagSelect', () => () => null)

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

jest.mock('@/stores', () => {
	const actual = jest.requireActual('@/stores')
	const userState = { user: { id: 'owner-1', is_server_owner: true } }
	const appState = { baseUrl: 'http://localhost', platform: 'browser' }
	return {
		...actual,
		useUserStore: jest.fn((selector) => (selector ? selector(userState) : userState)),
		useAppStore: jest.fn((selector) => (selector ? selector(appState) : appState)),
	}
})

function CreateLibraryFormWithSteppedContext() {
	const [step, setStep] = useState(1)

	return (
		<SteppedFormContext.Provider
			value={{
				currentStep: step,
				setStep,
				stepsBeforeReview: 3,
				localeBase: 'createLibraryScene',
			}}
		>
			<MemoryRouter>
				<CreateLibraryForm existingLibraries={[]} onSubmit={jest.fn()} isLoading={false} />
			</MemoryRouter>
		</SteppedFormContext.Provider>
	)
}

async function fillSecureLibraryFormAndSubmit(smk: string) {
	render(<CreateLibraryFormWithSteppedContext />)

	await userEvent.type(
		screen.getByPlaceholderText('createOrUpdateLibraryForm.fields.name.placeholder'),
		'Secure Lib',
	)
	await userEvent.type(
		screen.getByPlaceholderText('createOrUpdateLibraryForm.fields.path.placeholder'),
		'/secure/path',
	)

	await userEvent.click(screen.getByRole('button', { name: /Secure \(owner only\)/i }))
	await userEvent.click(screen.getByRole('button', { name: /Next step/i }))

	await userEvent.type(screen.getByPlaceholderText(/Paste SMK/i), smk)

	await userEvent.click(screen.getByRole('button', { name: /Create secure library/i }))
}

describe('Secure libraries admin flows', () => {
	afterEach(() => {
		jest.restoreAllMocks()
	})

	it('creates a secure library with valid SMK and form fields', async () => {
		const originalAtob = (global as any).atob
		;(global as any).atob = jest.fn(() => 'x'.repeat(32))

		const fetchMock = jest
			.spyOn(global, 'fetch' as any)
			.mockImplementation(async (input: any, init?: any) => {
				const url = typeof input === 'string' ? input : input.toString()

				if (url.endsWith('/admin/secure/libraries')) {
					expect(init?.method).toBe('POST')
					const headers = init?.headers as Record<string, string>
					expect(headers['X-SMK']).toBe('dummy-smk')

					const body = JSON.parse((init?.body as string) ?? '{}')
					expect(body).toEqual({ name: 'Secure Lib', path: '/secure/path' })

					return {
						ok: true,
						status: 201,
						json: async () => ({ id: 'secure-1' }),
						text: async () => '',
					} as any
				}

				if (url.endsWith('/users/me/keypair')) {
					return {
						ok: false,
						status: 404,
						json: async () => ({}),
						text: async () => '',
					} as any
				}

				return {
					ok: true,
					status: 200,
					json: async () => ({}),
					text: async () => '',
				} as any
			})

		await fillSecureLibraryFormAndSubmit('dummy-smk')

		await waitFor(() => {
			expect(fetchMock).toHaveBeenCalledWith(
				expect.stringContaining('/admin/secure/libraries'),
				expect.anything(),
			)
		})
		;(global as any).atob = originalAtob
	})

	it.each(['secure_dir_present', 'path_not_found', 'invalid_smk', 'missing_user_keypair'])(
		'surfaces canonical secure error code %s from create endpoint',
		async (errorCode) => {
			const originalAtob = (global as any).atob
			;(global as any).atob = jest.fn(() => 'x'.repeat(32))

			const alertMock = jest.spyOn(window, 'alert').mockImplementation(() => {})
			jest.spyOn(global, 'fetch' as any).mockImplementation(async (input: any) => {
				const url = typeof input === 'string' ? input : input.toString()

				// SDK uses axios which may not go through global.fetch, but CreateLibraryForm
				// uses direct fetch for /admin/secure/libraries. The sdk.auth.me() call is
				// handled via the mocked SDK in useSDK above.
				if (url.includes('/admin/secure/libraries')) {
					return {
						ok: false,
						status: 400,
						text: async () => JSON.stringify({ error: errorCode, message: 'failed' }),
					} as any
				}

				// Default: pass through other requests
				return {
					ok: true,
					status: 200,
					json: async () => ({}),
					text: async () => '',
				} as any
			})

			await fillSecureLibraryFormAndSubmit('dummy-smk')

			await waitFor(() => {
				expect(alertMock).toHaveBeenCalledWith(expect.stringContaining(errorCode as string))
			})
			;(global as any).atob = originalAtob
		},
	)

	it.each(['invalid_smk_format', 'invalid_smk', 'path_not_found', 'forbidden'] as const)(
		'surfaces canonical secure error code %s from scan endpoint',
		async (errorCode: string) => {
			const toastErrorMock = jest.spyOn(toast, 'error')
			jest.spyOn(global, 'fetch' as any).mockImplementation(async (input: any) => {
				const url = typeof input === 'string' ? input : input.toString()

				if (url.endsWith('/admin/secure/libraries/secure-1/status')) {
					return {
						ok: true,
						status: 200,
						json: async () => ({
							library_id: 'secure-1',
							encryption_status: 'ENCRYPTION_IDLE',
							encrypted_files: 0,
							total_files: 0,
							progress: 0,
							error: null,
						}),
						text: async () => '',
					} as any
				}

				if (url.endsWith('/admin/secure/libraries/secure-1/scan')) {
					return {
						ok: false,
						status: errorCode === 'forbidden' ? 403 : 400,
						text: async () => JSON.stringify({ error: errorCode, message: 'failed' }),
					} as any
				}

				return {
					ok: true,
					status: 200,
					json: async () => ({}),
					text: async () => '',
				} as any
			})

			const library: any = {
				id: 'secure-1',
				name: 'Secure Lib',
				is_secure: true,
				path: '/secure/path',
				tags: [],
			}

			render(
				<LibraryContext.Provider value={{ library }}>
					<MemoryRouter>
						<SecureScanSettingsScene />
					</MemoryRouter>
				</LibraryContext.Provider>,
			)

			await userEvent.type(
				await screen.findByPlaceholderText(/Enter SMK to start a secure scan/i),
				'dummy-smk',
			)
			await userEvent.click(screen.getByRole('button', { name: /Scan Secure Library/i }))

			await waitFor(() => {
				expect(toastErrorMock).toHaveBeenCalledWith(expect.stringContaining(errorCode as string))
			})
		},
	)

	it('renders ENCRYPTION_FAILED status in secure scan settings', async () => {
		jest.spyOn(global, 'fetch' as any).mockResolvedValueOnce({
			ok: true,
			json: async () => ({
				library_id: 'secure-1',
				encryption_status: 'ENCRYPTION_FAILED',
				encrypted_files: 1,
				total_files: 10,
				progress: 10,
				error: 'Failed to encrypt',
			}),
		} as any)

		const library: any = {
			id: 'secure-1',
			name: 'Secure Lib',
			is_secure: true,
			path: '/secure/path',
			tags: [],
		}

		render(
			<LibraryContext.Provider value={{ library }}>
				<MemoryRouter>
					<SecureScanSettingsScene />
				</MemoryRouter>
			</LibraryContext.Provider>,
		)

		const statusText = await screen.findByText(/Status: ENCRYPTION_FAILED/i)
		expect(statusText.textContent).toContain('Status: ENCRYPTION_FAILED')
		expect(statusText.textContent).toContain('Failed to encrypt')
	})
})
