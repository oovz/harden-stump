import { decryptPrivateKeyWithPassword } from '@stump/client'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useEffect } from 'react'

import { LAST_AUTH_KEY, useSessionRestoreController } from '@/sessionRestoreController'
import { useLmkStore } from '@/stores'

const mockUserState: {
	user: { username: string } | null
	userPreferences: Record<string, unknown>
	setUser: jest.Mock
} = {
	user: null,
	userPreferences: {},
	setUser: jest.fn(),
}

const mockClearLMK = jest.fn()
const mockClearKeypair = jest.fn()

let mockHandleUnauthenticated: ((redirectUrl?: string, data?: unknown) => void) | undefined
let mockRedirectUrl: string | null = null
const mockExternalUnauthenticated = jest.fn()

jest.mock('@/stores', () => {
	const actual = jest.requireActual('@/stores') as typeof import('@/stores')

	const useUserStore = (selector?: (state: typeof mockUserState) => any) =>
		selector ? selector(mockUserState) : mockUserState

	function useLmkStoreMock() {
		return {}
	}
	;(useLmkStoreMock as any).getState = () => ({
		clearLMK: mockClearLMK,
		clearKeypair: mockClearKeypair,
		setPrivateKey: jest.fn(),
		setPublicKey: jest.fn(),
	})

	return {
		...actual,
		useUserStore: jest.fn(useUserStore),
		useLmkStore: useLmkStoreMock,
	}
})

jest.mock('@stump/client', () => {
	const actual = jest.requireActual('@stump/client') as typeof import('@stump/client')

	const useLoginOrRegister = (options: any) => {
		const loginUser = jest.fn(async () => {
			if (options?.onSuccess) {
				await options.onSuccess({ id: 'user-1', username: 'alice' })
			}
		})

		return {
			isClaimed: true,
			isCheckingClaimed: false,
			loginUser,
			registerUser: jest.fn(),
			isLoggingIn: false,
			isRegistering: false,
			loginError: null,
		}
	}

	const useSDK = () => ({
		sdk: {
			serviceURL: 'http://localhost',
			token: 'token',
			auth: { keys: { me: ['me'] } },
		},
	})

	return {
		...actual,
		useLoginOrRegister,
		useSDK,
		decryptPrivateKeyWithPassword: jest.fn(),
	}
})

function Harness() {
	const { handleUnauthenticatedResponse, modal } = useSessionRestoreController({
		onExternalUnauthenticated: mockExternalUnauthenticated,
		handleRedirect: (url) => {
			mockRedirectUrl = url
		},
	})

	useEffect(() => {
		mockHandleUnauthenticated = handleUnauthenticatedResponse
	}, [handleUnauthenticatedResponse])

	return <>{modal}</>
}

describe('session restoration controller', () => {
	beforeEach(() => {
		jest.clearAllMocks()
		window.localStorage.clear()
		mockUserState.user = { username: 'alice' }
		mockUserState.userPreferences = {}
		mockUserState.setUser.mockClear()
		mockClearLMK.mockClear()
		mockClearKeypair.mockClear()
		mockRedirectUrl = null
		mockHandleUnauthenticated = undefined
		mockExternalUnauthenticated.mockClear()
	})

	it('opens SessionRestoreModal instead of redirect when within 7d window', async () => {
		window.localStorage.setItem(LAST_AUTH_KEY, Date.now().toString())

		render(<Harness />)

		await waitFor(() => {
			expect(mockHandleUnauthenticated).toBeDefined()
		})

		await act(async () => {
			mockHandleUnauthenticated?.('/auth')
		})

		expect(mockClearLMK).toHaveBeenCalledTimes(1)
		expect(mockClearKeypair).toHaveBeenCalledTimes(1)

		expect(await screen.findByText(/session expired/i)).toBeInTheDocument()
		expect(mockExternalUnauthenticated).not.toHaveBeenCalled()
		expect(mockRedirectUrl).toBeNull()
	})

	it('redirects to /auth when 7d window has expired', async () => {
		const eightDaysMs = 8 * 24 * 60 * 60 * 1000
		window.localStorage.setItem(LAST_AUTH_KEY, String(Date.now() - eightDaysMs))

		render(<Harness />)

		await waitFor(() => {
			expect(mockHandleUnauthenticated).toBeDefined()
		})

		await act(async () => {
			mockHandleUnauthenticated?.('/auth')
		})

		expect(mockClearLMK).toHaveBeenCalledTimes(1)
		expect(mockClearKeypair).toHaveBeenCalledTimes(1)
		expect(mockExternalUnauthenticated).toHaveBeenCalledWith('/auth')
		expect(mockRedirectUrl).toBe('/auth')
		expect(screen.queryByText(/session expired/i)).not.toBeInTheDocument()
	})

	it('performs password-only step-up re-auth and restores keypair within 7d window', async () => {
		window.localStorage.setItem(LAST_AUTH_KEY, Date.now().toString())

		const setPrivateKey = jest.fn()
		const setPublicKey = jest.fn()
		const getStateSpy = jest
			.spyOn(useLmkStore as unknown as { getState: () => any }, 'getState')
			.mockReturnValue({
				clearLMK: mockClearLMK,
				clearKeypair: mockClearKeypair,
				setPrivateKey,
				setPublicKey,
			})

		;(decryptPrivateKeyWithPassword as jest.Mock).mockResolvedValueOnce(new Uint8Array([1, 2, 3]))

		const fetchMock = jest.spyOn(global, 'fetch' as any).mockResolvedValueOnce({
			ok: true,
			json: async () => ({
				public_key: btoa('pub'),
				encrypted_private: 'cipher',
				nonce: 'nonce',
				salt: 'salt',
			}),
		} as any)

		render(<Harness />)

		await waitFor(() => {
			expect(mockHandleUnauthenticated).toBeDefined()
		})

		await act(async () => {
			mockHandleUnauthenticated?.('/auth')
		})

		await userEvent.type(await screen.findByLabelText(/password/i), 'secret')
		await userEvent.click(screen.getByRole('button', { name: /re-authenticate/i }))

		await waitFor(() => {
			expect(setPrivateKey).toHaveBeenCalledTimes(1)
			expect(setPublicKey).toHaveBeenCalledTimes(1)
			expect(decryptPrivateKeyWithPassword as jest.Mock).toHaveBeenCalledTimes(1)
		})

		await waitFor(() => {
			expect(screen.queryByText(/session expired/i)).not.toBeInTheDocument()
		})

		expect(window.localStorage.getItem(LAST_AUTH_KEY)).not.toBeNull()

		fetchMock.mockRestore()
		getStateSpy.mockRestore()
	})
})
