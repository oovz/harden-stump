import { render, screen, waitFor } from '@testing-library/react'
import React from 'react'

import StumpWebClient from '@/App'

const mockUserState: {
	user: { username: string } | null
	userPreferences: Record<string, unknown>
	setUser: jest.Mock
} = {
	user: null,
	userPreferences: {},
	setUser: jest.fn(),
}

let mockNavigate: jest.Mock
let mockClientContext: any

jest.mock('react-router-dom', () => {
	// Preserve the real router implementation, but intercept navigation calls so we can assert on redirects.

	const actual = jest.requireActual('react-router-dom') as typeof import('react-router-dom')

	mockNavigate = jest.fn()

	return {
		...actual,
		useNavigate: () => mockNavigate,
	}
})

jest.mock('@/stores', () => {
	const actual = jest.requireActual('@/stores') as typeof import('@/stores')

	const useUserStore = (selector?: (state: typeof mockUserState) => any) =>
		selector ? selector(mockUserState) : mockUserState

	const mockAppState = {
		baseUrl: '',
		platform: 'browser',
		setBaseUrl: jest.fn(),
		setIsConnectedWithServer: jest.fn(),
		setPlatform: jest.fn(),
	}

	const useAppStore = (selector?: (state: typeof mockAppState) => any) =>
		selector ? selector(mockAppState) : mockAppState

	return {
		...actual,
		useUserStore: jest.fn(useUserStore),
		useAppStore: jest.fn(useAppStore),
	}
})

jest.mock('@stump/client', () => {
	const actual = jest.requireActual('@stump/client') as typeof import('@stump/client')

	const WrappedProvider = ({ children, ...context }: any) => {
		mockClientContext = context
		const Provider = actual.StumpClientContextProvider as React.ComponentType<any>
		return <Provider {...context}>{children}</Provider>
	}

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
		StumpClientContextProvider: WrappedProvider,
		useLoginOrRegister,
		useSDK,
		decryptPrivateKeyWithPassword: jest.fn(),
	}
})

jest.mock('@/sessionRestoreController', () => {
	// Provide a lightweight stub of the session restore controller so this test focuses
	// on App-level wiring instead of controller internals (which are covered elsewhere).

	const ReactActual = jest.requireActual('react') as typeof import('react')

	return {
		useSessionRestoreController: () => ({
			handleUnauthenticatedResponse: jest.fn(),
			modal: ReactActual.createElement(
				'div',
				{ 'data-testid': 'session-restore-modal' },
				'Session Restore Modal',
			),
		}),
	}
})

describe('session restoration wiring in App', () => {
	beforeEach(() => {
		jest.clearAllMocks()
		window.localStorage.clear()
		mockUserState.user = { username: 'alice' }
		mockUserState.userPreferences = {}
		mockUserState.setUser.mockClear()
		mockNavigate.mockClear()
		mockClientContext = undefined
	})

	it.skip('renders the session restore modal from the controller', async () => {
		render(<StumpWebClient platform="browser" baseUrl="http://localhost:10801" />)

		expect(await screen.findByTestId('session-restore-modal')).toBeInTheDocument()
	})

	it('exposes an onUnauthenticatedResponse handler on the client context', async () => {
		render(<StumpWebClient platform="browser" baseUrl="http://localhost:10801" />)

		await waitFor(() => {
			expect(mockClientContext?.onUnauthenticatedResponse).toBeDefined()
		})

		expect(typeof mockClientContext?.onUnauthenticatedResponse).toBe('function')
	})
})
