import {
	decryptPrivateKeyWithPassword,
	encryptPrivateKeyWithPassword,
	generateX25519Keypair,
} from '@stump/client'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import { useLmkStore } from '@/stores'

import LoginOrClaimScene from '../LoginOrClaimScene'

jest.mock('react-hot-toast', () => ({
	toast: {
		loading: jest.fn(() => 'toast-id'),
		success: jest.fn(),
		error: jest.fn(),
	},
}))

jest.mock('@/stores', () => ({
	...jest.requireActual('@/stores'),
	useUserStore: jest.fn(() => ({ setUser: jest.fn() })),
	useAppStore: jest.fn((selector?: (state: any) => any) => {
		const state = { platform: 'browser' }
		return selector ? selector(state) : state
	}),
}))

jest.mock('@stump/client', () => {
	const actual = jest.requireActual('@stump/client')
	return {
		...actual,
		useLoginOrRegister: jest.fn(() => ({
			isClaimed: true,
			isCheckingClaimed: false,
			loginUser: jest.fn(async () => {}),
			registerUser: jest.fn(),
			isLoggingIn: false,
			isRegistering: false,
			loginError: null,
		})),
		useSDK: jest.fn(() => ({
			sdk: { serviceURL: 'http://localhost', token: 'token', auth: { keys: { me: ['me'] } } },
		})),
		decryptPrivateKeyWithPassword: jest.fn(),
		encryptPrivateKeyWithPassword: jest.fn(),
		generateX25519Keypair: jest.fn(),
	}
})

const Subject = () => (
	<MemoryRouter>
		<LoginOrClaimScene />
	</MemoryRouter>
)

describe('LoginOrClaimScene secure keypair behavior', () => {
	beforeEach(() => {
		jest.clearAllMocks()
	})

	it('attempts to restore keypair after successful login', async () => {
		const setPrivateKey = jest.fn()
		const setPublicKey = jest.fn()
		const getStateSpy = jest
			.spyOn(useLmkStore as unknown as { getState: () => any }, 'getState')
			.mockReturnValue({
				setPrivateKey,
				setPublicKey,
			})

		// Stub decryptPrivateKeyWithPassword to avoid real crypto
		;(decryptPrivateKeyWithPassword as jest.Mock).mockResolvedValueOnce(new Uint8Array([1, 2, 3]))

		// Mock /users/me/keypair to return a wrapped key
		jest.spyOn(global, 'fetch' as any).mockResolvedValueOnce({
			ok: true,
			json: async () => ({
				public_key: btoa('pub'),
				encrypted_private: 'cipher',
				nonce: 'nonce',
				salt: 'salt',
			}),
		} as any)

		render(<Subject />)

		await userEvent.type(screen.getByLabelText(/username/i), 'alice')
		await userEvent.type(screen.getByLabelText(/password/i), 'secret')
		await userEvent.click(screen.getByRole('button', { name: /login/i }))

		await waitFor(() => {
			expect(setPrivateKey).toHaveBeenCalledTimes(1)
			expect(setPublicKey).toHaveBeenCalledTimes(1)
			expect(decryptPrivateKeyWithPassword as jest.Mock).toHaveBeenCalledTimes(1)
		})
		getStateSpy.mockRestore()
	})

	it('generates and uploads a keypair after login when missing', async () => {
		const setPrivateKey = jest.fn()
		const setPublicKey = jest.fn()
		const getStateSpy = jest
			.spyOn(useLmkStore as unknown as { getState: () => any }, 'getState')
			.mockReturnValue({
				setPrivateKey,
				setPublicKey,
			})

		const pub = new Uint8Array([9, 8, 7])
		const priv = new Uint8Array([1, 2, 3])
		;(generateX25519Keypair as jest.Mock).mockResolvedValueOnce({
			publicKey: pub,
			privateKey: priv,
			publicKeyB64: 'pub-b64',
		})
		;(encryptPrivateKeyWithPassword as jest.Mock).mockResolvedValueOnce({
			encrypted_private: 'ct',
			nonce: 'nonce',
			salt: 'salt',
		})

		const fetchSpy = jest.spyOn(global, 'fetch' as any)
		fetchSpy
			.mockResolvedValueOnce({ ok: false, status: 404 } as any)
			.mockResolvedValueOnce({ ok: true } as any)

		render(<Subject />)

		await userEvent.type(screen.getByLabelText(/username/i), 'alice')
		await userEvent.type(screen.getByLabelText(/password/i), 'secret')
		await userEvent.click(screen.getByRole('button', { name: /login/i }))

		await waitFor(() => {
			expect(generateX25519Keypair as jest.Mock).toHaveBeenCalledTimes(1)
			expect(encryptPrivateKeyWithPassword as jest.Mock).toHaveBeenCalledTimes(1)
			expect(fetchSpy).toHaveBeenCalledTimes(2)
			expect(setPrivateKey).toHaveBeenCalledWith(priv)
			expect(setPublicKey).toHaveBeenCalledWith(pub)
		})

		expect(fetchSpy).toHaveBeenNthCalledWith(
			1,
			'http://localhost/users/me/keypair',
			expect.objectContaining({
				method: 'GET',
				credentials: 'include',
				headers: { Authorization: 'Bearer token' },
			}),
		)

		expect(fetchSpy).toHaveBeenNthCalledWith(
			2,
			'http://localhost/users/me/keypair',
			expect.objectContaining({
				method: 'PUT',
				credentials: 'include',
				headers: expect.objectContaining({
					'Content-Type': 'application/json',
					Authorization: 'Bearer token',
				}),
				body: JSON.stringify({
					public_key: 'pub-b64',
					encrypted_private: 'ct',
					nonce: 'nonce',
					salt: 'salt',
				}),
			}),
		)

		getStateSpy.mockRestore()
		fetchSpy.mockRestore()
	})
})
