import { zodResolver } from '@hookform/resolvers/zod'
import {
	decryptPrivateKeyWithPassword,
	encryptPrivateKeyWithPassword,
	generateX25519Keypair,
	useSDK,
} from '@stump/client'
import { Button, Form, Input, Text } from '@stump/components'
import { useForm } from 'react-hook-form'
import { toast } from 'react-hot-toast'
import { z } from 'zod'

import { useLmkStore } from '@/stores'

const schema = z
	.object({
		currentPassword: z.string().min(1, { message: 'Current password is required' }),
		newPassword: z.string().min(1, { message: 'New password is required' }),
		confirmPassword: z.string().min(1, { message: 'Please confirm new password' }),
	})
	.refine((values) => values.newPassword === values.confirmPassword, {
		path: ['confirmPassword'],
		message: 'Passwords do not match',
	})

type Schema = z.infer<typeof schema>

export default function ChangePasswordForm() {
	const { sdk } = useSDK()

	const form = useForm<Schema>({
		resolver: zodResolver(schema),
	})

	const handleSubmit = async (values: Schema) => {
		const { currentPassword, newPassword } = values
		const toastId = toast.loading('Updating password...')
		try {
			if (!sdk.serviceURL) {
				throw new Error('Missing service URL')
			}

			const keypairUrl = `${sdk.serviceURL}/users/me/keypair`
			const authHeaders: Record<string, string> = {}
			if (sdk.token) authHeaders['Authorization'] = `Bearer ${sdk.token}`

			let priv: Uint8Array | null = null
			let pubBytes: Uint8Array | null = null
			let encryptedPrivate: string
			let nonce: string
			let salt: string

			const resp = await fetch(keypairUrl, {
				method: 'GET',
				credentials: 'include',
				headers: authHeaders,
			})

			if (resp.ok) {
				const {
					public_key,
					encrypted_private,
					nonce: nonceB64,
					salt: saltB64,
				} = (await resp.json()) as {
					public_key: string
					encrypted_private: string
					nonce: string
					salt: string
				}

				priv = await decryptPrivateKeyWithPassword(
					encrypted_private,
					nonceB64,
					saltB64,
					currentPassword,
				)
				const bin = typeof atob === 'function' ? atob(public_key) : ''
				const pubArr = new Uint8Array(bin.length)
				for (let i = 0; i < bin.length; i++) {
					pubArr[i] = bin.charCodeAt(i)
				}
				pubBytes = pubArr

				const enc = await encryptPrivateKeyWithPassword(priv, newPassword)
				encryptedPrivate = enc.encrypted_private
				nonce = enc.nonce
				salt = enc.salt
			} else if (resp.status === 404) {
				const { publicKey, privateKey, publicKeyB64 } = await generateX25519Keypair()
				const enc = await encryptPrivateKeyWithPassword(privateKey, newPassword)
				encryptedPrivate = enc.encrypted_private
				nonce = enc.nonce
				salt = enc.salt

				const putHeaders: Record<string, string> = { 'Content-Type': 'application/json' }
				if (sdk.token) putHeaders['Authorization'] = `Bearer ${sdk.token}`
				const putResp = await fetch(keypairUrl, {
					method: 'PUT',
					credentials: 'include',
					headers: putHeaders,
					body: JSON.stringify({
						public_key: publicKeyB64,
						encrypted_private: encryptedPrivate,
						nonce,
						salt,
					}),
				})
				if (!putResp.ok) {
					throw new Error(`Failed to upload keypair (${putResp.status})`)
				}
				priv = privateKey
				pubBytes = publicKey
			} else {
				throw new Error('Failed to load keypair')
			}

			const passwordUrl = `${sdk.serviceURL}/users/me/password`
			const pwdHeaders: Record<string, string> = { 'Content-Type': 'application/json' }
			if (sdk.token) pwdHeaders['Authorization'] = `Bearer ${sdk.token}`

			const pwdResp = await fetch(passwordUrl, {
				method: 'PATCH',
				credentials: 'include',
				headers: pwdHeaders,
				body: JSON.stringify({
					current_password: currentPassword,
					new_password: newPassword,
					encrypted_private: encryptedPrivate,
					nonce,
					salt,
				}),
			})

			if (!pwdResp.ok) {
				if (pwdResp.status === 401) {
					throw new Error('Current password is incorrect')
				}
				throw new Error(`Failed to change password (${pwdResp.status})`)
			}

			if (priv && pubBytes) {
				const { setPrivateKey, setPublicKey } = useLmkStore.getState()
				setPrivateKey(priv)
				setPublicKey(pubBytes)
			}

			form.reset()
			toast.success('Password updated', { id: toastId })
		} catch (error) {
			console.error(error)
			const message = error instanceof Error ? error.message : 'Failed to change password'
			toast.error(message, { id: toastId })
		}
	}

	return (
		<Form form={form} onSubmit={handleSubmit}>
			<div className="mt-8 flex max-w-xl flex-col gap-4">
				<Input
					id="currentPassword"
					label="Current password"
					type="password"
					autoComplete="current-password"
					variant="primary"
					{...form.register('currentPassword')}
				/>
				<Input
					id="newPassword"
					label="New password"
					type="password"
					autoComplete="new-password"
					variant="primary"
					{...form.register('newPassword')}
				/>
				<Input
					id="confirmPassword"
					label="Confirm new password"
					type="password"
					autoComplete="new-password"
					variant="primary"
					{...form.register('confirmPassword')}
				/>
				<div className="flex items-center gap-3">
					<Button type="submit" variant="primary">
						Change password
					</Button>
					<Text size="xs" variant="muted">
						Your secure keypair will be re-encrypted with the new password.
					</Text>
				</div>
			</div>
		</Form>
	)
}
