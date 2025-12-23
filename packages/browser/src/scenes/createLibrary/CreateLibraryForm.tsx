import { zodResolver } from '@hookform/resolvers/zod'
import { queryClient, useSDK } from '@stump/client'
import { Button, cn, Form, Input, Label, Text } from '@stump/components'
import type { Library } from '@stump/sdk'
import { Eye, EyeOff } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useForm } from 'react-hook-form'
import { useNavigate } from 'react-router'

import { ContentContainer } from '@/components/container'
import DirectoryPickerModal from '@/components/DirectoryPickerModal'
import {
	buildSchema,
	CreateOrUpdateLibrarySchema,
	formDefaults,
} from '@/components/library/createOrUpdate/schema'
import {
	BasicLibraryInformation,
	FileConversionOptions,
	LibraryPattern as LibraryPatternSection,
	ScanMode,
	ScannerOptInFeatures,
	ThumbnailConfig,
} from '@/components/library/createOrUpdate/sections'
import IgnoreRulesConfig from '@/components/library/createOrUpdate/sections/IgnoreRulesConfig'
import { useSteppedFormContext } from '@/components/steppedForm'
import { useAppStore, useUserStore } from '@/stores'

import { formatSecureAdminError } from '../library/secureErrorHelpers'
import LibraryReview from './LibraryReview'

type Props = {
	existingLibraries: Library[]
	onSubmit: (values: CreateOrUpdateLibrarySchema) => void
	onSecureCreated?: () => void
	isLoading?: boolean
}

export default function CreateLibraryForm({
	existingLibraries,
	onSubmit,
	onSecureCreated,
	isLoading,
}: Props) {
	const { currentStep, setStep } = useSteppedFormContext()
	const navigate = useNavigate()
	const { sdk } = useSDK()
	const { baseUrl } = useAppStore((s) => ({ baseUrl: s.baseUrl }))
	const isOwner = useUserStore((s) => !!s.user?.is_server_owner)
	const currentUserId = useUserStore((s) => s.user?.id)

	const [showDirectoryPicker, setShowDirectoryPicker] = useState(false)
	const [smk, setSmk] = useState('')
	const [isCreatingSecure, setIsCreatingSecure] = useState(false)
	const [isSmkVisible, setIsSmkVisible] = useState(false)
	const [libraryType, setLibraryType] = useState<'normal' | 'secure'>(isOwner ? 'normal' : 'normal')

	const schema = useMemo(() => buildSchema(existingLibraries), [existingLibraries])
	const form = useForm<CreateOrUpdateLibrarySchema>({
		defaultValues: formDefaults(),
		reValidateMode: 'onChange',
		resolver: zodResolver(schema),
	})

	const { reset } = form
	useEffect(() => {
		return () => {
			reset()
		}
	}, [reset])

	/**
	 * The current path value from the form
	 */
	const [formPath] = form.watch(['path'])

	/**
	 * A callback to handle changing the form step. This will validate the current step
	 * before moving to the next step.
	 */
	const handleChangeStep = useCallback(
		async (nextStep: number) => {
			let isValid = false

			switch (currentStep) {
				case 1:
					isValid = await form.trigger(['name', 'description', 'path', 'tags'])
					break
				case 2:
					isValid = await form.trigger([
						'library_pattern',
						'ignore_rules',
						'convert_rar_to_zip',
						'hard_delete_conversions',
						'watch',
					])
					break
				case 3:
					// TODO: do I need to validate children?
					isValid = await form.trigger(['thumbnail_config'])
					break
				default:
					break
			}

			if (isValid) {
				// If creating a secure library, skip normal-only steps to the review
				if (libraryType === 'secure' && currentStep === 1 && nextStep === 2) {
					setStep(4)
					return
				}
				setStep(nextStep)
			}
		},
		[form, currentStep, setStep, libraryType],
	)

	/**
	 * Render the current step of the form
	 */
	const renderStep = () => {
		switch (currentStep) {
			case 1:
				return (
					<>
						<BasicLibraryInformation onSetShowDirectoryPicker={setShowDirectoryPicker} />
						{isOwner ? (
							<div className="mt-4 flex w-full flex-col gap-2 md:max-w-sm">
								<Label className="mb-1">Library type</Label>
								<div className="flex gap-2">
									<Button
										variant={libraryType === 'normal' ? 'secondary' : 'ghost'}
										onClick={() => setLibraryType('normal')}
									>
										Normal
									</Button>
									<Button
										variant={libraryType === 'secure' ? 'secondary' : 'ghost'}
										onClick={() => setLibraryType('secure')}
									>
										Secure (owner only)
									</Button>
								</div>
							</div>
						) : null}
						<div className="mt-6 flex w-full md:max-w-sm">
							<Button
								className="w-full md:w-auto"
								variant="primary"
								onClick={() => handleChangeStep(2)}
							>
								Next step
							</Button>
						</div>
					</>
				)
			case 2:
				return libraryType === 'secure' ? (
					<>
						<Text size="sm" variant="muted">
							No additional options for secure libraries.
						</Text>
						<div className="mt-6 flex w-full md:max-w-sm">
							<Button
								className="w-full md:w-auto"
								variant="primary"
								onClick={() => handleChangeStep(4)}
							>
								Continue to review
							</Button>
						</div>
					</>
				) : (
					<>
						<LibraryPatternSection />
						<ScannerOptInFeatures />
						<FileConversionOptions />
						<IgnoreRulesConfig />
						<div className="mt-6 flex w-full md:max-w-sm">
							<Button
								className="w-full md:w-auto"
								variant="primary"
								onClick={() => handleChangeStep(3)}
							>
								Next step
							</Button>
						</div>
					</>
				)
			case 3:
				return libraryType === 'secure' ? (
					<>
						<Text size="sm" variant="muted">
							Thumbnail configuration is not applicable for secure libraries.
						</Text>
						<div className="mt-6 flex w-full md:max-w-sm">
							<Button
								className="w-full md:w-auto"
								variant="primary"
								onClick={() => handleChangeStep(4)}
								type="button"
							>
								Continue to review
							</Button>
						</div>
					</>
				) : (
					<>
						<ThumbnailConfig />
						<div className="mt-6 flex w-full md:max-w-sm">
							<Button
								className="w-full md:w-auto"
								variant="primary"
								onClick={() => handleChangeStep(4)}
								type="button"
							>
								Continue to review
							</Button>
						</div>
					</>
				)
			default:
				return (
					<>
						<LibraryReview isSecure={libraryType === 'secure'} />
						{libraryType === 'normal' ? <ScanMode /> : null}
					</>
				)
		}
	}

	const handleCreateSecure = async () => {
		try {
			if (!isOwner) return
			if (!baseUrl) throw new Error('Missing baseUrl')
			const { name, path } = form.getValues()
			if (!name?.trim() || !path?.trim()) {
				alert('Name and path are required')
				return
			}
			if (!smk.trim()) {
				alert('Enter the System Master Key (SMK)')
				return
			}
			// Validate base64 length is 32 bytes
			const b642bytes = (b64: string) => {
				try {
					const bin = atob(b64)
					const bytes = new Uint8Array(bin.length)
					for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
					return bytes
				} catch {
					return new Uint8Array()
				}
			}
			const smkBytes = b642bytes(smk.trim())
			if (smkBytes.length !== 32) {
				alert('SMK must be a base64-encoded 32-byte key')
				return
			}
			setIsCreatingSecure(true)
			try {
				await sdk.auth.me()
			} catch (e) {
				console.warn('Session check failed before secure library creation', e)
				alert('Your session has expired. Please sign in again.')
				window.location.assign(`/auth?redirect=${encodeURIComponent('/libraries/create')}`)
				return
			}
			const headers: Record<string, string> = {
				'Content-Type': 'application/json',
				'X-SMK': smk.trim(),
			}
			if (sdk.token) headers['Authorization'] = `Bearer ${sdk.token}`
			const resp = await fetch(`${sdk.serviceURL}/admin/secure/libraries`, {
				method: 'POST',
				credentials: 'include',
				headers,
				body: JSON.stringify({ name: name.trim(), path: path.trim() }),
			})
			if (!resp.ok) {
				const friendly = await formatSecureAdminError('create', resp)
				throw new Error(friendly)
			}
			const data = (await resp.json()) as { id?: string }
			const id = data.id
			if (!id) {
				throw new Error('Server did not return id')
			}
			// Auto-grant creator access to the new secure library (best-effort)
			if (currentUserId && sdk.serviceURL) {
				try {
					// Only attempt auto-grant if the creator has a stored keypair
					if (sdk.token) {
						const keypairResp = await fetch(`${sdk.serviceURL}/users/me/keypair`, {
							method: 'GET',
							credentials: 'include',
							headers: { Authorization: `Bearer ${sdk.token}` },
						})
						if (keypairResp.status === 404) {
							// No keypair yet; skip auto-grant. User can generate keypair and grant later.
							console.warn('Skipping auto-grant: creator has no stored keypair')
						} else if (keypairResp.ok) {
							const grantHeaders: Record<string, string> = {
								'Content-Type': 'application/json',
								'X-SMK': smk.trim(),
							}
							if (sdk.token) grantHeaders['Authorization'] = `Bearer ${sdk.token}`
							await fetch(`${sdk.serviceURL}/admin/secure/libraries/${id}/grant-access`, {
								method: 'POST',
								credentials: 'include',
								headers: grantHeaders,
								body: JSON.stringify({ user_id: currentUserId }),
							})
						}
					}
				} catch (e) {
					console.error('Failed to auto-grant creator access', e)
				}
			}
			// Refresh libraries list so sidebar shows the new secure library immediately
			try {
				await queryClient.invalidateQueries([sdk.library.keys.get], { exact: false })
				await queryClient.invalidateQueries([sdk.library.keys.getLastVisited], { exact: false })
			} catch (e) {
				console.warn('Failed to invalidate library queries', e)
			}
			setSmk('')
			onSecureCreated?.()
			navigate(`/libraries/${id}/series`)
		} catch (e) {
			console.error(e)
			alert(e instanceof Error ? e.message : 'Failed to create secure library')
		} finally {
			setIsCreatingSecure(false)
		}
	}

	return (
		<>
			<DirectoryPickerModal
				isOpen={showDirectoryPicker}
				onClose={() => setShowDirectoryPicker(false)}
				startingPath={formPath}
				onPathChange={(path) => {
					if (path) {
						form.setValue('path', path)
					}
				}}
			/>
			<Form form={form} onSubmit={onSubmit} id="createLibraryForm">
				<ContentContainer className="mt-0">
					{renderStep()}
					<div
						className={cn('mt-6 flex w-full flex-col gap-4 md:max-w-xl', {
							'invisible hidden': currentStep < 4,
						})}
					>
						{libraryType === 'normal' ? (
							<div className="flex w-full md:max-w-sm">
								<Button
									type="submit"
									form="createLibraryForm"
									className="w-full md:w-auto"
									variant="primary"
									isLoading={isLoading}
								>
									Create library
								</Button>
							</div>
						) : null}

						{isOwner && libraryType === 'secure' ? (
							<div className="flex w-full flex-col gap-3 rounded-md border border-edge p-3">
								<Text size="sm" variant="muted">
									Create a secure library (owner only)
								</Text>
								<div className="flex flex-col gap-2 md:flex-row md:items-center">
									<div className="flex min-w-[240px] flex-1 flex-col">
										<Label className="mb-1">System Master Key (base64)</Label>
										<Input
											value={smk}
											onChange={(e) => setSmk(e.target.value)}
											placeholder="Paste SMK"
											type={isSmkVisible ? 'text' : 'password'}
											rightDecoration={
												<Button
													variant="ghost"
													size="icon"
													type="button"
													onClick={() => setIsSmkVisible((v) => !v)}
												>
													{isSmkVisible ? (
														<EyeOff className="h-4 w-4" />
													) : (
														<Eye className="h-4 w-4" />
													)}
												</Button>
											}
										/>
									</div>
									<div className="flex md:w-auto">
										<Button
											variant="secondary"
											onClick={handleCreateSecure}
											isLoading={isCreatingSecure}
										>
											Create secure library
										</Button>
									</div>
								</div>
								<Text size="xs" variant="muted">
									You do not need to do anything about keypairs here. The client will restore or
									generate your secure keypair automatically during login/unlock.
								</Text>
							</div>
						) : null}
					</div>
				</ContentContainer>
			</Form>
		</>
	)
}
