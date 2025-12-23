import { useSecureAccessStatus } from '@/hooks/useSecureAccessStatus'
import { useLmkStore } from '@/stores'

type UseSecureLibraryArgs = {
	libraryId: string
	isSecure: boolean
	encryptionStatus?: string
}

export function useSecureLibrary({ libraryId, isSecure, encryptionStatus }: UseSecureLibraryArgs) {
	const isNotEncrypted = isSecure && encryptionStatus === 'NOT_ENCRYPTED'

	const { data: access } = useSecureAccessStatus(libraryId)
	const hasAccess = access?.has_access === true

	const { getLMK } = useLmkStore((s) => ({ getLMK: s.getLMK }))
	const lmk = getLMK(libraryId)

	const getLMKForCatalog = async () => {
		const key = getLMK(libraryId)
		if (!key) {
			throw new Error('LMK not set')
		}
		return key
	}

	return {
		isSecure,
		encryptionStatus,
		isNotEncrypted,
		access,
		hasAccess,
		lmk,
		getLMKForCatalog,
	}
}
