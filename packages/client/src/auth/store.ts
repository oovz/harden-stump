import { create } from 'zustand'

export type SecureAccessStore = {
	accessibleLibraryIds: string[]
	setAccessibleLibraryIds: (ids: string[]) => void
	clear: () => void
}

export const useSecureAccessStore = create<SecureAccessStore>((set) => ({
	accessibleLibraryIds: [],
	setAccessibleLibraryIds: (ids) => set({ accessibleLibraryIds: ids }),
	clear: () => set({ accessibleLibraryIds: [] }),
}))

export const getAccessibleLibraryIds = () => useSecureAccessStore.getState().accessibleLibraryIds
export const setAccessibleLibraryIds = (ids: string[]) =>
	useSecureAccessStore.getState().setAccessibleLibraryIds(ids)
export const clearSecureAccess = () => useSecureAccessStore.getState().clear()
