import { useUploadConfig } from '@stump/client'

import { FileExplorer } from '@/components/explorer'
import { useAppContext } from '@/context'

import { useLibraryContext } from '../../context'

export default function LibraryExplorerScene() {
	const { library } = useLibraryContext()
	const { checkPermission } = useAppContext()
	const { uploadConfig } = useUploadConfig({ enabled: checkPermission('file:upload') })
	const isSecureLibrary = Boolean((library as Record<string, unknown>)['is_secure'])

	return (
		<div className="flex flex-1">
			<FileExplorer
				libraryID={library.id}
				rootPath={library.path}
				uploadConfig={uploadConfig}
				isSecureLibrary={isSecureLibrary}
			/>
		</div>
	)
}
