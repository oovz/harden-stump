export type ZipEntry = { name: string; bytes: Uint8Array }

// Stubs retained for potential future use; not used in MVP secure flow
export function extractImagesFromCbz(): ZipEntry[] {
	return []
}

export function toObjectUrls(entries: ZipEntry[], mimeByExt?: (name: string) => string): string[] {
	return entries.map((e) => {
		const mime = mimeByExt ? mimeByExt(e.name) : 'image/*'
		const ab = e.bytes.buffer.slice(0) as ArrayBuffer
		const blob = new Blob([ab], { type: mime })
		return URL.createObjectURL(blob)
	})
}

export function guessMime(name: string): string {
	const lower = name.toLowerCase()
	if (lower.endsWith('.png')) return 'image/png'
	if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg'
	if (lower.endsWith('.webp')) return 'image/webp'
	if (lower.endsWith('.gif')) return 'image/gif'
	if (lower.endsWith('.avif')) return 'image/avif'
	return 'application/octet-stream'
}
