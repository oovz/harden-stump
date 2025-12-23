const MAX_CACHE_BYTES = 500 * 1024 * 1024

type CacheEntry = {
	libraryId: string
	mediaId: string
	pages: string[]
	sizeBytes: number
	lastAccess: number
}

const cache = new Map<string, CacheEntry>()
let totalBytes = 0

function makeKey(libraryId: string, mediaId: string): string {
	return `${libraryId}:${mediaId}`
}

function revokeEntry(entry: CacheEntry) {
	for (const url of entry.pages) {
		try {
			URL.revokeObjectURL(url)
		} catch {
			// ignore
		}
	}
	totalBytes -= entry.sizeBytes
	if (totalBytes < 0) {
		totalBytes = 0
	}
}

function evictIfNeeded() {
	if (totalBytes <= MAX_CACHE_BYTES) return

	while (totalBytes > MAX_CACHE_BYTES && cache.size > 0) {
		let oldestKey: string | null = null
		let oldestTime = Number.POSITIVE_INFINITY

		for (const [key, entry] of cache) {
			if (entry.lastAccess < oldestTime) {
				oldestTime = entry.lastAccess
				oldestKey = key
			}
		}

		if (!oldestKey) {
			break
		}

		const entry = cache.get(oldestKey)
		if (!entry) {
			cache.delete(oldestKey)
			continue
		}

		revokeEntry(entry)
		cache.delete(oldestKey)
	}
}

export function getCachedSecurePages(libraryId: string, mediaId: string): string[] | undefined {
	const key = makeKey(libraryId, mediaId)
	const entry = cache.get(key)
	if (!entry) return undefined

	entry.lastAccess = Date.now()
	return entry.pages
}

export function putCachedSecurePages(
	libraryId: string,
	mediaId: string,
	pages: string[],
	sizeBytes: number,
): string[] {
	const key = makeKey(libraryId, mediaId)
	const existing = cache.get(key)
	if (existing) {
		revokeEntry(existing)
		cache.delete(key)
	}

	const entry: CacheEntry = {
		libraryId,
		mediaId,
		pages,
		sizeBytes,
		lastAccess: Date.now(),
	}

	cache.set(key, entry)
	totalBytes += sizeBytes
	evictIfNeeded()

	return entry.pages
}

export function clearSecureReaderCache() {
	for (const entry of cache.values()) {
		revokeEntry(entry)
	}
	cache.clear()
	totalBytes = 0
}
