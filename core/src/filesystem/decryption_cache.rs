//! Caching layer for decrypted content to avoid repeated decryption operations
//!
//! This module provides both memory and disk-based caching for decrypted comic pages
//! and files, significantly improving performance for frequently accessed encrypted content.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs;
use tracing::{debug, trace, warn};

use crate::{
    config::StumpConfig,
    error::{CoreError, CoreResult},
    filesystem::ContentType,
};

/// Configuration for the decryption cache
#[derive(Debug, Clone)]
pub struct DecryptionCacheConfig {
    /// Maximum memory cache size in bytes (default: 100MB)
    pub max_memory_size: usize,
    /// Maximum disk cache size in bytes (default: 1GB)
    pub max_disk_size: usize,
    /// TTL for cache entries (default: 1 hour)
    pub ttl: Duration,
    /// Whether disk caching is enabled
    pub disk_cache_enabled: bool,
    /// Whether memory caching is enabled
    pub memory_cache_enabled: bool,
}

impl Default for DecryptionCacheConfig {
    fn default() -> Self {
        Self {
            max_memory_size: 100 * 1024 * 1024, // 100MB
            max_disk_size: 1024 * 1024 * 1024,  // 1GB
            ttl: Duration::from_secs(3600),      // 1 hour
            disk_cache_enabled: true,
            memory_cache_enabled: true,
        }
    }
}

/// Cache key for identifying cached content
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    /// Original file path
    pub file_path: PathBuf,
    /// Page number for comic pages (None for full files)
    pub page: Option<i32>,
    /// File modification time for cache invalidation
    pub mtime: u64,
}

impl CacheKey {
    /// Create a cache key for a comic page
    pub fn for_page(file_path: PathBuf, page: i32, mtime: u64) -> Self {
        Self {
            file_path,
            page: Some(page),
            mtime,
        }
    }

    /// Create a cache key for a full file
    pub fn for_file(file_path: PathBuf, mtime: u64) -> Self {
        Self {
            file_path,
            page: None,
            mtime,
        }
    }

    /// Generate a filename-safe cache key
    pub fn to_cache_filename(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.file_path.to_string_lossy().as_bytes());
        let path_hash = format!("{:x}", hasher.finalize());
        match self.page {
            Some(page) => format!("{}_{}_p{}.cache", path_hash, self.mtime, page),
            None => format!("{}_{}_full.cache", path_hash, self.mtime),
        }
    }
}

/// Cached content with metadata
#[derive(Debug, Clone)]
pub struct CachedContent {
    pub content_type: ContentType,
    pub data: Vec<u8>,
    pub created_at: Instant,
    pub size: usize,
}

impl CachedContent {
    pub fn new(content_type: ContentType, data: Vec<u8>) -> Self {
        let size = data.len();
        Self {
            content_type,
            data,
            created_at: Instant::now(),
            size,
        }
    }

    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

/// Serializable cache entry for disk storage
#[derive(Debug, Serialize, Deserialize)]
pub struct DiskCacheEntry {
    pub content_type: String,
    pub created_at_secs: u64,
}

/// Memory cache with LRU eviction
#[derive(Debug)]
pub struct MemoryCache {
    entries: HashMap<CacheKey, CachedContent>,
    access_order: Vec<CacheKey>,
    current_size: usize,
    max_size: usize,
}

impl MemoryCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            access_order: Vec::new(),
            current_size: 0,
            max_size,
        }
    }

    pub fn get(&mut self, key: &CacheKey) -> Option<&CachedContent> {
        if let Some(content) = self.entries.get(key) {
            // Move to front (most recently used)
            self.access_order.retain(|k| k != key);
            self.access_order.push(key.clone());
            Some(content)
        } else {
            None
        }
    }

    pub fn put(&mut self, key: CacheKey, content: CachedContent) {
        // Remove existing entry if present
        if let Some(old_content) = self.entries.remove(&key) {
            self.current_size -= old_content.size;
            self.access_order.retain(|k| k != &key);
        }

        // Evict entries if needed
        while self.current_size + content.size > self.max_size && !self.access_order.is_empty() {
            if let Some(oldest_key) = self.access_order.first().cloned() {
                if let Some(removed) = self.entries.remove(&oldest_key) {
                    self.current_size -= removed.size;
                    self.access_order.remove(0);
                    trace!("Evicted cache entry: {:?}", oldest_key);
                }
            } else {
                break;
            }
        }

        // Add new entry
        self.current_size += content.size;
        self.entries.insert(key.clone(), content);
        self.access_order.push(key);
    }

    pub fn remove_expired(&mut self, ttl: Duration) {
        let expired_keys: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, content)| content.is_expired(ttl))
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            if let Some(content) = self.entries.remove(&key) {
                self.current_size -= content.size;
                self.access_order.retain(|k| k != &key);
                trace!("Removed expired cache entry: {:?}", key);
            }
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
        self.current_size = 0;
    }

    pub fn size(&self) -> usize {
        self.current_size
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Disk cache for persistent storage
#[derive(Debug)]
pub struct DiskCache {
    cache_dir: PathBuf,
    max_size: usize,
}

impl DiskCache {
    pub fn new(cache_dir: PathBuf, max_size: usize) -> CoreResult<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            cache_dir,
            max_size,
        })
    }

    pub async fn get(&self, key: &CacheKey, ttl: Duration) -> CoreResult<Option<CachedContent>> {
        let cache_file = self.cache_dir.join(key.to_cache_filename());
        let meta_file = self.cache_dir.join(format!("{}.meta", key.to_cache_filename()));

        if !cache_file.exists() || !meta_file.exists() {
            return Ok(None);
        }

        // Read metadata
        let meta_content = fs::read_to_string(&meta_file).await?;
        let meta: DiskCacheEntry = serde_json::from_str(&meta_content)?;

        // Check if expired
        let file_age = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(meta.created_at_secs);
        
        if file_age > ttl.as_secs() {
            // Clean up expired files
            let _ = fs::remove_file(&cache_file).await;
            let _ = fs::remove_file(&meta_file).await;
            return Ok(None);
        }

        // Read cached data
        let data = fs::read(&cache_file).await?;
        let size = data.len();

        Ok(Some(CachedContent {
            content_type: ContentType::from(meta.content_type.as_str()),
            data,
            created_at: Instant::now() - Duration::from_secs(file_age),
            size,
        }))
    }

    pub async fn put(&self, key: &CacheKey, content: &CachedContent) -> CoreResult<()> {
        let cache_file = self.cache_dir.join(key.to_cache_filename());
        let meta_file = self.cache_dir.join(format!("{}.meta", key.to_cache_filename()));

        // Write data file
        fs::write(&cache_file, &content.data).await?;

        // Write metadata file
        let meta = DiskCacheEntry {
            content_type: content.content_type.to_string(),
            created_at_secs: content.created_at.elapsed().as_secs(),
        };
        let meta_content = serde_json::to_string(&meta)?;
        fs::write(&meta_file, meta_content).await?;

        trace!("Cached to disk: {:?}", key);
        Ok(())
    }

    pub async fn cleanup_expired(&self, ttl: Duration) -> CoreResult<()> {
        let mut entries = fs::read_dir(&self.cache_dir).await?;
        let mut to_remove = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("meta") {
                if let Ok(meta_content) = fs::read_to_string(&path).await {
                    if let Ok(meta) = serde_json::from_str::<DiskCacheEntry>(&meta_content) {
                        let age = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or(Duration::ZERO)
                            .as_secs()
                            .saturating_sub(meta.created_at_secs);
                        
                        if age > ttl.as_secs() {
                            to_remove.push(path.clone());
                            // Also remove the corresponding data file
                            let data_file = path.with_extension("cache");
                            to_remove.push(data_file);
                        }
                    }
                }
            }
        }

        for file in to_remove {
            let _ = fs::remove_file(&file).await;
        }

        Ok(())
    }

    pub async fn clear(&self) -> CoreResult<()> {
        let mut entries = fs::read_dir(&self.cache_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let _ = fs::remove_file(entry.path()).await;
        }
        Ok(())
    }
}

/// Combined memory and disk cache for decrypted content
#[derive(Debug)]
pub struct DecryptionCache {
    memory_cache: Arc<RwLock<MemoryCache>>,
    disk_cache: Option<DiskCache>,
    config: DecryptionCacheConfig,
}

impl DecryptionCache {
    /// Create a new decryption cache
    pub fn new(stump_config: &StumpConfig, config: DecryptionCacheConfig) -> CoreResult<Self> {
        let memory_cache = Arc::new(RwLock::new(MemoryCache::new(config.max_memory_size)));
        
        let disk_cache = if config.disk_cache_enabled {
            let cache_dir = stump_config.get_cache_dir().join("decryption");
            Some(DiskCache::new(cache_dir, config.max_disk_size)?)
        } else {
            None
        };

        Ok(Self {
            memory_cache,
            disk_cache,
            config,
        })
    }

    /// Get content from cache (checks memory first, then disk)
    pub async fn get(&self, key: &CacheKey) -> CoreResult<Option<(ContentType, Vec<u8>)>> {
        // Try memory cache first
        if self.config.memory_cache_enabled {
            if let Ok(mut cache) = self.memory_cache.write() {
                if let Some(content) = cache.get(key) {
                    if !content.is_expired(self.config.ttl) {
                        trace!("Cache hit (memory): {:?}", key);
                        return Ok(Some((content.content_type, content.data.clone())));
                    } else {
                        // Remove expired entry from memory (need to work around borrow checker)
                        let should_remove = content.is_expired(self.config.ttl);
                        if should_remove {
                            let size = content.size;
                            let _ = content; // Release the borrow
                            cache.entries.remove(key);
                            cache.access_order.retain(|k| k != key);
                            cache.current_size -= size;
                        }
                    }
                }
            }
        }

        // Try disk cache if enabled
        if let Some(ref disk_cache) = self.disk_cache {
            if let Ok(Some(content)) = disk_cache.get(key, self.config.ttl).await {
                trace!("Cache hit (disk): {:?}", key);
                
                // Also put in memory cache for faster future access
                if self.config.memory_cache_enabled {
                    if let Ok(mut cache) = self.memory_cache.write() {
                        cache.put(key.clone(), content.clone());
                    }
                }
                
                return Ok(Some((content.content_type, content.data)));
            }
        }

        trace!("Cache miss: {:?}", key);
        Ok(None)
    }

    /// Store content in cache
    pub async fn put(&self, key: CacheKey, content_type: ContentType, data: Vec<u8>) -> CoreResult<()> {
        let content = CachedContent::new(content_type, data);

        // Store in memory cache if enabled
        if self.config.memory_cache_enabled {
            if let Ok(mut cache) = self.memory_cache.write() {
                cache.put(key.clone(), content.clone());
                trace!("Cached in memory: {:?} ({} bytes)", key, content.size);
            }
        }

        // Store in disk cache if enabled
        if let Some(ref disk_cache) = self.disk_cache {
            if let Err(e) = disk_cache.put(&key, &content).await {
                warn!("Failed to cache to disk: {:?} - {}", key, e);
            } else {
                trace!("Cached to disk: {:?} ({} bytes)", key, content.size);
            }
        }

        Ok(())
    }

    /// Clean up expired entries
    pub async fn cleanup_expired(&self) -> CoreResult<()> {
        // Clean memory cache
        if self.config.memory_cache_enabled {
            if let Ok(mut cache) = self.memory_cache.write() {
                cache.remove_expired(self.config.ttl);
            }
        }

        // Clean disk cache
        if let Some(ref disk_cache) = self.disk_cache {
            disk_cache.cleanup_expired(self.config.ttl).await?;
        }

        Ok(())
    }

    /// Clear all cached content
    pub async fn clear(&self) -> CoreResult<()> {
        // Clear memory cache
        if let Ok(mut cache) = self.memory_cache.write() {
            cache.clear();
        }

        // Clear disk cache
        if let Some(ref disk_cache) = self.disk_cache {
            disk_cache.clear().await?;
        }

        debug!("Cleared decryption cache");
        Ok(())
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let (memory_size, memory_entries) = if let Ok(cache) = self.memory_cache.read() {
            (cache.size(), cache.len())
        } else {
            (0, 0)
        };

        CacheStats {
            memory_size,
            memory_entries,
            memory_max_size: self.config.max_memory_size,
            disk_enabled: self.disk_cache.is_some(),
            disk_max_size: self.config.max_disk_size,
        }
    }
}

/// Cache statistics for monitoring
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub memory_size: usize,
    pub memory_entries: usize,
    pub memory_max_size: usize,
    pub disk_enabled: bool,
    pub disk_max_size: usize,
}

/// Get file modification time for cache invalidation
pub async fn get_file_mtime(path: &Path) -> CoreResult<u64> {
    let metadata = fs::metadata(path).await?;
    let mtime = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::InternalError("Invalid file modification time".to_string()))?
        .as_secs();
    Ok(mtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_key_generation() {
        let path = PathBuf::from("/test/comic.cbz");
        let mtime = 1234567890;

        let page_key = CacheKey::for_page(path.clone(), 5, mtime);
        let file_key = CacheKey::for_file(path, mtime);

        assert!(page_key.to_cache_filename().contains("_p5.cache"));
        assert!(file_key.to_cache_filename().contains("_full.cache"));
        assert_ne!(page_key.to_cache_filename(), file_key.to_cache_filename());
    }

    #[test]
    fn test_memory_cache_lru() {
        let mut cache = MemoryCache::new(100); // 100 bytes max
        
        let key1 = CacheKey::for_page(PathBuf::from("/test1.cbz"), 1, 123);
        let key2 = CacheKey::for_page(PathBuf::from("/test2.cbz"), 1, 124);
        let key3 = CacheKey::for_page(PathBuf::from("/test3.cbz"), 1, 125);

        let content1 = CachedContent::new(ContentType::JPEG, vec![0u8; 40]);
        let content2 = CachedContent::new(ContentType::PNG, vec![0u8; 40]);
        let content3 = CachedContent::new(ContentType::WEBP, vec![0u8; 40]);

        cache.put(key1.clone(), content1);
        cache.put(key2.clone(), content2);
        assert_eq!(cache.len(), 2);

        // This should evict key1 (oldest)
        cache.put(key3.clone(), content3);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_some());
        assert!(cache.get(&key3).is_some());
    }

    #[tokio::test]
    async fn test_disk_cache() {
        let temp_dir = TempDir::new().unwrap();
        let cache = DiskCache::new(temp_dir.path().to_path_buf(), 1024).unwrap();

        let key = CacheKey::for_page(PathBuf::from("/test.cbz"), 1, 123);
        let content = CachedContent::new(ContentType::JPEG, b"test data".to_vec());

        // Test put and get
        cache.put(&key, &content).await.unwrap();
        let retrieved = cache.get(&key, Duration::from_secs(3600)).await.unwrap().unwrap();
        
        assert_eq!(retrieved.content_type, ContentType::JPEG);
        assert_eq!(retrieved.data, b"test data");
    }
}
