// Copyright (c) 2019 Jason White
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::{
    channel::oneshot,
    future::{self, FutureExt, TryFutureExt},
    stream::{Stream, StreamExt, TryStreamExt},
};
use tokio::{self, sync::Mutex};

use crate::lru;

use super::{LFSObject, Storage, StorageKey, StorageStream};

type Cache = lru::Cache<StorageKey>;

/// Tracks which cache entries are currently being read so that they cannot be
/// deleted out from under an in-flight read.
///
/// An entry is protected for the entire lifetime of the byte stream returned
/// to the client. While pruning, protected entries are skipped over (they stay
/// in the LRU) and pruning continues with the next entry, so the cache still
/// makes as much progress as possible. Explicit deletions of a protected entry
/// (e.g. a corrupted object) remove it from the LRU immediately, but defer the
/// underlying file deletion until the last reader releases its reference.
struct RefRegistry {
    /// Number of active readers for each key.
    refs: HashMap<StorageKey, usize>,

    /// Keys whose underlying file must be deleted once their reference count
    /// drops to zero. An entry ends up here when it was evicted from the LRU
    /// while at least one reader still had the file open.
    pending_delete: HashMap<StorageKey, ()>,
}

impl RefRegistry {
    fn new() -> Self {
        RefRegistry {
            refs: HashMap::new(),
            pending_delete: HashMap::new(),
        }
    }

    /// Acquires a read reference for `key`. Must be paired with a `release`.
    fn acquire(&mut self, key: &StorageKey) {
        *self.refs.entry(key.clone()).or_insert(0) += 1;
    }

    /// Releases a read reference for `key`. Returns `true` if the key is now
    /// unreferenced. The pending-delete set is intentionally left untouched;
    /// the actual deletion decision is made later by
    /// [`RefRegistry::take_pending_if_unreferenced`].
    fn release(&mut self, key: &StorageKey) -> bool {
        let count = self
            .refs
            .get_mut(key)
            .expect("released a cache reference that was never acquired");

        *count -= 1;

        if *count == 0 {
            self.refs.remove(key);
            true
        } else {
            false
        }
    }

    /// Returns `true` if `key` currently has at least one active reader.
    fn is_referenced(&self, key: &StorageKey) -> bool {
        self.refs.contains_key(key)
    }

    /// Marks `key` for deletion once all of its active readers are done. The
    /// caller must have already removed the key from the LRU.
    fn mark_pending_delete(&mut self, key: &StorageKey) {
        self.pending_delete.insert(key.clone(), ());
    }

    /// Cancels any pending deletion of `key`.
    ///
    /// This is called when an entry is added back into the LRU (because the
    /// object was cached again). Otherwise, a reader finishing up could delete
    /// a freshly cached file that belongs to the new LRU entry.
    fn cancel_pending_delete(&mut self, key: &StorageKey) {
        self.pending_delete.remove(key);
    }

    /// Atomically removes `key` from the pending-delete set if it has no
    /// active readers. Returns `true` if the caller may now delete its file.
    /// If the key still has readers, it stays pending and `false` is returned.
    fn take_pending_if_unreferenced(&mut self, key: &StorageKey) -> bool {
        if self.refs.contains_key(key) {
            false
        } else {
            self.pending_delete.remove(key).is_some()
        }
    }
}

/// Owns a single read reference in a [`RefRegistry`]. The reference is
/// released when the guard is dropped, which happens when the wrapped stream
/// is consumed or dropped.
struct RefGuard {
    registry: Arc<StdMutex<RefRegistry>>,
    key: StorageKey,
}

impl Drop for RefGuard {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().unwrap();

        if registry.release(&self.key) {
            tracing::debug!("Last reader of cache entry {} finished", self.key);
        }
    }
}

/// Wraps a byte stream so that a [`RefGuard`] is kept alive for exactly as
/// long as the stream is.
struct GuardedStream {
    inner: super::ByteStream,
    _guard: RefGuard,
}

impl Stream for GuardedStream {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

#[derive(Debug)]
pub enum Error<C, S> {
    /// An error that occurred in the cache.
    Cache(C),

    /// An error that occurred in the storage backend.
    Storage(S),

    /// An error that occurred in the stream.
    Stream(io::Error),
}

impl<C, S> fmt::Display for Error<C, S>
where
    C: fmt::Display,
    S: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Cache(x) => fmt::Display::fmt(&x, f),
            Error::Storage(x) => fmt::Display::fmt(&x, f),
            Error::Stream(x) => fmt::Display::fmt(&x, f),
        }
    }
}

impl<C, S> Error<C, S> {
    pub fn from_cache(error: C) -> Self {
        Error::Cache(error)
    }

    pub fn from_storage(error: S) -> Self {
        Error::Storage(error)
    }

    pub fn from_stream(error: io::Error) -> Self {
        Error::Stream(error)
    }
}

impl<C, S> std::error::Error for Error<C, S>
where
    C: fmt::Debug + fmt::Display,
    S: fmt::Debug + fmt::Display,
{
}

/// Combines a cache with a permanent storage backend such that if a query to
/// the cache fails, it falls back to a permanent storage backend.
pub struct Backend<C, S> {
    lru: Arc<Mutex<Cache>>,
    /// Tracks entries that are being read so they cannot be deleted while an
    /// upload or download is still consuming their data.
    refs: Arc<StdMutex<RefRegistry>>,
    max_size: u64,
    cache: Arc<C>,
    storage: Arc<S>,
}

impl<C, S> Backend<C, S>
where
    C: Storage + Send + Sync,
    S: Storage,
{
    pub async fn new(
        max_size: u64,
        cache: C,
        storage: S,
    ) -> Result<Self, C::Error> {
        let lru = Cache::from_stream(cache.list()).await?;

        tracing::info!(
            "Prepopulated cache with {} entries ({})",
            lru.len(),
            humansize::format_size(lru.size(), humansize::DECIMAL),
        );

        let lru = Arc::new(Mutex::new(lru));
        let cache = Arc::new(cache);
        let refs = Arc::new(StdMutex::new(RefRegistry::new()));

        // Prune the cache. The maximum size setting may have changed
        // between server invocations. Thus, prune it down right away
        // instead of waiting for a client to do an upload.
        let count =
            prune_cache(lru.clone(), refs.clone(), max_size, cache.clone())
                .await?;

        if count > 0 {
            tracing::info!("Pruned {} entries from the cache", count);
        }

        Ok(Backend {
            lru,
            refs,
            max_size,
            cache,
            storage: Arc::new(storage),
        })
    }
}

/// Returns a future that prunes the least recently used entries that cause the
/// storage to exceed the given maximum size.
async fn prune_cache<S>(
    lru: Arc<Mutex<Cache>>,
    refs: Arc<StdMutex<RefRegistry>>,
    max_size: u64,
    storage: Arc<S>,
) -> Result<usize, S::Error>
where
    S: Storage + Send + Sync,
{
    let mut deleted = 0;

    let mut lru = lru.lock().await;

    if max_size != 0 {
        while lru.size() > max_size {
            // Pop the least recently used entry that has no active reader.
            // Entries that are currently being read are skipped over and left
            // in place so that pruning can continue with the next entry.
            let entry =
                lru.pop_if(|key| !refs.lock().unwrap().is_referenced(key));

            if let Some((key, _)) = entry {
                tracing::debug!("Pruning '{}' from cache", key);
                let _ = storage.delete(&key).await;
                deleted += 1;
            } else {
                // Nothing left in the LRU is safe to delete. The remaining
                // entries are all being read. They will become evictable once
                // their streams finish, so stop here for now.
                break;
            }
        }
    }

    // Clean up entries that were evicted earlier while a reader still had
    // their file open. Their file can now be removed. Holding the LRU lock
    // while deleting guarantees that a concurrent re-cache (which must first
    // take this lock) cannot have re-added the key underneath us.
    let pending: Vec<StorageKey> = refs
        .lock()
        .unwrap()
        .pending_delete
        .keys()
        .cloned()
        .collect();

    for key in pending {
        let can_delete =
            refs.lock().unwrap().take_pending_if_unreferenced(&key);

        if !can_delete {
            // A reader started again in the meantime; leave the deletion
            // deferred until the next prune.
            continue;
        }

        tracing::debug!(
            "Removing previously evicted cache entry '{}' now that its last \
             reader finished",
            key
        );
        let _ = storage.delete(&key).await;
        deleted += 1;
    }

    Ok(deleted)
}

async fn cache_and_prune<C>(
    cache: Arc<C>,
    key: StorageKey,
    obj: LFSObject,
    lru: Arc<Mutex<Cache>>,
    refs: Arc<StdMutex<RefRegistry>>,
    max_size: u64,
) -> Result<(), C::Error>
where
    C: Storage + Send + Sync,
{
    let len = obj.len();

    let oid = *key.oid();

    tracing::debug!("Caching {}", oid);
    cache.put(key.clone(), obj).await?;
    tracing::debug!("Finished caching {}", oid);

    // Add the object info to our LRU cache once the download from
    // permanent storage is complete.
    {
        let mut lru = lru.lock().await;

        // A previous incarnation of this object may still be waiting for its
        // last reader to finish. The freshly written file is a brand new
        // incarnation, so cancel that stale deletion.
        refs.lock().unwrap().cancel_pending_delete(&key);

        lru.push(key, len);
    }

    match prune_cache(lru, refs, max_size, cache).await {
        Ok(count) => {
            if count > 0 {
                tracing::info!("Pruned {} entries from the cache", count);
            }

            Ok(())
        }
        Err(err) => {
            tracing::error!("Error caching {} ({})", oid, err);
            Err(err)
        }
    }
}

#[async_trait]
impl<C, S> Storage for Backend<C, S>
where
    S: Storage + Send + Sync + 'static,
    S::Error: 'static,
    C: Storage + Send + Sync + 'static,
    C::Error: 'static,
{
    type Error = Error<C::Error, S::Error>;

    /// Tries to query the cache first. If that fails, falls back to the
    /// permanent storage backend.
    async fn get(
        &self,
        key: &StorageKey,
    ) -> Result<Option<LFSObject>, Self::Error> {
        // TODO: Keep stats on cache hits and misses. We can then display those
        // stats on a web page or send them to another service such as
        // Prometheus.
        // Acquire the read reference while the LRU lock is still held so that
        // a concurrent prune cannot pop and delete the entry in the gap
        // between checking the LRU and opening the cached file.
        let is_cached = self.lru.lock().await.get_refresh(key).is_some();

        if is_cached {
            // Cache hit! (Probably)
            let guard = RefGuard {
                registry: self.refs.clone(),
                key: key.clone(),
            };
            self.refs.lock().unwrap().acquire(key);

            let obj = match self.cache.get(key).await {
                Ok(obj) => obj,
                Err(err) => {
                    drop(guard);
                    return Err(Error::from_cache(err));
                }
            };

            return match obj {
                Some(obj) => {
                    // Keep the reference alive for the whole lifetime of the
                    // returned stream so that the underlying file cannot be
                    // evicted while it is being read.
                    let (len, stream) = obj.into_parts();
                    Ok(Some(LFSObject::new(
                        len,
                        Box::pin(GuardedStream {
                            inner: stream,
                            _guard: guard,
                        }),
                    )))
                }
                None => {
                    // If the cache doesn't actually have it, release the
                    // reference and delete the entry from our LRU. This can
                    // happen if the cache is cleared out manually.
                    drop(guard);

                    let mut lru = self.lru.lock().await;
                    lru.remove(key);

                    // Fall back to permanent storage. Note that this won't
                    // actually cache the object. This will be done next time
                    // the same object is requested.
                    self.storage.get(key).await.map_err(Error::from_storage)
                }
            };
        }

        // Cache miss. Get the object from permanent storage. If successful, we
        // need to cache the resulting byte stream.
        let lru = self.lru.clone();
        let refs = self.refs.clone();
        let max_size = self.max_size;
        let cache = self.cache.clone();
        let key = key.clone();

        let obj = self.storage.get(&key).await.map_err(Error::from_storage)?;

        match obj {
            Some(obj) => {
                // Cache the returned LFS object.
                let (f, a, b) = obj.fanout();

                // Cache the object in the background. Whether or not this
                // succeeds shouldn't prevent the client from getting the LFS
                // object. For example, even if we run out of disk space, the
                // server should still continue operating.
                let cache =
                    cache_and_prune(cache, key.clone(), b, lru, refs, max_size)
                        .map_err(Error::from_cache);

                tokio::spawn(
                    future::try_join(f.map_err(Error::from_stream), cache)
                        .map_ok(|((), ())| ())
                        .map_err(move |err: Self::Error| {
                            tracing::error!("Error caching {} ({})", key, err);
                        }),
                );

                // Send the object from permanent-storage.
                Ok(Some(a))
            }
            None => {
                // The permanent storage also doesn't have it.
                //
                // Note that we cannot cache the non-existence of an object
                // because the storage backend can be manipulated independently
                // of the cache. There can also be multiple instances of caches
                // per storage backend.
                Ok(None)
            }
        }
    }

    async fn put(
        &self,
        key: StorageKey,
        value: LFSObject,
    ) -> Result<(), Self::Error> {
        let lru = self.lru.clone();
        let refs = self.refs.clone();
        let max_size = self.max_size;
        let cache = self.cache.clone();

        let (f, a, b) = value.fanout();

        // Note: We can only cache an object if it is successfully uploaded to
        // the store. Thus, we do something clever with this one shot channel.
        //
        // When the permanent storage finishes receiving its LFS object, we send
        // a signal to be received by an empty chunk at the end of the stream
        // going to the cache. Then, the cache only receives its last (empty)
        // chunk when the LFS object has been successfully stored.
        let (signal_sender, signal_receiver) = oneshot::channel();

        let store = self
            .storage
            .put(key.clone(), a)
            .map_ok(move |()| {
                // Send a signal to the cache so that it can complete its write.
                tracing::debug!("Received last chunk from server.");
                signal_sender.send(()).unwrap_or(())
            })
            .map_err(Error::from_storage);

        let (len, stream) = b.into_parts();

        // Add an empty chunk to the end of the stream whose only job is to
        // complete when it receives a signal that the upload to permanent
        // storage has completed.
        let stream = stream.chain(
            signal_receiver
                .map_ok(|()| Bytes::new())
                .map_err(io::Error::other)
                .into_stream(),
        );

        let cache = cache_and_prune(
            cache,
            key,
            LFSObject::new(len, Box::pin(stream)),
            lru,
            refs,
            max_size,
        )
        .map_err(Error::from_cache);

        future::try_join3(f.map_err(Error::from_stream), cache, store).await?;

        Ok(())
    }

    async fn size(&self, key: &StorageKey) -> Result<Option<u64>, Self::Error> {
        // Get just the size of an object without perturbing the LRU ordering.
        // Only downloads or uploads need to perturb the LRU ordering.
        let lru = self.lru.lock().await;
        if let Some(size) = lru.get(key) {
            // Cache hit!
            Ok(Some(size))
        } else {
            // Cache miss. Check permanent storage.
            self.storage.size(key).await.map_err(Error::from_storage)
        }
    }

    /// Deletes an item from the cache (not from permanent storage).
    async fn delete(&self, key: &StorageKey) -> Result<(), Self::Error> {
        // Only ever delete items from the cache. This may be called when a
        // corrupted object is detected while a download is streaming it. In
        // that case the entry is removed from the LRU immediately so that it
        // cannot be handed out again, but the underlying file deletion is
        // deferred until the last in-flight reader releases its reference.
        {
            let mut lru = self.lru.lock().await;
            lru.remove(key);
        }

        let busy = self.refs.lock().unwrap().is_referenced(key);

        if busy {
            tracing::info!(
                "Deferring deletion of {} from the cache until its in-flight \
                 readers finish",
                key
            );
            self.refs.lock().unwrap().mark_pending_delete(key);
            Ok(())
        } else {
            tracing::info!("Deleted {} from the cache", key);
            self.cache.delete(key).await.map_err(Error::from_cache)
        }
    }

    /// Returns a stream of cached items.
    fn list(&self) -> StorageStream<(StorageKey, u64), Self::Error> {
        // TODO: Use the LRU instead to get this list.
        Box::pin(self.cache.list().map_err(Error::from_cache))
    }

    /// Returns the total size of the LRU cache (not the total size of the
    /// permanent storage).
    async fn total_size(&self) -> Option<u64> {
        Some(self.lru.lock().await.size())
    }

    /// Returns the maximum size of the LRU cache (not the maximum size of the
    /// permanent storage).
    async fn max_size(&self) -> Option<u64> {
        if self.max_size == 0 {
            None
        } else {
            Some(self.max_size)
        }
    }

    fn public_url(&self, key: &StorageKey) -> Option<String> {
        self.storage.public_url(key)
    }

    async fn upload_url(
        &self,
        key: &StorageKey,
        expires_in: Duration,
    ) -> Option<String> {
        self.storage.upload_url(key, expires_in).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::stream::{self, StreamExt, TryStreamExt};
    use tempfile::TempDir;

    use super::{Backend, RefRegistry};
    use crate::lfs::Oid;
    use crate::storage::Disk;
    use crate::storage::{
        LFSObject, Namespace, Storage, StorageKey, StorageStream,
    };

    fn make_key(seed: u8) -> StorageKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        StorageKey::new(
            Namespace::new("org".into(), "project".into()),
            Oid::from(bytes),
        )
    }

    fn make_object(len: usize, byte: u8) -> LFSObject {
        let chunk = Bytes::from(vec![byte; len]);
        let stream = stream::once(async move { Ok::<_, io::Error>(chunk) });
        LFSObject::new(len as u64, Box::pin(stream))
    }

    fn object_from_bytes(data: Vec<u8>) -> LFSObject {
        let len = data.len() as u64;
        let stream =
            stream::once(async move { Ok::<_, io::Error>(Bytes::from(data)) });
        LFSObject::new(len, Box::pin(stream))
    }

    async fn collect(obj: LFSObject) -> Vec<u8> {
        obj.stream()
            .try_fold(Vec::new(), |mut acc, chunk| async move {
                acc.extend_from_slice(&chunk);
                Ok(acc)
            })
            .await
            .expect("stream must succeed")
    }

    /// A minimal in-memory "permanent" storage backend used to drive the
    /// caching backend without depending on S3.
    #[derive(Default)]
    struct MemoryStorage {
        objects: StdMutex<HashMap<StorageKey, Vec<u8>>>,
    }

    #[async_trait]
    impl Storage for MemoryStorage {
        type Error = io::Error;

        async fn get(
            &self,
            key: &StorageKey,
        ) -> Result<Option<LFSObject>, Self::Error> {
            let data = self.objects.lock().unwrap().get(key).cloned();
            Ok(data.map(|data| {
                let len = data.len();
                let stream = stream::once(async move { Ok(Bytes::from(data)) });
                LFSObject::new(len as u64, Box::pin(stream))
            }))
        }

        async fn put(
            &self,
            key: StorageKey,
            value: LFSObject,
        ) -> Result<(), Self::Error> {
            let (_, stream) = value.into_parts();
            let data: Vec<u8> = stream
                .try_fold(Vec::new(), |mut acc, chunk| async move {
                    acc.extend_from_slice(&chunk);
                    Ok(acc)
                })
                .await?;
            self.objects.lock().unwrap().insert(key, data);
            Ok(())
        }

        async fn size(
            &self,
            key: &StorageKey,
        ) -> Result<Option<u64>, Self::Error> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .map(|data| data.len() as u64))
        }

        async fn delete(&self, key: &StorageKey) -> Result<(), Self::Error> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }

        fn list(&self) -> StorageStream<(StorageKey, u64), Self::Error> {
            let entries: Vec<_> = self
                .objects
                .lock()
                .unwrap()
                .iter()
                .map(|(key, data)| (key.clone(), data.len() as u64))
                .collect();
            Box::pin(stream::iter(entries).map(Ok))
        }

        fn public_url(&self, _key: &StorageKey) -> Option<String> {
            None
        }

        async fn upload_url(
            &self,
            _key: &StorageKey,
            _expires_in: Duration,
        ) -> Option<String> {
            None
        }
    }

    /// Waits until `pred` is true or the timeout elapses. This is used to wait
    /// for a background `cache_and_prune` task to finish.
    async fn wait_until<F>(mut pred: F)
    where
        F: FnMut() -> bool,
    {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if pred() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition was not met before the timeout");
    }

    /// A prune triggered while a cached object is being read must not delete
    /// that object's file, and the in-flight read must complete with all of
    /// its bytes intact.
    #[tokio::test]
    async fn prune_does_not_delete_object_being_read() {
        let dir = TempDir::new().unwrap();
        let cache = Disk::new(dir.path().to_path_buf()).await.unwrap();
        let probe = Disk::new(dir.path().to_path_buf()).await.unwrap();
        let permanent = MemoryStorage::default();

        let key = make_key(1);
        let data = vec![0xABu8; 1024];
        let expected = data.clone();

        permanent
            .put(key.clone(), object_from_bytes(data.clone()))
            .await
            .unwrap();

        // The object fits within the cache, but adding a second object pushes
        // the cache over the limit and forces an eviction.
        let backend = Backend::new(2048, cache, permanent).await.unwrap();

        // First read populates the cache in the background. Wait until it is
        // actually cached and present in the LRU.
        let first = backend.get(&key).await.unwrap().unwrap();
        let bytes = collect(first).await;
        assert_eq!(bytes, expected);

        wait_until(|| {
            !backend.refs.lock().unwrap().is_referenced(&key)
                && backend
                    .lru
                    .try_lock()
                    .is_ok_and(|lru| lru.get(&key).is_some())
        })
        .await;

        // This read is a cache hit and must hold a reference for the whole
        // lifetime of the returned stream.
        let in_flight = backend.get(&key).await.unwrap().unwrap();
        assert!(backend.refs.lock().unwrap().is_referenced(&key));
        let cached_path = probe.object_path(&key);
        assert!(
            cached_path.exists(),
            "the cached file must exist before pruning runs"
        );

        // Keep the stream open while more uploads push the cache over its
        // limit and trigger pruning.
        let other = make_key(2);
        let other2 = make_key(3);
        backend
            .put(other.clone(), make_object(1024, 0xCD))
            .await
            .unwrap();
        backend
            .put(other2.clone(), make_object(1024, 0xEF))
            .await
            .unwrap();

        // The read protected its key from eviction. Pruning still made
        // progress by evicting the unreferenced `other` object, so the cache
        // ends up holding the protected key plus the newest object.
        assert!(backend.lru.lock().await.get(&key).is_some());
        assert!(backend.lru.lock().await.get(&other).is_none());
        assert!(backend.lru.lock().await.get(&other2).is_some());
        assert_eq!(backend.lru.lock().await.len(), 2);
        assert!(
            cached_path.exists(),
            "the cached file must not be deleted while a read is in flight"
        );

        // The object being read is still protected, so its cached file must
        // still exist and the stream must read back the full object.
        let bytes = collect(in_flight).await;
        assert_eq!(bytes, expected);
        assert!(!backend.refs.lock().unwrap().is_referenced(&key));

        // A subsequent prune (triggered here by another upload) is now allowed
        // to evict the previously protected object since its reader finished.
        let key_d = make_key(4);
        backend.put(key_d, make_object(1024, 0x11)).await.unwrap();
    }

    /// Objects with no active reader are still evicted normally, proving that
    /// reference tracking does not disable cache pruning.
    #[tokio::test]
    async fn prune_still_evicts_unreferenced_objects() {
        let dir = TempDir::new().unwrap();
        let cache = Disk::new(dir.path().to_path_buf()).await.unwrap();
        let permanent = MemoryStorage::default();

        let key_a = make_key(1);
        let key_b = make_key(2);
        let key_c = make_key(3);

        permanent
            .put(key_a.clone(), make_object(1024, 0x01))
            .await
            .unwrap();
        permanent
            .put(key_b.clone(), make_object(1024, 0x02))
            .await
            .unwrap();
        permanent
            .put(key_c.clone(), make_object(1024, 0x03))
            .await
            .unwrap();

        // The cache can hold two objects; the third object forces the least
        // recently used one out.
        let backend = Backend::new(2048, cache, permanent).await.unwrap();

        // Cache A, then B, then C. Caching C prunes A (the least recently
        // used) since it has no readers.
        // Fully consume the stream (as a real client download would). Dropping
        // it early would cancel the fanout and abort the background caching.
        let obj_a = backend.get(&key_a).await.unwrap().unwrap();
        assert_eq!(collect(obj_a).await, vec![0x01u8; 1024]);
        wait_until(|| {
            backend
                .lru
                .try_lock()
                .is_ok_and(|lru| lru.get(&key_a).is_some())
        })
        .await;

        let obj_b = backend.get(&key_b).await.unwrap().unwrap();
        assert_eq!(collect(obj_b).await, vec![0x02u8; 1024]);
        wait_until(|| {
            backend
                .lru
                .try_lock()
                .is_ok_and(|lru| lru.get(&key_b).is_some())
        })
        .await;

        let obj_c = backend.get(&key_c).await.unwrap().unwrap();
        let bytes_c = collect(obj_c).await;
        assert_eq!(bytes_c, vec![0x03u8; 1024]);

        wait_until(|| {
            backend
                .lru
                .try_lock()
                .is_ok_and(|lru| lru.get(&key_a).is_none())
        })
        .await;

        // B and C remain in the LRU; A was evicted.
        let lru = backend.lru.lock().await;
        assert_eq!(lru.len(), 2);
        assert!(lru.get(&key_c).is_some());
        assert!(lru.get(&key_b).is_some());
        assert!(lru.get(&key_a).is_none());
        assert!(!backend.refs.lock().unwrap().is_referenced(&key_c));
    }

    /// Deleting a busy entry defers the file deletion until the last reader
    /// releases its reference; after that, the next prune removes the file.
    #[tokio::test]
    async fn delete_busy_entry_is_deferred_until_reader_finishes() {
        let dir = TempDir::new().unwrap();
        let cache = Disk::new(dir.path().to_path_buf()).await.unwrap();
        let probe = Disk::new(dir.path().to_path_buf()).await.unwrap();
        let permanent = MemoryStorage::default();

        let key = make_key(7);
        let data = vec![0x42u8; 2048];
        let expected = data.clone();

        permanent
            .put(key.clone(), object_from_bytes(data.clone()))
            .await
            .unwrap();

        // Unlimited cache so that ordinary pruning never touches the entry.
        let backend = Backend::new(0, cache, permanent).await.unwrap();

        let first = backend.get(&key).await.unwrap().unwrap();
        assert_eq!(collect(first).await, expected);
        wait_until(|| backend.lru.try_lock().is_ok_and(|lru| lru.len() == 1))
            .await;

        // Start a cache-hit read and keep it in flight.
        let in_flight = backend.get(&key).await.unwrap().unwrap();
        assert!(backend.refs.lock().unwrap().is_referenced(&key));
        let cached_path = probe.object_path(&key);
        assert!(cached_path.exists());

        // Simulate a corruption-triggered deletion while the read is active.
        backend.delete(&key).await.unwrap();

        // The entry is gone from the LRU, but the file deletion is pending.
        assert!(backend.lru.lock().await.get(&key).is_none());
        assert!(
            backend
                .refs
                .lock()
                .unwrap()
                .pending_delete
                .contains_key(&key)
        );
        assert!(
            cached_path.exists(),
            "the file must survive while the reader is still active"
        );

        // The in-flight read still returns every byte.
        assert_eq!(collect(in_flight).await, expected);

        // The pending deletion is cleaned up on the next prune.
        let cache = backend.cache.clone();
        super::prune_cache(backend.lru.clone(), backend.refs.clone(), 1, cache)
            .await
            .unwrap();

        assert!(
            !cached_path.exists(),
            "the file must be removed once the last reader finished"
        );

        assert!(
            !backend
                .refs
                .lock()
                .unwrap()
                .pending_delete
                .contains_key(&key)
        );
    }

    /// Unit tests for the reference registry state machine itself.
    #[test]
    fn ref_registry_lifecycle() {
        let key = make_key(9);
        let mut registry = RefRegistry::new();

        assert!(!registry.is_referenced(&key));

        registry.acquire(&key);
        registry.acquire(&key);
        assert!(registry.is_referenced(&key));

        // Releasing one of two readers must not trigger a pending deletion.
        registry.mark_pending_delete(&key);
        assert!(!registry.release(&key));
        assert!(registry.is_referenced(&key));
        assert!(registry.pending_delete.contains_key(&key));

        // While a reader still exists, a pending deletion cannot be taken.
        assert!(!registry.take_pending_if_unreferenced(&key));

        // After the last release the pending deletion can be taken.
        assert!(registry.release(&key));
        assert!(!registry.is_referenced(&key));
        assert!(registry.take_pending_if_unreferenced(&key));
        assert!(!registry.pending_delete.contains_key(&key));

        // Re-caching an entry cancels a pending deletion.
        registry.mark_pending_delete(&key);
        registry.cancel_pending_delete(&key);
        assert!(!registry.take_pending_if_unreferenced(&key));
    }
}
