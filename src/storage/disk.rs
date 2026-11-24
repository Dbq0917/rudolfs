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
use std::io;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_stream::try_stream;
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures::stream::{StreamExt, TryStreamExt};
use tokio::{self, fs, sync::Mutex};
use tokio_util::codec::{Decoder, Encoder, Framed};
use uuid::Uuid;

use super::{LFSObject, Namespace, Storage, StorageKey, StorageStream};
use crate::lfs::Oid;
use crate::util::NamedTempFile;

/// Number of logical buckets that objects are distributed across.
const BUCKET_COUNT: usize = 16;

#[derive(Default)]
struct BucketState {
    /// Bytes actually written for each bucket.
    used: [u64; BUCKET_COUNT],

    /// The bucket each object was placed in.
    locations: HashMap<StorageKey, u8>,

    /// The on-disk size of each object, used to update `used` when an object is
    /// replaced or deleted.
    sizes: HashMap<StorageKey, u64>,
}

impl BucketState {
    fn choose(&self) -> usize {
        // Balanced allocation: put new objects in the bucket with the fewest
        // bytes currently stored. Ties are resolved by the bucket index.
        (0..BUCKET_COUNT)
            .min_by_key(|&bucket| self.used[bucket])
            .unwrap_or(0)
    }

    fn insert(&mut self, key: StorageKey, bucket: u8, size: u64) {
        let bucket = bucket as usize;
        let old_bucket = self.locations.get(&key).copied();
        let old_size = self.sizes.get(&key).copied();

        if let (Some(old_bucket), Some(old_size)) = (old_bucket, old_size) {
            self.used[old_bucket as usize] =
                self.used[old_bucket as usize].saturating_sub(old_size);
        }

        self.used[bucket] = self.used[bucket].saturating_add(size);
        self.locations.insert(key.clone(), bucket as u8);
        self.sizes.insert(key, size);
    }

    fn remove(&mut self, key: &StorageKey) {
        if let Some(bucket) = self.locations.remove(key)
            && let Some(size) = self.sizes.remove(key)
        {
            self.used[bucket as usize] =
                self.used[bucket as usize].saturating_sub(size);
        }
    }
}

pub struct Backend {
    root: PathBuf,
    buckets: Arc<Mutex<BucketState>>,
}

impl Backend {
    pub async fn new(root: PathBuf) -> Result<Self, io::Error> {
        fs::create_dir_all(&root).await?;

        let backend = Backend {
            root,
            buckets: Arc::new(Mutex::new(BucketState::default())),
        };

        // Rebuild the bucket accounting once at startup. Writes and deletes
        // update it incrementally afterwards; they never rescan the tree.
        backend.rebuild_bucket_state().await?;

        // TODO: Clean out files in the "incomplete" folder?
        Ok(backend)
    }

    fn bucket_path(&self, key: &StorageKey, bucket: u8) -> PathBuf {
        self.root.join(format!(
            "objects/{}/{:x}/{}",
            key.namespace(),
            bucket,
            key.oid().path()
        ))
    }

    /// Path used by older versions of Rudolfs. Objects in this layout are still
    /// readable so that upgrading doesn't lose data.
    fn legacy_path(&self, key: &StorageKey) -> PathBuf {
        self.root.join(format!(
            "objects/{}/{}",
            key.namespace(),
            key.oid().path()
        ))
    }

    async fn existing_path(&self, key: &StorageKey) -> Option<PathBuf> {
        let bucket = self.buckets.lock().await.locations.get(key).copied();

        if let Some(bucket) = bucket {
            let path = self.bucket_path(key, bucket);
            if fs::metadata(&path).await.is_ok() {
                return Some(path);
            }
        }

        // Objects written by older versions live in the prefix layout.
        let legacy = self.legacy_path(key);
        if fs::metadata(&legacy).await.is_ok() {
            return Some(legacy);
        }

        // If the in-memory index is stale (for example, because another process
        // wrote to this directory), probe the buckets before giving up.
        for bucket in 0..BUCKET_COUNT as u8 {
            let path = self.bucket_path(key, bucket);
            if fs::metadata(&path).await.is_ok() {
                return Some(path);
            }
        }

        None
    }

    async fn rebuild_bucket_state(&self) -> Result<(), io::Error> {
        let mut entries: HashMap<StorageKey, (Option<u8>, u64)> =
            HashMap::new();
        let mut objects = self.scan_objects();

        while let Some((key, size, bucket)) = objects.try_next().await? {
            match entries.get(&key) {
                // Prefer the new layout if an object exists in both layouts.
                Some((Some(_), _)) if bucket.is_none() => {}
                _ => {
                    entries.insert(key, (bucket, size));
                }
            }
        }

        let mut state = BucketState::default();

        for (key, (bucket, size)) in entries {
            if let Some(bucket) = bucket {
                state.insert(key, bucket, size);
            }
        }

        *self.buckets.lock().await = state;
        Ok(())
    }

    /// Scans all objects on disk, yielding the storage key, size, and bucket.
    ///
    /// Legacy objects have no bucket. The scan is used to initialize the
    /// in-memory accounting and is not part of the normal write path.
    fn scan_objects(
        &self,
    ) -> StorageStream<(StorageKey, u64, Option<u8>), io::Error> {
        let backend_root = self.root.clone();
        let root = backend_root.join("objects");

        let objects = try_stream! {
            let mut dirs = vec![root];

            while let Some(dir) = dirs.pop() {
                let mut entries = match fs::read_dir(&dir).await {
                    Ok(entries) => entries,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        continue;
                    }
                    Err(err) => Err(err)?,
                };

                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    let file_type = entry.file_type().await?;

                    if file_type.is_dir() {
                        dirs.push(path);
                    } else if file_type.is_file()
                        && let Some((key, bucket)) = parse_object_path(&backend_root, &path)
                    {
                        let metadata = entry.metadata().await?;
                        yield (key, metadata.len(), bucket);
                    }
                }
            }
        };

        Box::pin(objects)
    }
}

#[async_trait]
impl Storage for Backend {
    type Error = io::Error;

    async fn get(
        &self,
        key: &StorageKey,
    ) -> Result<Option<LFSObject>, Self::Error> {
        let path = match self.existing_path(key).await {
            Some(path) => path,
            None => return Ok(None),
        };

        let file = match fs::File::open(path).await {
            Ok(file) => file,
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    return Ok(None);
                } else {
                    return Err(err);
                }
            }
        };

        let metadata = file.metadata().await?;

        let stream =
            Framed::new(file, BytesCodec::new()).map_ok(BytesMut::freeze);

        Ok(Some(LFSObject::new(metadata.len(), Box::pin(stream))))
    }

    async fn put(
        &self,
        key: StorageKey,
        value: LFSObject,
    ) -> Result<(), Self::Error> {
        let (len, stream) = value.into_parts();

        let incomplete = self.root.join("incomplete");
        let temp_path = incomplete.join(Uuid::new_v4().to_string());

        fs::create_dir_all(incomplete).await?;

        // Note that when this is dropped, the file is deleted. Thus, if
        // anything goes wrong we are not left with a temporary file laying
        // around.
        let file = NamedTempFile::new(temp_path).await?;

        let mut sink = Framed::new(file, BytesCodec::new());

        stream.forward(&mut sink).await?;

        let written = sink.codec().written();
        let file = sink.into_inner();

        if written != len {
            // If we didn't get a full object, we cannot save it to disk. This
            // can happen if we're using the disk as a cache and there is an
            // error in the middle of the upload.
            Err(io::Error::other("got incomplete object"))
        } else {
            // Hold the allocation lock while committing the file. This makes
            // the bucket selection and the bucket accounting atomic with
            // respect to other uploads without serializing their byte streams.
            let mut buckets = self.buckets.lock().await;

            let bucket = buckets
                .locations
                .get(&key)
                .copied()
                .unwrap_or_else(|| buckets.choose() as u8);
            let path = self.bucket_path(&key, bucket);
            let dir = path.parent().unwrap().to_path_buf();

            fs::create_dir_all(dir).await?;
            file.persist(path).await?;

            // Count the bytes that actually landed on disk, including any
            // encryption header added by an outer storage adaptor.
            buckets.insert(key, bucket, written);
            Ok(())
        }
    }

    async fn size(&self, key: &StorageKey) -> Result<Option<u64>, Self::Error> {
        let path = match self.existing_path(key).await {
            Some(path) => path,
            None => return Ok(None),
        };

        fs::metadata(path)
            .await
            .map(move |metadata| Some(metadata.len()))
            .or_else(move |err| match err.kind() {
                io::ErrorKind::NotFound => Ok(None),
                _ => Err(err),
            })
    }

    async fn delete(&self, key: &StorageKey) -> Result<(), Self::Error> {
        // TODO: Attempt to delete the parent folder(s)? This would keep the
        // directory tree clean but it could also cause a race condition when
        // directories are created during `put` operations.
        if let Some(path) = self.existing_path(key).await {
            fs::remove_file(path).await.or_else(move |err| {
                match err.kind() {
                    io::ErrorKind::NotFound => Ok(()),
                    _ => Err(err),
                }
            })?;
        }

        self.buckets.lock().await.remove(key);
        Ok(())
    }

    /// Lists the objects that are on disk.
    ///
    /// The directory structure is assumed to be like this:
    ///
    ///   objects/{org}/{project}/
    ///   ├── 0
    ///   │   ├── 07
    ///   │   │   └── 0007941906960...
    ///   │   └── ff
    ///   │       └── 00ff9e9c69224...
    ///   ├── 1
    ///   │   ├── 89
    ///   │   │   └── 0189e5fd19477...
    ///   │   └── f5
    ///   │       └── 01f5c45c65e62...
    ///               ^^^^
    ///
    /// Note that the first four characters are repeated in the file name so
    /// that transforming the file name into an object ID is simpler.
    fn list(&self) -> StorageStream<(StorageKey, u64), Self::Error> {
        Box::pin(
            self.scan_objects()
                .map_ok(|(key, size, _bucket)| (key, size)),
        )
    }

    async fn total_size(&self) -> Option<u64> {
        Some(self.buckets.lock().await.used.iter().sum())
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

/// Extracts the storage key and bucket from a path below `objects/`.
///
/// New objects are stored as `{org}/{project}/{bucket}/{xx}/{yy}/{oid}` where
/// the bucket is a single hexadecimal digit. Legacy objects are stored as
/// `{org}/{project}/{xx}/{yy}/{oid}` and have no bucket.
fn parse_object_path(
    root: &Path,
    path: &Path,
) -> Option<(StorageKey, Option<u8>)> {
    let objects = root.join("objects");
    let relative = path.strip_prefix(objects).ok()?;

    let components: Vec<&str> = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Option<_>>()?;

    let (namespace, bucket, oid_name) = match components.as_slice() {
        [org, project, bucket, _tier1, _tier2, oid] if bucket.len() == 1 => {
            let bucket = u8::from_str_radix(bucket, 16).ok()?;
            if bucket as usize >= BUCKET_COUNT {
                return None;
            }

            (
                Namespace::new((*org).into(), (*project).into()),
                Some(bucket),
                *oid,
            )
        }
        [org, project, _tier1, _tier2, oid] => {
            (Namespace::new((*org).into(), (*project).into()), None, *oid)
        }
        _ => return None,
    };

    let oid = Oid::from_str(oid_name).ok()?;
    Some((StorageKey::new(namespace, oid), bucket))
}

/// A simple bytes codec that keeps track of its length.
struct BytesCodec {
    written: u64,
}

impl BytesCodec {
    pub fn new() -> Self {
        BytesCodec { written: 0 }
    }

    pub fn written(&self) -> u64 {
        self.written
    }
}

impl Decoder for BytesCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if !buf.is_empty() {
            let len = buf.len();
            Ok(Some(buf.split_to(len)))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<Bytes> for BytesCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        data: Bytes,
        buf: &mut BytesMut,
    ) -> Result<(), io::Error> {
        let len = data.len();
        self.written += len as u64;
        buf.reserve(len);
        buf.put(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::stream;

    use super::*;

    fn key(value: u8) -> StorageKey {
        StorageKey::new(
            Namespace::new("org".into(), "project".into()),
            Oid::from([value; 32]),
        )
    }

    async fn put(backend: &Backend, key: StorageKey, bytes: Vec<u8>) {
        let len = bytes.len() as u64;
        let stream = stream::iter(vec![Ok(Bytes::from(bytes))]);
        backend
            .put(key, LFSObject::new(len, Box::pin(stream)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn distributes_objects_by_written_size() {
        let dir = tempfile::TempDir::new().unwrap();
        let backend = Backend::new(dir.path().to_path_buf()).await.unwrap();

        // Equal-sized objects should fill all buckets before doubling up.
        for value in 0..BUCKET_COUNT as u8 {
            put(&backend, key(value), vec![value; 100]).await;
        }

        {
            let state = backend.buckets.lock().await;
            assert_eq!(state.used, [100; BUCKET_COUNT]);
        }

        // The next object goes to the first bucket, not a fixed prefix bucket.
        put(&backend, key(100), vec![0; 100]).await;

        {
            let state = backend.buckets.lock().await;
            assert_eq!(state.used[0], 200);
            assert!(state.used[1..].iter().all(|&size| size == 100));
        }
    }

    #[tokio::test]
    async fn routes_new_writes_away_from_the_heaviest_bucket() {
        let dir = tempfile::TempDir::new().unwrap();
        let backend = Backend::new(dir.path().to_path_buf()).await.unwrap();

        // Make the first bucket much heavier than the rest.
        put(&backend, key(0), vec![0; 16 * 1024]).await;

        for value in 1..BUCKET_COUNT as u8 {
            put(&backend, key(value), vec![value; 1024]).await;
        }

        put(&backend, key(100), vec![0; 1024]).await;

        let state = backend.buckets.lock().await;
        assert_eq!(state.used[0], 16 * 1024);
        assert_eq!(state.used[1], 2 * 1024);
    }

    #[tokio::test]
    async fn rebuilds_bucket_sizes_without_rescanning_on_each_write() {
        let dir = tempfile::TempDir::new().unwrap();
        let first = key(1);

        {
            let backend = Backend::new(dir.path().to_path_buf()).await.unwrap();

            put(&backend, first.clone(), vec![1; 4096]).await;
            put(&backend, key(2), vec![2; 1024]).await;
        }

        // Restarting reloads the accounting once from the files on disk.
        let backend = Backend::new(dir.path().to_path_buf()).await.unwrap();

        {
            let state = backend.buckets.lock().await;
            assert_eq!(state.used[0], 4096);
            assert_eq!(state.used[1], 1024);
        }

        assert_eq!(backend.size(&first).await.unwrap(), Some(4096));
        assert_eq!(backend.total_size().await, Some(5120));

        backend.delete(&first).await.unwrap();
        assert_eq!(backend.size(&first).await.unwrap(), None);
        assert_eq!(backend.total_size().await, Some(1024));
    }

    #[tokio::test]
    async fn reads_objects_from_the_legacy_layout() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = key(7);
        let path = dir.path().join(format!(
            "objects/{}/{}",
            key.namespace(),
            key.oid().path()
        ));

        fs::create_dir_all(path.parent().unwrap()).await.unwrap();
        fs::write(&path, b"legacy").await.unwrap();

        let backend = Backend::new(dir.path().to_path_buf()).await.unwrap();

        assert_eq!(backend.size(&key).await.unwrap(), Some(6));

        let object = backend.get(&key).await.unwrap().unwrap();
        assert_eq!(object.len(), 6);
    }
}
