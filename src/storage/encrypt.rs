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
use std::io;
use std::sync::{RwLock, RwLockReadGuard};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use chacha::{ChaCha, KeyStream};
use futures::{
    Stream,
    stream::{self, StreamExt},
};
use serde::{Deserialize, Serialize};

pub use super::keys::{
    DEFAULT_ROTATION_WINDOW, KeyFingerprint, KeyId, KeyManager, KeyRing,
    KeyRingBuilder, KeyRingError, KeyVersion, Keychain, ROTATION_WINDOW,
    VersionedKey,
};
use super::{LFSObject, Storage, StorageKey, StorageStream};

/// Magic prefix for a versioned encrypted object.
pub const ENCRYPTION_MAGIC: [u8; 8] = *b"RDLFSENC";

/// First version of the versioned encryption envelope.
pub const ENCRYPTION_FORMAT_V1: u8 = 1;

/// Flag indicating that the payload is encrypted.
pub const ENCRYPTION_FLAG_ENCRYPTED: u8 = 0x01;

/// Size of the binary envelope header.
///
/// Layout:
/// - 8 byte magic
/// - 1 byte envelope format version
/// - 1 byte flags
/// - 4 byte key version, little-endian
/// - 32 byte SHA-256 key identifier
pub const ENCRYPTION_HEADER_LEN: usize = 46;

/// Versioned metadata stored at the beginning of encrypted objects.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptionMetadata {
    pub format_version: u8,
    pub flags: u8,
    pub key_version: KeyVersion,
    pub key_id: KeyId,
}

/// Alternative name for the metadata envelope stored with an object.
pub type ObjectHeader = EncryptionMetadata;

impl EncryptionMetadata {
    pub fn new(key_version: KeyVersion, key_id: KeyId) -> Self {
        Self {
            format_version: ENCRYPTION_FORMAT_V1,
            flags: ENCRYPTION_FLAG_ENCRYPTED,
            key_version,
            key_id,
        }
    }

    pub fn encrypted(&self) -> bool {
        self.flags & ENCRYPTION_FLAG_ENCRYPTED != 0
    }

    /// Non-secret fingerprint of the key named by this header.
    pub fn key_fingerprint(&self) -> KeyId {
        self.key_id
    }

    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(ENCRYPTION_HEADER_LEN);
        bytes.extend_from_slice(&ENCRYPTION_MAGIC);
        bytes.extend_from_slice(&[self.format_version, self.flags]);
        bytes.extend_from_slice(&self.key_version.to_le_bytes());
        bytes.extend_from_slice(self.key_id.as_bytes());
        debug_assert_eq!(bytes.len(), ENCRYPTION_HEADER_LEN);
        bytes.freeze()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EncryptionHeaderError> {
        if bytes.len() < ENCRYPTION_HEADER_LEN {
            return Err(EncryptionHeaderError::Truncated {
                expected: ENCRYPTION_HEADER_LEN,
                found: bytes.len(),
            });
        }

        if bytes[..ENCRYPTION_MAGIC.len()] != ENCRYPTION_MAGIC {
            return Err(EncryptionHeaderError::InvalidMagic);
        }

        let format_version = bytes[8];
        if format_version != ENCRYPTION_FORMAT_V1 {
            return Err(EncryptionHeaderError::UnsupportedVersion(
                format_version,
            ));
        }

        let flags = bytes[9];
        let mut version_bytes = [0; 4];
        version_bytes.copy_from_slice(&bytes[10..14]);
        let key_version = KeyVersion::from_le_bytes(version_bytes);

        let mut key_id = [0; 32];
        key_id.copy_from_slice(&bytes[14..ENCRYPTION_HEADER_LEN]);

        Ok(Self {
            format_version,
            flags,
            key_version,
            key_id: KeyId::from(key_id),
        })
    }
}

/// Human-facing object metadata.
///
/// This is useful when code needs to answer "is this encrypted and which key
/// generation does it use?" without exposing key material.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectMetadata {
    pub encrypted: bool,
    pub key_version: Option<KeyVersion>,
    pub key_id: Option<KeyId>,
}

impl From<EncryptionMetadata> for ObjectMetadata {
    fn from(metadata: EncryptionMetadata) -> Self {
        Self {
            encrypted: metadata.encrypted(),
            key_version: Some(metadata.key_version),
            key_id: Some(metadata.key_id),
        }
    }
}

impl ObjectMetadata {
    pub const fn unencrypted() -> Self {
        Self {
            encrypted: false,
            key_version: None,
            key_id: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EncryptionHeaderError {
    #[error(
        "truncated encryption metadata: expected {expected} bytes, found {found}"
    )]
    Truncated { expected: usize, found: usize },

    #[error("invalid encryption header magic")]
    InvalidMagic,

    #[error("unsupported encryption header version: {0}")]
    UnsupportedVersion(u8),
}

/// A storage adaptor that encrypts/decrypts all data that passes through.
pub struct Backend<S> {
    storage: S,
    keys: RwLock<KeyRing>,
}

impl<S> Backend<S> {
    /// Creates an encrypted backend with one key at version `1`.
    pub fn new(key: [u8; 32], storage: S) -> Self {
        Self::with_key_ring(KeyRing::new(key), storage)
    }

    /// Creates an encrypted backend with a complete key ring.
    pub fn with_key_ring(keys: KeyRing, storage: S) -> Self {
        Backend {
            storage,
            keys: RwLock::new(keys),
        }
    }

    /// Alias for [`Backend::with_key_ring`].
    pub fn with_keys(keys: KeyRing, storage: S) -> Self {
        Self::with_key_ring(keys, storage)
    }

    /// Creates a backend with one explicitly numbered current key.
    pub fn with_key_version(
        version: KeyVersion,
        key: [u8; 32],
        storage: S,
    ) -> Self {
        Self::with_key_ring(KeyRing::with_version(version, key), storage)
    }

    /// Creates a backend with a current key and its immediately previous key.
    pub fn with_previous_key(
        current: [u8; 32],
        previous: [u8; 32],
        storage: S,
    ) -> Self {
        let keys = KeyRing::new(current).with_previous_key(previous);
        Self::with_key_ring(keys, storage)
    }

    /// Returns a snapshot of the configured key ring.
    pub fn key_ring(&self) -> KeyRing {
        self.keys.read().expect("key ring lock poisoned").clone()
    }

    /// Replaces the key ring.
    pub fn set_key_ring(&self, keys: KeyRing) {
        *self.keys.write().expect("key ring lock poisoned") = keys;
    }

    /// Rotates to the next key version while retaining the old key according
    /// to the ring's rotation window.
    pub fn rotate_key(&self, new_key: [u8; 32]) -> KeyVersion {
        let mut keys = self.keys.write().expect("key ring lock poisoned");
        keys.rotate(new_key).version()
    }

    /// Rotates to an explicit key version.
    pub fn rotate_key_to_version(
        &self,
        version: KeyVersion,
        new_key: [u8; 32],
    ) -> KeyVersion {
        let mut keys = self.keys.write().expect("key ring lock poisoned");
        keys.rotate_with_version(version, new_key).version()
    }

    fn read_keys(&self) -> RwLockReadGuard<'_, KeyRing> {
        self.keys.read().expect("key ring lock poisoned")
    }
}

fn nonce_for(key: &StorageKey) -> [u8; 24] {
    // Use the first part of the SHA256 as the nonce.
    let mut nonce: [u8; 24] = [0; 24];
    nonce.copy_from_slice(&key.oid().bytes()[0..24]);
    nonce
}

fn xor_stream<S>(
    mut chacha: ChaCha,
    stream: S,
) -> impl Stream<Item = Result<Bytes, io::Error>>
where
    S: Stream<Item = Result<Bytes, io::Error>>,
{
    stream.map(move |bytes| {
        let mut bytes = BytesMut::from(bytes?.as_ref());

        chacha.xor_read(bytes.as_mut()).map_err(|_| {
            io::Error::other("reached end of xchacha20 keystream")
        })?;

        Ok(bytes.freeze())
    })
}

fn error_object(len: u64, error: io::Error) -> LFSObject {
    let stream = Box::pin(stream::once(async move { Err(error) }));
    LFSObject::new(len, stream)
}

#[async_trait]
impl<S> Storage for Backend<S>
where
    S: Storage + Send + Sync + 'static,
    S::Error: 'static,
{
    type Error = S::Error;

    async fn get(
        &self,
        key: &StorageKey,
    ) -> Result<Option<LFSObject>, Self::Error> {
        let Some(obj) = self.storage.get(key).await? else {
            return Ok(None);
        };

        let (physical_len, mut upstream) = obj.into_parts();

        // Read enough bytes to inspect the plaintext envelope header. The
        // header is never encrypted; only the payload after it is.
        let mut prefix = BytesMut::new();
        let mut read_error = None;
        while prefix.len() < ENCRYPTION_HEADER_LEN {
            match upstream.next().await {
                Some(Ok(chunk)) => prefix.extend_from_slice(&chunk),
                Some(Err(error)) => {
                    read_error = Some(error);
                    break;
                }
                None => break,
            }
        }

        let prefix = prefix.freeze();
        let has_magic = prefix.len() >= ENCRYPTION_MAGIC.len()
            && prefix[..ENCRYPTION_MAGIC.len()] == ENCRYPTION_MAGIC;

        let (metadata, buffered_payload, logical_len) = if has_magic {
            match EncryptionMetadata::decode(&prefix) {
                Ok(metadata) => {
                    let payload_prefix = prefix.slice(ENCRYPTION_HEADER_LEN..);
                    let logical_len = physical_len
                        .saturating_sub(ENCRYPTION_HEADER_LEN as u64);
                    (Some(metadata), payload_prefix, logical_len)
                }
                Err(error) => {
                    return Ok(Some(error_object(
                        physical_len
                            .saturating_sub(ENCRYPTION_HEADER_LEN as u64),
                        io::Error::other(error),
                    )));
                }
            }
        } else {
            // Objects written before versioned envelopes are length-preserving
            // XChaCha20 streams. Use the configured legacy key for them.
            (None, prefix, physical_len)
        };

        let prefix_stream =
            stream::iter((!buffered_payload.is_empty()).then_some(Ok::<
                Bytes,
                io::Error,
            >(
                buffered_payload,
            )));

        let payload: super::ByteStream = match read_error {
            Some(error) => Box::pin(prefix_stream.chain(
                stream::once(async move { Err(error) }).chain(upstream),
            )),
            None => Box::pin(prefix_stream.chain(upstream)),
        };

        let ring = self.read_keys();
        let secret = match metadata {
            Some(metadata) => {
                match ring.decryption_key(metadata.key_id, metadata.key_version)
                {
                    Some(key) => *key.secret(),
                    None => {
                        let error = KeyRingError::UnknownKey {
                            version: metadata.key_version,
                            key_id: metadata.key_id,
                        };
                        return Ok(Some(error_object(
                            logical_len,
                            io::Error::other(error),
                        )));
                    }
                }
            }
            None => *ring.legacy_key().secret(),
        };
        drop(ring);

        let chacha = ChaCha::new_xchacha20(&secret, &nonce_for(key));

        Ok(Some(LFSObject::new(
            logical_len,
            Box::pin(xor_stream(chacha, payload)),
        )))
    }

    async fn put(
        &self,
        key: StorageKey,
        value: LFSObject,
    ) -> Result<(), Self::Error> {
        let (metadata, secret) = {
            let ring = self.read_keys();
            let current = ring.current_key();
            (
                EncryptionMetadata::new(current.version(), current.key_id()),
                *current.secret(),
            )
        };
        let header = metadata.encode();

        let chacha = ChaCha::new_xchacha20(&secret, &nonce_for(&key));

        let (len, stream) = value.into_parts();
        let encrypted_payload = xor_stream(chacha, stream);
        let stream: super::ByteStream = Box::pin(
            stream::iter([Ok::<Bytes, io::Error>(header)])
                .chain(encrypted_payload),
        );

        self.storage
            .put(
                key,
                LFSObject::new(
                    len.saturating_add(ENCRYPTION_HEADER_LEN as u64),
                    stream,
                ),
            )
            .await
    }

    async fn size(&self, key: &StorageKey) -> Result<Option<u64>, Self::Error> {
        // Versioned envelopes have a fixed header size. Legacy headerless
        // objects have identical physical and logical lengths; callers that
        // still have such objects should retain the old key and may use
        // `get` for exact header detection during migration.
        Ok(self.storage.size(key).await?.map(|physical_len| {
            physical_len
                .checked_sub(ENCRYPTION_HEADER_LEN as u64)
                .unwrap_or(physical_len)
        }))
    }

    async fn delete(&self, key: &StorageKey) -> Result<(), Self::Error> {
        self.storage.delete(key).await
    }

    fn list(&self) -> StorageStream<(StorageKey, u64), Self::Error> {
        self.storage.list()
    }

    async fn total_size(&self) -> Option<u64> {
        self.storage.total_size().await
    }

    async fn max_size(&self) -> Option<u64> {
        self.storage.max_size().await
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
    use super::*;
    use crate::sha256::Sha256;
    use crate::storage::Namespace;
    use futures::TryStreamExt;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    use tokio::sync::Mutex;

    #[derive(Default, Clone)]
    struct MemoryStorage {
        objects: Arc<Mutex<HashMap<StorageKey, Bytes>>>,
    }

    #[async_trait]
    impl Storage for MemoryStorage {
        type Error = io::Error;

        async fn get(
            &self,
            key: &StorageKey,
        ) -> Result<Option<LFSObject>, io::Error> {
            let objects = self.objects.lock().await;
            let Some(bytes) = objects.get(key).cloned() else {
                return Ok(None);
            };
            let len = bytes.len() as u64;
            let stream = Box::pin(stream::once(async move { Ok(bytes) }));
            Ok(Some(LFSObject::new(len, stream)))
        }

        async fn put(
            &self,
            key: StorageKey,
            value: LFSObject,
        ) -> Result<(), io::Error> {
            let (_, stream) = value.into_parts();
            let bytes = stream
                .try_fold(Vec::new(), |mut accumulated, chunk| async move {
                    accumulated.extend_from_slice(&chunk);
                    Ok(accumulated)
                })
                .await?;
            self.objects.lock().await.insert(key, Bytes::from(bytes));
            Ok(())
        }

        async fn size(
            &self,
            key: &StorageKey,
        ) -> Result<Option<u64>, io::Error> {
            Ok(self
                .objects
                .lock()
                .await
                .get(key)
                .map(|bytes| bytes.len() as u64))
        }

        async fn delete(&self, key: &StorageKey) -> Result<(), io::Error> {
            self.objects.lock().await.remove(key);
            Ok(())
        }

        fn list(&self) -> StorageStream<(StorageKey, u64), io::Error> {
            Box::pin(stream::empty())
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

    fn test_key(byte: u8) -> StorageKey {
        StorageKey::new(
            Namespace::new("org".into(), "project".into()),
            Sha256::from([byte; 32]),
        )
    }

    async fn read_all(object: LFSObject) -> io::Result<Vec<u8>> {
        let (_, stream) = object.into_parts();
        stream
            .try_fold(Vec::new(), |mut accumulated, chunk| async move {
                accumulated.extend_from_slice(&chunk);
                Ok(accumulated)
            })
            .await
    }

    #[test]
    fn metadata_records_version_and_fingerprint_not_secret() {
        let secret = [0x42; 32];
        let id = KeyId::from_secret(&secret);
        let metadata = EncryptionMetadata::new(7, id);

        let encoded = metadata.encode();
        let decoded = EncryptionMetadata::decode(&encoded).unwrap();

        assert_eq!(decoded.key_version, 7);
        assert_eq!(decoded.key_id, id);
        assert!(decoded.encrypted());
        assert!(!encoded.windows(32).any(|window| window == secret));
        assert!(encoded.windows(32).any(|window| window == id.as_bytes()));
    }

    #[test]
    fn rotation_window_keeps_old_key_for_seven_days() {
        let issued =
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let old_key = [1; 32];
        let new_key = [2; 32];

        let mut ring = KeyRing::with_version_at(1, old_key, issued);
        ring.rotate_at(2, new_key, issued + Duration::from_secs(10));

        assert_eq!(ring.current_version(), 2);
        assert!(ring.get_version(1).is_some());
        assert!(ring.within_rotation_window_at(
            issued + Duration::from_secs(10 + 7 * 24 * 60 * 60)
        ));

        let mut expired = ring.clone();
        assert!(expired.expire_rotation_window_at(
            issued + Duration::from_secs(11 + 7 * 24 * 60 * 60)
        ));
        assert!(expired.get_version(1).is_none());
        assert_eq!(expired.current_version(), 2);
    }

    #[tokio::test]
    async fn rotates_key_and_still_reads_old_object() {
        let backend = Backend::new([1; 32], MemoryStorage::default());
        let old_storage_key = test_key(10);
        let new_storage_key = test_key(20);
        let old_plaintext = b"old object payload";
        let new_plaintext = b"new object payload";

        backend
            .put(
                old_storage_key.clone(),
                LFSObject::new(
                    old_plaintext.len() as u64,
                    Box::pin(stream::once(async move {
                        Ok(Bytes::from_static(old_plaintext))
                    })),
                ),
            )
            .await
            .unwrap();

        assert_eq!(backend.rotate_key([2; 32]), 2);

        backend
            .put(
                new_storage_key.clone(),
                LFSObject::new(
                    new_plaintext.len() as u64,
                    Box::pin(stream::once(async move {
                        Ok(Bytes::from_static(new_plaintext))
                    })),
                ),
            )
            .await
            .unwrap();

        assert_eq!(
            backend.size(&old_storage_key).await.unwrap(),
            Some(old_plaintext.len() as u64)
        );
        assert_eq!(
            backend.size(&new_storage_key).await.unwrap(),
            Some(new_plaintext.len() as u64)
        );

        let old_object = backend.get(&old_storage_key).await.unwrap().unwrap();
        assert_eq!(read_all(old_object).await.unwrap(), old_plaintext);

        let new_object = backend.get(&new_storage_key).await.unwrap().unwrap();
        assert_eq!(read_all(new_object).await.unwrap(), new_plaintext);
    }

    #[tokio::test]
    async fn restarted_backend_can_use_configured_previous_key() {
        let memory = MemoryStorage::default();
        let key = test_key(30);
        let plaintext = b"persisted across server restarts";

        let writer = Backend::new([9; 32], memory.clone());
        writer
            .put(
                key.clone(),
                LFSObject::new(
                    plaintext.len() as u64,
                    Box::pin(stream::once(async move {
                        Ok(Bytes::from_static(plaintext))
                    })),
                ),
            )
            .await
            .unwrap();

        let ring = KeyRing::with_version(2, [10; 32])
            .with_key(1, [9; 32])
            .with_legacy_version(1)
            .unwrap();
        let reader = Backend::with_key_ring(ring, memory);

        let object = reader.get(&key).await.unwrap().unwrap();
        assert_eq!(read_all(object).await.unwrap(), plaintext);
    }

    #[tokio::test]
    async fn unknown_key_is_reported_as_key_error() {
        let memory = MemoryStorage::default();
        let key = test_key(40);

        let writer = Backend::new([1; 32], memory.clone());
        writer
            .put(
                key.clone(),
                LFSObject::new(
                    5,
                    Box::pin(stream::once(async {
                        Ok(Bytes::from_static(b"hello"))
                    })),
                ),
            )
            .await
            .unwrap();

        let reader = Backend::new([2; 32], memory);
        let object = reader.get(&key).await.unwrap().unwrap();
        let error = read_all(object).await.unwrap_err();
        assert!(error.to_string().contains("not configured"));
    }
}
