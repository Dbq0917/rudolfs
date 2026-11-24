use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Numeric key generation stored in encrypted object metadata.
pub type KeyVersion = u32;

/// Keys issued before this overlap remain available for decryption.
pub const ROTATION_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Alias used by callers that prefer the "rotation window" terminology.
pub const DEFAULT_ROTATION_WINDOW: Duration = ROTATION_WINDOW;

/// Non-secret identifier for a key.
///
/// The identifier is the SHA-256 digest of the raw key. It lets an object
/// name the key needed to decrypt it without storing the key itself.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct KeyId([u8; 32]);

impl KeyId {
    /// Computes the non-secret identifier for a 32-byte key.
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        KeyId(Sha256::digest(secret).into())
    }

    /// Alias for [`KeyId::from_secret`].
    pub fn from_key(secret: &[u8; 32]) -> Self {
        Self::from_secret(secret)
    }

    /// Returns the raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the identifier as lowercase hexadecimal.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// A non-secret fingerprint used to identify a key version.
pub type KeyFingerprint = KeyId;

impl From<[u8; 32]> for KeyId {
    fn from(bytes: [u8; 32]) -> Self {
        KeyId(bytes)
    }
}

impl FromStr for KeyId {
    type Err = hex::FromHexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes)?;
        Ok(KeyId(bytes))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyId").field(&self.to_hex()).finish()
    }
}

impl Serialize for KeyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            KeyId::from_str(&value).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; 32]>::deserialize(deserializer)?;
            Ok(KeyId(bytes))
        }
    }
}

/// A key together with its version and non-secret identifier.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VersionedKey {
    version: KeyVersion,
    id: KeyId,
    secret: [u8; 32],
    created_at: SystemTime,
}

impl VersionedKey {
    /// Creates a versioned key stamped with the current time.
    pub fn new(version: KeyVersion, secret: [u8; 32]) -> Self {
        Self::at(version, secret, SystemTime::now())
    }

    /// Creates a versioned key with an explicit issue time.
    pub fn at(
        version: KeyVersion,
        secret: [u8; 32],
        created_at: SystemTime,
    ) -> Self {
        Self {
            version,
            id: KeyId::from_secret(&secret),
            secret,
            created_at,
        }
    }

    pub const fn version(&self) -> KeyVersion {
        self.version
    }

    pub const fn key_id(&self) -> KeyId {
        self.id
    }

    pub const fn id(&self) -> KeyId {
        self.id
    }

    pub fn fingerprint(&self) -> KeyId {
        self.id
    }

    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Returns the secret key material.
    ///
    /// This is intentionally not exposed through [`fmt::Debug`].
    pub const fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub const fn key(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl fmt::Debug for VersionedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionedKey")
            .field("version", &self.version)
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Errors returned when selecting a decryption key.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KeyRingError {
    #[error("encryption key version {version} ({key_id}) is not configured")]
    UnknownKey { version: KeyVersion, key_id: KeyId },
}

/// All known encryption keys and the key currently used for new objects.
#[derive(Clone, Debug)]
pub struct KeyRing {
    keys: BTreeMap<KeyId, VersionedKey>,
    versions: BTreeMap<KeyVersion, KeyId>,
    current: KeyId,
    legacy: Option<KeyId>,
    rotated_at: Option<SystemTime>,
    rotation_window: Duration,
}

/// Alternative name for a key ring.
pub type KeyManager = KeyRing;

/// Alternative name for a key ring.
pub type Keychain = KeyRing;

impl KeyRing {
    /// Creates a ring whose first key is version `1`.
    pub fn new(current: [u8; 32]) -> Self {
        Self::with_version(1, current)
    }

    /// Creates a ring with an explicit current key version.
    pub fn with_version(version: KeyVersion, current: [u8; 32]) -> Self {
        Self::with_version_at(version, current, SystemTime::now())
    }

    /// Creates a ring with an explicit current key version and issue time.
    pub fn with_version_at(
        version: KeyVersion,
        current: [u8; 32],
        created_at: SystemTime,
    ) -> Self {
        let key = VersionedKey::at(version, current, created_at);
        let mut keys = BTreeMap::new();
        let mut versions = BTreeMap::new();
        keys.insert(key.id, key);
        versions.insert(version, key.id);

        Self {
            current: key.id,
            keys,
            versions,
            legacy: None,
            rotated_at: None,
            rotation_window: ROTATION_WINDOW,
        }
    }

    /// Creates a builder for rings with several configured versions.
    pub fn builder() -> KeyRingBuilder {
        KeyRingBuilder::default()
    }

    /// Adds another key version, keeping the current write key unchanged.
    pub fn with_key(mut self, version: KeyVersion, secret: [u8; 32]) -> Self {
        self.add(version, secret);
        self
    }

    /// Adds another key version issued at an explicit time.
    pub fn with_key_at(
        mut self,
        version: KeyVersion,
        secret: [u8; 32],
        created_at: SystemTime,
    ) -> Self {
        let key = VersionedKey::at(version, secret, created_at);
        self.insert(key);
        self
    }

    /// Supplies the key used for old length-preserving objects without an
    /// envelope header.
    pub fn with_legacy_key(mut self, secret: [u8; 32]) -> Self {
        let id = KeyId::from_secret(&secret);
        if !self.keys.contains_key(&id) {
            let version = self.next_version();
            let key = VersionedKey::new(version, secret);
            self.insert(key);
        }
        self.legacy = Some(id);
        self
    }

    /// Selects a configured version as the key for legacy headerless objects.
    pub fn with_legacy_version(
        mut self,
        version: KeyVersion,
    ) -> Result<Self, KeyRingError> {
        let id = self.required_version_id(version)?;
        self.legacy = Some(id);
        Ok(self)
    }

    /// Adds the previous key to a ring already containing the new key.
    ///
    /// If the current key is version `1`, it is renumbered to version `2` so
    /// that the supplied previous key can be version `1`.
    pub fn with_previous_key(mut self, previous: [u8; 32]) -> Self {
        let current = *self.current_key();
        if current.version == 1 && self.versions.len() == 1 {
            let renumbered =
                VersionedKey::at(2, *current.secret(), current.created_at);
            self.keys.remove(&current.id);
            self.versions.remove(&1);
            self.insert(renumbered);
        }

        let previous_version = if self.versions.contains_key(&1) {
            self.versions
                .keys()
                .copied()
                .filter(|version| *version != self.current_version())
                .min()
                .unwrap_or(1)
        } else {
            1
        };

        let old = VersionedKey::new(previous_version, previous);
        self.insert(old);
        self.legacy = Some(old.id);
        self.rotated_at = Some(SystemTime::now());
        self
    }

    /// Alias for [`KeyRing::with_previous_key`].
    pub fn with_old_key(self, old: [u8; 32]) -> Self {
        self.with_previous_key(old)
    }

    /// Returns the number of configured keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns whether the ring is empty. A valid ring always has a current key.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Overrides the overlap window. The default is seven days.
    pub const fn with_rotation_window(mut self, window: Duration) -> Self {
        self.rotation_window = window;
        self
    }

    /// Inserts or replaces a key version.
    pub fn add(
        &mut self,
        version: KeyVersion,
        secret: [u8; 32],
    ) -> VersionedKey {
        let key = VersionedKey::new(version, secret);
        self.insert(key);
        key
    }

    fn insert(&mut self, key: VersionedKey) {
        self.keys.insert(key.id, key);
        self.versions.insert(key.version, key.id);
    }

    fn required_version_id(
        &self,
        version: KeyVersion,
    ) -> Result<KeyId, KeyRingError> {
        self.versions
            .get(&version)
            .copied()
            .ok_or(KeyRingError::UnknownKey {
                version,
                key_id: KeyId([0; 32]),
            })
    }

    /// Returns the key used for new objects.
    pub fn current_key(&self) -> &VersionedKey {
        self.keys
            .get(&self.current)
            .expect("key ring current key is always present")
    }

    pub fn current_version(&self) -> KeyVersion {
        self.current_key().version
    }

    pub const fn rotation_window(&self) -> Duration {
        self.rotation_window
    }

    pub const fn rotated_at(&self) -> Option<SystemTime> {
        self.rotated_at
    }

    /// Returns the next unused numeric version.
    pub fn next_version(&self) -> KeyVersion {
        self.versions
            .keys()
            .next_back()
            .copied()
            .map(|version| version.saturating_add(1))
            .unwrap_or(1)
    }

    /// Rotates to a new key using the next numeric version.
    pub fn rotate(&mut self, secret: [u8; 32]) -> VersionedKey {
        let version = self.next_version();
        self.rotate_at(version, secret, SystemTime::now())
    }

    /// Rotates to an explicit new version at the current time.
    pub fn rotate_with_version(
        &mut self,
        version: KeyVersion,
        secret: [u8; 32],
    ) -> VersionedKey {
        self.rotate_at(version, secret, SystemTime::now())
    }

    /// Rotates to a new key with an explicit rotation timestamp.
    pub fn rotate_at(
        &mut self,
        version: KeyVersion,
        secret: [u8; 32],
        rotated_at: SystemTime,
    ) -> VersionedKey {
        let previous = self.current;
        let key = VersionedKey::at(version, secret, rotated_at);
        self.insert(key);
        self.current = key.id;
        self.legacy.get_or_insert(previous);
        self.rotated_at = Some(rotated_at);
        key
    }

    pub fn get(&self, id: &KeyId) -> Option<&VersionedKey> {
        self.keys.get(id)
    }

    pub fn get_version(&self, version: KeyVersion) -> Option<&VersionedKey> {
        self.versions.get(&version).and_then(|id| self.keys.get(id))
    }

    /// Finds a key from object metadata.
    ///
    /// The fingerprint is authoritative when present. Falling back to the
    /// version keeps version-only metadata usable in tests and migrations.
    pub fn decryption_key(
        &self,
        key_id: KeyId,
        version: KeyVersion,
    ) -> Option<&VersionedKey> {
        if let Some(key) = self.keys.get(&key_id) {
            return Some(key);
        }

        // Allow version-only metadata, represented by the zero identifier.
        // Never substitute a different key for a non-zero fingerprint merely
        // because it reuses the same numeric version.
        if key_id == KeyId([0; 32]) {
            return self.get_version(version);
        }

        None
    }

    /// Returns the key for old headerless objects.
    pub fn legacy_key(&self) -> &VersionedKey {
        if let Some(id) = self.legacy
            && let Some(key) = self.keys.get(&id)
        {
            return key;
        }

        // Headerless objects predate explicit key identifiers. When no legacy
        // key is explicitly selected, use the oldest configured generation.
        self.versions
            .values()
            .next()
            .and_then(|id| self.keys.get(id))
            .unwrap_or_else(|| self.current_key())
    }

    /// Whether the rotation overlap is still active at `now`.
    pub fn within_rotation_window_at(&self, now: SystemTime) -> bool {
        match self.rotated_at {
            Some(rotated_at) => now
                .duration_since(rotated_at)
                .map(|age| age <= self.rotation_window)
                .unwrap_or(true),
            None => true,
        }
    }

    pub fn within_rotation_window(&self) -> bool {
        self.within_rotation_window_at(SystemTime::now())
    }

    /// Forgets non-current keys once the seven-day overlap has elapsed.
    ///
    /// Keys explicitly retained by the operator can still be kept in a
    /// newly constructed ring; this method only applies the rotation policy.
    pub fn expire_rotation_window_at(&mut self, now: SystemTime) -> bool {
        if self.within_rotation_window_at(now) {
            return false;
        }

        let current = self.current;
        self.keys.retain(|id, _| *id == current);
        self.versions.retain(|_, id| *id == current);
        self.legacy = None;
        true
    }

    pub fn expire_rotation_window(&mut self) -> bool {
        self.expire_rotation_window_at(SystemTime::now())
    }
}

/// Builder for [`KeyRing`].
#[derive(Clone, Debug, Default)]
pub struct KeyRingBuilder {
    keys: Vec<(KeyVersion, [u8; 32])>,
    current: Option<KeyVersion>,
    legacy: Option<KeyVersion>,
    rotation_window: Option<Duration>,
}

impl KeyRingBuilder {
    pub fn key(mut self, version: KeyVersion, secret: [u8; 32]) -> Self {
        self.keys.push((version, secret));
        self
    }

    pub fn current_key(
        mut self,
        version: KeyVersion,
        secret: [u8; 32],
    ) -> Self {
        self.current = Some(version);
        self.key(version, secret)
    }

    pub fn previous_key(self, secret: [u8; 32]) -> Self {
        self.key(1, secret)
    }

    pub fn legacy_version(mut self, version: KeyVersion) -> Self {
        self.legacy = Some(version);
        self
    }

    pub fn rotation_window(mut self, window: Duration) -> Self {
        self.rotation_window = Some(window);
        self
    }

    pub fn build(self) -> Result<KeyRing, KeyRingError> {
        let current_version = self
            .current
            .or_else(|| self.keys.last().map(|(version, _)| *version))
            .ok_or(KeyRingError::UnknownKey {
                version: 0,
                key_id: KeyId([0; 32]),
            })?;

        let current_secret = self
            .keys
            .iter()
            .rev()
            .find(|(version, _)| *version == current_version)
            .map(|(_, secret)| *secret)
            .ok_or(KeyRingError::UnknownKey {
                version: current_version,
                key_id: KeyId([0; 32]),
            })?;

        let mut ring = KeyRing::with_version(current_version, current_secret);
        for (version, secret) in self
            .keys
            .into_iter()
            .filter(|(version, _)| *version != current_version)
        {
            ring.add(version, secret);
        }

        if let Some(legacy) = self.legacy {
            ring = ring.with_legacy_version(legacy)?;
        }
        if let Some(window) = self.rotation_window {
            ring.rotation_window = window;
        }
        Ok(ring)
    }
}
