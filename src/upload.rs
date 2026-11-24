use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, Weak};

use hyper::{HeaderMap, Uri};
use sha2::{Digest, Sha256};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncWriteExt, copy};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::storage::StorageKey;

const OFFSET_HEADERS: &[&str] = &[
    "upload-offset",
    "x-upload-offset",
    "x-lfs-upload-offset",
    "x-lfs-offset",
    "x-offset",
];

const LENGTH_HEADERS: &[&str] = &[
    "upload-length",
    "x-upload-length",
    "x-lfs-upload-length",
    "x-object-size",
    "x-file-size",
    "x-total-length",
];

/// Describes a single chunk of a resumable upload.
#[derive(Clone, Copy, Debug)]
pub struct ChunkSpec {
    /// Offset of the first byte in this chunk.
    pub offset: u64,

    /// Offset of the last byte in this chunk, if known.
    pub end: Option<u64>,

    /// Total size of the complete object, if known.
    pub total: Option<u64>,

    /// Explicitly marks this chunk as the last one.
    pub complete: bool,
}

impl ChunkSpec {
    /// Returns the expected number of bytes in this chunk, if known.
    pub fn len(&self) -> Option<u64> {
        self.end.map(|end| end - self.offset + 1)
    }

    /// Parses a resumable chunk request from its headers and query string.
    ///
    /// Returns `Ok(None)` for a regular (non-chunked) upload.
    pub fn parse(
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<Option<Self>, String> {
        let mut offset = None;
        let mut end = None;
        let mut total = None;
        let mut complete = false;
        let mut is_chunked = false;

        if let Some(value) = header_value(headers, "content-range")
            .or_else(|| header_value(headers, "x-content-range"))
            && let Some((start, last, size)) = parse_content_range(value)?
        {
            is_chunked = true;
            set_value(&mut offset, start, "offset")?;
            end = last;

            if let Some(size) = size {
                set_value(&mut total, size, "total length")?;
            }
        }

        if let Some(value) = header_u64(headers, OFFSET_HEADERS)? {
            is_chunked = true;
            set_value(&mut offset, value, "offset")?;
        }

        if let Some(value) = header_u64(headers, LENGTH_HEADERS)? {
            is_chunked = true;
            set_value(&mut total, value, "total length")?;
        }

        for name in [
            "upload-complete",
            "x-upload-complete",
            "x-last-chunk",
            "last-chunk",
        ] {
            if let Some(value) = header_value(headers, name) {
                let value = value.trim().trim_start_matches('?');
                complete = parse_bool(value)?;
                is_chunked |= complete;
                break;
            }
        }

        if let Some(value) = header_value(headers, "range")
            && let Some((start, last)) = parse_range(value)?
            && offset.is_none()
        {
            is_chunked = true;
            offset = Some(start);
            end = last;
        }

        if let Some(value) = query_value(uri, &["offset", "start"])? {
            is_chunked = true;
            set_value(&mut offset, value, "offset")?;
        }

        if let Some(value) = query_value(uri, &["total", "size", "length"])? {
            is_chunked = true;
            set_value(&mut total, value, "total length")?;
        }

        if let Some(value) = query_raw(uri, &["complete", "final", "last"])? {
            complete = parse_bool(value)?;
            is_chunked |= complete;
        }

        if !is_chunked {
            return Ok(None);
        }

        let offset = offset.unwrap_or(0);

        if let Some(end) = end
            && end < offset
        {
            return Err(format!(
                "invalid chunk range: end ({end}) is before offset ({offset})"
            ));
        }

        if let (Some(end), Some(total)) = (end, total)
            && end >= total
        {
            return Err(format!(
                "invalid chunk range: end ({end}) is outside object size \
                 ({total})"
            ));
        }

        if let Some(total) = total
            && offset > total
        {
            return Err(format!(
                "invalid chunk offset: offset ({offset}) is outside object \
                 size ({total})"
            ));
        }

        Ok(Some(ChunkSpec {
            offset,
            end,
            total,
            complete,
        }))
    }
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn header_u64(
    headers: &HeaderMap,
    names: &[&str],
) -> Result<Option<u64>, String> {
    for name in names {
        if let Some(value) = headers.get(*name) {
            let value = value
                .to_str()
                .map_err(|_| format!("invalid {name} header"))?
                .trim()
                .trim_matches('"');

            return value
                .parse()
                .map(Some)
                .map_err(|_| format!("invalid {name} header: {value}"));
        }
    }

    Ok(None)
}

fn query_value(uri: &Uri, names: &[&str]) -> Result<Option<u64>, String> {
    match query_raw(uri, names)? {
        Some(value) => value.parse().map(Some).map_err(|_| {
            format!("invalid numeric query parameter value: {value}")
        }),
        None => Ok(None),
    }
}

fn query_raw<'a>(
    uri: &'a Uri,
    names: &[&str],
) -> Result<Option<&'a str>, String> {
    let Some(query) = uri.query() else {
        return Ok(None);
    };

    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));

        if names.contains(&name) {
            if value.is_empty() {
                return Err(format!(
                    "missing value for query parameter {name}"
                ));
            }

            return Ok(Some(value));
        }
    }

    Ok(None)
}

fn parse_bool(value: impl AsRef<str>) -> Result<bool, String> {
    match value.as_ref().trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "final" | "complete" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        value => Err(format!("invalid boolean value: {value}")),
    }
}

fn set_value(
    slot: &mut Option<u64>,
    value: u64,
    name: &str,
) -> Result<(), String> {
    match slot {
        Some(existing) if *existing != value => {
            Err(format!("conflicting {name} values: {existing} and {value}"))
        }
        _ => {
            *slot = Some(value);
            Ok(())
        }
    }
}

type ParsedContentRange = (u64, Option<u64>, Option<u64>);

fn parse_content_range(
    value: &str,
) -> Result<Option<ParsedContentRange>, String> {
    let value = value.trim();
    let value = value
        .strip_prefix("bytes ")
        .or_else(|| value.strip_prefix("bytes="))
        .unwrap_or(value);

    if value.starts_with("*/") {
        return Ok(None);
    }

    let (range, total) = value.split_once('/').unwrap_or((value, "*"));

    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| format!("invalid Content-Range header: {value}"))?;

    let start = start
        .trim()
        .parse()
        .map_err(|_| format!("invalid Content-Range start: {start}"))?;

    let end = if end.trim().is_empty() {
        None
    } else {
        Some(
            end.trim()
                .parse()
                .map_err(|_| format!("invalid Content-Range end: {end}"))?,
        )
    };

    let total = if total.trim() == "*" {
        None
    } else {
        Some(
            total
                .trim()
                .parse()
                .map_err(|_| format!("invalid Content-Range total: {total}"))?,
        )
    };

    Ok(Some((start, end, total)))
}

fn parse_range(value: &str) -> Result<Option<(u64, Option<u64>)>, String> {
    let value = value.trim();
    let value = value
        .strip_prefix("bytes=")
        .or_else(|| value.strip_prefix("bytes "))
        .unwrap_or(value);

    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| format!("invalid Range header: {value}"))?;

    let start = start
        .trim()
        .parse()
        .map_err(|_| format!("invalid Range start: {start}"))?;

    let end = if end.trim().is_empty() {
        None
    } else {
        Some(
            end.trim()
                .parse()
                .map_err(|_| format!("invalid Range end: {end}"))?,
        )
    };

    Ok(Some((start, end)))
}

/// Tracks in-progress resumable uploads and serializes commits per object.
pub struct Uploads {
    dir: PathBuf,
    locks: StdMutex<HashMap<StorageKey, Weak<Mutex<()>>>>,
}

impl Uploads {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rudolfs-uploads-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));

        Self::with_dir(dir)
    }

    pub fn with_dir(dir: PathBuf) -> Self {
        Uploads {
            dir,
            locks: StdMutex::new(HashMap::new()),
        }
    }

    /// Gets the lock used to serialize commits for an object.
    ///
    /// Weak references are used so that completed uploads do not leak a lock
    /// for every object ever uploaded.
    pub fn lock(&self, key: &StorageKey) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().unwrap();

        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return lock;
        }

        let lock = Arc::new(Mutex::new(()));
        locks.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }

    /// Creates a temporary file to receive one request body.
    pub async fn create_chunk(&self) -> io::Result<(PathBuf, File)> {
        self.ensure_dir().await?;

        let path = self.dir.join(format!("{}.chunk", Uuid::new_v4()));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await?;

        Ok((path, file))
    }

    /// Gets the current committed offset of an object.
    ///
    /// A partial file is authoritative while an upload is in progress. Once it
    /// is finalized, the size of the stored object is authoritative.
    pub async fn current_offset(
        &self,
        key: &StorageKey,
        stored_size: Option<u64>,
    ) -> io::Result<u64> {
        match fs::metadata(self.part_path(key)).await {
            Ok(metadata) => Ok(metadata.len()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                Ok(stored_size.unwrap_or(0))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn has_partial(&self, key: &StorageKey) -> io::Result<bool> {
        match fs::metadata(self.part_path(key)).await {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Appends a fully received chunk to the partial object.
    ///
    /// If the append fails, the partial object is truncated back to its
    /// previous length so that a client can safely retry from that offset.
    pub async fn append(
        &self,
        key: &StorageKey,
        expected_offset: u64,
        chunk: &Path,
    ) -> io::Result<u64> {
        self.ensure_dir().await?;

        let part = self.part_path(key);
        let mut dst = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&part)
            .await?;

        let current = dst.metadata().await?.len();
        if current != expected_offset {
            return Err(io::Error::other(format!(
                "offset mismatch: expected {expected_offset}, found {current}"
            )));
        }

        let mut src = File::open(chunk).await?;

        match copy(&mut src, &mut dst).await {
            Ok(_) => {
                dst.flush().await?;
                Ok(dst.metadata().await?.len())
            }
            Err(err) => {
                let _ = dst.set_len(current).await;
                Err(err)
            }
        }
    }

    /// Truncates a partial upload back to a known good offset.
    pub async fn truncate(
        &self,
        key: &StorageKey,
        offset: u64,
    ) -> io::Result<()> {
        if offset == 0 {
            return self.remove_partial(key).await;
        }

        let part = self.part_path(key);
        let file = OpenOptions::new().write(true).open(part).await?;
        file.set_len(offset).await
    }

    /// Opens a completed partial upload for committing to storage.
    pub async fn open_partial(
        &self,
        key: &StorageKey,
    ) -> io::Result<Option<File>> {
        match File::open(self.part_path(key)).await {
            Ok(file) => Ok(Some(file)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn remove_chunk(&self, chunk: &Path) {
        let _ = fs::remove_file(chunk).await;
    }

    pub async fn remove_partial(&self, key: &StorageKey) -> io::Result<()> {
        fs::remove_file(self.part_path(key)).await.or_else(|err| {
            match err.kind() {
                io::ErrorKind::NotFound => Ok(()),
                _ => Err(err),
            }
        })
    }

    async fn ensure_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.dir).await
    }

    fn part_path(&self, key: &StorageKey) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(key.to_string().as_bytes());
        let digest = hex::encode(hasher.finalize());

        self.dir.join(format!("{digest}.part"))
    }
}

impl Drop for Uploads {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_range() {
        let uri: Uri = "/api/org/project/object/abc".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-range", "bytes 10-19/100".parse().unwrap());

        let spec = ChunkSpec::parse(&uri, &headers).unwrap().unwrap();
        assert_eq!(spec.offset, 10);
        assert_eq!(spec.end, Some(19));
        assert_eq!(spec.total, Some(100));
        assert_eq!(spec.len(), Some(10));
    }

    #[test]
    fn parses_upload_offset() {
        let uri: Uri = "/api/org/project/object/abc".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("upload-offset", "20".parse().unwrap());
        headers.insert("upload-length", "100".parse().unwrap());

        let spec = ChunkSpec::parse(&uri, &headers).unwrap().unwrap();
        assert_eq!(spec.offset, 20);
        assert_eq!(spec.total, Some(100));
    }

    #[test]
    fn rejects_conflicting_offsets() {
        let uri: Uri = "/api/org/project/object/abc?offset=30".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-range", "bytes 10-19/100".parse().unwrap());

        assert!(ChunkSpec::parse(&uri, &headers).is_err());
    }
}
