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
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use core::task::{Context, Poll};

use askama::Template;
use futures::{
    future::{self, BoxFuture},
    stream::TryStreamExt,
};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

use hyper::{
    self, HeaderMap, Method, Request, Response, StatusCode, Uri, body::Body,
    header, service::Service,
};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::hyperext::RequestExt;
use crate::lfs;
use crate::storage::{ByteStream, LFSObject, Namespace, Storage, StorageKey};
use crate::upload::{ChunkSpec, Uploads};
use std::time::Duration;

const UPLOAD_EXPIRATION: Duration = Duration::from_secs(30 * 60);

async fn from_json<T>(mut body: Body) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    let mut buf = Vec::new();

    while let Some(chunk) = body.try_next().await? {
        buf.extend(chunk);
    }

    Ok(serde_json::from_slice(&buf)?)
}

fn into_json<T>(value: &T) -> Result<Body, Error>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec_pretty(value)?;
    Ok(bytes.into())
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    title: &'a str,
    api: Uri,
}

#[derive(Clone)]
pub struct App<S> {
    storage: S,
    uploads: Arc<Uploads>,
}

impl<S> App<S> {
    #[allow(dead_code)]
    pub fn new(storage: S) -> Self {
        App {
            storage,
            uploads: Arc::new(Uploads::new()),
        }
    }

    pub fn with_uploads(storage: S, uploads: Arc<Uploads>) -> Self {
        App { storage, uploads }
    }
}

impl<S> App<S>
where
    S: Storage + Send + Sync,
    S::Error: Into<Error>,
    Error: From<S::Error>,
{
    /// Handles the index route.
    fn index(req: Request<Body>) -> Result<Response<Body>, Error> {
        let template = IndexTemplate {
            title: "Rudolfs",
            api: req.base_uri().path_and_query("/api").build().unwrap(),
        };

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html")
            .body(template.render()?.into())?)
    }

    /// Generates a "404 not found" response.
    fn not_found(_req: Request<Body>) -> Result<Response<Body>, Error> {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("Not found".into())?)
    }

    /// Handles `/api` routes.
    async fn api(
        storage: S,
        uploads: Arc<Uploads>,
        req: Request<Body>,
    ) -> Result<Response<Body>, Error> {
        let mut parts = req.uri().path().split('/').filter(|s| !s.is_empty());

        // Skip over the '/api' part.
        assert_eq!(parts.next(), Some("api"));

        // Extract the namespace.
        let namespace = match (parts.next(), parts.next()) {
            (Some(org), Some(project)) => {
                Namespace::new(org.into(), project.into())
            }
            _ => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Missing org/project in URL"))?);
            }
        };

        match parts.next() {
            Some("object") => {
                // Upload or download a single object.
                let oid = parts.next().and_then(|x| x.parse::<lfs::Oid>().ok());
                let oid = match oid {
                    Some(oid) => oid,
                    None => {
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from("Missing OID parameter."))?);
                    }
                };

                let key = StorageKey::new(namespace, oid);

                match *req.method() {
                    Method::GET => Self::download(storage, req, key).await,
                    Method::HEAD => {
                        Self::upload_status(storage, uploads, key).await
                    }
                    Method::PUT | Method::PATCH => {
                        Self::upload(storage, uploads, req, key).await
                    }
                    _ => Self::not_found(req),
                }
            }
            Some("objects") => match (req.method(), parts.next()) {
                (&Method::POST, Some("batch")) => {
                    Self::batch(storage, req, namespace).await
                }
                (&Method::POST, Some("verify")) => {
                    Self::verify(storage, req, namespace).await
                }
                _ => Self::not_found(req),
            },
            _ => Self::not_found(req),
        }
    }

    /// Downloads a single LFS object.
    async fn download(
        storage: S,
        _req: Request<Body>,
        key: StorageKey,
    ) -> Result<Response<Body>, Error> {
        if let Some(object) = storage.get(&key).await? {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, object.len())
                .body(Body::wrap_stream(object.stream()))?)
        } else {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())?)
        }
    }

    /// Uploads a single LFS object.
    async fn upload(
        storage: S,
        uploads: Arc<Uploads>,
        req: Request<Body>,
        key: StorageKey,
    ) -> Result<Response<Body>, Error> {
        let spec = match ChunkSpec::parse(req.uri(), req.headers()) {
            Ok(Some(spec)) => spec,
            Ok(None) => return Self::upload_whole(storage, req, key).await,
            Err(err) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(err))?);
            }
        };

        Self::upload_chunk(storage, uploads, req, key, spec).await
    }

    /// Uploads a complete LFS object in a single request.
    async fn upload_whole(
        storage: S,
        req: Request<Body>,
        key: StorageKey,
    ) -> Result<Response<Body>, Error> {
        let len = req
            .headers()
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let len = match len {
            Some(len) => len,
            None => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Invalid Content-Length header."))
                    .map_err(Into::into);
            }
        };

        // Verify the SHA256 of the uploaded object as it is being uploaded.
        let stream = req.into_body().map_err(io::Error::other);

        let object = LFSObject::new(len, Box::pin(stream));

        storage.put(key, object).await?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())?)
    }

    /// Receives one chunk of a resumable upload and commits it if its offset
    /// still matches the server's committed offset.
    async fn upload_chunk(
        storage: S,
        uploads: Arc<Uploads>,
        req: Request<Body>,
        key: StorageKey,
        spec: ChunkSpec,
    ) -> Result<Response<Body>, Error> {
        let (chunk_path, mut chunk_file) = uploads.create_chunk().await?;
        let mut received = 0u64;
        let mut body = req.into_body().map_err(io::Error::other);

        loop {
            let bytes = match body.try_next().await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => break,
                Err(err) => {
                    drop(chunk_file);
                    uploads.remove_chunk(&chunk_path).await;
                    return Err(err.into());
                }
            };

            if let Err(err) = chunk_file.write_all(&bytes).await {
                drop(chunk_file);
                uploads.remove_chunk(&chunk_path).await;
                return Err(err.into());
            }

            received += bytes.len() as u64;
        }

        if let Err(err) = chunk_file.flush().await {
            drop(chunk_file);
            uploads.remove_chunk(&chunk_path).await;
            return Err(err.into());
        }

        drop(chunk_file);

        if let Some(expected) = spec.len()
            && received != expected
        {
            uploads.remove_chunk(&chunk_path).await;
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!(
                    "invalid chunk length: expected {expected}, got {received}"
                )))?);
        }

        let lock = uploads.lock(&key);
        let _guard = lock.lock().await;

        let has_partial = uploads.has_partial(&key).await?;
        let stored_size = if has_partial {
            None
        } else {
            storage.size(&key).await?
        };

        let current = uploads.current_offset(&key, stored_size).await?;

        if spec.offset != current {
            uploads.remove_chunk(&chunk_path).await;
            return offset_conflict(spec.offset, current);
        }

        let new_offset = match current.checked_add(received) {
            Some(offset) => offset,
            None => {
                uploads.remove_chunk(&chunk_path).await;
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("upload length overflow"))?);
            }
        };

        if let Some(total) = spec.total
            && new_offset > total
        {
            uploads.remove_chunk(&chunk_path).await;
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!(
                    "chunk exceeds object size: offset={new_offset}, \
                     size={total}"
                )))?);
        }

        let new_offset = match uploads.append(&key, current, &chunk_path).await
        {
            Ok(offset) => offset,
            Err(err) => {
                uploads.remove_chunk(&chunk_path).await;
                return Err(err.into());
            }
        };

        uploads.remove_chunk(&chunk_path).await;

        let complete = spec.complete
            || spec.total.is_some_and(|total| new_offset == total);

        if complete {
            let total = spec.total.unwrap_or(new_offset);

            if new_offset != total {
                let _ = uploads.truncate(&key, current).await;
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!(
                        "incomplete object: got {new_offset} of {total} bytes"
                    )))?);
            }

            let Some(file) = uploads.open_partial(&key).await? else {
                return Err(io::Error::other("missing partial upload").into());
            };

            let stream: ByteStream = Box::pin(ReaderStream::new(file));

            if let Err(err) = storage
                .put(key.clone(), LFSObject::new(total, stream))
                .await
            {
                let _ = uploads.truncate(&key, current).await;
                return Err(err.into());
            }

            let _ = uploads.remove_partial(&key).await;
        }

        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Upload-Offset", new_offset);

        if let Some(total) = spec.total {
            response = response.header("Upload-Length", total);
        }

        if !complete && new_offset > 0 {
            response =
                response.header("Range", format!("bytes=0-{}", new_offset - 1));
        }

        Ok(response.body(Body::empty())?)
    }

    /// Reports the committed offset of an in-progress or completed upload.
    async fn upload_status(
        storage: S,
        uploads: Arc<Uploads>,
        key: StorageKey,
    ) -> Result<Response<Body>, Error> {
        let lock = uploads.lock(&key);
        let _guard = lock.lock().await;

        let has_partial = uploads.has_partial(&key).await?;
        let stored_size = if has_partial {
            None
        } else {
            storage.size(&key).await?
        };

        if !has_partial && stored_size.is_none() {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())?);
        }

        let offset = uploads.current_offset(&key, stored_size).await?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Upload-Offset", offset)
            .header(header::CONTENT_LENGTH, 0)
            .body(Body::empty())?)
    }

    /// Verifies that an LFS object exists on the server.
    async fn verify(
        storage: S,
        req: Request<Body>,
        namespace: Namespace,
    ) -> Result<Response<Body>, Error> {
        let val: lfs::VerifyRequest = from_json(req.into_body()).await?;
        let key = StorageKey::new(namespace, val.oid);

        if let Some(size) = storage.size(&key).await?
            && size == val.size
        {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())?);
        }

        // Object doesn't exist or the size is incorrect.
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())?)
    }

    /// Batch API endpoint for the Git LFS server spec.
    ///
    /// See also:
    /// https://github.com/git-lfs/git-lfs/blob/master/docs/api/batch.md
    async fn batch(
        storage: S,
        req: Request<Body>,
        namespace: Namespace,
    ) -> Result<Response<Body>, Error> {
        // Get the host name and scheme.
        let uri = req.base_uri().path_and_query("/").build().unwrap();
        let headers = req.headers().clone();

        match from_json::<lfs::BatchRequest>(req.into_body()).await {
            Ok(val) => {
                let operation = val.operation;

                // For each object, check if it exists in the storage
                // backend.
                let objects = val.objects.into_iter().map(|object| {
                    let uri = uri.clone();
                    let key = StorageKey::new(namespace.clone(), object.oid);

                    async {
                        let size = storage.size(&key).await;

                        let (namespace, _) = key.into_parts();
                        Ok(basic_response(
                            uri, &headers, &storage, object, operation, size,
                            namespace,
                        )
                        .await)
                    }
                });

                let objects = future::try_join_all(objects).await?;
                let response = lfs::BatchResponse {
                    transfer: Some(lfs::Transfer::Basic),
                    objects,
                };

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(into_json(&response)?)?)
            }
            Err(err) => {
                let response = lfs::BatchResponseError {
                    message: err.to_string(),
                    documentation_url: None,
                    request_id: None,
                };

                Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(into_json(&response).unwrap())?)
            }
        }
    }
}

async fn basic_response<E, S>(
    uri: Uri,
    headers: &HeaderMap,
    storage: &S,
    object: lfs::RequestObject,
    op: lfs::Operation,
    size: Result<Option<u64>, E>,
    namespace: Namespace,
) -> lfs::ResponseObject
where
    E: fmt::Display,
    S: Storage,
{
    if let Ok(Some(size)) = size {
        // Ensure that the client and server agree on the size of the object.
        if object.size != size {
            return lfs::ResponseObject {
                oid: object.oid,
                size,
                error: Some(lfs::ObjectError {
                    code: 400,
                    message: format!(
                        "bad object size: requested={}, actual={}",
                        object.size, size
                    ),
                }),
                authenticated: Some(true),
                actions: None,
            };
        }
    }

    let size = match size {
        Ok(size) => size,
        Err(err) => {
            tracing::error!("batch response error: {err}");

            // Return a generic "500 - Internal Server Error" for objects that
            // we failed to get the size of. This is usually caused by some
            // intermittent problem on the storage backend. A retry strategy
            // should be implemented on the storage backend to help mitigate
            // this possibility because the git-lfs client does not currenty
            // implement retries in this case.
            return lfs::ResponseObject {
                oid: object.oid,
                size: object.size,
                error: Some(lfs::ObjectError {
                    code: 500,
                    message: err.to_string(),
                }),
                authenticated: Some(true),
                actions: None,
            };
        }
    };

    match op {
        lfs::Operation::Upload => {
            // If the object does exist, then we should not return any action.
            //
            // If the object does not exist, then we should return an upload
            // action.
            let upload_expiry_secs = UPLOAD_EXPIRATION.as_secs() as i32;
            match size {
                Some(size) => lfs::ResponseObject {
                    oid: object.oid,
                    size,
                    error: None,
                    authenticated: Some(true),
                    actions: None,
                },
                None => lfs::ResponseObject {
                    oid: object.oid,
                    size: object.size,
                    error: None,
                    authenticated: Some(true),
                    actions: Some(lfs::Actions {
                        download: None,
                        upload: Some(lfs::Action {
                            href: storage
                                .upload_url(
                                    &StorageKey::new(
                                        namespace.clone(),
                                        object.oid,
                                    ),
                                    UPLOAD_EXPIRATION,
                                )
                                .await
                                .unwrap_or_else(|| {
                                    format!(
                                        "{}api/{}/object/{}",
                                        uri, namespace, object.oid
                                    )
                                }),
                            header: extract_auth_header(headers),
                            expires_in: Some(upload_expiry_secs),
                            expires_at: None,
                        }),
                        verify: Some(lfs::Action {
                            href: format!(
                                "{uri}api/{namespace}/objects/verify"
                            ),
                            header: extract_auth_header(headers),
                            expires_in: None,
                            expires_at: None,
                        }),
                    }),
                },
            }
        }
        lfs::Operation::Download => {
            // If the object does not exist, then we should return a 404 error
            // for this object.
            match size {
                Some(size) => lfs::ResponseObject {
                    oid: object.oid,
                    size,
                    error: None,
                    authenticated: Some(true),
                    actions: Some(lfs::Actions {
                        download: Some(lfs::Action {
                            href: storage
                                .public_url(&StorageKey::new(
                                    namespace.clone(),
                                    object.oid,
                                ))
                                .unwrap_or_else(|| {
                                    format!(
                                        "{}api/{}/object/{}",
                                        uri, namespace, object.oid
                                    )
                                }),
                            header: extract_auth_header(headers),
                            expires_in: None,
                            expires_at: None,
                        }),
                        upload: None,
                        verify: None,
                    }),
                },
                None => lfs::ResponseObject {
                    oid: object.oid,
                    size: object.size,
                    error: Some(lfs::ObjectError {
                        code: 404,
                        message: "object not found".into(),
                    }),
                    authenticated: Some(true),
                    actions: None,
                },
            }
        }
    }
}

/// Extracts the authorization headers so that they can be reflected back to the
/// `git-lfs` client.  If we're behind a reverse proxy that provides
/// authentication, the `git-lfs` client will send an `Authorization` header on
/// the first connection, however in order for subsequent requests to also be
/// authenticated, the `header` field in the `lfs::ResponseObject` must be
/// populated.
fn extract_auth_header(
    headers: &HeaderMap,
) -> Option<BTreeMap<String, String>> {
    let headers = headers.iter().filter_map(|(k, v)| {
        if k == header::AUTHORIZATION {
            let value = String::from_utf8_lossy(v.as_bytes()).to_string();
            Some((k.to_string(), value))
        } else {
            None
        }
    });
    let map = BTreeMap::from_iter(headers);
    if map.is_empty() { None } else { Some(map) }
}

impl<S> Service<Request<Body>> for App<S>
where
    S: Storage + Clone + Send + Sync + 'static,
    S::Error: Into<Error> + 'static,
    Error: From<S::Error>,
{
    type Response = Response<Body>;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut Context,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if req.uri().path() == "/" {
            Box::pin(future::ready(Self::index(req)))
        } else if req.uri().path().starts_with("/api/") {
            Box::pin(Self::api(self.storage.clone(), self.uploads.clone(), req))
        } else {
            Box::pin(future::ready(Self::not_found(req)))
        }
    }
}

fn offset_conflict(
    expected: u64,
    current: u64,
) -> Result<Response<Body>, Error> {
    let mut response = Response::builder()
        .status(StatusCode::CONFLICT)
        .header("Upload-Offset", current);

    if current > 0 {
        response = response.header("Range", format!("bytes=0-{}", current - 1));
    }

    Ok(response.body(Body::from(format!(
        "stale upload offset: expected {expected}, server has {current}"
    )))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Disk;
    use bytes::Bytes;
    use futures::stream;
    use hyper::body::to_bytes;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    fn chunk_request(
        uri: &str,
        data: &[u8],
        start: u64,
        end: u64,
        total: u64,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header(header::CONTENT_LENGTH, data.len())
            .header("Content-Range", format!("bytes {start}-{end}/{total}"))
            .body(Body::from(data.to_vec()))
            .unwrap()
    }

    #[tokio::test]
    async fn concurrent_resume_at_same_offset_is_rejected() {
        const CHUNK: usize = 16 * 1024;
        const TOTAL: usize = CHUNK * 4;

        let mut data = vec![0u8; TOTAL];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let oid = crate::lfs::Oid::from(<[u8; 32]>::from(hasher.finalize()));
        let dir = TempDir::new().unwrap();
        let disk = Arc::new(Disk::new(dir.path().to_path_buf()).await.unwrap());
        let uploads = Arc::new(Uploads::new());
        let app = App::with_uploads(disk, uploads);
        let uri = format!("/api/test/test/object/{oid}");

        let mut first = app.clone();
        let response = first
            .call(chunk_request(
                &uri,
                &data[..CHUNK],
                0,
                CHUNK as u64 - 1,
                TOTAL as u64,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut client_a = app.clone();
        let mut client_b = app.clone();
        let request_a = chunk_request(
            &uri,
            &data[CHUNK..CHUNK * 2],
            CHUNK as u64,
            (CHUNK * 2) as u64 - 1,
            TOTAL as u64,
        );
        let request_b = chunk_request(
            &uri,
            &data[CHUNK..CHUNK * 2],
            CHUNK as u64,
            (CHUNK * 2) as u64 - 1,
            TOTAL as u64,
        );

        let (response_a, response_b) = tokio::join!(
            async move { client_a.call(request_a).await.unwrap() },
            async move { client_b.call(request_b).await.unwrap() },
        );

        let mut statuses = [response_a.status(), response_b.status()];
        statuses.sort();

        assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);

        let mut client = app.clone();
        let response = client
            .call(chunk_request(
                &uri,
                &data[CHUNK * 2..],
                (CHUNK * 2) as u64,
                TOTAL as u64 - 1,
                TOTAL as u64,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let request = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body()).await.unwrap();
        assert_eq!(body.as_ref(), data.as_slice());
    }

    #[tokio::test]
    async fn interrupted_chunk_does_not_advance_offset() {
        const CHUNK: usize = 16 * 1024;

        let mut data = vec![0u8; CHUNK * 2];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 239) as u8;
        }

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let oid = crate::lfs::Oid::from(<[u8; 32]>::from(hasher.finalize()));

        let dir = TempDir::new().unwrap();
        let disk = Arc::new(Disk::new(dir.path().to_path_buf()).await.unwrap());
        let app = App::with_uploads(disk, Arc::new(Uploads::new()));
        let uri = format!("/api/test/test/object/{oid}");

        let mut client = app.clone();
        let response = client
            .call(chunk_request(
                &uri,
                &data[..CHUNK],
                0,
                CHUNK as u64 - 1,
                (CHUNK * 2) as u64,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let partial = data[CHUNK..CHUNK + 1024].to_vec();
        let body = Body::wrap_stream(stream::iter(vec![
            Ok::<_, io::Error>(Bytes::from(partial)),
            Err(io::Error::other("client disconnected")),
        ]));
        let request = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .header(
                "Content-Range",
                format!("bytes {}-{}/{}", CHUNK, CHUNK * 2 - 1, CHUNK * 2),
            )
            .body(body)
            .unwrap();

        let mut client = app.clone();
        assert!(client.call(request).await.is_err());

        let request = Request::builder()
            .method(Method::HEAD)
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("Upload-Offset")
                .unwrap()
                .to_str()
                .unwrap(),
            CHUNK.to_string()
        );

        let mut client = app.clone();
        let response = client
            .call(chunk_request(
                &uri,
                &data[CHUNK..],
                CHUNK as u64,
                (CHUNK * 2) as u64 - 1,
                (CHUNK * 2) as u64,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let request = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().call(request).await.unwrap();
        let body = to_bytes(response.into_body()).await.unwrap();
        assert_eq!(body.as_ref(), data.as_slice());
    }
}
