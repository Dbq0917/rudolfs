// Copyright (c) 2021 Jason White
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
mod common;

use std::io;
use std::net::SocketAddr;
use std::path::Path;

use futures::future::Either;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rudolfs::LocalServerBuilder;
use tokio::sync::oneshot;

use common::{GitRepo, SERVER_ADDR, init_logger};

#[tokio::test(flavor = "multi_thread")]
async fn local_smoke_test_encrypted() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = init_logger();

    // Make sure our seed is deterministic. This makes it easier to reproduce
    // the same repo every time.
    let mut rng = StdRng::seed_from_u64(42);

    let data = tempfile::TempDir::new()?;
    let key = rng.random();

    let mut server = LocalServerBuilder::new(data.path().into());
    server.key(key);
    let server = server.spawn(SERVER_ADDR).await?;
    let addr = server.addr();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server = tokio::spawn(futures::future::select(shutdown_rx, server));

    exercise_server(addr, &mut rng)?;

    shutdown_tx.send(()).expect("server died too soon");

    if let Either::Right((result, _)) = server.await? {
        // If the server exited first, then propagate the error.
        result?;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn local_encrypted_key_rotation_reads_old_object()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = init_logger();

    let mut rng = StdRng::seed_from_u64(7);
    let data = tempfile::TempDir::new()?;
    let old_key = rng.random();
    let new_key = rng.random();

    let mut first_server = LocalServerBuilder::new(data.path().into());
    first_server.key(old_key);
    let first_server = first_server.spawn(SERVER_ADDR).await?;
    let first_addr = first_server.addr();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let first_join =
        tokio::spawn(futures::future::select(shutdown_rx, first_server));

    let repo = GitRepo::init(first_addr)?;
    repo.add_random(Path::new("rotate.bin"), 1024 * 1024, &mut rng)?;
    repo.commit("Add object before key rotation")?;
    repo.lfs_push()?;

    shutdown_tx.send(()).expect("first server died too soon");
    let _ = first_join.await?;

    let mut rotated_server = LocalServerBuilder::new(data.path().into());
    rotated_server.key(new_key).previous_key(old_key);
    let rotated_server = rotated_server.spawn(SERVER_ADDR).await?;
    let rotated_addr = rotated_server.addr();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let rotated_join =
        tokio::spawn(futures::future::select(shutdown_rx, rotated_server));

    repo.set_lfs_endpoint(rotated_addr)?;
    repo.clean_lfs()?;

    // The one-week rotation overlap is represented by configuring both keys.
    // The object header selects `old_key` by its version and fingerprint.
    repo.lfs_pull()?;

    repo.add_random(Path::new("after-rotation.bin"), 512 * 1024, &mut rng)?;
    repo.commit("Add object after key rotation")?;
    repo.lfs_push()?;

    // Force both the old-key and new-key objects to be downloaded again.
    repo.clean_lfs()?;
    repo.lfs_pull()?;

    shutdown_tx.send(()).expect("rotated server died too soon");
    if let Either::Right((result, _)) = rotated_join.await? {
        result?;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn local_smoke_test_unencrypted() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = init_logger();

    // Make sure our seed is deterministic. This makes it easier to reproduce
    // the same repo every time.
    let mut rng = StdRng::seed_from_u64(42);

    let data = tempfile::TempDir::new()?;

    let server = LocalServerBuilder::new(data.path().into());
    let server = server.spawn(SERVER_ADDR).await?;
    let addr = server.addr();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let server = tokio::spawn(futures::future::select(shutdown_rx, server));

    exercise_server(addr, &mut rng)?;

    shutdown_tx.send(()).expect("server died too soon");

    if let Either::Right((result, _)) = server.await? {
        // If the server exited first, then propagate the error.
        result?;
    }

    Ok(())
}

/// Creates a repository with a few LFS files in it to exercise the LFS server.
fn exercise_server(addr: SocketAddr, rng: &mut impl Rng) -> io::Result<()> {
    let repo = GitRepo::init(addr)?;
    repo.add_random(Path::new("4mb.bin"), 4 * 1024 * 1024, rng)?;
    repo.add_random(Path::new("8mb.bin"), 8 * 1024 * 1024, rng)?;
    repo.add_random(Path::new("16mb.bin"), 16 * 1024 * 1024, rng)?;
    repo.commit("Add LFS objects")?;

    // Make sure we can push LFS objects to the server.
    repo.lfs_push()?;

    // Push again. This should be super fast.
    repo.lfs_push()?;

    // This should be fast since we already have the data
    repo.lfs_pull()?;

    // Make sure we can re-download the same objects in another repo
    let repo_clone = repo.clone_repo().expect("unable to clone");

    // This should be fast since the lfs data should come along properly with
    // the clone
    repo_clone.lfs_pull()?;

    // Add some more files and make sure you can pull those into the clone
    repo.add_random(Path::new("4mb_2.bin"), 4 * 1024 * 1024, rng)?;
    repo.add_random(Path::new("8mb_2.bin"), 8 * 1024 * 1024, rng)?;
    repo.add_random(Path::new("16mb_2.bin"), 16 * 1024 * 1024, rng)?;
    repo.commit("Add LFS objects 2")?;

    repo_clone.pull()?;

    Ok(())
}
