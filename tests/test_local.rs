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

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use futures::future::Either;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rudolfs::LocalServerBuilder;
use tokio::sync::oneshot;

use common::{GitRepo, SERVER_ADDR, init_logger};

#[tokio::test(flavor = "multi_thread")]
async fn local_encrypted_writes_are_balanced_across_buckets()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = init_logger();

    let mut rng = StdRng::seed_from_u64(42);

    let data = tempfile::TempDir::new()?;
    let key = rng.random();

    let mut server = LocalServerBuilder::new(data.path().into());
    server.key(key);
    let server = server.spawn(SERVER_ADDR).await?;
    let addr = server.addr();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(futures::future::select(shutdown_rx, server));

    const OBJECT_SIZE: usize = 8192;
    const OBJECT_COUNT: usize = 32;

    let repo = GitRepo::init(addr)?;
    for i in 0..OBJECT_COUNT {
        repo.add_random(
            &PathBuf::from(format!("{i}.bin")),
            OBJECT_SIZE,
            &mut rng,
        )?;
    }
    repo.commit("Add many equally-sized LFS objects")?;
    repo.lfs_push()?;

    shutdown_tx.send(()).expect("server died too soon");

    if let Either::Right((result, _)) = server.await? {
        result?;
    }

    let sizes = bucket_sizes(&data.path().join("objects/test/test"))?;

    assert_eq!(sizes.len(), 16, "all buckets should be used: {sizes:?}");

    let min = *sizes.first().unwrap();
    let max = *sizes.last().unwrap();

    assert!(
        max - min <= OBJECT_SIZE as u64,
        "bucket sizes are imbalanced: {sizes:?}"
    );

    Ok(())
}

fn bucket_sizes(namespace: &Path) -> io::Result<Vec<u64>> {
    let mut sizes = Vec::new();

    for entry in fs::read_dir(namespace)? {
        let entry = entry?;

        if !entry.file_type()?.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let name = name.to_string_lossy();

        if name.len() == 1 && u8::from_str_radix(&name, 16).is_ok() {
            sizes.push(dir_size(&entry.path())?);
        }
    }

    sizes.sort_unstable();
    Ok(sizes)
}

fn dir_size(path: &Path) -> io::Result<u64> {
    let mut size = 0;

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            size += dir_size(&entry.path())?;
        } else if file_type.is_file() {
            size += entry.metadata()?.len();
        }
    }

    Ok(size)
}

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
