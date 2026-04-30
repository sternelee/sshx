//! Baseline benchmark for `Session::snapshot()`.
//!
//! Measures the cost of serializing a populated session and zstd-compressing
//! the result. Used to validate the §3.1 zstd 15 → 3 change and provide a
//! reference for future snapshot-format work.

use std::hint::black_box;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sshx_core::Sid;
use sshx_server::session::{Metadata, Session};

fn build_session(num_shells: usize, bytes_per_shell: usize) -> Session {
    let session = Session::new(Metadata {
        encrypted_zeros: Bytes::from_static(&[0u8; 16]),
        name: "bench".to_string(),
        write_password_hash: None,
    });
    // 4 KiB chunks — typical PTY read size.
    let chunk = vec![0xa5u8; 4096];
    let chunks_per_shell = bytes_per_shell.div_ceil(chunk.len());
    for sid in 1..=num_shells {
        let id = Sid(sid as u32);
        session.add_shell(id, (0, 0)).expect("add_shell");
        let mut seq: u64 = 0;
        for _ in 0..chunks_per_shell {
            let data = Bytes::from(chunk.clone());
            session.add_data(id, data, seq).expect("add_data");
            // Server records ciphertext length; bench passes raw bytes which
            // is fine for snapshot benchmarking, the prune logic is identical.
            seq += chunk.len() as u64;
        }
    }
    session
}

fn bench_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_snapshot");
    // Shells × bytes-per-shell. Total is the throughput input.
    //
    // Small variants (≤ 2 MiB total) match the original §3.1 baseline.
    // Large variants (2 MiB per shell) approximate a populated rolling
    // buffer at the cold-tier eviction snapshot size, validating that
    // the lifted MAX_SNAPSHOT_SIZE (4 MiB → 64 MiB) does not regress
    // the encode path and giving us an apples-to-apples decode number
    // for thaw cost on the WebSocket reconnect path.
    let cases: [(usize, usize); 6] = [
        (1, 32 * 1024),
        (4, 64 * 1024),
        (16, 128 * 1024),
        (1, 2 * 1024 * 1024),
        (4, 2 * 1024 * 1024),
        (16, 2 * 1024 * 1024),
    ];
    for &(shells, per_shell_bytes) in &cases {
        let total_bytes = (shells * per_shell_bytes) as u64;
        let label = if per_shell_bytes >= 1024 * 1024 {
            format!("{shells}sh_{}MiB", per_shell_bytes / (1024 * 1024))
        } else {
            format!("{shells}sh_{}KiB", per_shell_bytes / 1024)
        };
        let session = build_session(shells, per_shell_bytes);
        group.throughput(Throughput::Bytes(total_bytes));
        group.bench_with_input(
            BenchmarkId::new("encode+zstd3", &label),
            &session,
            |b, session| {
                b.iter(|| {
                    let buf = session.snapshot().expect("snapshot");
                    black_box(buf);
                })
            },
        );

        // Decode path uses a freshly-encoded snapshot per benchmark
        // group setup; iter_with_setup keeps measurement focused on
        // restore (zstd decompress + ciborium decode + Session rebuild)
        // without re-encoding on every sample.
        let snapshot = session.snapshot().expect("snapshot for decode bench");
        group.bench_with_input(
            BenchmarkId::new("decode+zstd3", &label),
            &snapshot,
            |b, snapshot| {
                b.iter(|| {
                    let restored = Session::restore(snapshot).expect("restore");
                    black_box(restored);
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_snapshot);
criterion_main!(benches);
