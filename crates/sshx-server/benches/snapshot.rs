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
        encrypted_zeros: Bytes::from_static(&[0u8; 44]),
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
    for &(shells, per_shell_kib) in &[(1usize, 32usize), (4, 64), (16, 128)] {
        let total_bytes = (shells * per_shell_kib * 1024) as u64;
        let session = build_session(shells, per_shell_kib * 1024);
        group.throughput(Throughput::Bytes(total_bytes));
        group.bench_with_input(
            BenchmarkId::new("encode+zstd3", format!("{shells}sh_{per_shell_kib}KiB")),
            &session,
            |b, session| {
                b.iter(|| {
                    let buf = session.snapshot().expect("snapshot");
                    black_box(buf);
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_snapshot);
criterion_main!(benches);
