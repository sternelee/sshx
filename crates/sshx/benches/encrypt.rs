//! Baseline benchmarks for `Encrypt`.
//!
//! Measures the per-chunk cost of AES-256-GCM (V2) encrypt and decrypt at the
//! sizes typical of PTY output: 4 KiB segments. Used to validate the §5.4
//! AeadInOut in-place rewrite and to provide a reference number for future
//! optimisation work.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use sshx::encrypt::Encrypt;

const CHUNK_SIZE: usize = 4096;

fn bench_encrypt_v2(c: &mut Criterion) {
    let encrypt = Encrypt::new("benchmark key");
    let data = vec![0xa5u8; CHUNK_SIZE];
    let mut group = c.benchmark_group("encrypt_v2");
    group.throughput(Throughput::Bytes(CHUNK_SIZE as u64));
    group.bench_function("4KiB", |b| {
        b.iter(|| {
            let ct = encrypt.encrypt(black_box(1), black_box(0), black_box(&data));
            black_box(ct);
        })
    });
    group.finish();
}

fn bench_decrypt_v2(c: &mut Criterion) {
    let encrypt = Encrypt::new("benchmark key");
    let data = vec![0xa5u8; CHUNK_SIZE];
    let ciphertext = encrypt.encrypt(1, 0, &data);
    let mut group = c.benchmark_group("decrypt_v2");
    group.throughput(Throughput::Bytes(CHUNK_SIZE as u64));
    group.bench_function("4KiB", |b| {
        b.iter(|| {
            let pt = encrypt
                .decrypt(black_box(1), black_box(0), black_box(&ciphertext))
                .expect("decrypt");
            black_box(pt);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_encrypt_v2, bench_decrypt_v2);
criterion_main!(benches);
