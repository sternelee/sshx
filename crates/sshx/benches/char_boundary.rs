//! Baseline benchmark for `prev_char_boundary` (`runner.rs:146`).
//!
//! Pure regression guard: after the §1.5 O(N) → O(1) rewrite, scanning
//! the same long multi-byte string from a high index should be a constant
//! handful of `is_char_boundary` checks regardless of input length.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

/// Mirrors `crates/sshx/src/runner.rs::prev_char_boundary`.
fn prev_char_boundary(s: &str, mut i: usize) -> usize {
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn bench_char_boundary(c: &mut Criterion) {
    let mut group = c.benchmark_group("prev_char_boundary");
    // Mostly multi-byte CJK so most byte indices are NOT boundaries.
    let unit = "中文测试χρϊστ";
    for &len_kb in &[4u64, 64, 1024] {
        let s = unit.repeat((len_kb as usize * 1024) / unit.len() + 1);
        let target = s.len() - 7; // arbitrary mid-codepoint offset near the end
        group.bench_with_input(
            BenchmarkId::new("multibyte", format!("{len_kb}KiB")),
            &(s, target),
            |b, (s, target)| {
                b.iter(|| black_box(prev_char_boundary(black_box(s), black_box(*target))));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_char_boundary);
criterion_main!(benches);
