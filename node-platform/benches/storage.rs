use criterion::{black_box, criterion_group, criterion_main, Criterion};
fn storage(c: &mut Criterion) {
    let payload = vec![0x5au8; 4096];
    c.bench_function("storage", |b| {
        b.iter(|| synergy_benchmarks::bounded_fold(black_box(&payload)))
    });
}
criterion_group!(benches, storage);
criterion_main!(benches);
