use criterion::{black_box, criterion_group, criterion_main, Criterion};
fn etdag_ordering(c: &mut Criterion) {
    let payload = vec![0x5au8; 4096];
    c.bench_function("etdag_ordering", |b| {
        b.iter(|| synergy_benchmarks::bounded_fold(black_box(&payload)))
    });
}
criterion_group!(benches, etdag_ordering);
criterion_main!(benches);
