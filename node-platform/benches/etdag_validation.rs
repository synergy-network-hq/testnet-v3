use criterion::{black_box, criterion_group, criterion_main, Criterion};
fn etdag_validation(c: &mut Criterion) {
    let payload = vec![0x5au8; 4096];
    c.bench_function("etdag_validation", |b| {
        b.iter(|| synergy_benchmarks::bounded_fold(black_box(&payload)))
    });
}
criterion_group!(benches, etdag_validation);
criterion_main!(benches);
