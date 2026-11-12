use criterion::{black_box, criterion_group, criterion_main, Criterion};
fn certificate_validation(c: &mut Criterion) {
    let payload = vec![0x5au8; 4096];
    c.bench_function("certificate_validation", |b| {
        b.iter(|| synergy_benchmarks::bounded_fold(black_box(&payload)))
    });
}
criterion_group!(benches, certificate_validation);
criterion_main!(benches);
