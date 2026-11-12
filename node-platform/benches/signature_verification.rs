use criterion::{black_box, criterion_group, criterion_main, Criterion};
fn signature_verification(c: &mut Criterion) {
    let payload = vec![0x5au8; 4096];
    c.bench_function("signature_verification", |b| {
        b.iter(|| synergy_benchmarks::bounded_fold(black_box(&payload)))
    });
}
criterion_group!(benches, signature_verification);
criterion_main!(benches);
