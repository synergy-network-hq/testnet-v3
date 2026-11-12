use criterion::{black_box, criterion_group, criterion_main, Criterion};
fn state_transition(c: &mut Criterion) {
    let payload = vec![0x5au8; 4096];
    c.bench_function("state_transition", |b| {
        b.iter(|| synergy_benchmarks::bounded_fold(black_box(&payload)))
    });
}
criterion_group!(benches, state_transition);
criterion_main!(benches);
