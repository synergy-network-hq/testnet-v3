use criterion::{black_box, criterion_group, criterion_main, Criterion};
fn posy_vote_processing(c: &mut Criterion) {
    let payload = vec![0x5au8; 4096];
    c.bench_function("posy_vote_processing", |b| {
        b.iter(|| synergy_benchmarks::bounded_fold(black_box(&payload)))
    });
}
criterion_group!(benches, posy_vote_processing);
criterion_main!(benches);
