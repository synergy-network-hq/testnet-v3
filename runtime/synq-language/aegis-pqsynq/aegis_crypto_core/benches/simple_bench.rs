use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn simple_benchmark(c: &mut Criterion) {
    c.bench_function("simple_operation", |b| {
        b.iter(|| {
            let result = black_box(2 + 2);
            black_box(result)
        })
    });
}

criterion_group!(benches, simple_benchmark);
criterion_main!(benches);
