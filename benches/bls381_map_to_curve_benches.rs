extern crate amcl;
extern crate bls_aggregates;
extern crate criterion;
extern crate hex;

use self::amcl::{bls381 as BLSCurve};
use bls_aggregates::*;
use criterion::{black_box, criterion_group, criterion_main, Benchmark, Criterion};
use BLSCurve::big::BIG;
use BLSCurve::ecp::ECP;

pub type BigNum = BIG;
pub type GroupG1 = ECP;

fn g1(c: &mut Criterion) {
    let msg = [1 as u8; 32];

    c.bench(
        "hash_to_g1",
        Benchmark::new("Hash and test x100", move |b| {
            b.iter(|| {
                for i in 0..100 {
                    black_box(hash_and_test_g1(&msg, i));
                }
            })
        })
        .sample_size(10),
    );

    c.bench(
        "hash_to_g1",
        Benchmark::new("Fouque Tibouchi x100", move |b| {
            b.iter(|| {
                for i in 0..100 {
                    black_box(fouque_tibouchi_g1(&msg, i));
                }
            })
        })
        .sample_size(10),
    );

    c.bench(
        "hash_to_g1",
        Benchmark::new("Fouque Tibouchi Twice x100", move |b| {
            b.iter(|| {
                for i in 0..100 {
                    black_box(fouque_tibouchi_twice_g1(&msg, i));
                }
            })
        })
        .sample_size(10),
    );
}

fn g2(c: &mut Criterion) {
    let msg = [1 as u8; 32];

    c.bench(
        "hash_to_g2",
        Benchmark::new("Hash and test x100", move |b| {
            b.iter(|| {
                for i in 0..100 {
                    black_box(hash_and_test_g2(&msg, i));
                }
            })
        })
        .sample_size(10),
    );

    c.bench(
        "hash_to_g2",
        Benchmark::new("Fouque Tibouchi x100", move |b| {
            b.iter(|| {
                for i in 0..100 {
                    black_box(fouque_tibouchi_g2(&msg, i));
                }
            })
        })
        .sample_size(10),
    );

    c.bench(
        "hash_to_g2",
        Benchmark::new("Fouque Tibouchi Twice x100", move |b| {
            b.iter(|| {
                for i in 0..100 {
                    black_box(fouque_tibouchi_twice_g2(&msg, i));
                }
            })
        })
        .sample_size(10),
    );
}

criterion_group!(
    benches,
    g1,
    g2,
);
criterion_main!(benches);
