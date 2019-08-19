extern crate amcl;
extern crate criterion;
extern crate hex;
extern crate milagro_bls;
extern crate rand;

use self::amcl::bls381 as BLSCurve;
use criterion::{black_box, criterion_group, criterion_main, Benchmark, Criterion};
use milagro_bls::*;
use BLSCurve::big::BIG;
use BLSCurve::ecp::ECP;

pub type BigNum = BIG;
pub type GroupG1 = ECP;

fn compression_signature(c: &mut Criterion) {
    let compressed_g2 = hex::decode("a666d31d7e6561371644eb9ca7dbcb87257d8fd84a09e38a7a491ce0bbac64a324aa26385aebc99f47432970399a2ecb0def2d4be359640e6dae6438119cbdc4f18e5e4496c68a979473a72b72d3badf98464412e9d8f8d2ea9b31953bb24899").unwrap();
    let mut signature = Signature::from_bytes(&compressed_g2).unwrap();

    c.bench(
        "compression",
        Benchmark::new("Decompress a Signature", move |b| {
            b.iter(|| {
                black_box(Signature::from_bytes(&compressed_g2).unwrap());
            })
        })
        .sample_size(100),
    );

    c.bench(
        "compression",
        Benchmark::new("Compress a Signature", move |b| {
            b.iter(|| {
                black_box(Signature::as_bytes(&mut signature));
            })
        })
        .sample_size(10),
    );
}

fn compression_public_key(c: &mut Criterion) {
    let compressed_g1 = hex::decode("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a").unwrap();
    let mut public_key = PublicKey::from_bytes(&compressed_g1).unwrap();

    c.bench(
        "compression",
        Benchmark::new("Decompress a PublicKey", move |b| {
            b.iter(|| {
                black_box(PublicKey::from_bytes(&compressed_g1).unwrap());
            })
        })
        .sample_size(100),
    );

    c.bench(
        "compression",
        Benchmark::new("Compress a PublicKey", move |b| {
            b.iter(|| {
                black_box(PublicKey::as_bytes(&mut public_key));
            })
        })
        .sample_size(10),
    );
}

fn compression_public_key_bigs(c: &mut Criterion) {
    let compressed_g1 = hex::decode("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a").unwrap();
    let mut public_key = PublicKey::from_bytes(&compressed_g1).unwrap();
    let uncompressed_bytes = public_key.as_uncompressed_bytes();

    c.bench(
        "compression",
        Benchmark::new("Decompress a PublicKey from Bigs", move |b| {
            b.iter(|| {
                black_box(PublicKey::from_uncompressed_bytes(&uncompressed_bytes)).unwrap();
            })
        })
        .sample_size(100),
    );

    c.bench(
        "compression",
        Benchmark::new("Compress a PublicKey to Bigs", move |b| {
            b.iter(|| {
                black_box(public_key.as_uncompressed_bytes());
            })
        })
        .sample_size(10),
    );
}

fn signing(c: &mut Criterion) {
    let keypair = Keypair::random(&mut rand::thread_rng());
    let sk = keypair.sk;
    let pk = keypair.pk;

    let msg = "Some msg";
    let domain = 42;
    let sig = Signature::new(&msg.as_bytes(), domain, &sk);

    c.bench(
        "signing",
        Benchmark::new("Create a Signature", move |b| {
            b.iter(|| {
                black_box(Signature::new(&msg.as_bytes(), domain, &sk));
            })
        })
        .sample_size(10),
    );

    c.bench(
        "signing",
        Benchmark::new("Verify a Signature", move |b| {
            b.iter(|| {
                black_box(sig.verify(&msg.as_bytes(), domain, &pk));
            })
        })
        .sample_size(10),
    );
}

fn aggregation(c: &mut Criterion) {
    let keypair = Keypair::random(&mut rand::thread_rng());
    let sk = keypair.sk;
    let pk = keypair.pk;

    let msg = "Some msg";
    let domain = 42;
    let sig = Signature::new(&msg.as_bytes(), domain, &sk);

    let mut aggregate_publickey = AggregatePublicKey::new();
    aggregate_publickey.add(&pk);

    let mut aggregate_signature = AggregateSignature::new();
    aggregate_signature.add(&sig);

    c.bench(
        "aggregation",
        Benchmark::new("Aggregate a PublicKey", move |b| {
            b.iter(|| {
                black_box(aggregate_publickey.add(&pk));
            })
        })
        .sample_size(100),
    );

    c.bench(
        "aggregation",
        Benchmark::new("Aggregate a Signature", move |b| {
            b.iter(|| {
                black_box(aggregate_signature.add(&sig));
            })
        })
        .sample_size(100),
    );
}

fn aggregate_verfication(c: &mut Criterion) {
    let n = 128;

    let mut pubkeys = vec![];
    let mut agg_sig = AggregateSignature::new();
    let msg = b"signed message";
    let domain = 0;

    for _ in 0..n {
        let keypair = Keypair::random(&mut rand::thread_rng());
        let sig = Signature::new(&msg[..], domain, &keypair.sk);
        agg_sig.add(&sig);
        pubkeys.push(keypair.pk);
    }

    assert_eq!(pubkeys.len(), n);

    c.bench(
        "aggregation",
        Benchmark::new("Verifying aggregate of 128 signatures", move |b| {
            b.iter(|| {
                let pubkeys_as_ref: Vec<&PublicKey> = pubkeys.iter().collect();
                let agg_pub = AggregatePublicKey::from_public_keys(pubkeys_as_ref.as_slice());
                let verified = agg_sig.verify(&msg[..], domain, &agg_pub);
                assert!(verified);
            })
        })
        .sample_size(100),
    );
}

fn aggregate_verfication_multiple_messages(c: &mut Criterion) {
    let n = 128;

    let mut pubkeys = vec![];
    let mut agg_sig = AggregateSignature::new();

    let msgs = vec![vec![0; 32], vec![1; 32]];

    let domain = 0;

    for i in 0..n {
        let keypair = Keypair::random(&mut rand::thread_rng());

        let msg = &msgs[i / (n / msgs.len())];

        let sig = Signature::new(&msg[..], domain, &keypair.sk);
        agg_sig.add(&sig);

        pubkeys.push(keypair.pk);
    }

    c.bench(
        "aggregation",
        Benchmark::new(
            "Verifying aggregate of 128 signatures with two distinct messages",
            move |b| {
                b.iter(|| {
                    let mut agg_pubs = vec![AggregatePublicKey::new(); 2];

                    for i in 0..n {
                        agg_pubs[i / (n / msgs.len())].add(&pubkeys[i]);
                    }
                    let agg_pubs_refs: Vec<&AggregatePublicKey> = agg_pubs.iter().collect();
                    let verified = agg_sig.verify_multiple(&msgs, domain, agg_pubs_refs.as_slice());

                    assert!(verified);
                })
            },
        )
        .sample_size(100),
    );
}

fn aggregate_verfication_multiple_signatures(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let n = 10;
    let m = 3;
    let domains: Vec<u64> = vec![1; n];
    let mut msgs: Vec<Vec<Vec<u8>>> = vec![vec![vec![]; m]; n];
    let mut public_keys: Vec<Vec<G1Point>> = vec![vec![]; n];
    let mut aggregate_signatures: Vec<AggregateSignature> = vec![];

    for i in 0..n {
        let mut aggregate_signature = AggregateSignature::new();
        for j in 0..m {
            msgs[i][j] = vec![(j * i) as u8; 32];
            let keypair = Keypair::random(&mut rng);
            public_keys[i].push(keypair.pk.point);

            let signature = Signature::new(&msgs[i][j], domains[i], &keypair.sk);
            aggregate_signature.add(&signature);
        }
        aggregate_signatures.push(aggregate_signature);
    }

    c.bench(
        "multiple-signatures-verification-30",
        Benchmark::new(
            "Verification of multiple aggregate signatures with optimizations",
            move |b| {
                let mega_iter = aggregate_signatures
                    .iter()
                    .cloned()
                    .map(|agg_sig| agg_sig.point)
                    .zip(public_keys.iter().cloned())
                    .zip(msgs.iter().cloned())
                    .zip(domains.iter().cloned())
                    .map(|(((a, b), c), d)| (a, b, c, d));
                b.iter(|| {
                    assert!(AggregateSignature::verify_multiple_signatures(
                        &mut rng,
                        mega_iter.clone()
                    ));
                })
            },
        )
        .sample_size(10),
    );

    let mut rng = rand::thread_rng();
    let n = 50;
    let m = 5;
    let domains: Vec<u64> = vec![1; n];
    let mut msgs: Vec<Vec<Vec<u8>>> = vec![vec![vec![]; m]; n];
    let mut public_keys: Vec<Vec<G1Point>> = vec![vec![]; n];
    let mut aggregate_signatures: Vec<AggregateSignature> = vec![];

    for i in 0..n {
        let mut aggregate_signature = AggregateSignature::new();
        for j in 0..m {
            msgs[i][j] = vec![(j * i) as u8; 32];
            let keypair = Keypair::random(&mut rng);
            public_keys[i].push(keypair.pk.point);

            let signature = Signature::new(&msgs[i][j], domains[i], &keypair.sk);
            aggregate_signature.add(&signature);
        }
        aggregate_signatures.push(aggregate_signature);
    }

    c.bench(
        "multiple-signatures-verification-250",
        Benchmark::new(
            "Verification of multiple aggregate signatures with optimizations",
            move |b| {
                let mega_iter = aggregate_signatures
                    .iter()
                    .cloned()
                    .map(|agg_sig| agg_sig.point)
                    .zip(public_keys.iter().cloned())
                    .zip(msgs.iter().cloned())
                    .zip(domains.iter().cloned())
                    .map(|(((a, b), c), d)| (a, b, c, d));
                b.iter(|| {
                    assert!(AggregateSignature::verify_multiple_signatures(
                        &mut rng,
                        mega_iter.clone()
                    ));
                })
            },
        )
        .sample_size(10),
    );
}

fn key_generation(c: &mut Criterion) {
    c.bench(
        "key generation",
        Benchmark::new("Generate random keypair", move |b| {
            b.iter(|| {
                black_box(Keypair::random(&mut rand::thread_rng()));
            })
        }),
    );

    c.bench(
        "key generation",
        Benchmark::new("Generate keypair from known string", move |b| {
            b.iter(|| {
                let secret = vec![42; 48];
                let sk = SecretKey::from_bytes(&secret).unwrap();
                let pk = PublicKey::from_secret_key(&sk);
                let keypair = Keypair { sk, pk };
                black_box(keypair);
            })
        }),
    );
}

criterion_group!(
    benches,
    aggregate_verfication_multiple_signatures,
    aggregate_verfication_multiple_messages,
    signing,
    aggregate_verfication,
    aggregation,
    compression_signature,
    compression_public_key,
    compression_public_key_bigs,
    key_generation
);
criterion_main!(benches);
