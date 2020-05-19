extern crate amcl;
extern crate criterion;
extern crate hex;
extern crate milagro_bls;
extern crate rand;

use criterion::{black_box, criterion_group, criterion_main, Benchmark, Criterion};
use milagro_bls::*;

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
    let sig = Signature::new(&msg.as_bytes(), &sk);

    c.bench(
        "signing",
        Benchmark::new("Create a Signature", move |b| {
            b.iter(|| {
                black_box(Signature::new(&msg.as_bytes(), &sk));
            })
        })
        .sample_size(10),
    );

    c.bench(
        "signing",
        Benchmark::new("Verify a Signature", move |b| {
            b.iter(|| {
                black_box(sig.verify(&msg.as_bytes(), &pk));
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
    let sig = Signature::new(&msg.as_bytes(), &sk);

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

    for _ in 0..n {
        let keypair = Keypair::random(&mut rand::thread_rng());
        let sig = Signature::new(&msg[..], &keypair.sk);
        agg_sig.add(&sig);
        pubkeys.push(keypair.pk);
    }

    assert_eq!(pubkeys.len(), n);

    c.bench(
        "aggregation",
        Benchmark::new("Verifying aggregate of 128 signatures", move |b| {
            b.iter(|| {
                let pubkeys_as_ref: Vec<&PublicKey> = pubkeys.iter().collect();
                let agg_pub = AggregatePublicKey::aggregate(pubkeys_as_ref.as_slice());
                let verified = agg_sig.fast_aggregate_verify_pre_aggregated(&msg[..], &agg_pub);
                assert!(verified);
            })
        })
        .sample_size(100),
    );
}

fn aggregate_verfication_multiple_signatures(c: &mut Criterion) {
    let mut rng = &mut rand::thread_rng();
    let n = 10; // Signatures
    let m = 3; // PublicKeys per Signature
    let mut msgs: Vec<Vec<u8>> = vec![vec![]; n];
    let mut aggregate_public_keys: Vec<AggregatePublicKey> = vec![];
    let mut aggregate_signatures: Vec<AggregateSignature> = vec![];

    let keypairs: Vec<Keypair> = (0..n * m).map(|_| Keypair::random(&mut rng)).collect();

    for i in 0..n {
        let mut aggregate_signature = AggregateSignature::new();
        let mut aggregate_public_key = AggregatePublicKey::new();
        msgs[i] = vec![i as u8; 32];
        for j in 0..m {
            let keypair = &keypairs[i * m + j];
            let signature = Signature::new(&msgs[i], &keypair.sk);

            aggregate_public_key.add(&keypair.pk);
            aggregate_signature.add(&signature);
        }
        aggregate_public_keys.push(aggregate_public_key);
        aggregate_signatures.push(aggregate_signature);
    }

    // Remove mutability
    let msgs: Vec<Vec<u8>> = msgs;
    let aggregate_public_keys: Vec<AggregatePublicKey> = aggregate_public_keys;
    let aggregate_signatures: Vec<AggregateSignature> = aggregate_signatures;

    c.bench(
        "multiple-signatures-verification-30",
        Benchmark::new(
            "Verification of multiple aggregate signatures with optimizations",
            move |b| {
                b.iter(|| {
                    let mut rng = rand::thread_rng();
                    // Create reference iterators
                    let ref_vec = vec![1u8; 32];
                    let ref_apk = AggregatePublicKey::new();
                    let ref_as = AggregateSignature::new();
                    let mut msgs_refs: Vec<&[u8]> = vec![&ref_vec; n];
                    let mut aggregate_public_keys_refs: Vec<&AggregatePublicKey> =
                        vec![&ref_apk; n];
                    let mut aggregate_signatures_refs: Vec<&AggregateSignature> = vec![&ref_as; n];

                    for i in 0..n {
                        msgs_refs[i] = &msgs[i];
                        aggregate_signatures_refs[i] = &aggregate_signatures[i];
                        aggregate_public_keys_refs[i] = &aggregate_public_keys[i];
                    }
                    let signature_sets = aggregate_signatures_refs
                        .into_iter()
                        .zip(aggregate_public_keys_refs)
                        .zip(msgs_refs.iter().map(|x| *x))
                        .map(|((a, b), c)| (a, b, c));
                    AggregateSignature::verify_multiple_aggregate_signatures(
                        &mut rng,
                        signature_sets,
                    );
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
                let sk = SecretKey::random(&mut rand::thread_rng());
                let pk = PublicKey::from_secret_key(&sk);
                let keypair = Keypair { sk, pk };
                black_box(keypair);
            })
        }),
    );
}

criterion_group!(
    benches,
    signing,
    aggregate_verfication_multiple_signatures,
    aggregate_verfication,
    aggregation,
    compression_signature,
    compression_public_key,
    compression_public_key_bigs,
    key_generation
);
criterion_main!(benches);
