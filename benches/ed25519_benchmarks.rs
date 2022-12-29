// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2018-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[macro_use]
extern crate criterion;
extern crate ed25519_dalek;
extern crate rand;

use criterion::Criterion;

mod ed25519_benches {
    use super::*;

    #[cfg(all(
        any(feature = "batch", feature = "batch_deterministic"),
        any(feature = "alloc", feature = "std")
    ))]
    use noah_ed25519_dalek::verify_batch;

    use noah_ed25519_dalek::Keypair;
    use noah_ed25519_dalek::Signature;
    use noah_ed25519_dalek::Signer;
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    fn sign(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";

        c.bench_function("Ed25519 signing", move |b| b.iter(|| keypair.sign(msg)));
    }

    fn verify(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let sig: Signature = keypair.sign(msg);

        c.bench_function("Ed25519 signature verification", move |b| {
            b.iter(|| keypair.verify(msg, &sig))
        });
    }

    fn verify_strict(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let sig: Signature = keypair.sign(msg);

        c.bench_function("Ed25519 strict signature verification", move |b| {
            b.iter(|| keypair.verify_strict(msg, &sig))
        });
    }

    #[cfg(all(
        any(feature = "batch", feature = "batch_deterministic"),
        any(feature = "alloc", feature = "std")
    ))]
    fn verify_batch_signatures(c: &mut Criterion) {
        use criterion::BenchmarkId;
        use ed25519_dalek::PublicKey;

        static BATCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 96, 128, 256];
        let mut group = c.benchmark_group("batch-signature-verification");
        for i in BATCH_SIZES {
            group.bench_with_input(
                BenchmarkId::new("Ed25519 batch signature verification", &i),
                &i,
                |b, &size| {
                    let mut csprng: ThreadRng = thread_rng();
                    let keypairs: Vec<Keypair> =
                        (0..size).map(|_| Keypair::generate(&mut csprng)).collect();
                    let msg: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                    let messages: Vec<&[u8]> = (0..size).map(|_| msg).collect();
                    let signatures: Vec<Signature> =
                        keypairs.iter().map(|key| key.sign(&msg)).collect();
                    let public_keys: Vec<PublicKey> =
                        keypairs.iter().map(|key| key.public_key()).collect();

                    b.iter(|| verify_batch(&messages[..], &signatures[..], &public_keys[..]));
                },
            );
        }
    }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();

        c.bench_function("Ed25519 keypair generation", move |b| {
            b.iter(|| Keypair::generate(&mut csprng))
        });
    }

    #[cfg(all(
        any(feature = "batch", feature = "batch_deterministic"),
        any(feature = "alloc", feature = "std")
    ))]
    criterion_group! {
        name = ed25519_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            verify_strict,
            verify_batch_signatures,
            key_generation,
    }

    #[cfg(not(all(
        any(feature = "batch", feature = "batch_deterministic"),
        any(feature = "alloc", feature = "std")
    )))]
    criterion_group! {
        name = ed25519_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            verify_strict,
            key_generation,
    }
}

criterion_main!(ed25519_benches::ed25519_benches);
