use criterion::{Criterion, criterion_group, criterion_main};

use rand::thread_rng;
use sha2::Sha512;

use chameleon_hashing::{ChameleonHash, dss_pkc_20::DssPkc20};
use encryption::elgamal::ElGamalMessage;

pub fn bench_keygen(c: &mut Criterion) {
    c.bench_function("dss_20_key_gen", |b| {
        b.iter(|| {
            let (_sk, _pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();
        })
    });
}

pub fn bench_hash(c: &mut Criterion) {
    let (_sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());

    c.bench_function("dss_20_hash", |b| {
        b.iter(|| {
            let (_h, _r) = DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng())
                .expect("Error upon hashing");
        })
    });
}

pub fn bench_adapt(c: &mut Criterion) {
    let (sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());

    let (h, r) =
        DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng()).expect("Error upon hashing");

    let msg_adapted = ElGamalMessage::from_string::<Sha512>("Adapted".to_string());

    c.bench_function("dss_20_adapt", |b| {
        b.iter(|| {
            let _r_adapt =
                DssPkc20::adapt(&sk, &msg_original, &msg_adapted, &r, &h, &mut thread_rng())
                    .expect("Error upon adapting");
        })
    });
}

pub fn bench_verify(c: &mut Criterion) {
    let (_sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());

    let (h, r) =
        DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng()).expect("Error upon hashing");

    c.bench_function("dss_20_verify", |b| {
        b.iter(|| {
            let _success = DssPkc20::check(&pk, msg_original.clone(), &r, &h);
        })
    });
}

criterion_group!(benches, bench_keygen, bench_hash, bench_adapt, bench_verify);
criterion_main!(benches);
