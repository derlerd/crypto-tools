use digest::Digest;
use sha2::Sha256;

use crate::hashing::{DomainSeparatedHash, DomainSeparator};

fn assert_fn_panics<F: FnOnce() + std::panic::UnwindSafe>(f: F) {
    if std::panic::catch_unwind(f).is_ok() {
        panic!("Expected call to fail but it succeeded");
    }
}

fn input_without_init_helper() {
    let mut h = DomainSeparatedHash::<Sha256>::new();
    h.input(b"0101");
}

fn chain_without_init_helper() {
    let h = DomainSeparatedHash::<Sha256>::new();
    h.chain(b"0101");
}

fn result_without_init_helper() {
    let h = DomainSeparatedHash::<Sha256>::new();
    h.result();
}

fn result_reset_without_init_helper() {
    let mut h = DomainSeparatedHash::<Sha256>::new();
    h.result_reset();
}

fn reset_without_init_helper() {
    let mut h = DomainSeparatedHash::<Sha256>::new();
    h.reset();
}

fn digest_panics_helper() {
    DomainSeparatedHash::<Sha256>::digest(b"0101");
}

#[test]
fn test_uninitialized_calls_fail() {
    assert_fn_panics(|| {
        input_without_init_helper();
    });
    assert_fn_panics(|| {
        chain_without_init_helper();
    });
    assert_fn_panics(|| {
        result_without_init_helper();
    });
    assert_fn_panics(|| {
        result_reset_without_init_helper();
    });
    assert_fn_panics(|| {
        reset_without_init_helper();
    });
    assert_fn_panics(|| {
        digest_panics_helper();
    });
}

fn initialize_hash_tuple<DIG: Digest>() -> (DIG, DomainSeparatedHash<DIG>) {
    let mut h1 = DIG::new();
    h1.input("4test".to_string());

    let mut h2 = DomainSeparatedHash::<DIG>::new();
    let context = DomainSeparator::from_string("test".to_string());
    h2.init(context);

    (h1, h2)
}

#[test]
fn test_output_size_equal_to_underlying_hash() {
    assert_eq!(
        DomainSeparatedHash::<Sha256>::output_size(),
        Sha256::output_size(),
        "Expected that DomainSeparatedHash has the same output 
               size as the underlying hash. Expected {}, got {}.",
        DomainSeparatedHash::<Sha256>::output_size(),
        Sha256::output_size()
    );
}

#[test]
fn test_hashes_yield_same_result() {
    let (h1, h2) = initialize_hash_tuple::<Sha256>();

    assert_eq!(
        h1.chain("test".to_string()).result(),
        h2.chain("test".to_string()).result()
    );

    let (mut h1, mut h2) = initialize_hash_tuple::<Sha256>();

    h1.input("test".to_string());
    h2.input("test".to_string());

    assert_eq!(h1.result_reset(), h2.result_reset());

    assert_fn_panics(move || {
        h2.input(b"0101");
    });
}
