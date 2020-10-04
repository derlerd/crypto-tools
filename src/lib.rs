//! A modular implementation various modern cryptographic tools and primitives.

// We allow clippy::op_ref for some of the modules, because this warning fires
// when calling `&a * &b` when `a` and `b` are copy types. The warning suggests
// to do `a * b` instead but this would cause an implicit copy of the object
// in some cases, resulting in a performance penalty.
//
/// Chameleon hashes.
#[allow(clippy::op_ref)]
pub mod chameleon_hashing;
/// Encryption schemes.
#[allow(clippy::op_ref)]
pub mod encryption;
/// Convenience functions for hashing.
pub mod hashing;
/// Zero-knowledge proofs, Sigma protocols, Fiat-Shamir transformation, Compositions, ...
#[allow(clippy::op_ref)]
pub mod zkproofs;
