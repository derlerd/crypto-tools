use crate::zkproofs::sigma_protocols::{Challenge, SigmaProtocol};

use digest::generic_array::typenum::U64;
use digest::Digest;

/// Represents a [Fiat-Shamir](https://doi.org/10.1007%2F3-540-68339-9_33)
/// convertible Sigma protocol. The interface is aligned with the compiler
/// in [FMKV'12](https://eprint.iacr.org/2012/704.pdf) so that one can
/// also implement variants of the FS transform providing stronger guarantees
/// regarding non-malleability.
///
/// # Some background on the FS transform
/// The Fiat-Shamir transform allows to transfer Sigma protocols, which are
/// interactive 3-move protocols, into their non-interactive counterparts.
/// The idea behind the Fiat-Shamir transform is to compute the challenge
/// that is otherwise sent as the first message of the verifier after it
/// has seen the first message of the prover as a hash of the first message
/// of the prover. Intuitively, this ensures that--analogously to the
/// interactive version--the prover can not predict the challenge before
/// committing itself to the first message. One can argue about its security
/// in the random oracle model.
pub trait FsConvertibleSigmaProtocol<SP, DIG>
where
    DIG: Digest<OutputSize = U64>,
    SP: SigmaProtocol,
{
    /// The space where the corresponding proofs live in.
    type FSP;

    /// Returns the domain separator to be used upon hashing the challenge.
    /// This is provided as an explicit function to allow to combine domain
    /// separators upon generic compositions of Sigma protocols.
    fn domain_separator() -> String;

    /// Returns the hash of the given `statement` (optionally) and the given
    /// `commitment` and computes a `Challenge` according to the used variant
    /// of the FS transform.
    fn hash_challenge(statement: &SP::S, commitment: &SP::COM) -> Challenge;

    /// Compiles a proof from a given `commitment` and a given `response`.
    fn compile_proof(commitment: SP::COM, response: SP::RSP) -> Self::FSP;

    /// Unwraps a given `proof` and returns a commitment-response tuple
    /// to be used for verification in the underlying sigma protocol.
    fn unwrap_proof(proof: &Self::FSP) -> (&SP::COM, &SP::RSP);
}
