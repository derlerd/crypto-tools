/// Sigma protocols and Fiat-Shamir transform related implementations for
/// the language `S = { (g_1, g_2) | ∃ x : g_1^x = g_2 }`, where `g_1` and
/// `g_2` are elements of the underlying group.
pub mod dlog;

/// Sigma protocols and Fiat-Shamir transform related implementations for
/// the language `S = { (g_1, g_2, h_1, h_2) | ∃ x : g_1^x = g_2 ∧ h_1^x = h_2 }`,
/// where `g_1`, g_2`, `h_1`, and `h_2` are elements of the underlying group.
pub mod dlogeq;

/// Fiat-Shamir transform related things.
pub mod fiat_shamir;

/// Generic OR-composition of Sigma protocols and their Fiat-Shamir transform.
pub mod or_composition;

#[cfg(test)]
mod tests;

use curve25519_dalek::scalar::Scalar;

use std::ops::{Add, Sub};

use rand::{CryptoRng, RngCore};

#[derive(Debug)]
pub enum Error {
    InvalidWitness,
}

/// The challenge common to all Sigma protocols implementing the
/// Sigma protocol trait.
#[derive(Clone)]
pub struct Challenge(Scalar);

impl Sub for &Challenge {
    type Output = Challenge;

    fn sub(self, other: &Challenge) -> Challenge {
        Challenge(self.0 - other.0)
    }
}

impl Add for &Challenge {
    type Output = Challenge;

    fn add(self, other: &Challenge) -> Challenge {
        Challenge(self.0 + other.0)
    }
}

/// Represents a [Sigma protocol](https://cs.au.dk/~ivan/Sigma.pdf). All
/// Sigma protocols in this module are assumed to have the same challenge
/// space to ensure the possibility of composing them.
///
/// # Intuition of Sigma protocols
/// Sigma protocols are interactive 3-move protocols executed by a prover
/// and a verifier. In the first phase, the prover sends a first message
/// representing a commitment to its random coins. The verifier replies
/// with a random challenge, and, finally, the prover answers with the
/// a response. Based on this response the verifier decides whether to
/// accept or reject the transcript. A Sigma protocols is defined for
/// a particular NP-language `S` with associated witness relation `R`,
/// i.e., so that a statement `s` is in `S` if there exists a witness
/// `w` so that `R(s, w) = 1`. A Sigma protocol for some language `S`
/// can be used to convince a verifier that some statement `s` is in
/// `S`.
///
/// The [challenge space](struct.Challenge.html) to be the same for all
/// Sigma protocols implementing this trait.  
pub trait SigmaProtocol {
    /// The space the statements live in.
    type S;

    /// The space the witnesses live in.
    type W;

    /// The space the first message from the prover to the verifier lives
    /// in (i.e., commitments to the random coins)
    type COM;

    /// The space the prover state, used to pass information from the
    /// algorithm representing the first prover phase to the algorithm
    /// representing the second prover phase.
    type ST;

    /// The space the prover's responses live in.
    type RSP;

    /// The space the simulator state lives in.
    type STS: SimulatorState<RSP = Self::RSP>;

    /// Runs the first phase of the prover which takes a `statement`,
    /// a `witness`, as well as an `rng`, and returns a commitment to
    /// the prover's random coins and some state to be passed to the
    /// `response` algorithm representing the second prover phase.
    fn commit<RNG: RngCore + CryptoRng>(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Result<(Self::COM, Self::ST), Error>;

    /// Runs the first phase of the verifier which takes an `rng` and
    /// returns a `Challenge`.
    fn challenge<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Challenge;

    /// Runs the second phase of the prover which takes a `statement`,
    /// a `witness`, a `challenge` and some `state`, and returns a
    /// response.
    fn response(
        statement: &Self::S,
        witness: &Self::W,
        challenge: &Challenge,
        state: Self::ST,
    ) -> Self::RSP;

    /// The algorithm representing the decision phase of the verifier,
    /// which takes a `statement`, a `commitment`, a `challenge`, as
    /// well as a `response` and outputs `true` if the transcript is
    /// considered valid, and `false` otherwise.
    fn check(
        statement: &Self::S,
        commitment: &Self::COM,
        challenge: &Challenge,
        response: &Self::RSP,
    ) -> bool;

    /// Outputs a simulated transcript.
    fn simulate<RNG: RngCore + CryptoRng>(
        statement: &Self::S,
        rng: &mut RNG,
    ) -> (Self::COM, Self::STS);
}

/// Represents the simulator state of a Sigma protocol and a
/// way for decomposing it into its individual components.
pub trait SimulatorState {
    type RSP;
    fn decompose(self) -> (Challenge, Self::RSP);
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidWitness => write!(
                f,
                "The given witness does not attest membership of the statement in the language."
            ),
        }
    }
}
