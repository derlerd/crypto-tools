pub mod dlog;
pub mod dlogeq;
pub mod fiat_shamir;
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

pub trait SigmaProtocol {
    type S;
    type W;
    type COM;
    type ST;
    type RSP;
    type STS: SimulatorState<RSP = Self::RSP>;

    fn commit<RNG: RngCore + CryptoRng>(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Result<(Self::COM, Self::ST), Error>;
    fn challenge<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Challenge;
    fn response(
        statement: &Self::S,
        witness: &Self::W,
        challenge: &Challenge,
        state: Self::ST,
    ) -> Self::RSP;
    fn check(
        statement: &Self::S,
        commitment: &Self::COM,
        challenge: &Challenge,
        response: &Self::RSP,
    ) -> bool;
    fn simulate<RNG: RngCore + CryptoRng>(
        statement: &Self::S,
        rng: &mut RNG,
    ) -> (Self::COM, Self::STS);
}

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
