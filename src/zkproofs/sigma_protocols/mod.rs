pub mod dlog;
pub mod dlogeq;
pub mod fiat_shamir;
pub mod or_composition;

use curve25519_dalek::scalar::Scalar;

use std::ops::{Add, Sub};

pub struct Challenge(pub Scalar);

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

pub trait SigmaProtocol<RNG> {
    type S;
    type W;
    type COM;
    type ST;
    type RSP;
    type STS: SimulatorState<RSP = Self::RSP>;

    fn commit(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Option<(Self::COM, Self::ST)>;
    fn challenge(rng: &mut RNG) -> Challenge;
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
    fn simulate(statement: &Self::S, rng: &mut RNG) -> (Self::COM, Self::STS);
}

pub trait SimulatorState {
    type RSP;
    fn decompose(self) -> (Challenge, Self::RSP);
}