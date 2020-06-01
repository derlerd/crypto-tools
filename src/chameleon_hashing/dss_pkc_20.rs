use rand::{CryptoRng, RngCore};

use std::marker::PhantomData;

use crate::chameleon_hashing::{ChameleonHash, Error};
use crate::encryption::elgamal::{
    ElGamal, ElGamalCiphertext, ElGamalMessage, ElGamalPublicKey, ElGamalSecretKey,
};
use crate::encryption::EncryptionScheme;
use crate::encryption::Error as EncryptionError;
use crate::zkproofs::sigma_protocols::dlog::DlogWitness;
use crate::zkproofs::sigma_protocols::Error as SigmaProtocolError;
use crate::zkproofs::Error as ProofSystemError;
use crate::zkproofs::{DlOrDlEq, ProofSystem};

pub struct DssPkc20<RNG: RngCore + CryptoRng> {
    phantom_rng: PhantomData<RNG>,
}

#[derive(Debug)]
pub enum DssPkc20Error {
  ProofSystemError(ProofSystemError),
  SigmaProtocolError(SigmaProtocolError),
}

impl From<EncryptionError> for Error<DssPkc20Error> {
    fn from(error: EncryptionError) -> Error<DssPkc20Error> {
        match error {
            EncryptionError::UnsupportedKeyLength(key_len) => Error::UnsupportedKeyLength(key_len),
        }
    }
}

impl From<ProofSystemError> for Error<DssPkc20Error> {
    fn from(error: ProofSystemError) -> Error<DssPkc20Error> {
        Error::ImplementationSpecificError(DssPkc20Error::ProofSystemError(error))
    }
}

impl From<SigmaProtocolError> for Error<DssPkc20Error> {
    fn from(error: SigmaProtocolError) -> Error<DssPkc20Error> {
        Error::ImplementationSpecificError(DssPkc20Error::SigmaProtocolError(error))
    }
}

impl std::fmt::Display for DssPkc20Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "daaaaamn this went wrong")
    }
}

impl<RNG: RngCore + CryptoRng> ChameleonHash<RNG> for DssPkc20<RNG> {
    type SK = ElGamalSecretKey;
    type PK = ElGamalPublicKey;
    type MSG = ElGamalMessage;
    type CH = ElGamalCiphertext;
    type RND = <DlOrDlEq<RNG> as ProofSystem<RNG>>::P;
    type E = DssPkc20Error;

    fn key_gen(key_len: u32, rng: &mut RNG) -> Result<(ElGamalSecretKey, ElGamalPublicKey), Error<DssPkc20Error>> {
        let key_pair = ElGamal::<RNG>::key_gen(key_len, rng)?;

        Ok(key_pair)
    }

    fn hash(
        public_key: &Self::PK,
        message: Self::MSG,
        rng: &mut RNG,
    ) -> Result<(Self::CH, Self::RND), Error<DssPkc20Error>> {
        let (c, r) = ElGamal::<RNG>::encrypt_reveal_randomness(public_key, &message, rng);

        let x1 = public_key.clone().into();

        let x2 =
            ElGamal::<RNG>::prepare_well_formedness_proof(public_key.clone(), c.clone(), message)
                .into();
        let w2 = r.into();

        let x = DlOrDlEq::<RNG>::compile_statement(x1, x2);
        let w = DlOrDlEq::<RNG>::compile_witness(None, Some(w2))?;

        let p = DlOrDlEq::<RNG>::prove(&x, &w, rng)?;

        Ok((c, p))
    }
    fn check(
        public_key: &Self::PK,
        message: Self::MSG,
        randomness: &Self::RND,
        hash: &Self::CH,
    ) -> bool {
        let x1 = public_key.clone().into();
        let x2 = ElGamal::<RNG>::prepare_well_formedness_proof(
            public_key.clone(),
            hash.clone(),
            message,
        )
        .into();
        let x = DlOrDlEq::<RNG>::compile_statement(x1, x2);

        DlOrDlEq::<RNG>::verify(&x, randomness)
    }
    fn adapt(
        secret_key: &Self::SK,
        old_message: &Self::MSG,
        new_message: &Self::MSG,
        randomness: &Self::RND,
        hash: &Self::CH,
        rng: &mut RNG,
    ) -> Result<Self::RND, Error<DssPkc20Error>> {
        if Self::check(&secret_key.into(), old_message.clone(), randomness, hash) == false {
            panic!("{:?}");
        }

        let pk: ElGamalPublicKey = secret_key.into();

        let x1 = pk.clone().into();
        let x2 = ElGamal::<RNG>::prepare_well_formedness_proof(
            pk.clone(),
            hash.clone(),
            new_message.clone(),
        )
        .into();

        let w1: DlogWitness = secret_key.clone().into();

        let x = DlOrDlEq::<RNG>::compile_statement(x1, x2);
        let w = DlOrDlEq::<RNG>::compile_witness(Some(w1), None)?;

        let p = DlOrDlEq::<RNG>::prove(&x, &w, rng)?;

        Ok(p)
    }
}
