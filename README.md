# Crypto Tools

The goal of this library is to provide efficient and easy to use implementations for prototyping cryptographic implementations. We put a special focus on abstractions in the sense that generic transformations known from the cryptographic literature are generically implemented. This minimizes (1) the amount of code that needs to be written to add an implementation of a new scheme, as well as (2) the potential to introduce errors when implementing the same "generic" transformations individually for every scheme.

_WARNING: This code is currently work in progress and not intended for production use!_

## Traits defining cryptographic primitives

- Sigma protocols for statements over prime order `p` groups (`SigmaProtocol`). The challenge space of all Sigma protocols implementing this trait must be `ℤ_p` to be able to generically derive implementations of conjunctions and disjunctions of languages.
- [Fiat-Shamir](https://doi.org/10.1007%2F3-540-68339-9_33) convertible Sigma protocols (`FsConvertibleSigmaProtocol`). The interface is aligned with the compiler in [FMKV'12](https://eprint.iacr.org/2012/704.pdf) so that one can also implement variants of the FS transform providing stronger guarantees regarding non-malleability.
- Fiat-Shamir-type proof systems over prime order groups (`FsProofSystem`).
- Encryption schemes (`EncryptionScheme`).
- Common trait that allows to define how certain objects should be hashed (`Hashable`). 
- Chameleon hash functions (`ChameleonHash`).

Note that we currently fix the [Ristretto group](https://ristretto.group/) as the used prime order group and use the implementation provided by the [curve25519-dalek library](https://github.com/dalek-cryptography/curve25519-dalek). In the future we plan to introduce an abstraction layer to allow use of this library with arbitrary prime-order groups. 

## Implementations 

- The `Hash` and `Hashable` traits provide several convenience methods for domain separated hashing.
- Sigma protocols for proving knowledge of the following:
  - A discrete logarithm `x` relative to two group elements `(g, h)` so that `h = g^x`.    
  - A discrete logarithm `x` relative to four group elements `(g, h, g', h')` so that `h = g^x ∧ h' = g'^x`.
- A generic implementation of the OR composition of two Sigma protocols.
- A generic implementation turning every Sigma protocol that implements the `FsConvertibleSigmaProtocol` trait into a `FsProofSystem`, i.e., generically applies the [Fiat-Shamir](https://doi.org/10.1007%2F3-540-68339-9_33) transform and additionally includes the statement in the hash when obtaining the challenge for stronger non-malleability guarantees [FMKV'12](https://eprint.iacr.org/2012/704.pdf).
- [ElGamal](https://doi.org/10.1007%2FBFb0054851) encryption. 
- Fully collision resistant chameleon hashes from [this paper](https://eprint.iacr.org/2020/403.pdf). 

## TODO 

A non-exhaustive list of open TODOs and other future plans can be found below:

- Abstract groups so that implementation is generic over which groups are used
- Serialization and deserialization logic
- In-depth review
