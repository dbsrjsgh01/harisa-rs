pub mod data_structure;
pub mod generator;
pub mod prover;
pub mod verifier;

pub mod arithm;
pub mod bound;

pub mod hash_to_prime;

// mod test;

use std::marker::PhantomData;

pub use crate::core::cc_snark::*;
use crate::BasePrimeField;

pub use ark_ec::pairing::Pairing;
use ark_r1cs_std::pairing::PairingVar;

pub struct Harisa<E: Pairing> {
    _curve: PhantomData<E>,
}

impl<E: Pairing> Harisa<E> {}
