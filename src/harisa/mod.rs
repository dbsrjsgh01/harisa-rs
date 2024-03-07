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

use ark_crypto_primitives::snark::*;
pub use ark_ec::pairing::Pairing;
use ark_r1cs_std::pairing::PairingVar;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::RngCore;

pub struct Harisa<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _curve: PhantomData<(E, QAP)>,
}
