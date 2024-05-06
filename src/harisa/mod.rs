pub mod data_structure;
pub mod prover;
pub mod setup;
pub mod verifier;

pub mod arithm;
pub mod bound;
pub mod constants;
pub mod harisa;
pub mod preprocess;

pub mod hash_to_prime;

mod test;

use std::marker::PhantomData;

pub use crate::core::cc_snark::*;
use crate::core::pedersen::data_structure::{Commitment, Parameters, Plaintext, Randomness};

use ark_crypto_primitives::snark::*;
use ark_ec::pairing::Pairing;
use ark_r1cs_std::pairing::PairingVar;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::{CryptoRng, Rng, RngCore};

pub type Error = Box<dyn ark_std::error::Error>;

pub trait Membership<E: Pairing> {
    type Parameters;
    type CMPP;
    type Table;
    type Proof;

    fn setup<
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        set: Vec<E::ScalarField>,
        arithm_circuit: Arithm,
        bound_circuit: Bound,
        rng: &mut R,
    ) -> Result<(Self::Parameters, Self::Table), Error>;

    fn prove<
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        pp: Self::Parameters,
        accum: E::G1Affine,
        cm_u: Commitment<E::G1>,
        u: Plaintext<E::G1>,
        o_u: Randomness<E::G1>,
        arithm_circuit: Arithm,
        bound_circuit: Bound,
        rng: &mut R,
    ) -> Result<Self::Proof, Error>;

    fn verify(
        pp: Self::Parameters,
        accum: E::G1Affine,
        c_u: Commitment<E::G1>,
        proof: Self::Proof,
    ) -> Result<bool, Error>;
}
