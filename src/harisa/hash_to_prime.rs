use crate::BasePrimeField;

use ark_ec::pairing::Pairing;

use ark_std::rand::Rng;
use ark_std::{
    cfg_into_iter, cfg_iter,
    ops::{AddAssign, Mul},
    vec::Vec,
};

use ark_relations::r1cs::SynthesisError;

use ark_std::rand::{CryptoRng, RngCore, SeedableRng};
use ark_std::{test_rng, UniformRand};

pub fn hash_to_prime<E: Pairing, R: Rng + RngCore + CryptoRng>(
    input: Vec<E::G1Affine>,
    rng: &mut R,
) -> Result<E::ScalarField, SynthesisError> {
    // 기존 Harisa: Poseidon
    // 우리는? 그냥 bit transition & circuit에서 확인

    Ok(E::ScalarField::rand(rng))
}
