pub mod data_structure;
pub mod generator;
pub mod prover;
pub mod r1cs_to_qap;
pub mod verifier;

mod test;

pub use self::data_structure::*;
pub use self::{generator::*, prover::*, verifier::*};
pub use r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

use std::marker::PhantomData;

use ark_crypto_primitives::snark::*;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::{
    rand::{CryptoRng, RngCore},
    vec::Vec,
};

pub struct CcGroth16<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: PhantomData<(E, QAP)>,
}

impl<E: Pairing, QAP: R1CSToQAP> SNARK<E::ScalarField> for CcGroth16<E, QAP> {
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type Proof = Proof<E>;
    type Error = SynthesisError;
    type ProcessedVerifyingKey = PreparedVerifyingKey<E>;

    fn circuit_specific_setup<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore + CryptoRng>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        let pk = Self::generate_random_parameters_with_reduction(circuit, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }

    fn prove<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore + CryptoRng>(
        pk: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        Self::create_random_proof_with_reduction(circuit, pk, rng)
    }

    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        Ok(prepare_verifying_key(circuit_vk))
    }

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        public_inputs: &[E::ScalarField],
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        Ok(Self::verify_proof(&circuit_pvk, proof, &public_inputs)?)
    }
}
