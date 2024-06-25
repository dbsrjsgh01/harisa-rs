use std::marker::PhantomData;
use std::str::FromStr;

use crate::ConstraintF;
use crate::{
    cc_snark::{
        data_structure::{ProvingKey, VerifyingKey},
        r1cs_to_qap::R1CSToQAP,
        CcGroth16,
    },
    harisa::constants::RSA_2048,
};

use super::data_structure::HarisaPP;
use super::harisa::Harisa;
use super::precompute::*;

use ark_crypto_primitives::snark::*;
use ark_ec::pairing::Pairing;
use ark_r1cs_std::pairing::PairingVar;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::{
    rand::{CryptoRng, Rng, RngCore},
    UniformRand,
};
use num_bigint::BigInt;

impl<E: Pairing, QAP: R1CSToQAP> Harisa<E, QAP> {
    pub fn generate_cc_snark_parameters<
        C: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng,
    >(
        circuit: C,
        rng: &mut R,
    ) -> Result<(ProvingKey<E>, VerifyingKey<E>), SynthesisError> {
        let cc_snark_generator = start_timer!(|| "ccGroth::Generator");
        let (cc_ek, cc_vk) = CcGroth16::<E>::circuit_specific_setup(circuit, rng).unwrap();
        end_timer!(cc_snark_generator);
        Ok((cc_ek, cc_vk))
    }

    pub fn generate_harisa_parameters<
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        set: Vec<BigInt>,
        arithm_circuit: Arithm,
        bound_circuit: Bound,
        rng: &mut R,
    ) -> Result<(HarisaPP<E>, Vec<BigInt>), SynthesisError> {
        let num = set.len();
        let harisa_generation = start_timer!(|| "HARiSA::Generator");

        let arithm_generation = start_timer!(|| "arithm::generator");
        let (arithm_ek, arithm_vk) =
            Self::generate_cc_snark_parameters(arithm_circuit, rng).unwrap();
        end_timer!(arithm_generation);

        let bound_generation = start_timer!(|| "bound::generator");
        let (bound_ek, bound_vk) = Self::generate_cc_snark_parameters(bound_circuit, rng).unwrap();
        end_timer!(bound_generation);

        end_timer!(harisa_generation);

        let (g, mod_n) = rsa_setup();

        let preprocessing = start_timer!(|| "HARiSA::Preprocess");
        let table = precompute(g.clone(), mod_n.clone(), set);
        end_timer!(preprocessing);

        Ok((
            HarisaPP {
                arithm_ek: arithm_ek.clone(),
                arithm_vk: arithm_vk.clone(),
                bound_ek: bound_ek.clone(),
                bound_vk: bound_vk.clone(),
                g: g.clone(),
                mod_n: mod_n.clone(),
            },
            table,
        ))
    }
}
