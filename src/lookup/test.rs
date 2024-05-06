use crate::core::cc_snark::{prepare_verifying_key, CcGroth16};
use crate::core::pedersen::data_structure::{Commitment, Parameters, Plaintext, Randomness};
use crate::core::pedersen::Pedersen;
use crate::harisa::constants::*;
use crate::harisa::harisa::Harisa;
use crate::lookup::{
    concatenate::concatenate, copy_this_or_that::CopyThisOrThat, lookup::HarisaLookup,
    well_transform::WellTransform,
};
use crate::ConstraintF;
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_r1cs_std::pairing::PairingVar;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::{
    rand::{Rng, RngCore, SeedableRng},
    test_rng, One, UniformRand,
};

const LOOKUP_SIZE: usize = 32;

#[allow(non_camel_case_types)]
struct TestCircuit<F: Field> {
    msg_vec: [Option<F>; LOOKUP_SIZE],
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for TestCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        for (idx, msg) in self.msg_vec.iter().enumerate() {
            cs.new_input_variable(|| msg.ok_or(SynthesisError::AssignmentMissing))?;
        }
        Ok(())
    }
}

fn test_lookup<E: Pairing>() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let mut set = Vec::new();

    for i in 0..ODD_PRIME.len() {
        set.push(E::ScalarField::from(ODD_PRIME[i]));
    }

    let pp = HarisaLookup::<E, Harisa<E>>::generate_lookup_parameter(
        set,
        Some(TestCircuit {
            msg_vec: [None; LOOKUP_SIZE],
        }),
        Some(TestCircuit {
            msg_vec: [None; LOOKUP_SIZE],
        }),
        Some(TestCircuit {
            msg_vec: [None; LOOKUP_SIZE],
        }),
        Some(TestCircuit {
            msg_vec: [None; LOOKUP_SIZE],
        }),
        &mut rng,
    )
    .unwrap();

    let mut lookup = Vec::new();

    for i in 0..LOOKUP_SIZE {
        let prob: usize = rng.gen::<usize>() % 100;

        let l_i = if prob > 40 {
            E::ScalarField::from(ODD_PRIME[i])
        } else {
            let r: usize = rng.gen::<usize>() % 256;
            E::ScalarField::from(ODD_PRIME[r])
        };

        lookup.push(l_i);
    }

    // (pp, cm_u, cm_a, cm_z, u, a, z, o_u, o_a, o_z)
}
