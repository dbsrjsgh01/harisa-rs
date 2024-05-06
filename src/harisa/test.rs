use std::ops::Bound;

use crate::{
    core::pedersen::{
        self,
        data_structure::{Commitment, Parameters, Plaintext, Randomness},
        Pedersen,
    },
    harisa::{arithm::ArithmCircuit, bound::BoundCircuit, harisa::Harisa},
    ConstraintF,
};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_r1cs_std::pairing::PairingVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{
    rand::{CryptoRng, Rng, RngCore, SeedableRng},
    test_rng, UniformRand,
};

use super::prepare_verifying_key;

const SET_SIZE: usize = 32;

#[allow(non_camel_case_types)]
struct TestCircuit<F: Field> {
    msg_vec: [Option<F>; SET_SIZE],
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

fn test_harisa<E: Pairing, P: PairingVar<E, ConstraintF<E::G1>>>(set: Vec<E::ScalarField>) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    // setup
    let (pp, tree) = Harisa::<E>::generate_harisa_parameters(
        set,
        TestCircuit {
            msg_vec: [None; SET_SIZE],
        },
        TestCircuit {
            msg_vec: [None; SET_SIZE],
        },
        &mut rng,
    )
    .unwrap();

    // u commit
    let u_vec = Vec::new();
    let u = Plaintext::<E::G1>::from_plaintext_vec(u_vec);
    let (cm_u, o_u) = Pedersen::<E::G1>::commit(pp.cm_pp.clone(), u.clone(), &mut rng).unwrap();

    let accum = tree[0];

    // prove
    // let prf = Harisa::<E>::generate_harisa_opt_proof(
    //     pp.clone(),
    //     accum,
    //     cm_u.clone(),
    //     u.clone(),
    //     o_u.clone(),
    //     &mut rng,
    // )
    // .unwrap();

    // // verify
    // assert!(
    //     Harisa::<E>::harisa_verify(pp, accum, cm_u, proof).unwrap(),
    //     "Verify Failed"
    // );
}
