use std::ops::Bound;

use crate::{
    harisa::{arithm::ArithmCircuit, bound::BoundCircuit, harisa::Harisa},
    utils::Utils,
    ConstraintF,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::pairing::PairingVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{
    rand::{Rng, RngCore, SeedableRng},
    test_rng, One, UniformRand,
};
use num_bigint::BigInt;

use super::{bound, prepare_verifying_key};

const SET_SIZE: usize = 32;

fn test_harisa<E: Pairing>(set: Vec<BigInt>, l_size: usize) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    // u commit
    let mut u = Vec::new();

    for i in 0..l_size {
        u.push(set[i].clone());
    }

    let arithm_circuit = ArithmCircuit::<E::ScalarField>::mock(l_size);
    let bound_circuit = BoundCircuit::<E::ScalarField>::mock(l_size);

    // setup
    let (pp, tree) = Harisa::<E>::generate_harisa_parameters(
        set.clone(),
        arithm_circuit,
        bound_circuit,
        &mut rng,
    )
    .unwrap();

    // let (cm_u, o_u) = Utils::<E>::pedersen(pp.g.clone(), u.clone(), &mut rng).unwrap();

    let accum = tree[0].clone() * set[0].clone();

    // prove: Circuit을 prove 내에 집어넣는 방법
    let proof = Harisa::<E>::generate_harisa_opt_proof(
        pp.clone(),
        tree,
        accum.clone(),
        // cm_u.clone(),
        u.clone(),
        // o_u.clone(),
        &mut rng,
    )
    .unwrap();

    // verify
    assert!(
        // Harisa::<E>::harisa_verify(pp, accum, cm_u, proof).unwrap(),
        Harisa::<E>::harisa_verify(pp, accum, proof).unwrap(),
        "[Harisa] Verify Failed"
    );
}

// fn set<E: Pairing>(n: usize) -> Vec<E::ScalarField> {
fn set(n: usize) -> Vec<BigInt> {
    use crate::harisa::constants::ODD_PRIME;

    let mut res = Vec::new();
    for i in 0..n {
        // res.push(E::ScalarField::from(ODD_PRIME[i]));
        res.push(BigInt::from(ODD_PRIME[i]));
    }

    res
}

#[test]
fn test_harisa_bn254() {
    // use crate::harisa::constants::ODD_PRIME;
    use ark_bn254::{Bn254 as E, Fr as F};
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    // let set = set::<Bn254>(256);
    let set = set(256);

    test_harisa::<E>(set, SET_SIZE);
}
