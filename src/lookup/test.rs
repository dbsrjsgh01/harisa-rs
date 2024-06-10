use crate::{
    harisa::{arithm::ArithmCircuit, bound::BoundCircuit, harisa::Harisa},
    lookup::{copy_this_or_that::CTTCircuit, lookup::HarisaPlus, well_transformed::WTCircuit},
    utils::Utils,
};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_std::{test_rng, One, Zero};
use rand_core::{RngCore, SeedableRng};

fn test_lookup<E: Pairing>(set: Vec<E::ScalarField>, l_size: usize) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let mut u = Vec::new();

    for i in 0..l_size {
        u.push(set.clone()[i]);
    }

    let arithm_circuit = ArithmCircuit::<E::ScalarField>::mock(l_size);
    let bound_circuit = BoundCircuit::<E::ScalarField>::mock(l_size);

    let ctt_circuit = CTTCircuit::<E::ScalarField>::mock(l_size);
    let wt_circuit = WTCircuit::<E::ScalarField>::mock(l_size);

    let (pp, tree) = HarisaPlus::<E, Harisa<E>>::generate_lookup_parameters(
        set.clone(),
        ctt_circuit,
        wt_circuit,
        arithm_circuit,
        bound_circuit,
        &mut rng,
    )
    .unwrap();

    let (cm_u, o_u) = Utils::<E>::pedersen(pp.m_pp.g.clone(), u.clone(), &mut rng).unwrap();

    let accum = (tree[0] * set[0].clone()).into();

    let ctt_circuit = CTTCircuit::<E::ScalarField>::new(set.clone(), u.clone());

    let wt_circuit = WTCircuit::<E::ScalarField>::new(set.clone(), u.clone(), u.clone());

    let proof = HarisaPlus::<E, Harisa<E>>::generate_lookup_proof(
        pp.clone(), // Error: unsatisfy `clone` trait bound
        accum,
        tree,
        set,
        u.clone(),
        u.clone(),
        ctt_circuit,
        wt_circuit,
        cm_u,
        o_u,
        &mut rng,
    )
    .unwrap();

    assert!(
        HarisaPlus::<E, Harisa<E>>::verify_lookup(pp, accum, cm_u, cm_u, cm_u, proof).unwrap(),
        "[Harisa+] Verify Failed"
    );
}

const SET_SIZE: usize = 32;

#[test]
fn test_lookup_bn254() {
    use ark_bn254::{Bn254, Fr as F};

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let set = Utils::<Bn254>::set(256);

    test_lookup::<Bn254>(set, SET_SIZE);
    // test_lookup::<Bn254>(set, 10);
}
