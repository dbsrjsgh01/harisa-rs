use std::str::FromStr;

use crate::{
    harisa::{
        arithm::ArithmCircuit, bound::BoundCircuit, harisa::Harisa, type_conversion::bigint_to_fr,
    },
    linker::snark::LinkSnark,
    lookup::{copy_this_or_that::CTTCircuit, lookup::HarisaPlus, well_transformed::WTCircuit},
};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_std::{test_rng, One, Zero};
use num_bigint::BigInt;
use rand_core::{RngCore, SeedableRng};

fn test_lookup<E: Pairing>(l_size: usize)
where
    <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
{
    let set = set(256);

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let mut u = Vec::new();

    for i in 0..l_size {
        u.push(set[i].clone());
    }

    let z = set.clone();

    let mut set_hat = set.clone();
    let mut u_hat = u.clone();

    for i in 0..set_hat.len() {
        set_hat[i] = set_hat[i].clone() * BigInt::from(2).pow(14) + z[i].clone();
    }

    for i in 0..u_hat.len() {
        u_hat[i] = u_hat[i].clone() * BigInt::from(2).pow(14) + z[i].clone();
    }

    let arithm_circuit = ArithmCircuit::<E::ScalarField>::mock(l_size);
    let bound_circuit = BoundCircuit::<E::ScalarField>::mock(l_size);

    let ctt_circuit = CTTCircuit::<E::ScalarField>::mock(set.len(), l_size);
    let wt_circuit = WTCircuit::<E::ScalarField>::mock(l_size, l_size, z.len());

    let (pp, tree) =
        HarisaPlus::<E, Harisa<E, LinkSnark<E>>, LinkSnark<E>>::generate_lookup_parameters(
            set_hat.clone(),
            ctt_circuit,
            wt_circuit,
            arithm_circuit,
            bound_circuit,
            &mut rng,
        )
        .unwrap();

    // let (cm_u, o_u) = Utils::<E>::pedersen(pp.m_pp.g.clone(), u.clone(), &mut rng).unwrap();

    let accum = tree[0].clone() * set[0].clone();

    let mut circuit_set: Vec<E::ScalarField> = Vec::new();
    let mut circuit_set_hat: Vec<E::ScalarField> = Vec::new();
    let mut circuit_u: Vec<E::ScalarField> = Vec::new();
    let mut circuit_u_hat: Vec<E::ScalarField> = Vec::new();
    let mut circuit_z: Vec<E::ScalarField> = Vec::new();

    for s_i in set.clone() {
        circuit_set.push(bigint_to_fr(s_i));
    }

    for s_hat_i in set_hat.clone() {
        circuit_set_hat.push(bigint_to_fr(s_hat_i));
    }

    for u_i in u.clone() {
        circuit_u.push(bigint_to_fr(u_i));
    }

    for u_hat_i in u_hat.clone() {
        circuit_u_hat.push(bigint_to_fr(u_hat_i));
    }

    for z_i in z.clone() {
        circuit_z.push(bigint_to_fr(z_i));
    }

    let ctt_circuit =
        CTTCircuit::<E::ScalarField>::new(circuit_set_hat.clone(), circuit_u_hat.clone());

    let wt_circuit = WTCircuit::<E::ScalarField>::new(
        circuit_u_hat.clone(),
        circuit_u.clone(),
        circuit_z.clone(),
    );

    let proof = HarisaPlus::<E, Harisa<E, LinkSnark<E>>, LinkSnark<E>>::generate_lookup_proof(
        pp.clone(),
        accum.clone(),
        tree,
        u_hat.clone(),
        z.clone(),
        ctt_circuit,
        wt_circuit,
        cm_u,
        o_u,
        &mut rng,
    )
    .unwrap();

    assert!(
        HarisaPlus::<E, Harisa<E, LinkSnark<E>>, LinkSnark<E>>::verify_lookup(
            pp, accum, cm_u, cm_u, cm_u, proof
        )
        .unwrap(),
        "[Harisa+] Verify Failed"
    );
}

const SET_SIZE: usize = 32;

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
fn test_lookup_bn254() {
    use ark_bn254::{Bn254, Fr as F};

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let set = set(256);

    test_lookup::<Bn254>(SET_SIZE);
    // test_lookup::<Bn254>(set, 10);
}
