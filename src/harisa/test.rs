use std::ops::Bound;

use crate::{
    core::pedersen::{
        self,
        data_structure::{Commitment, Parameters, Plaintext, Randomness},
        Pedersen,
    },
    harisa::{arithm::ArithmCircuit, bound::BoundCircuit, Harisa},
    BasePrimeField,
};
use ark_ec::pairing::Pairing;
use ark_r1cs_std::pairing::PairingVar;
use ark_std::{
    rand::{CryptoRng, Rng, RngCore, SeedableRng},
    test_rng, UniformRand,
};

use super::prepare_verifying_key;

fn test_harisa<E: Pairing, P: PairingVar<E, BasePrimeField<E>>>(n: usize) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let cm_pp = Pedersen::<E>::setup(n, &mut rng).unwrap();

    let mut msg = Vec::new();
    for _ in 0..n {
        let m_i = E::ScalarField::rand(&mut rng);
        msg.push(m_i);
    }

    let u = Plaintext::<E>::from_plaintext_vec(msg.clone());

    let (cm_u, o_u) = Pedersen::<E>::commit(cm_pp.clone(), u.clone(), &mut rng).unwrap();

    let mut sr_vec = Vec::new();
    for _ in 0..2 {
        let m_i = E::ScalarField::rand(&mut rng);
        sr_vec.push(m_i);
    }

    let sr = Plaintext::<E>::from_plaintext_vec(sr_vec);

    let (cm_sr, o_sr) = Pedersen::<E>::commit(cm_pp.clone(), sr.clone(), &mut rng).unwrap();

    // h, l, k, p
    let h = Randomness::<E>::to_rand(<E as Pairing>::ScalarField::rand(&mut rng));

    let l = Randomness::<E>::to_rand(<E as Pairing>::ScalarField::rand(&mut rng));

    let k = Randomness::<E>::to_rand(calculate_k::<E>(sr.clone(), h.clone(), u.clone()).unwrap());

    let p = Randomness::<E>::to_rand(<E as Pairing>::ScalarField::one());

    let arithm_circuit = ArithmCircuit::<E, P>::new(
        cm_pp.clone(),
        cm_u.clone(),
        cm_sr.clone(),
        h.clone(),
        l.clone(),
        k.clone(),
        u.clone(),
        o_u.clone(),
        sr.clone(),
        o_sr.clone(),
    );

    let bound_circuit = BoundCircuit::<E, P>::new(
        cm_pp.clone(),
        cm_u.clone(),
        p.clone(),
        u.clone(),
        o_u.clone(),
    );

    let harisa_pp =
        Harisa::<E>::generate_harisa_parameters(n, arithm_circuit, bound_circuit, &mut rng)
            .unwrap();

    let arithm_circuit = ArithmCircuit::<E, P>::new(
        cm_pp.clone(),
        cm_u.clone(),
        cm_sr.clone(),
        h.clone(),
        l.clone(),
        k.clone(),
        u.clone(),
        o_u.clone(),
        sr.clone(),
        o_sr.clone(),
    );

    let bound_circuit = BoundCircuit::<E, P>::new(
        cm_pp.clone(),
        cm_u.clone(),
        p.clone(),
        u.clone(),
        o_u.clone(),
    );

    let proof = Harisa::<E>::generate_harisa_proof(
        &harisa_pp,
        accum,
        cm_u,
        w,
        u,
        o_u,
        p,
        arithm_circuit,
        bound_circuit,
        &mut rng,
    )
    .unwrap();

    assert!(Harisa::<E>::harisa_verify(harisa_pp, accum, c_u, proof).unwrap());
}

mod arithm {
    use super::test_harisa;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::bls12::Bls12;

    #[test]
    fn test_cc_groth16_arithm_bls12_377() {
        use crate::core::cc_snark::{prepare_verifying_key, CcGroth16};
        use crate::core::pedersen::Pedersen;
        use crate::harisa::arithm::ArithmCircuit;
        use ark_bls12_377::{
            constraints::{G1Var, PairingVar as EV},
            Bls12_377 as E, Config, Fr,
        };
        use ark_bw6_761::BW6_761 as P;
        use ark_ec::pairing::Pairing;

        test_harisa::<E, EV>(8);
    }
}
