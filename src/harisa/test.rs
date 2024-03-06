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

    let mut i = msg.iter();
    let s_vec = i.next().unwrap();
    let r_vec = i.next().unwrap();

    let s = Plaintext::<E>::from_plaintext_vec(vec![*s_vec]);
    let r = Plaintext::<E>::from_plaintext_vec(vec![*r_vec]);

    let (cm_sr, o_sr) = Pedersen::<E>::commit(
        cm_pp.clone(),
        Plaintext::<E>::from_plaintext_vec(vec![s_vec.clone(), r_vec.clone()]),
        &mut rng,
    )
    .unwrap();

    // h, l, k, p

    let arithm_circuit = ArithmCircuit::<E, P>::new(
        cm_pp.clone(),
        cm_u.clone(),
        cm_sr.clone(),
        h,
        l,
        k,
        u.clone(),
        o_u.clone(),
        r.clone(),
        s.clone(),
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
        h,
        l,
        k,
        u.clone(),
        o_u.clone(),
        r.clone(),
        s.clone(),
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

fn random_value<E: Pairing, R: Rng>(rng: &mut R) -> E::ScalarField {
    E::ScalarField::rand(rng)
}

mod arithm {
    use super::{random_value, test_harisa};
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::bls12::Bls12;
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng,
    };

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

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let pp = Pedersen::<E>::setup(8, &mut rng).unwrap();

        let (cm_u, u, o_u) = test_commit::<E>(pp.clone(), 8);

        let (cm_sr, sr, o_sr) = test_commit::<E>(pp.clone(), 2);

        let s = sr.clone().msg.into_iter().nth(0).unwrap();
        let r = sr.clone().msg.into_iter().nth(1).unwrap();

        let h: <E as Pairing>::ScalarField = random_value(&mut rng);

        let l: <E as Pairing>::ScalarField = random_value(&mut rng);

        let k: <E as Pairing>::ScalarField = random_value(&mut rng);

        let arithm_circuit = ArithmCircuit::<E, EV>::new(
            pp.clone(),
            cm_u.clone(),
            cm_sr.clone(),
            h.clone(),
            l.clone(),
            k.clone(),
            u.clone(),
            o_u.clone(),
            s.clone(),
            r.clone(),
            o_sr.clone(),
        );

        let (ek, vk) = CcGroth16::<P>::circuit_specific_setup(circuit, &mut rng).unwrap();

        let pvk = prepare_verifying_key::<P>(&vk);

        let circuit = ArithmCircuit::<E, EV>::new(pp, cm_u, cm_sr, h, l, k, u, o_u, s, r, o_sr);

        let proof = CcGroth16::<P>::prove(&ek, circuit, &mut rng).unwrap();

        assert!(CcGroth16::<P>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
    }
}
