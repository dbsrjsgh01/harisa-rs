use crate::core::pedersen::{Commitment, Parameters, Pedersen, Plaintext, Randomness};
use ark_ec::CurveGroup;
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::{test_rng, UniformRand};

fn test_commit<C: CurveGroup>(
    n: usize,
) -> (Parameters<C>, Commitment<C>, Plaintext<C>, Randomness<C>) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let pp = Pedersen::<C>::setup(n, &mut rng).unwrap();

    let mut msg = Vec::new();
    for _ in 0..n {
        let m_i = C::ScalarField::rand(&mut rng);
        msg.push(m_i);
    }

    let pt = Plaintext::<C>::from_plaintext_vec(msg);

    let (cm, r) = Pedersen::<C>::commit(pp.clone(), pt.clone(), &mut rng).unwrap();

    assert!(Pedersen::<C>::verify(pp.clone(), pt.clone(), cm.clone(), r.clone()).unwrap());

    (pp, cm, pt, r)
}

mod pedersen {
    use super::test_commit;
    use crate::core::{
        cc_snark::{prepare_verifying_key, CcGroth16},
        pedersen::circuit::PedersenCircuit,
    };
    use ark_crypto_primitives::snark::SNARK;
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng,
    };
    use std::marker::PhantomData;

    #[test]
    fn test_pedersen_commitment_bn254() {
        use ark_ed_on_bn254::EdwardsProjective as C;
        test_commit::<C>(8);
    }

    #[test]
    fn test_pedersen_commitment_groth16_bn254() {
        use ark_bn254::Bn254;
        use ark_ed_on_bn254::{constraints::EdwardsVar as GG, EdwardsProjective as C};

        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pp, cm, pt, rand) = test_commit::<C>(8);

        let circuit = PedersenCircuit::<C, GG> {
            pp,
            pt,
            cm,
            rand,
            _curve: PhantomData,
        };

        let (pk, vk) = CcGroth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
        let pvk = prepare_verifying_key(&vk);

        let proof = CcGroth16::<Bn254>::prove(&pk, circuit, rng).unwrap();

        assert!(CcGroth16::<Bn254>::verify_with_processed_vk(&pvk, &[], &proof).unwrap())
    }
}
