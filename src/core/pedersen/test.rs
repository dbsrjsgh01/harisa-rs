use crate::core::pedersen::{Commitment, Parameters, Pedersen, Plaintext, Randomness};
use ark_ec::pairing::Pairing;
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::{test_rng, UniformRand};

fn test_commit<E: Pairing>(
    n: usize,
) -> (Parameters<E>, Commitment<E>, Plaintext<E>, Randomness<E>) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let pp = Pedersen::<E>::setup(n, &mut rng).unwrap();

    let mut msg = Vec::new();
    for _ in 0..n {
        let m_i = E::ScalarField::rand(&mut rng);
        msg.push(m_i);
    }

    let pt = Plaintext::<E>::from_plaintext_vec(msg);

    let (cm, r) = Pedersen::<E>::commit(pp.clone(), pt.clone(), &mut rng).unwrap();

    assert!(Pedersen::<E>::verify(pp.clone(), pt.clone(), cm.clone(), r.clone()).unwrap());

    (pp, cm, pt, r)
}

mod pedersen {
    use super::test_commit;
    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::snark::SNARK;
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng,
    };

    #[test]
    fn test_pedersen_commitment_bls12_381() {
        test_commit::<Bls12_381>(8);
    }

    #[test]
    fn test_cc_groth16_pedersen_bls12_377() {
        use crate::core::cc_snark::{prepare_verifying_key, CcGroth16};
        use crate::core::pedersen::circuit::PedersenCircuit;
        use ark_bls12_377::{
            constraints::{G1Var, PairingVar as EV},
            Bls12_377 as E, Config, Fr,
        };
        use ark_bw6_761::BW6_761 as P;

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pp, cm, pt, rand) = test_commit::<E>(8);

        let circuit =
            PedersenCircuit::<E, EV>::new(pp.clone(), cm.clone(), pt.clone(), rand.clone());

        let (ek, vk) = CcGroth16::<P>::circuit_specific_setup(circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key::<P>(&vk);

        let circuit = PedersenCircuit::<E, EV>::new(pp, cm, pt, rand);

        let proof = CcGroth16::<P>::prove(&ek, circuit, &mut rng).unwrap();

        assert!(CcGroth16::<P>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
    }
}
