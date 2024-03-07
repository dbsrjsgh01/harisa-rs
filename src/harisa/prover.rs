use super::{
    arithm::ArithmCircuit,
    data_structure::{HarisaPP, HarisaProof},
    hash_to_prime::hash_to_prime,
    r1cs_to_qap::LibsnarkReduction,
};

use crate::core::pedersen::Pedersen;
use crate::core::{
    cc_snark::{
        data_structure::{Proof, ProvingKey},
        r1cs_to_qap::R1CSToQAP,
        CcGroth16,
    },
    pedersen::data_structure::{Commitment, Plaintext},
};
use crate::{core::pedersen::data_structure::Randomness, BasePrimeField};

use ark_crypto_primitives::snark::*;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError,
};
use ark_std::{
    rand::{CryptoRng, Rng, RngCore},
    One, UniformRand, Zero,
};

use super::Harisa;

impl<E: Pairing, QAP: R1CSToQAP> Harisa<E, QAP> {
    fn generate_cc_proof<C, R>(
        pk: &ProvingKey<E>,
        circuit: C,
        rng: &mut R,
    ) -> Result<Proof<E>, SynthesisError>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        R: Rng + RngCore + CryptoRng,
    {
        let cc_snark_prover_time = start_timer!(|| "ccGroth::Prover");

        let cc_prf = CcGroth16::<E, QAP>::prove(&pk, circuit, rng).unwrap();

        end_timer!(cc_snark_prover_time);

        Ok(cc_prf)
    }

    pub fn generate_harisa_proof<
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        pp: &HarisaPP<E>,
        accum: E::G1Affine,
        cm_u: Commitment<E>,
        w: E::G1Affine,
        u: Plaintext<E>,
        o_u: Randomness<E>,
        p: Vec<E::ScalarField>,
        arithm_circuit: Arithm,
        bound_circuit: Bound,
        rng: &mut R,
    ) -> Result<HarisaProof<E>, SynthesisError> {
        // let cs = ConstraintSystem::new_ref();

        // cs.set_optimization_goal(OptimizationGoal::Constraints);

        // pstar
        let mut p_star = E::ScalarField::one();
        // accumulator hat 구하기
        for p_i in p.clone() {
            p_star *= p_i;
        }
        let accum_hat = accum * p_star;

        // ustar
        let mut u_star = E::ScalarField::one();
        for u_i in u.msg.clone() {
            u_star *= u_i;
        }

        // sample b
        let b_rand = E::ScalarField::rand(rng);
        let mut b_bits = b_rand.into_bigint().to_bits_le();
        b_bits.truncate(p.clone().into_iter().len());

        for _ in b_bits.len()..p.clone().len() {
            b_bits.push(false);
        }

        b_bits.reverse();

        // calculate s, s_bar
        let (mut s, mut s_bar) = (E::ScalarField::one(), E::ScalarField::one());

        for (p_i, b_bits_i) in p.clone().iter().zip(b_bits.clone().into_iter()) {
            match b_bits_i {
                false => s_bar *= p_i,
                true => s *= p_i,
            };
        }

        // calculate w_hat
        let w_hat = w * s_bar;

        // sample r
        let r_rand = E::ScalarField::rand(rng);

        // cm_sr
        let (cm_sr, o_sr) = Pedersen::<E>::commit(
            pp.cm_pp.clone(),
            Plaintext::<E>::from_plaintext_vec(vec![s, r_rand.clone()]),
            rng,
        )
        .unwrap();

        // calculate R
        let r = w_hat * r_rand;

        // hash h
        let h = E::ScalarField::rand(rng);

        // calculate k
        let mut k = r_rand + u_star * s * h;

        // PoKE => prf1
        // 1. Hash-to-prime(crs, A, B) => l
        // 2. Q = W^{lower(x / l)}, res = k
        let l = hash_to_prime::<E, R>(
            vec![
                *pp.cm_pp.g.clone().first().unwrap(),
                w_hat.into(),
                ((accum_hat * h) + r).into(),
            ],
            rng,
        )
        .unwrap();

        let quot = k / l;
        let rem: E::ScalarField = k - l * quot;
        let q: E::G1 = w_hat * quot;

        // Hash-to-prime => l
        let l = hash_to_prime::<E, R>(vec![w_hat.into()], rng).unwrap();

        // arithm_circuit.generate_constraints(cs.clone())?;
        // debug_assert!(cs.is_satisfied().unwrap());
        // cs.finalize();

        // arithm => prf2
        let arithm_prf =
            Self::generate_cc_proof(&pp.arithm_ek.clone(), arithm_circuit, rng).unwrap();

        // bound => prf3
        let bound_prf = Self::generate_cc_proof(&pp.bound_ek.clone(), bound_circuit, rng).unwrap();

        Ok(HarisaProof {
            w_hat: w_hat.into(),
            r: r.into(),
            cm_sr: cm_sr,
            q: q.into(),
            k: rem.into(),
            arithm_prf: arithm_prf,
            bound_prf: bound_prf,
        })
    }
}
