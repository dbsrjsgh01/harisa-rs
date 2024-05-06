use super::{
    arithm::ArithmCircuit,
    data_structure::{HarisaPP, HarisaProof},
    hash_to_prime::hash_to_prime,
    preprocess::*,
    r1cs_to_qap::LibsnarkReduction,
};

use crate::core::pedersen::data_structure::Randomness;
use crate::core::pedersen::Pedersen;
use crate::core::{
    cc_snark::{
        data_structure::{Proof, ProvingKey},
        r1cs_to_qap::R1CSToQAP,
        CcGroth16,
    },
    pedersen::data_structure::{Commitment, Plaintext},
};

use ark_crypto_primitives::snark::*;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError,
};
use ark_std::{
    rand::{CryptoRng, Rng, RngCore},
    One, UniformRand, Zero,
};

use super::harisa::Harisa;

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
        pp: HarisaPP<E>,
        accum: E::G1Affine,
        cm_u: Commitment<E::G1>,
        w: E::G1Affine,
        u: Plaintext<E::G1>,
        o_u: Randomness<E::G1>,
        arithm_circuit: Arithm,
        bound_circuit: Bound,
        rng: &mut R,
    ) -> Result<HarisaProof<E>, SynthesisError> {
        // pstar
        let mut p_star = E::ScalarField::one();
        // accumulator hat 구하기
        for p_i in u.msg.clone() {
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
        b_bits.truncate(u.msg.clone().into_iter().len());

        for _ in b_bits.len()..u.msg.clone().len() {
            b_bits.push(false);
        }

        b_bits.reverse();

        // calculate s, s_bar
        let (mut s, mut s_bar) = (E::ScalarField::one(), E::ScalarField::one());

        for (p_i, b_bits_i) in u.msg.clone().iter().zip(b_bits.clone().into_iter()) {
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
        let (cm_sr, o_sr) = Pedersen::<E::G1>::commit(
            pp.cm_pp.clone(),
            Plaintext::<E::G1>::from_plaintext_vec(vec![s, r_rand.clone()]),
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
            vec![],
            8,
            rng,
        )
        .unwrap();

        let quot = k / l;
        let rem: E::ScalarField = k - l * quot;
        let q: E::G1 = w_hat * quot;

        // Hash-to-prime => l (이 때의 hash는 poseidon이겠지?)
        let l = hash_to_prime::<E, R>(vec![w_hat.into()], vec![], 8, rng).unwrap();

        // arithm => prf2
        let arithm_prf =
            Self::generate_cc_proof(&pp.arithm_ek.clone(), arithm_circuit, rng).unwrap();

        // bound => prf3
        let bound_prf = Self::generate_cc_proof(&pp.bound_ek.clone(), bound_circuit, rng).unwrap();

        Ok(HarisaProof {
            w_hat: w_hat.into(),
            r: r.into(),
            cm_sr,
            q: q.into(),
            k: rem.into(),
            arithm_prf,
            bound_prf,
        })
    }

    pub fn generate_harisa_opt_proof<
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        pp: HarisaPP<E>,
        accum: E::G1Affine,
        cm_u: Commitment<E::G1>,
        u: Plaintext<E::G1>,
        o_u: Randomness<E::G1>,
        arithm_circuit: Arithm,
        bound_circuit: Bound,
        rng: &mut R,
    ) -> Result<HarisaProof<E>, SynthesisError> {
        let mut w: Vec<E::G1Affine> = Vec::new();
        let g: E::G1Affine = *pp.cm_pp.g.clone().first().unwrap();

        for u_i in u.msg.clone().iter() {
            w.push((g.clone() * u_i).into());
        }

        let mut w_len = w.len();

        while w_len > 1 {
            w_len >>= 1;

            for i in 0..w_len {
                w[i] = assemble::<E>(
                    u.msg.clone()[2 * i],
                    u.msg.clone()[2 * i + 1],
                    w[2 * i].clone(),
                    w[2 * i + 1].clone(),
                );
            }
            w.truncate(w_len);
        }
        let w_u = *w.first().unwrap();

        let proof = Self::generate_harisa_proof(
            pp,
            accum,
            cm_u,
            w_u,
            u,
            o_u,
            arithm_circuit,
            bound_circuit,
            rng,
        )
        .unwrap();

        Ok(proof)
    }
}
