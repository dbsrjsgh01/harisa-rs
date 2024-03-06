use super::{
    arithm::ArithmCircuit,
    data_structure::{HarisaPP, HarisaProof},
    hash_to_prime::hash_to_prime,
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
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::{
    rand::{CryptoRng, Rng, RngCore},
    One, UniformRand, Zero,
};

use super::Harisa;

impl<E: Pairing> Harisa<E> {
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

        let cc_prf = CcGroth16::<E>::prove(&pk, circuit, rng).unwrap();

        end_timer!(cc_snark_prover_time);

        Ok(cc_prf)
    }

    fn generate_cp_arithm_proof<C, R>(
        pk: &ProvingKey<E>,
        circuit: C,
        rng: &mut R,
    ) -> Result<Proof<E>, SynthesisError>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        R: Rng + RngCore + CryptoRng,
    {
        let arithm_proof = Ok(CcGroth16::<E>::prove(&pk, circuit, rng).unwrap());

        arithm_proof
    }

    pub fn generate_harisa_proof<C, R>(
        pp: &HarisaPP<E>,
        accum: E::G1Affine,
        cm_u: Commitment<E>,
        w: E::G1Affine,
        u: Plaintext<E>,
        o_u: Randomness<E>,
        p: Vec<E::ScalarField>,
        arithm_circuit: C,
        bound_circuit: C,
        rng: &mut R,
    ) -> Result<HarisaProof<E>, SynthesisError>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        R: Rng + RngCore + CryptoRng,
    {
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

        // let arithm_circuit = ArithmCircuit::<E, P>::new(
        //     pp.cm_pp.clone(),
        //     cm_u.clone(),
        //     cm_sr.clone(),
        //     Plaintext::<E>::from_plaintext_vec(vec![h.clone()]),
        //     Plaintext::<E>::from_plaintext_vec(vec![l.clone()]),
        //     Plaintext::<E>::from_plaintext_vec(vec![k.clone()]),
        //     u.clone(),
        //     o_u.clone(),
        //     Plaintext::<E>::from_plaintext_vec(vec![r_rand.clone()]),
        //     Plaintext::<E>::from_plaintext_vec(vec![s.clone()]),
        //     o_sr.clone(),
        // );

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
