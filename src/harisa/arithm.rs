use crate::core::pedersen::{
    circuit::{CommitmentVar, ParametersVar, PedersenGadget, PlaintextVar, RandomnessVar},
    data_structure::{Commitment, Parameters, Plaintext, Randomness},
};
use crate::BasePrimeField;

use ark_ec::pairing::Pairing;
use ark_r1cs_std::{fields::fp::FpVar, pairing::PairingVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, SynthesisMode};
use std::marker::PhantomData;

pub struct ArithmCircuit<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    // statements
    pp: Parameters<E>,
    cm_u: Commitment<E>,
    cm_sr: Commitment<E>,
    h: Plaintext<E>, // Todo: Plaintext<E> -> BasePrimeField<E>
    l: Plaintext<E>,
    k: Plaintext<E>,
    // h: BasePrimeField<E>,
    // l: BasePrimeField<E>,
    // k: BasePrimeField<E>,

    // witness
    u: Plaintext<E>,
    o_u: Randomness<E>,
    r: Plaintext<E>,
    s: Plaintext<E>,
    // r: BasePrimeField<E>,
    // s: BasePrimeField<E>,
    o_sr: Randomness<E>,
    _curve: PhantomData<P>,
}

impl<E, P> ArithmCircuit<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    pub fn new(
        pp: Parameters<E>,
        cm_u: Commitment<E>,
        cm_sr: Commitment<E>,
        h: Plaintext<E>, // Todo: Plaintext<E> -> BasePrimeField<E>
        l: Plaintext<E>,
        k: Plaintext<E>,
        // h: BasePrimeField<E>,
        // l: BasePrimeField<E>,
        // k: BasePrimeField<E>,
        u: Plaintext<E>,
        o_u: Randomness<E>,
        r: Plaintext<E>,
        s: Plaintext<E>,
        // r: BasePrimeField<E>,
        // s: BasePrimeField<E>,
        o_sr: Randomness<E>,
    ) -> Self {
        Self {
            pp,
            cm_u,
            cm_sr,
            h,
            l,
            k,
            u,
            o_u,
            r,
            s,
            o_sr,
            _curve: PhantomData,
        }
    }
}

pub struct ArithmGadget<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    // statements
    pp: ParametersVar<E, P>,
    cm_u: CommitmentVar<E, P>,
    cm_sr: CommitmentVar<E, P>,
    h: PlaintextVar<E, P>,
    l: PlaintextVar<E, P>,
    k: PlaintextVar<E, P>,
    // h: FpVar<BasePrimeField<E>>,
    // l: FpVar<BasePrimeField<E>>,
    // k: FpVar<BasePrimeField<E>>,

    // witness
    u: PlaintextVar<E, P>,
    o_u: RandomnessVar<E, P>,
    r: PlaintextVar<E, P>,
    s: PlaintextVar<E, P>,
    // r: FpVar<BasePrimeField<E>>,
    // s: FpVar<BasePrimeField<E>>,
    o_sr: RandomnessVar<E, P>,
}

impl<E, P> ArithmGadget<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new(
        pp: ParametersVar<E, P>,
        cm_u: CommitmentVar<E, P>,
        cm_sr: CommitmentVar<E, P>,
        h: PlaintextVar<E, P>,
        l: PlaintextVar<E, P>,
        k: PlaintextVar<E, P>,
        // h: FpVar<BasePrimeField<E>>,
        // l: FpVar<BasePrimeField<E>>,
        // k: FpVar<BasePrimeField<E>>,
        u: PlaintextVar<E, P>,
        o_u: RandomnessVar<E, P>,
        r: PlaintextVar<E, P>,
        s: PlaintextVar<E, P>,
        // r: FpVar<BasePrimeField<E>>,
        // s: FpVar<BasePrimeField<E>>,
        o_sr: RandomnessVar<E, P>,
    ) -> Self {
        Self {
            pp,
            cm_u,
            cm_sr,
            h,
            l,
            k,
            u,
            o_u,
            s,
            r,
            o_sr,
        }
    }

    fn cparithm(&self) -> Result<(), SynthesisError> {
        //  1. k_hat = s * h * prod_{i in m} u_i + r mod l ==> 아직 구현 안함
        //  2. c_u = COMM(u, o_u)
        //  3. c_sr = COMM(s, r, o_sr) ==> 현재 에러 파트

        let rand_u = self.o_u.rand.clone().to_bits_le()?;

        let mut circuit_cm_u = self.pp.h.clone().scalar_mul_le(rand_u.clone().iter())?;

        for (g_i, m_i) in self.pp.g.clone().iter().zip(self.u.msg.clone().into_iter()) {
            let computed_cm_u_i = g_i.scalar_mul_le(m_i.to_bits_le()?.iter())?;
            circuit_cm_u += computed_cm_u_i;
        }

        self.cm_u.cm.enforce_equal(&circuit_cm_u)?;

        let rand_sr = self.o_sr.rand.clone().to_bits_le()?;

        let mut circuit_cm_sr = self.pp.h.clone().scalar_mul_le(rand_sr.clone().iter())?;

        let vec_sr = [self.s.msg.clone(), self.r.msg.clone()].concat();

        for (g_i, m_i) in self.pp.g.iter().zip(vec_sr.into_iter()) {
            let computed_cm_sr_i = g_i.scalar_mul_le(m_i.to_bits_le()?.iter())?;
            circuit_cm_sr += computed_cm_sr_i;
        }

        self.cm_sr.cm.enforce_equal(&circuit_cm_sr)?;

        Ok(())
    }
}

impl<E, P> ConstraintSynthesizer<BasePrimeField<E>> for ArithmCircuit<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<BasePrimeField<E>>,
    ) -> Result<(), SynthesisError> {
        let circuit_pp =
            ParametersVar::new_input(ark_relations::ns!(cs, "cparithm::crs"), || Ok(&self.pp))?;

        let circuit_cm_u =
            CommitmentVar::new_input(ark_relations::ns!(cs, "cparithm::cm_u"), || Ok(&self.cm_u))?;

        let circuit_cm_sr = CommitmentVar::new_input(
            ark_relations::ns!(cs, "cparithm::cm_sr"),
            || Ok(&self.cm_sr),
        )?;

        let circuit_h =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cparithm::h"), || Ok(&self.h))?;

        let circuit_l =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cparithm::l"), || Ok(&self.l))?;

        let circuit_k =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cparithm::k"), || Ok(&self.k))?;

        // let circuit_h =
        //     FpVar::<BasePrimeField<E>>::new_input(ark_relations::ns!(cs, "cparithm::h"), || {
        //         Ok(&self.h)
        //     })?;

        // let circuit_l =
        //     FpVar::<BasePrimeField<E>>::new_input(ark_relations::ns!(cs, "cparithm::l"), || {
        //         Ok(&self.l)
        //     })?;

        // let circuit_k =
        //     FpVar::<BasePrimeField<E>>::new_input(ark_relations::ns!(cs, "cparithm::k"), || {
        //         Ok(&self.k)
        //     })?;

        let circuit_u =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cparithm::u"), || Ok(&self.u))?;

        let circuit_o_u =
            RandomnessVar::new_witness(ark_relations::ns!(cs, "cparithm::o_u"), || Ok(&self.o_u))?;

        let circuit_s =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cparithm::s"), || Ok(&self.s))?;

        let circuit_r =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cparithm::r"), || Ok(&self.r))?;

        // let circuit_s =
        //     FpVar::<BasePrimeField<E>>::new_input(ark_relations::ns!(cs, "cparithm::s"), || {
        //         Ok(&self.s)
        //     })?;

        // let circuit_r =
        //     FpVar::<BasePrimeField<E>>::new_input(ark_relations::ns!(cs, "cparithm::r"), || {
        //         Ok(&self.r)
        //     })?;

        let circuit_o_sr = RandomnessVar::new_witness(
            ark_relations::ns!(cs, "cparithm::o_sr"),
            || Ok(&self.o_sr),
        )?;

        let arithm = ArithmGadget::<E, P>::new(
            circuit_pp,
            circuit_cm_u,
            circuit_cm_sr,
            circuit_h,
            circuit_l,
            circuit_k,
            circuit_u,
            circuit_o_u,
            circuit_s,
            circuit_r,
            circuit_o_sr,
        );

        arithm.cparithm()
    }
}

#[cfg(test)]
mod bls12_377 {
    use super::ArithmCircuit;
    use crate::core::cc_snark::{prepare_verifying_key, CcGroth16};
    use crate::core::pedersen::data_structure::{Parameters, Plaintext};
    use crate::core::pedersen::Pedersen;
    use ark_bls12_377::{
        constraints::{G1Var, PairingVar as EV},
        Bls12_377 as E, Config, Fr,
    };
    use ark_bw6_761::BW6_761 as P;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng, UniformRand,
    };

    #[test]
    fn test_cp_arithm_bls12_377() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let u_len = 8;

        let pp = Pedersen::<E>::setup(u_len + 1, &mut rng).unwrap();

        let mut u_vec = Vec::new();

        for _ in 0..u_len {
            let u_i = <E as Pairing>::ScalarField::rand(&mut rng);
            u_vec.push(u_i);
        }

        let u = Plaintext::<E>::from_plaintext_vec(u_vec);

        let (cm_u, o_u) = Pedersen::<E>::commit(pp.clone(), u.clone(), &mut rng).unwrap();

        let s_vec = <E as Pairing>::ScalarField::rand(&mut rng);
        let r_vec = <E as Pairing>::ScalarField::rand(&mut rng);

        let sr = Plaintext::<E>::from_plaintext_vec(vec![s_vec.clone(), r_vec.clone()]);

        let (cm_sr, o_sr) = Pedersen::<E>::commit(pp.clone(), sr.clone(), &mut rng).unwrap();

        println!("cm_sr: {:#?}", cm_sr.cm);

        let s = Plaintext::<E>::from_plaintext_vec(vec![s_vec]);

        let r = Plaintext::<E>::from_plaintext_vec(vec![r_vec]);

        let h =
            Plaintext::<E>::from_plaintext_vec(vec![<E as Pairing>::ScalarField::rand(&mut rng)]);

        let l =
            Plaintext::<E>::from_plaintext_vec(vec![<E as Pairing>::ScalarField::rand(&mut rng)]);

        let k =
            Plaintext::<E>::from_plaintext_vec(vec![<E as Pairing>::ScalarField::rand(&mut rng)]);

        // Field 내에서 multiplication만 가능하다면 되는데...
        // let k_field = s_vec * h.msg + r_vec;

        // let k = Plaintext::<E>::from_plaintext_vec(vec![k_field]);

        let circuit = ArithmCircuit::<E, EV>::new(
            pp.clone(),
            cm_u.clone(),
            cm_sr.clone(),
            h.clone(),
            l.clone(),
            k.clone(),
            u.clone(),
            o_u.clone(),
            r.clone(),
            s.clone(),
            o_sr.clone(),
        );

        let (ek, vk) = CcGroth16::<P>::circuit_specific_setup(circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);

        let circuit = ArithmCircuit::<E, EV>::new(pp, cm_u, cm_sr, h, l, k, u, o_u, r, s, o_sr);

        let proof = CcGroth16::<P>::prove(&ek, circuit, &mut rng).unwrap();
        std::env::set_var("RUST_BACKTRACE", "full");
        // assert!(CcGroth16::<P>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
        let result = CcGroth16::<P>::verify_with_processed_vk(&pvk, &[], &proof).unwrap();
        println!("Result: {:#?}", result);
        // 현재 유일하게 test fail이 뜸 (예상은 s, r 커밋하는데에서 예상 중)
    }
}

// ---- harisa::arithm::bls12_377::test_cp_arithm_bls12_377 stdout ----
// Constraint trace requires enabling `ConstraintLayer`
// thread 'harisa::arithm::bls12_377::test_cp_arithm_bls12_377' panicked at src/core/cc_snark/prover.rs:227:9:
// assertion failed: cs.is_satisfied().unwrap()
// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
