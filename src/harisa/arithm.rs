use crate::core::pedersen::{
    circuit::{CommitmentVar, ParametersVar, PedersenGadget, PlaintextVar, RandomnessVar},
    data_structure::{Commitment, Parameters, Plaintext, Randomness},
};
use crate::BasePrimeField;

use ark_ec::pairing::Pairing;
use ark_ff::One;
use ark_r1cs_std::{fields::fp::FpVar, pairing::PairingVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, SynthesisMode};
use std::{
    marker::PhantomData,
    ops::{AddAssign, Mul, MulAssign},
};

pub struct ArithmCircuit<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    // statements
    pp: Parameters<E>,
    cm_u: Commitment<E>,
    cm_sr: Commitment<E>,
    h: Randomness<E>,
    l: Randomness<E>,
    k: Randomness<E>,

    // witness
    u: Plaintext<E>,
    o_u: Randomness<E>,
    sr: Plaintext<E>,
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
        h: Randomness<E>,
        l: Randomness<E>,
        k: Randomness<E>,
        u: Plaintext<E>,
        o_u: Randomness<E>,
        sr: Plaintext<E>,
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
            sr,
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
    h: RandomnessVar<E, P>,
    l: RandomnessVar<E, P>,
    k: RandomnessVar<E, P>,

    // witness
    u: PlaintextVar<E, P>,
    o_u: RandomnessVar<E, P>,
    sr: PlaintextVar<E, P>,
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
        h: RandomnessVar<E, P>,
        l: RandomnessVar<E, P>,
        k: RandomnessVar<E, P>,
        u: PlaintextVar<E, P>,
        o_u: RandomnessVar<E, P>,
        sr: PlaintextVar<E, P>,
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
            sr,
            o_sr,
        }
    }

    fn cparithm(&self) -> Result<(), SynthesisError> {
        //  1. k_hat = s * h * prod_{i in m} u_i + r mod l ==> 현재 에러 파트
        //  2. c_u = COMM(u, o_u)
        //  3. c_sr = COMM(s, r, o_sr)

        let rand_u = self.o_u.rand.clone().to_bits_le()?;

        let mut circuit_cm_u = self.pp.h.clone().scalar_mul_le(rand_u.clone().iter())?;

        for (g_i, m_i) in self.pp.g.clone().iter().zip(self.u.msg.clone().into_iter()) {
            let computed_cm_u_i = g_i.scalar_mul_le(m_i.to_bits_le()?.iter())?;
            circuit_cm_u += computed_cm_u_i;
        }

        self.cm_u.cm.enforce_equal(&circuit_cm_u)?;

        let rand_sr = self.o_sr.rand.clone().to_bits_le()?;

        let mut circuit_cm_sr = self.pp.h.clone().scalar_mul_le(rand_sr.clone().iter())?;

        for (g_i, m_i) in self
            .pp
            .g
            .clone()
            .iter()
            .zip(self.sr.msg.clone().into_iter())
        {
            let computed_cm_sr_i = g_i.scalar_mul_le(m_i.to_bits_le()?.iter())?;
            circuit_cm_sr += computed_cm_sr_i;
        }

        self.cm_sr.cm.enforce_equal(&circuit_cm_sr)?;

        // k_hat = s * h * prod_{i in m} u_i + r mod l (자동 modulus가 안된다?)
        let binding = self.sr.msg.clone();
        let mut sr_iter = binding.iter();

        let s = sr_iter.next().unwrap();
        let r = sr_iter.next().unwrap();

        let mut computed_k = s * self.h.rand.clone();

        for m_i in self.u.msg.clone().iter() {
            computed_k *= m_i;
        }

        computed_k += r;

        self.k.rand.enforce_equal(&computed_k)?;
        // FpVar에서의 enforce_equal과 G1Var에서의 enforce_equal는 다를지도...? 이걸 다시 little endian으로 해야 하나...?

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
            RandomnessVar::new_input(ark_relations::ns!(cs, "cparithm::h"), || Ok(&self.h))?;

        let circuit_l =
            RandomnessVar::new_input(ark_relations::ns!(cs, "cparithm::l"), || Ok(&self.l))?;

        let circuit_k =
            RandomnessVar::new_input(ark_relations::ns!(cs, "cparithm::k"), || Ok(&self.k))?;

        let circuit_u =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cparithm::u"), || Ok(&self.u))?;

        let circuit_o_u =
            RandomnessVar::new_witness(ark_relations::ns!(cs, "cparithm::o_u"), || Ok(&self.o_u))?;

        let circuit_sr =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cparithm::sr"), || Ok(&self.sr))?;

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
            circuit_sr,
            circuit_o_sr,
        );

        arithm.cparithm()
    }
}

fn calculate_k<E: Pairing>(
    sr: Plaintext<E>,
    h: Randomness<E>,
    u: Plaintext<E>,
) -> Result<E::ScalarField, SynthesisError> {
    let mut k = sr.msg.clone()[0] * h.rand.clone();
    for m_i in u.msg.clone().iter() {
        k *= m_i;
    }

    k += sr.msg.clone()[1];

    Ok(k.into())
}

#[cfg(test)]
mod bls12_377 {
    use super::{calculate_k, ArithmCircuit};
    use crate::core::cc_snark::{prepare_verifying_key, CcGroth16};
    use crate::core::pedersen::data_structure::{Parameters, Plaintext, Randomness};
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

        let mut sr_vec = Vec::new();

        for _ in 0..2 {
            let sr_i = <E as Pairing>::ScalarField::rand(&mut rng);
            sr_vec.push(sr_i);
        }

        let sr = Plaintext::<E>::from_plaintext_vec(sr_vec);

        let (cm_sr, o_sr) = Pedersen::<E>::commit(pp.clone(), sr.clone(), &mut rng).unwrap();

        let h = Randomness::<E>::to_rand(<E as Pairing>::ScalarField::rand(&mut rng));

        let l = Randomness::<E>::to_rand(<E as Pairing>::ScalarField::rand(&mut rng));

        let k_vec = calculate_k::<E>(sr.clone(), h.clone(), u.clone()).unwrap();

        let k = Randomness::<E>::to_rand(k_vec);

        let circuit = ArithmCircuit::<E, EV>::new(
            pp.clone(),
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

        let (ek, vk) = CcGroth16::<P>::circuit_specific_setup(circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);

        let circuit = ArithmCircuit::<E, EV>::new(pp, cm_u, cm_sr, h, l, k, u, o_u, sr, o_sr);

        let proof = CcGroth16::<P>::prove(&ek, circuit, &mut rng).unwrap();
        // assert!(CcGroth16::<P>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
        let result = CcGroth16::<P>::verify_with_processed_vk(&pvk, &[], &proof).unwrap();
        println!("Result: {:#?}", result);
    }
}
