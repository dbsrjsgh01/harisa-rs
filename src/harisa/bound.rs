use crate::core::pedersen::{
    circuit::{CommitmentVar, ParametersVar, PedersenGadget, PlaintextVar, RandomnessVar},
    data_structure::{Commitment, Parameters, Plaintext, Randomness},
};
use crate::BasePrimeField;

use ark_ec::pairing::Pairing;
use ark_r1cs_std::{fields::fp::FpVar, pairing::PairingVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, SynthesisMode};
use std::marker::PhantomData;

pub struct BoundCircuit<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    // statements
    pp: Parameters<E>,
    cm_u: Commitment<E>,
    p: Randomness<E>,

    // witness
    u: Plaintext<E>,
    o_u: Randomness<E>,
    _curve: PhantomData<P>,
}

impl<E, P> BoundCircuit<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    pub fn new(
        pp: Parameters<E>,
        cm_u: Commitment<E>,
        p: Randomness<E>,
        u: Plaintext<E>,
        o_u: Randomness<E>,
    ) -> Self {
        Self {
            pp: pp,
            cm_u: cm_u,
            p: p,
            u: u,
            o_u: o_u,
            _curve: PhantomData,
        }
    }
}

pub struct BoundGadget<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pp: ParametersVar<E, P>,
    cm_u: CommitmentVar<E, P>,
    p: RandomnessVar<E, P>,
    u: PlaintextVar<E, P>,
    o_u: RandomnessVar<E, P>,
}

impl<E, P> BoundGadget<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new(
        pp: ParametersVar<E, P>,
        cm_u: CommitmentVar<E, P>,
        p: RandomnessVar<E, P>,
        u: PlaintextVar<E, P>,
        o_u: RandomnessVar<E, P>,
    ) -> Self {
        Self {
            pp,
            cm_u,
            p,
            u,
            o_u,
        }
    }

    fn cpbound(&self) -> Result<(), SynthesisError> {
        // 1. cm_u == COMM(u; o_u)
        let rand_u = self.o_u.rand.clone().to_bits_le()?;

        let mut circuit_cm_u = self.pp.h.clone().scalar_mul_le(rand_u.clone().iter())?;

        for (g_i, m_i) in self.pp.g.clone().iter().zip(self.u.msg.clone().into_iter()) {
            let computed_cm_u_i = g_i.scalar_mul_le(m_i.to_bits_le()?.iter())?;

            circuit_cm_u += computed_cm_u_i;
        }

        self.cm_u.cm.enforce_equal(&circuit_cm_u)?;

        // 2. All of u_i are greater than B
        for m_i in self.u.msg.iter() {
            m_i.enforce_cmp(&self.p.rand.clone(), std::cmp::Ordering::Greater, false)?;
        }

        Ok(())
    }
}

impl<E, P> ConstraintSynthesizer<BasePrimeField<E>> for BoundCircuit<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<BasePrimeField<E>>,
    ) -> Result<(), SynthesisError> {
        let circuit_pp =
            ParametersVar::new_input(ark_relations::ns!(cs, "cpbound::crs"), || Ok(&self.pp))?;

        let circuit_cm_u =
            CommitmentVar::new_input(ark_relations::ns!(cs, "cpbound::cm_u"), || Ok(&self.cm_u))?;

        let circuit_p =
            RandomnessVar::new_input(ark_relations::ns!(cs, "cpbound::p"), || Ok(&self.p))?;

        let circuit_u =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cpbound::u"), || Ok(&self.u))?;

        let circuit_o_u = RandomnessVar::new_witness(
            ark_relations::ns!(cs, "cpbound::rand_u"),
            || Ok(&self.o_u),
        )?;

        let bound =
            BoundGadget::<E, P>::new(circuit_pp, circuit_cm_u, circuit_p, circuit_u, circuit_o_u);

        bound.cpbound()
    }
}

#[cfg(test)]
mod bls12_377 {
    use super::BoundCircuit;
    use crate::core::cc_snark::{prepare_verifying_key, CcGroth16};
    use crate::core::pedersen::data_structure::{Plaintext, Randomness};
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
        test_rng, One, UniformRand,
    };

    #[test]
    fn test_cp_bound_bls12_377() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let u_len = 8;

        let pp = Pedersen::<E>::setup(u_len, &mut rng).unwrap();

        let mut u_vec = Vec::new();

        for _ in 0..u_len {
            let u_i = <E as Pairing>::ScalarField::rand(&mut rng);
            u_vec.push(u_i);
        }

        let u = Plaintext::<E>::from_plaintext_vec(u_vec);

        let (cm_u, o_u) = Pedersen::<E>::commit(pp.clone(), u.clone(), &mut rng).unwrap();

        let p = Randomness::<E>::to_rand(<E as Pairing>::ScalarField::one());

        let circuit =
            BoundCircuit::<E, EV>::new(pp.clone(), cm_u.clone(), p.clone(), u.clone(), o_u.clone());

        let (ek, vk) = CcGroth16::<P>::circuit_specific_setup(circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);

        let circuit = BoundCircuit::<E, EV>::new(pp, cm_u, p, u, o_u);

        let proof = CcGroth16::<P>::prove(&ek, circuit, &mut rng).unwrap();

        assert!(CcGroth16::<P>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
    }
}
