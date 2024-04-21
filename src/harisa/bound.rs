use crate::core::pedersen::{
    circuit::{CommitmentVar, ParametersVar, PedersenGadget, PlaintextVar, RandomnessVar},
    data_structure::{Commitment, Parameters, Plaintext, Randomness},
};
use crate::ConstraintF;

use ark_ec::CurveGroup;
use ark_r1cs_std::{fields::fp::FpVar, pairing::PairingVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, SynthesisMode};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct BoundCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    // statements
    pp: Parameters<C>,
    cm_u: Commitment<C>,
    p: Randomness<C>,

    // witness
    u: Plaintext<C>,
    o_u: Randomness<C>,
    _curve: PhantomData<GG>,
}

impl<C, GG> BoundCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    pub fn new(
        pp: Parameters<C>,
        cm_u: Commitment<C>,
        p: Randomness<C>,
        u: Plaintext<C>,
        o_u: Randomness<C>,
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

pub struct BoundGadget<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    pp: ParametersVar<C, GG>,
    cm_u: CommitmentVar<C, GG>,
    p: RandomnessVar<C, GG>,
    u: PlaintextVar<C, GG>,
    o_u: RandomnessVar<C, GG>,
}

impl<C, GG> BoundGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn new(
        pp: ParametersVar<C, GG>,
        cm_u: CommitmentVar<C, GG>,
        p: RandomnessVar<C, GG>,
        u: PlaintextVar<C, GG>,
        o_u: RandomnessVar<C, GG>,
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

impl<C, GG> ConstraintSynthesizer<ConstraintF<C>> for BoundCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<ConstraintF<C>>,
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
            BoundGadget::<C, GG>::new(circuit_pp, circuit_cm_u, circuit_p, circuit_u, circuit_o_u);

        bound.cpbound()
    }
}

#[cfg(test)]
mod bound {
    use super::BoundCircuit;
    use crate::core::cc_snark::{prepare_verifying_key, CcGroth16};
    use crate::core::pedersen::data_structure::{Commitment, Parameters, Plaintext, Randomness};
    use crate::core::pedersen::Pedersen;
    use crate::ConstraintF;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::pairing::Pairing;
    use ark_ec::CurveGroup;
    use ark_r1cs_std::groups::CurveVar;
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng, One, UniformRand,
    };

    fn test_cp_bound<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>() -> (
        Parameters<C>,
        Commitment<C>,
        Randomness<C>,
        Plaintext<C>,
        Randomness<C>,
    ) {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let u_len = 8;

        let pp = Pedersen::<C>::setup(u_len, &mut rng).unwrap();

        let mut u_vec = Vec::new();

        for _ in 0..u_len {
            let u_i = C::ScalarField::rand(&mut rng);
            u_vec.push(u_i);
        }

        let u = Plaintext::<C>::from_plaintext_vec(u_vec);

        let (cm_u, o_u) = Pedersen::<C>::commit(pp.clone(), u.clone(), &mut rng).unwrap();

        let p = Randomness::<C>::to_rand(C::ScalarField::one());

        (pp, cm_u, p, u, o_u)
    }

    #[test]
    fn test_cp_bound_circuit() {
        use ark_bn254::Bn254;
        use ark_ed_on_bn254::{constraints::EdwardsVar as GG, EdwardsProjective as C};
        use ark_relations::r1cs::ConstraintSynthesizer;

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pp, cm_u, p, u, o_u) = test_cp_bound::<C, GG>();

        let circuit = BoundCircuit::<C, GG>::new(pp, cm_u, p, u, o_u);

        let (ek, _) =
            CcGroth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_cp_bound_groth16_bn254() {
        use ark_bn254::Bn254;
        use ark_ed_on_bn254::{constraints::EdwardsVar as GG, EdwardsProjective as C};

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pp, cm_u, p, u, o_u) = test_cp_bound::<C, GG>();

        let circuit = BoundCircuit::<C, GG>::new(pp, cm_u, p, u, o_u);

        let (ek, vk) =
            CcGroth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);

        let proof = CcGroth16::<Bn254>::prove(&ek, circuit, &mut rng).unwrap();

        assert!(CcGroth16::<Bn254>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
    }
}
