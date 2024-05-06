use super::data_structure::{Commitment, Parameters, Plaintext, Randomness};
use crate::ConstraintF;
use ark_ec::CurveGroup;

use ark_ff::{
    fields::{Field, PrimeField},
    BigInteger,
};

use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    pairing::PairingVar,
    prelude::*,
};

use ark_relations::r1cs::{ConstraintSynthesizer, Namespace, SynthesisError};
use ark_std::{borrow::Borrow, vec::Vec};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ParametersVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    pub g: Vec<GG>,
    pub h: GG,

    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|param| {
            let Parameters { g, h } = param.borrow().clone();

            let g = Vec::new_variable(ark_relations::ns!(cs, "pp g"), || Ok(g), mode)?;

            let h = GG::new_variable(ark_relations::ns!(cs, "pp h"), || Ok(h), mode)?;

            Ok(Self {
                g,
                h,
                _curve: PhantomData,
            })
        })
    }
}

#[derive(Debug)]
pub struct PlaintextVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    pub msg: Vec<FpVar<ConstraintF<C>>>,
    #[doc(hidden)]
    _curve: PhantomData<GG>,
}

impl<C, GG> AllocVar<Plaintext<C>, ConstraintF<C>> for PlaintextVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn new_variable<T: Borrow<Plaintext<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|pt| {
            let Plaintext { msg } = pt.borrow().clone();

            let mut msg_vec = Vec::new();

            for m_i in msg.iter() {
                let mut m_bits = m_i.into_bigint().to_bits_le();
                m_bits.truncate(C::ScalarField::MODULUS_BIT_SIZE as usize);
                for _ in m_bits.len()..C::ScalarField::MODULUS_BIT_SIZE as usize {
                    m_bits.push(false);
                }
                m_bits.reverse();

                let elem = ConstraintF::<C>::from_bigint(
                    <ConstraintF<C> as PrimeField>::BigInt::from_bits_be(&m_bits),
                )
                .unwrap();
                msg_vec.push(elem);
            }

            let msg = Vec::new_variable(ark_relations::ns!(cs, "msg"), || Ok(msg_vec), mode)?;

            Ok(Self {
                msg,
                _curve: PhantomData,
            })
        })
    }
}

pub struct CommitmentVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    pub cm: GG,

    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Commitment<C>, ConstraintF<C>> for CommitmentVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn new_variable<T: Borrow<Commitment<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|cm| {
            let Commitment { cm } = cm.borrow().clone();

            let cm = GG::new_variable(ark_relations::ns!(cs, "cm"), || Ok(cm), mode)?;

            Ok(CommitmentVar {
                cm,
                _curve: PhantomData,
            })
        })
    }
}

pub struct RandomnessVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    pub rand: FpVar<ConstraintF<C>>,
    _curve: PhantomData<GG>,
}

impl<C, GG> AllocVar<Randomness<C>, ConstraintF<C>> for RandomnessVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|rand| {
            let Randomness { rand } = rand.borrow().clone();

            let mut rand_bits = rand.into_bigint().to_bits_le();
            rand_bits.truncate(C::ScalarField::MODULUS_BIT_SIZE as usize);
            for _ in rand_bits.len()..C::ScalarField::MODULUS_BIT_SIZE as usize {
                rand_bits.push(false);
            }
            rand_bits.reverse();

            let elem = ConstraintF::<C>::from_bigint(
                <ConstraintF<C> as PrimeField>::BigInt::from_bits_be(&rand_bits),
            )
            .unwrap();

            let r = FpVar::<ConstraintF<C>>::new_variable(
                ark_relations::ns!(cs, "rand"),
                || Ok(elem),
                mode,
            )?;

            Ok(RandomnessVar {
                rand: r,
                _curve: PhantomData,
            })
        })
    }
}

#[derive(Clone)]
pub struct PedersenCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    pub pp: Parameters<C>,
    pub pt: Plaintext<C>,
    pub cm: Commitment<C>,
    pub rand: Randomness<C>,
    #[doc(hidden)]
    pub _curve: PhantomData<GG>,
}

impl<C, GG> PedersenCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    pub fn new(
        pp: Parameters<C>,
        cm: Commitment<C>,
        pt: Plaintext<C>,
        rand: Randomness<C>,
    ) -> Self {
        Self {
            pp,
            pt,
            cm,
            rand,
            _curve: PhantomData,
        }
    }
}

pub struct PedersenGadget<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    pp: ParametersVar<C, GG>,
    cm: CommitmentVar<C, GG>,
    pt: PlaintextVar<C, GG>,
    rand: RandomnessVar<C, GG>,
}

impl<C, GG> PedersenGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn new(
        pp: ParametersVar<C, GG>,
        cm: CommitmentVar<C, GG>,
        pt: PlaintextVar<C, GG>,
        rand: RandomnessVar<C, GG>,
    ) -> Self {
        Self { pp, cm, pt, rand }
    }

    fn commit(&self) -> Result<(), SynthesisError> {
        let rand = self.rand.rand.clone().to_bits_le()?;

        let mut circuit_cm = self.pp.h.clone().scalar_mul_le(rand.clone().iter())?;

        for (g_i, m_i) in self
            .pp
            .g
            .clone()
            .iter()
            .zip(self.pt.msg.clone().into_iter())
        {
            let computed_cm_i = g_i.scalar_mul_le(m_i.to_bits_le()?.iter())?;
            circuit_cm += computed_cm_i;
        }

        self.cm.cm.enforce_equal(&circuit_cm)?;

        Ok(())
    }
}

impl<C, GG> ConstraintSynthesizer<ConstraintF<C>> for PedersenCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        let circuit_pp =
            ParametersVar::new_input(ark_relations::ns!(cs, "param"), || Ok(&self.pp))?;

        let circuit_cm =
            CommitmentVar::new_input(ark_relations::ns!(cs, "commitment"), || Ok(&self.cm))?;

        let circuit_pt =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "plaintext"), || Ok(&self.pt))
                .unwrap();

        let circuit_rand =
            RandomnessVar::new_witness(ark_relations::ns!(cs, "randomness"), || Ok(&self.rand))
                .unwrap();

        let pedersen =
            PedersenGadget::<C, GG>::new(circuit_pp, circuit_cm, circuit_pt, circuit_rand);

        pedersen.commit()
    }
}
