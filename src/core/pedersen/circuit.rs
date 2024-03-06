use super::data_structure::{Commitment, Parameters, Plaintext, Randomness};
use crate::BasePrimeField;

use ark_ec::pairing::Pairing;
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

#[derive(Clone)]
pub struct ParametersVar<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pub g: Vec<P::G1Var>,
    pub h: P::G1Var,
}

impl<E, P> AllocVar<Parameters<E>, BasePrimeField<E>> for ParametersVar<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new_variable<T: Borrow<Parameters<E>>>(
        cs: impl Into<Namespace<BasePrimeField<E>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|param| {
            let Parameters { g, h } = param.borrow().clone();

            let g = Vec::new_variable(ark_relations::ns!(cs, "pp g"), || Ok(g), mode)?;

            let h = P::G1Var::new_variable(ark_relations::ns!(cs, "pp h"), || Ok(h), mode)?;

            Ok(Self { g, h })
        })
    }
}

pub struct PlaintextVar<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pub msg: Vec<FpVar<BasePrimeField<E>>>,
    _pairing: PhantomData<P>,
}

impl<E, P> AllocVar<Plaintext<E>, BasePrimeField<E>> for PlaintextVar<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new_variable<T: Borrow<Plaintext<E>>>(
        cs: impl Into<Namespace<BasePrimeField<E>>>,
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
                m_bits.truncate(E::ScalarField::MODULUS_BIT_SIZE as usize);
                for _ in m_bits.len()..E::ScalarField::MODULUS_BIT_SIZE as usize {
                    m_bits.push(false);
                }
                m_bits.reverse();

                let elem = BasePrimeField::<E>::from_bigint(
                    <BasePrimeField<E> as PrimeField>::BigInt::from_bits_be(&m_bits),
                )
                .unwrap();
                msg_vec.push(elem);
            }

            let msg = Vec::new_variable(ark_relations::ns!(cs, "msg"), || Ok(msg_vec), mode)?;

            Ok(Self {
                msg: msg,
                _pairing: PhantomData,
            })
        })
    }
}

pub struct CommitmentVar<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pub cm: P::G1Var,
}

impl<E, P> AllocVar<Commitment<E>, BasePrimeField<E>> for CommitmentVar<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new_variable<T: Borrow<Commitment<E>>>(
        cs: impl Into<Namespace<BasePrimeField<E>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|cm| {
            let Commitment { cm } = cm.borrow().clone();

            let cm = P::G1Var::new_variable(ark_relations::ns!(cs, "cm"), || Ok(cm), mode)?;

            Ok(CommitmentVar { cm })
        })
    }
}

pub struct RandomnessVar<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pub rand: FpVar<BasePrimeField<E>>,
    _curve: PhantomData<P>,
}

impl<E, P> AllocVar<Randomness<E>, BasePrimeField<E>> for RandomnessVar<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new_variable<T: Borrow<Randomness<E>>>(
        cs: impl Into<Namespace<BasePrimeField<E>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|rand| {
            let Randomness { rand } = rand.borrow().clone();

            let mut rand_bits = rand.into_bigint().to_bits_le();
            rand_bits.truncate(E::ScalarField::MODULUS_BIT_SIZE as usize);
            for _ in rand_bits.len()..E::ScalarField::MODULUS_BIT_SIZE as usize {
                rand_bits.push(false);
            }
            rand_bits.reverse();

            let elem = BasePrimeField::<E>::from_bigint(
                <BasePrimeField<E> as PrimeField>::BigInt::from_bits_be(&rand_bits),
            )
            .unwrap();

            let r = FpVar::<BasePrimeField<E>>::new_variable(
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

pub struct PedersenCircuit<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pub pp: Parameters<E>,
    pub pt: Plaintext<E>,
    pub cm: Commitment<E>,
    pub rand: Randomness<E>,
    _pairing: PhantomData<P>,
}

impl<E, P> PedersenCircuit<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    pub fn new(
        pp: Parameters<E>,
        cm: Commitment<E>,
        pt: Plaintext<E>,
        rand: Randomness<E>,
    ) -> Self {
        Self {
            pp,
            pt,
            cm,
            rand,
            _pairing: PhantomData,
        }
    }
}

pub struct PedersenGadget<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pp: ParametersVar<E, P>,
    cm: CommitmentVar<E, P>,
    pt: PlaintextVar<E, P>,
    rand: RandomnessVar<E, P>,
}

impl<E, P> PedersenGadget<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new(
        pp: ParametersVar<E, P>,
        cm: CommitmentVar<E, P>,
        pt: PlaintextVar<E, P>,
        rand: RandomnessVar<E, P>,
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

impl<E, P> ConstraintSynthesizer<BasePrimeField<E>> for PedersenCircuit<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<BasePrimeField<E>>,
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
            PedersenGadget::<E, P>::new(circuit_pp, circuit_cm, circuit_pt, circuit_rand);

        pedersen.commit()
    }
}
