use std::{marker::PhantomData, str::FromStr};

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::{CryptoRng, Rng, RngCore};
use num_bigint::BigInt;

use crate::harisa::{
    data_structure::{HarisaPP, HarisaProof},
    precompute::*,
    Membership,
};

pub type Error = Box<dyn ark_std::error::Error>;

use crate::cc_snark::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

#[derive(Clone)]
pub struct Harisa<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: PhantomData<(E, QAP)>,
}

impl<E: Pairing> Membership<E> for Harisa<E> {
    type Table = Vec<BigInt>;
    type Parameters = HarisaPP<E>;
    type Proof = HarisaProof<E>;

    fn setup<
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        set: Vec<BigInt>,
        arithm_circuit: Arithm,
        bound_circuit: Bound,
        rng: &mut R,
    ) -> Result<(Self::Parameters, Self::Table), Error> {
        let (pp, table) =
            Self::generate_harisa_parameters(set, arithm_circuit, bound_circuit, rng).unwrap();

        Ok((pp, table))
    }

    fn prove<R: RngCore + CryptoRng + Rng>(
        pp: Self::Parameters,
        tree: Self::Table,
        accum: BigInt,
        u: Vec<BigInt>,
        rng: &mut R,
    ) -> Result<Self::Proof, Error>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        let proof = Self::generate_harisa_opt_proof(pp, tree, accum, u, rng).unwrap();

        Ok(proof)
    }

    fn verify(
        pp: Self::Parameters,
        accum: BigInt,
        // c_u: E::G1Affine,
        proof: Self::Proof,
    ) -> Result<bool, Error>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        // let res = Self::harisa_verify(pp, accum, c_u, proof).unwrap();
        let res = Self::harisa_verify(pp, accum, proof).unwrap();

        Ok(res)
    }
}
