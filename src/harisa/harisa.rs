use std::{marker::PhantomData, str::FromStr};

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::{CryptoRng, Rng, RngCore};
use num_bigint::BigInt;

use crate::{
    harisa::{
        data_structure::{HarisaPP, HarisaProof},
        precompute::*,
        Membership,
    },
    linker::Linker,
};

pub type Error = Box<dyn ark_std::error::Error>;

use crate::cc_snark::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

#[derive(Clone)]
pub struct Harisa<E: Pairing, LNK: Linker<E>, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: PhantomData<(E, LNK, QAP)>,
}

impl<E: Pairing, LNK: Linker<E>> Membership<E, LNK> for Harisa<E, LNK> {
    type Table = Vec<BigInt>;
    type Parameters = HarisaPP<E, LNK>;
    type Proof = HarisaProof<E, LNK>;

    fn setup<
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        set: Vec<BigInt>,
        arithm_circuit: Arithm,
        bound_circuit: Bound,
        rng: &mut R,
    ) -> Result<(Self::Parameters, Self::Table, Vec<E::G1Affine>), Error> {
        let (pp, table, ck) =
            Self::generate_harisa_parameters(set, arithm_circuit, bound_circuit, rng).unwrap();

        Ok((pp, table, ck))
    }

    fn prove<R: RngCore + CryptoRng + Rng>(
        pp: Self::Parameters,
        tree: Self::Table,
        accum: BigInt,
        cm_u: E::G1Affine,
        u: Vec<BigInt>,
        o_u: E::ScalarField,
        rng: &mut R,
    ) -> Result<Self::Proof, Error>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        let proof = Self::generate_harisa_opt_proof(pp, tree, accum, cm_u, u, o_u, rng).unwrap();

        Ok(proof)
    }

    fn verify(
        pp: Self::Parameters,
        accum: BigInt,
        c_u: E::G1Affine,
        proof: Self::Proof,
    ) -> Result<bool, Error>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        let res = Self::harisa_verify(pp, accum, c_u, proof).unwrap();

        Ok(res)
    }
}
