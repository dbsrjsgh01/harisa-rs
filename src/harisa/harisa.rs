use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::{CryptoRng, Rng, RngCore};

use crate::harisa::{
    data_structure::{HarisaPP, HarisaProof},
    preprocess::*,
    Membership,
};

pub type Error = Box<dyn ark_std::error::Error>;

use crate::cc_snark::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

#[derive(Clone)]
pub struct Harisa<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: PhantomData<(E, QAP)>,
}

impl<E: Pairing> Membership<E> for Harisa<E> {
    type Table = Vec<E::G1Affine>;
    type Parameters = HarisaPP<E>;
    type Proof = HarisaProof<E>;

    fn setup<
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        set: Vec<E::ScalarField>,
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
        accum: E::G1Affine,
        cm_u: E::G1Affine,
        u: Vec<E::ScalarField>,
        o_u: E::ScalarField,
        rng: &mut R,
    ) -> Result<Self::Proof, Error> {
        let proof = Self::generate_harisa_opt_proof(pp, tree, accum, cm_u, u, o_u, rng).unwrap();

        Ok(proof)
    }

    fn verify(
        pp: Self::Parameters,
        accum: E::G1Affine,
        c_u: E::G1Affine,
        proof: Self::Proof,
    ) -> Result<bool, Error> {
        let res = Self::harisa_verify(pp, accum, c_u, proof).unwrap();

        Ok(res)
    }
}
