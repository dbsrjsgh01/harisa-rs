use std::{marker::PhantomData, str::FromStr};

use crate::{
    cc_snark::{LibsnarkReduction, R1CSToQAP},
    harisa::Membership,
    lookup::{
        data_structure::{LookupPP, LookupProof},
        Lookup,
    },
};

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::{CryptoRng, Rng, RngCore};
use num_bigint::BigInt;

pub type Error = Box<dyn ark_std::error::Error>;

pub struct HarisaPlus<E: Pairing, M: Membership<E>, QAP: R1CSToQAP = LibsnarkReduction> {
    _curve: PhantomData<(E, M, QAP)>,
}

impl<E: Pairing, M: Membership<E>> Lookup<E, M> for HarisaPlus<E, M> {
    type Accum = BigInt;
    type Table = M::Table;
    type CM = E::G1Affine;
    type PP = LookupPP<E, M>;
    type Proof = LookupProof<E, M>;

    fn setup<
        CTT: ConstraintSynthesizer<E::ScalarField>,
        WT: ConstraintSynthesizer<E::ScalarField>,
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        set: Vec<BigInt>,
        arithm_circuit: Option<Arithm>,
        bound_circuit: Option<Bound>,
        ctt_circuit: Option<CTT>,
        wt_circuit: Option<WT>,
        rng: &mut R,
    ) -> Result<(Self::PP, Self::Table), Error> {
        let (pp, table) = Self::generate_lookup_parameters(
            set,
            ctt_circuit.unwrap(),
            wt_circuit.unwrap(),
            arithm_circuit.unwrap(),
            bound_circuit.unwrap(),
            rng,
        )
        .unwrap();

        Ok((pp, table))
    }

    fn prove<
        CTT: ConstraintSynthesizer<E::ScalarField>,
        WT: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        pp: Self::PP,
        acc: Self::Accum,
        tree: Self::Table,
        lookup: Vec<BigInt>,
        elem: Vec<BigInt>,
        ctt_circuit: Option<CTT>,
        wt_circuit: Option<WT>,
        rng: &mut R,
    ) -> Result<Self::Proof, Error>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        let prf = Self::generate_lookup_proof(
            pp,
            acc,
            tree,
            lookup,
            elem,
            ctt_circuit.unwrap(),
            wt_circuit.unwrap(),
            rng,
        )
        .unwrap();

        Ok(prf)
    }

    fn verify(
        pp: Self::PP,
        acc: Self::Accum,
        // cm_u: Self::CM,
        // cm_a: Self::CM,
        // cm_z: Self::CM,
        prf: Self::Proof,
    ) -> Result<bool, Error>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        // let res = Self::verify_lookup(pp, acc, cm_u, cm_a, cm_z, prf).unwrap();
        let res = Self::verify_lookup(pp, acc, prf).unwrap();

        Ok(res)
    }
}
