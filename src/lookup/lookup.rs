use crate::{
    core::{
        cc_snark::{LibsnarkReduction, R1CSToQAP},
        pedersen::data_structure::Commitment,
    },
    harisa::Membership,
    lookup::{
        data_structure::{LookupPP, LookupProof},
        Lookup,
    },
};
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::{CryptoRng, Rng, RngCore};
use std::marker::PhantomData;

pub struct HarisaLookup<E: Pairing, M: Membership<E>, QAP: R1CSToQAP = LibsnarkReduction> {
    _curve: PhantomData<(E, M, QAP)>,
}

impl<E: Pairing, M: Membership<E>> Lookup<E, M> for HarisaLookup<E, M> {
    type Accum = E::G1Affine;
    type CM = Commitment<E::G1>;
    type PP = LookupPP<E, M>;
    type Proof = LookupProof<E, M>;
    type Error = SynthesisError;

    fn setup<R1CS: ConstraintSynthesizer<E::ScalarField>, R: RngCore + CryptoRng + Rng>(
        set: Vec<E::ScalarField>,
        arithm_circuit: Option<R1CS>,
        bound_circuit: Option<R1CS>,
        ctt_circuit: Option<R1CS>,
        wt_circuit: Option<R1CS>,
        rng: &mut R,
    ) -> Result<Self::PP, Self::Error> {
        let lookup_param = Self::generate_lookup_parameter(
            set,
            arithm_circuit,
            bound_circuit,
            ctt_circuit,
            wt_circuit,
            rng,
        )
        .unwrap();

        Ok(lookup_param)
    }

    fn prove<R1CS: ConstraintSynthesizer<E::ScalarField>, R: RngCore + CryptoRng + Rng>(
        pp: Self::PP,
        acc: Self::Accum,
        lookup: Vec<E::ScalarField>,
        arithm_circuit: Option<R1CS>,
        bound_circuit: Option<R1CS>,
        ctt_circuit: Option<R1CS>,
        wt_circuit: Option<R1CS>,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        let lookup_proof = Self::generate_lookup_proof(
            pp,
            acc,
            lookup,
            arithm_circuit,
            bound_circuit,
            ctt_circuit,
            wt_circuit,
            rng,
        )
        .unwrap();

        Ok(lookup_proof)
    }

    fn verify(
        pp: Self::PP,
        acc: Self::Accum,
        cm_u: Self::CM,
        cm_a: Self::CM,
        cm_z: Self::CM,
        prf: Self::Proof,
    ) -> Result<bool, Self::Error> {
        let result = Self::verify_lookup(pp, acc, cm_u, cm_a, cm_z, prf).unwrap();

        Ok(result)
    }
}
