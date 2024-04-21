pub mod concatenate;
pub mod copy_this_or_that;
pub mod data_structure;
pub mod lookup;
pub mod prover;
pub mod setup;
pub mod verifier;
pub mod well_transform;

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::{CryptoRng, Rng, RngCore};

use crate::harisa::Membership;

pub trait Lookup<E: Pairing, M: Membership<E>> {
    type PP;
    type Accum;
    type Proof;
    type Error;
    type CM;

    fn setup<R1CS: ConstraintSynthesizer<E::ScalarField>, R: RngCore + CryptoRng + Rng>(
        set: Vec<E::ScalarField>,
        arithm_circuit: Option<R1CS>,
        bound_circuit: Option<R1CS>,
        ctt_circuit: Option<R1CS>,
        wt_circuit: Option<R1CS>,
        rng: &mut R,
    ) -> Result<Self::PP, Self::Error>;

    fn prove<R1CS: ConstraintSynthesizer<E::ScalarField>, R: RngCore + CryptoRng + Rng>(
        pp: Self::PP,
        acc: Self::Accum,
        lookup: Vec<E::ScalarField>,
        arithm_circuit: Option<R1CS>,
        bound_circuit: Option<R1CS>,
        ctt_circuit: Option<R1CS>,
        wt_circuit: Option<R1CS>,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error>;

    fn verify(
        pp: Self::PP,
        acc: Self::Accum,
        cm_u: Self::CM,
        cm_a: Self::CM,
        cm_z: Self::CM,
        prf: Self::Proof,
    ) -> Result<bool, Self::Error>;
}
