use crate::{
    core::pedersen::data_structure::Commitment, harisa::Membership,
    lookup::data_structure::LookupPP,
};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_r1cs_std::alloc::AllocationMode;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub struct CopyThisOrThat<E: Pairing, M: Membership<E>> {
    // statement
    pub pp: LookupPP<E, M>,
    pub c_u: Commitment<E::G1>,
    pub c_a: Commitment<E::G1>,

    // witness
    pub u: Vec<E::ScalarField>,
    pub a: Vec<E::ScalarField>,
}

impl<E: Pairing, M: Membership<E>> ConstraintSynthesizer<E::ScalarField> for CopyThisOrThat<E, M> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), SynthesisError> {
        // 1. commitment 확인

        // 2. relation check ( (a_i - a_i+1)(a_i - t_i) == 0 )

        Ok(())
    }
}
