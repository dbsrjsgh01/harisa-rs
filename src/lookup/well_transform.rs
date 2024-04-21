use crate::{
    core::pedersen::data_structure::Commitment, harisa::Membership,
    lookup::data_structure::LookupPP,
};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_r1cs_std::alloc::AllocationMode;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub struct WellTransform<E: Pairing, M: Membership<E>> {
    // statement
    pub pp: LookupPP<E, M>,
    pub c_u: Commitment<E::G1>,
    pub c_a: Commitment<E::G1>,
    pub c_z: Commitment<E::G1>,

    // witness
    pub u: Vec<E::ScalarField>,
    pub a: Vec<E::ScalarField>,
    pub z: Vec<E::ScalarField>,
}

impl<E: Pairing, M: Membership<E>> ConstraintSynthesizer<E::ScalarField> for WellTransform<E, M> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), SynthesisError> {
        // 1. commitment 제대로 생성이 되었는가 (c_u, c_f, c_z)

        // 2. relation (hat_f = f||z)

        Ok(())
    }
}
