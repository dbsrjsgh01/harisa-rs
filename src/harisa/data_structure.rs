// harisa crs, proof
use crate::core::{
    cc_snark::data_structure::{Proof, ProvingKey, VerifyingKey},
    pedersen::data_structure::{Commitment, Parameters},
};
use ark_ec::pairing::Pairing;

#[derive(Clone, Default, Debug, PartialEq)]
pub struct HarisaPP<E: Pairing> {
    pub arithm_ek: ProvingKey<E>,
    pub arithm_vk: VerifyingKey<E>,
    pub bound_ek: ProvingKey<E>,
    pub bound_vk: VerifyingKey<E>,
    pub cm_pp: Parameters<E>,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct HarisaProof<E: Pairing> {
    pub w_hat: E::G1Affine,
    pub r: E::G1Affine,
    pub cm_sr: Commitment<E>,
    pub q: E::G1Affine,
    pub k: E::ScalarField,
    pub arithm_prf: Proof<E>,
    pub bound_prf: Proof<E>,
}
