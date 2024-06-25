use crate::cc_snark::data_structure::{Proof, ProvingKey, VerifyingKey};
use ark_ec::pairing::Pairing;
use num_bigint::BigInt;

#[derive(Clone, Default, Debug, PartialEq)]
pub struct HarisaPP<E: Pairing> {
    pub arithm_ek: ProvingKey<E>,
    pub arithm_vk: VerifyingKey<E>,
    pub bound_ek: ProvingKey<E>,
    pub bound_vk: VerifyingKey<E>,
    pub g: BigInt,
    pub mod_n: BigInt,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct HarisaProof<E: Pairing> {
    pub w_hat: BigInt,
    pub r: BigInt,
    pub q: BigInt,
    pub k: BigInt,
    pub arithm_prf: Proof<E>,
    pub bound_prf: Proof<E>,
}
