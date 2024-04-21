use crate::core::cc_snark::{Proof, ProvingKey, VerifyingKey};
use crate::core::pedersen::data_structure::Parameters;
use crate::harisa::data_structure::{HarisaPP, HarisaProof};
use crate::harisa::Membership;
use ark_ec::pairing::Pairing;

#[derive(Clone, Debug, Default)]
pub struct LookupPP<E: Pairing, M: Membership<E>> {
    pub harisa_crs: M::Parameters,
    pub wt_ek: ProvingKey<E>,
    pub wt_vk: VerifyingKey<E>,
    pub ctt_ek: ProvingKey<E>,
    pub ctt_vk: VerifyingKey<E>,
    pub cm_pp: Parameters<E::G1>,
    pub table: M::Table,
}

#[derive(Clone, Debug, Default)]
pub struct LookupProof<E: Pairing, M: Membership<E>> {
    pub harisa_prf: M::Proof,
    pub wt_prf: Proof<E>,
    pub ctt_prf: Proof<E>,
}
