use crate::{
    cc_snark::{Proof, ProvingKey, VerifyingKey},
    harisa::Membership,
};

use ark_ec::pairing::Pairing;

pub struct LookupPP<E: Pairing, M: Membership<E>> {
    pub m_pp: M::Parameters,
    pub ctt_ek: ProvingKey<E>,
    pub ctt_vk: VerifyingKey<E>,
    pub wt_ek: ProvingKey<E>,
    pub wt_vk: VerifyingKey<E>,
}

pub struct LookupProof<E: Pairing, M: Membership<E>> {
    pub m_prf: M::Proof,
    pub ctt_prf: Proof<E>,
    pub wt_prf: Proof<E>,
}
