use crate::{
    cc_snark::{Proof, ProvingKey, VerifyingKey},
    harisa::Membership,
};

use ark_ec::pairing::Pairing;

#[derive(Default, Debug, PartialEq)]
pub struct LookupPP<E: Pairing, M: Membership<E>> {
    pub m_pp: M::Parameters,
    pub ctt_ek: ProvingKey<E>,
    pub ctt_vk: VerifyingKey<E>,
    pub wt_ek: ProvingKey<E>,
    pub wt_vk: VerifyingKey<E>,
}

impl<E: Pairing, M: Membership<E>> Clone for LookupPP<E, M> {
    fn clone(&self) -> Self {
        Self {
            m_pp: self.m_pp.clone(),
            ctt_ek: self.ctt_ek.clone(),
            ctt_vk: self.ctt_vk.clone(),
            wt_ek: self.wt_ek.clone(),
            wt_vk: self.wt_vk.clone(),
        }
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct LookupProof<E: Pairing, M: Membership<E>> {
    pub m_prf: M::Proof,
    pub ctt_prf: Proof<E>,
    pub wt_prf: Proof<E>,
}
