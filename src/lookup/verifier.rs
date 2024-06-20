use crate::{
    cc_snark::{prepare_verifying_key, CcGroth16, R1CSToQAP},
    harisa::{Membership, Proof},
    lookup::{
        data_structure::{LookupPP, LookupProof},
        lookup::HarisaPlus,
    },
};

use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::SynthesisError;
use num_bigint::BigInt;

impl<E, M, QAP> HarisaPlus<E, M, QAP>
where
    E: Pairing,
    M: Membership<E>,
    QAP: R1CSToQAP,
{
    pub fn verify_lookup(
        pp: LookupPP<E, M>,
        accum: BigInt,
        cm_u: E::G1Affine,
        cm_f: E::G1Affine,
        cm_z: E::G1Affine,
        proof: LookupProof<E, M>,
    ) -> Result<bool, SynthesisError> {
        let mem_verify = start_timer!(|| "mem::verify");
        // let mem_result = M::verify(pp.m_pp, accum, cm_u, proof.m_prf).unwrap();
        let mem_result = M::verify(pp.m_pp, accum, proof.m_prf).unwrap();
        end_timer!(mem_verify);

        let ctt_pvk = prepare_verifying_key(&pp.ctt_vk.clone());
        let ctt_verify = start_timer!(|| "cpctt::verify");
        let ctt_result = CcGroth16::<E, QAP>::verify_proof(&ctt_pvk, &proof.ctt_prf, &[]).unwrap();
        end_timer!(ctt_verify);

        let wt_pvk = prepare_verifying_key(&pp.wt_vk.clone());
        let wt_verify = start_timer!(|| "cpbound::verify");
        let wt_result = CcGroth16::<E, QAP>::verify_proof(&wt_pvk, &proof.wt_prf, &[]).unwrap();
        end_timer!(wt_verify);

        assert_eq!(mem_result, true, "[HARiSA] Membership Check Failed");
        assert_eq!(ctt_result, true, "[Copy this or that] Verification Failed");
        assert_eq!(wt_result, true, "[Well Transformed] Verification Failed");

        Ok(true)
    }
}
