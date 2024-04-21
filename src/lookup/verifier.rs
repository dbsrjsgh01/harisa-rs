use crate::{
    core::{
        cc_snark::{CcGroth16, R1CSToQAP},
        pedersen::data_structure::Commitment,
    },
    harisa::Membership,
};

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::SynthesisError;
use core::ops::{AddAssign, MulAssign};

use super::{
    data_structure::{LookupPP, LookupProof},
    lookup::HarisaLookup,
};
use crate::core::cc_snark::prepare_verifying_key;

impl<E, M, QAP> HarisaLookup<E, M, QAP>
where
    E: Pairing,
    M: Membership<E>,
    QAP: R1CSToQAP,
{
    pub fn verify_lookup(
        pp: LookupPP<E, M>,
        acc: E::G1Affine,
        cm_u: Commitment<E::G1>,
        cm_a: Commitment<E::G1>,
        cm_z: Commitment<E::G1>,
        prf: LookupProof<E, M>,
    ) -> Result<bool, SynthesisError> {
        let harisa_verify = start_timer!(|| "harisa::verify");
        let harisa_result = M::verify(pp.harisa_crs, acc, cm_u, prf.harisa_prf).unwrap();
        end_timer!(harisa_verify);

        let wt_pvk = prepare_verifying_key(&pp.wt_vk.clone());
        let wt_verify = start_timer!(|| "well-transformed::verify");
        let wt_result = CcGroth16::<E>::verify_proof(&wt_pvk, &prf.wt_prf, &[]).unwrap();
        end_timer!(wt_verify);

        let ctt_pvk = prepare_verifying_key(&pp.ctt_vk.clone());
        let ctt_verify = start_timer!(|| "copy-this-or-that::verify");
        let ctt_result = CcGroth16::<E>::verify_proof(&ctt_pvk, &prf.ctt_prf, &[]).unwrap();

        assert_eq!(harisa_result, true, "[Failed] Harisa Verification");
        assert_eq!(wt_result, true, "[Failed] Well-transformed");
        assert_eq!(ctt_result, true, "[Failed] Copy-this-or-that");

        Ok(true)
    }
}
