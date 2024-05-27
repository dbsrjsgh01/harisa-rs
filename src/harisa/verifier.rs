use crate::cc_snark::CcGroth16;
use crate::harisa::hash_to_prime::hash_to_prime;
use crate::ConstraintF;

use ark_ec::pairing::Pairing;
use ark_r1cs_std::pairing::PairingVar;
use ark_relations::r1cs::SynthesisError;
use core::ops::{AddAssign, MulAssign};

use super::prepare_verifying_key;
use super::r1cs_to_qap::R1CSToQAP;
use super::{
    data_structure::{HarisaPP, HarisaProof},
    harisa::Harisa,
};

impl<E: Pairing, QAP: R1CSToQAP> Harisa<E, QAP> {
    pub fn harisa_verify(
        pp: HarisaPP<E>,
        accum: E::G1Affine,
        cm_u: E::G1Affine,
        proof: HarisaProof<E>,
    ) -> Result<bool, SynthesisError> {
        // proof = w_hat, r, cm_sr, q, k, arithm_prf, bound_prf
        let h = hash_to_prime::<E>(
            vec![
                pp.g.clone(),
                accum,
                cm_u.clone(),
                proof.cm_sr.clone(),
                proof.w_hat.into(),
                proof.r.clone(),
            ],
            vec![],
            8,
        )
        .unwrap();
        // 1. acc_hat = acc^{h * prod_pi} + R
        let acc_hat = (accum * h + proof.r).into();

        // hash-to-prime => l
        let l =
            hash_to_prime::<E>(vec![pp.g.clone(), proof.w_hat.into(), acc_hat], vec![], 8).unwrap();

        // PoKE verify
        // assert_eq!(
        //     (proof.q * l + proof.w_hat * proof.k).into(),
        //     acc_hat,
        //     "[PoKE] Verification Failed"
        // );

        let arithm_pvk = prepare_verifying_key(&pp.arithm_vk.clone());
        let arithm_verify = start_timer!(|| "cparithm::verify");
        let arithm_result =
            CcGroth16::<E, QAP>::verify_proof(&arithm_pvk, &proof.arithm_prf, &[]).unwrap();
        end_timer!(arithm_verify);

        let bound_pvk = prepare_verifying_key(&pp.bound_vk.clone());
        let bound_verify = start_timer!(|| "cpbound::verify");
        let bound_result =
            CcGroth16::<E, QAP>::verify_proof(&bound_pvk, &proof.bound_prf, &[]).unwrap();
        end_timer!(bound_verify);

        assert_eq!(arithm_result, true, "[Arithm] Verification Failed");
        assert_eq!(bound_result, true, "[Bound] Verification Failed");

        Ok(true)
    }
}
