use crate::core::{cc_snark::CcGroth16, pedersen::data_structure::Commitment};
use crate::BasePrimeField;

use ark_ec::pairing::Pairing;
use ark_r1cs_std::pairing::PairingVar;
use ark_relations::r1cs::SynthesisError;
use core::ops::{AddAssign, MulAssign};

use super::prepare_verifying_key;
use super::r1cs_to_qap::R1CSToQAP;
use super::{
    data_structure::{HarisaPP, HarisaProof},
    Harisa,
};

impl<E: Pairing, QAP: R1CSToQAP> Harisa<E, QAP> {
    pub fn harisa_verify(
        pp: HarisaPP<E>,
        accum: Vec<E::ScalarField>,
        c_u: Commitment<E>,
        proof: HarisaProof<E>,
    ) -> Result<bool, SynthesisError> {
        // 1. acc_hat = acc^prod_pi

        // hash-to-prime => l

        // PoKE verify

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

        assert_eq!(arithm_result, true);
        assert_eq!(bound_result, true);

        Ok(true)
    }
}
