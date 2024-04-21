use crate::core::cc_snark::{r1cs_to_qap::R1CSToQAP, CcGroth16, ProvingKey, VerifyingKey};
use crate::core::pedersen::Pedersen;
use crate::harisa::preprocess::*;
use crate::harisa::{setup::*, Membership};
use crate::lookup::concatenate::*;
use crate::lookup::data_structure::LookupPP;
use crate::lookup::lookup::HarisaLookup;
use ark_crypto_primitives::snark::*;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::{CryptoRng, Rng, RngCore};

impl<E: Pairing, M: Membership<E>, QAP: R1CSToQAP> HarisaLookup<E, M, QAP> {
    pub fn generate_cc_snark_parameters<
        C: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng,
    >(
        circuit: C,
        rng: &mut R,
    ) -> Result<(ProvingKey<E>, VerifyingKey<E>), SynthesisError> {
        let cc_snark_generator = start_timer!(|| "ccGroth::Generator");
        let (cc_ek, cc_vk) = CcGroth16::<E>::circuit_specific_setup(circuit, rng).unwrap();
        end_timer!(cc_snark_generator);
        Ok((cc_ek, cc_vk))
    }

    pub fn generate_lookup_parameter<
        R1CS: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        set: Vec<E::ScalarField>,
        arithm_circuit: Option<R1CS>,
        bound_circuit: Option<R1CS>,
        ctt_circuit: Option<R1CS>,
        wt_circuit: Option<R1CS>,
        rng: &mut R,
    ) -> Result<LookupPP<E, M>, SynthesisError> {
        let num = set.len();

        // table hat_T = T || z
        let table = concatenate::<E>(set.clone(), set.clone(), num);

        let (harisa_crs, table) = M::setup(
            set.clone(),
            arithm_circuit.unwrap(),
            bound_circuit.unwrap(),
            rng,
        )
        .unwrap();

        let (ctt_ek, ctt_vk) =
            Self::generate_cc_snark_parameters(ctt_circuit.unwrap(), rng).unwrap();

        let (wt_ek, wt_vk) = Self::generate_cc_snark_parameters(wt_circuit.unwrap(), rng).unwrap();

        let cm_pp = Pedersen::<E::G1>::setup(set.len(), rng).unwrap();

        Ok(LookupPP {
            harisa_crs,
            wt_ek,
            wt_vk,
            ctt_ek,
            ctt_vk,
            cm_pp,
            table,
        })
    }
}
