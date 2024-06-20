use crate::{
    cc_snark::{prepare_verifying_key, CcGroth16, ProvingKey, VerifyingKey},
    harisa::{harisa::Harisa, Membership},
    lookup::{
        data_structure::{LookupPP, LookupProof},
        lookup::HarisaPlus,
    },
};

use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::{CryptoRng, Rng, RngCore};
use num_bigint::BigInt;

impl<E, M> HarisaPlus<E, M>
where
    E: Pairing,
    M: Membership<E>,
{
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

    pub fn generate_lookup_parameters<
        CTT: ConstraintSynthesizer<E::ScalarField>,
        WT: ConstraintSynthesizer<E::ScalarField>,
        Arithm: ConstraintSynthesizer<E::ScalarField>,
        Bound: ConstraintSynthesizer<E::ScalarField>,
        R: Rng + RngCore + CryptoRng,
    >(
        set: Vec<BigInt>,
        ctt_circuit: CTT,
        wt_circuit: WT,
        arithm_circuit: Arithm,
        bound_circuit: Bound,
        rng: &mut R,
    ) -> Result<(LookupPP<E, M>, M::Table), SynthesisError> {
        let lookup_generation = start_timer!(|| "HARiSA+::Generator");

        let (m_pp, tree) = M::setup(set, arithm_circuit, bound_circuit, rng).unwrap();

        let ctt_generation = start_timer!(|| "ctt::generator");
        let (ctt_ek, ctt_vk) = Self::generate_cc_snark_parameters(ctt_circuit, rng).unwrap();
        end_timer!(ctt_generation);

        let wt_generation = start_timer!(|| "wt::generator");
        let (wt_ek, wt_vk) = Self::generate_cc_snark_parameters(wt_circuit, rng).unwrap();
        end_timer!(wt_generation);

        end_timer!(lookup_generation);

        Ok((
            LookupPP {
                m_pp,
                ctt_ek,
                ctt_vk,
                wt_ek,
                wt_vk,
            },
            tree,
        ))
    }
}
