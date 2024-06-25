use std::str::FromStr;

use crate::{
    cc_snark::{CcGroth16, Proof, ProvingKey, R1CSToQAP},
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

impl<E, M, QAP> HarisaPlus<E, M, QAP>
where
    E: Pairing,
    M: Membership<E>,
    QAP: R1CSToQAP,
{
    fn generate_cc_proof<C, R>(
        pk: &ProvingKey<E>,
        circuit: C,
        rng: &mut R,
    ) -> Result<Proof<E>, SynthesisError>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        R: Rng + RngCore + CryptoRng,
    {
        let cc_snark_prover_time = start_timer!(|| "ccGroth::Prover");

        let cc_prf = CcGroth16::<E, QAP>::prove(&pk, circuit, rng).unwrap();

        end_timer!(cc_snark_prover_time);

        Ok(cc_prf)
    }

    pub fn generate_lookup_proof<
        CTT: ConstraintSynthesizer<E::ScalarField>,
        WT: ConstraintSynthesizer<E::ScalarField>,
        R: Rng + RngCore + CryptoRng,
    >(
        pp: LookupPP<E, M>,
        accum: BigInt,
        tree: M::Table,
        lookup: Vec<BigInt>,
        elem: Vec<BigInt>,
        ctt_circuit: CTT,
        wt_circuit: WT,
        rng: &mut R,
    ) -> Result<LookupProof<E, M>, SynthesisError>
    where
        <<E as Pairing>::ScalarField as FromStr>::Err: core::fmt::Debug,
    {
        let m_prf = M::prove(pp.m_pp, tree, accum, lookup, rng).unwrap();

        let ctt_prf = Self::generate_cc_proof(&pp.ctt_ek, ctt_circuit, rng).unwrap();

        let wt_prf = Self::generate_cc_proof(&pp.wt_ek, wt_circuit, rng).unwrap();

        Ok(LookupProof {
            m_prf,
            ctt_prf,
            wt_prf,
        })
    }
}
