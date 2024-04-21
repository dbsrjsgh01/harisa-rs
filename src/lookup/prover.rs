use crate::core::cc_snark::Proof;
// lookup prover
use crate::core::cc_snark::{r1cs_to_qap::R1CSToQAP, CcGroth16, ProvingKey, VerifyingKey};
use crate::core::pedersen::{data_structure::Plaintext, Pedersen};
use crate::harisa::preprocess::*;
use crate::harisa::{prover::*, Membership};
use crate::lookup::concatenate::*;
use crate::lookup::data_structure::{LookupPP, LookupProof};
use crate::lookup::lookup::HarisaLookup;
use ark_crypto_primitives::snark::*;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::{CryptoRng, Rng, RngCore};

impl<E, M, QAP> HarisaLookup<E, M, QAP>
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
        R1CS: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore + CryptoRng + Rng,
    >(
        pp: LookupPP<E, M>,
        acc: E::G1Affine,
        lookup: Vec<E::ScalarField>,
        arithm_circuit: Option<R1CS>,
        bound_circuit: Option<R1CS>,
        ctt_circuit: Option<R1CS>,
        wt_circuit: Option<R1CS>,
        rng: &mut R,
    ) -> Result<LookupProof<E, M>, SynthesisError> {
        // lookup hat_F = F||z
        let u_plain = concatenate::<E>(lookup.clone(), lookup.clone(), lookup.len());

        let u = Plaintext::<E::G1>::from_plaintext_vec(u_plain);

        // cm_u = COMM(u; o_u)
        let (cm_u, o_u) = Pedersen::<E::G1>::commit(pp.cm_pp, u.clone(), rng).unwrap();

        let harisa_prf = M::prove(
            pp.harisa_crs,
            acc,
            cm_u,
            u,
            o_u,
            arithm_circuit.unwrap(),
            bound_circuit.unwrap(),
            rng,
        )
        .unwrap();

        let ctt_prf =
            Self::generate_cc_proof(&pp.ctt_ek.clone(), ctt_circuit.unwrap(), rng).unwrap();

        let wt_prf = Self::generate_cc_proof(&pp.wt_ek.clone(), wt_circuit.unwrap(), rng).unwrap();

        Ok(LookupProof {
            harisa_prf,
            wt_prf,
            ctt_prf,
        })
    }
}
