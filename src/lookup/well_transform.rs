use std::marker::PhantomData;

use crate::core::pedersen::circuit::{CommitmentVar, ParametersVar, PlaintextVar, RandomnessVar};
use crate::ConstraintF;
use crate::{
    core::pedersen::data_structure::{Commitment, Parameters, Plaintext, Randomness},
    harisa::Membership,
    lookup::data_structure::LookupPP,
};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::alloc::AllocationMode;
// use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{eq::EqGadget, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::str::FromStr;

const SHIFT_SIZE: usize = 8;

pub struct WTGadget<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    // statement
    pub pp: ParametersVar<C, GG>,
    pub cm_u: CommitmentVar<C, GG>,
    pub cm_a: CommitmentVar<C, GG>,
    pub cm_z: CommitmentVar<C, GG>,

    // witness
    pub u: PlaintextVar<C, GG>,
    pub a: PlaintextVar<C, GG>,
    pub z: PlaintextVar<C, GG>,

    pub o_u: RandomnessVar<C, GG>,
    pub o_a: RandomnessVar<C, GG>,
    pub o_z: RandomnessVar<C, GG>,

    pub two: FpVar<ConstraintF<C>>,
}

impl<C, GG> WTGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    pub fn new(
        pp: ParametersVar<C, GG>,
        cm_u: CommitmentVar<C, GG>,
        cm_a: CommitmentVar<C, GG>,
        cm_z: CommitmentVar<C, GG>,
        u: PlaintextVar<C, GG>,
        a: PlaintextVar<C, GG>,
        z: PlaintextVar<C, GG>,
        o_u: RandomnessVar<C, GG>,
        o_a: RandomnessVar<C, GG>,
        o_z: RandomnessVar<C, GG>,
        two: FpVar<ConstraintF<C>>,
    ) -> Self {
        Self {
            pp,
            cm_u,
            cm_a,
            cm_z,
            u,
            a,
            z,
            o_u,
            o_a,
            o_z,
            two,
        }
    }

    pub fn welltransform(&self) -> Result<(), SynthesisError> {
        // 1. Check commitment (cm_u, cm_f, cm_z)
        let rand_u = self.o_u.rand.clone().to_bits_le()?;

        let mut computed_cm_u = self.pp.h.clone().scalar_mul_le(rand_u.clone().iter())?;

        for (g_i, u_i) in self.pp.g.clone().iter().zip(self.u.msg.clone().into_iter()) {
            let computed_cm_u_i = g_i.scalar_mul_le(u_i.to_bits_le()?.iter())?;

            computed_cm_u += computed_cm_u_i;
        }

        self.cm_u.cm.enforce_equal(&computed_cm_u)?;

        let rand_a = self.o_a.rand.clone().to_bits_le()?;

        let mut computed_cm_a = self.pp.h.clone().scalar_mul_le(rand_a.clone().iter())?;

        for (g_i, a_i) in self.pp.g.clone().iter().zip(self.a.msg.clone().into_iter()) {
            let computed_cm_a_i = g_i.scalar_mul_le(a_i.to_bits_le()?.iter())?;

            computed_cm_a += computed_cm_a_i;
        }

        self.cm_a.cm.enforce_equal(&computed_cm_a)?;

        let rand_z = self.o_z.rand.clone().to_bits_le()?;

        let mut computed_cm_z = self.pp.h.clone().scalar_mul_le(rand_z.clone().iter())?;

        for (g_i, z_i) in self.pp.g.clone().iter().zip(self.z.msg.clone().into_iter()) {
            let computed_cm_z_i = g_i.scalar_mul_le(z_i.to_bits_le()?.iter())?;

            computed_cm_z += computed_cm_z_i;
        }

        self.cm_z.cm.enforce_equal(&computed_cm_z)?;

        // 2. relation (hat_f = f||z)

        let mut shift = self.two.clone();

        for _ in 0..SHIFT_SIZE.ilog2() {
            // for _ in 0..SHIFT_SIZE {
            let _ = shift.square_in_place();
        }

        for (u_i, (a_i, z_i)) in self.u.msg.clone().iter().zip(
            self.a
                .msg
                .clone()
                .into_iter()
                .zip(self.z.msg.clone().into_iter()),
        ) {
            // TODO: concatenation으로 수정해야 함

            // Case 1. fpvar => tobitsgadget => fpvar
            // Big Endian으로 고쳐서 뒤에 false element를 추가하면 넣은 만큼 shift가 될 것임
            // 문제는 tobitsgadget(Vec<Boolean>)에서 fpvar로 다시 넘어오는 것

            // let mut a_bit = a_i.to_bits_be()?;
            // let z_bit = z_i.to_bits_be()?;

            // for _ in 0..(SHIFT_SIZE - z_bit.len()) {
            //     a_bit.push(Boolean::<ConstraintF<C>>::FALSE);
            // }

            // a_bit.concat(z_bit)?;

            // let computed_u = FpVar::<ConstraintF<C>>::from(a_bit.reverse());

            // ====================================================================================
            // 2. 그냥 더하고 곱하고 (어찌보면 가장 쉬운 방법)

            let computed_u = a_i.clone() * shift.clone() + z_i.clone();

            u_i.enforce_equal(&computed_u)?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct WellTransform<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    // statement
    pub pp: Parameters<C>,
    pub cm_u: Commitment<C>,
    pub cm_a: Commitment<C>,
    pub cm_z: Commitment<C>,

    // witness
    pub u: Plaintext<C>,
    pub a: Plaintext<C>,
    pub z: Plaintext<C>,

    pub o_u: Randomness<C>,
    pub o_a: Randomness<C>,
    pub o_z: Randomness<C>,

    _curve: PhantomData<GG>,
}

impl<C, GG> WellTransform<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    pub fn new(
        pp: Parameters<C>,
        cm_u: Commitment<C>,
        cm_a: Commitment<C>,
        cm_z: Commitment<C>,
        u: Plaintext<C>,
        a: Plaintext<C>,
        z: Plaintext<C>,
        o_u: Randomness<C>,
        o_a: Randomness<C>,
        o_z: Randomness<C>,
    ) -> Self {
        Self {
            pp,
            cm_u,
            cm_a,
            cm_z,
            u,
            a,
            z,
            o_u,
            o_a,
            o_z,
            _curve: PhantomData,
        }
    }
}

impl<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> ConstraintSynthesizer<ConstraintF<C>>
    for WellTransform<C, GG>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        let circuit_pp =
            ParametersVar::new_input(ark_relations::ns!(cs, "cpwt::crs"), || Ok(&self.pp))?;

        let circuit_cm_u =
            CommitmentVar::new_input(ark_relations::ns!(cs, "cpwt::cm_u"), || Ok(&self.cm_u))?;

        let circuit_cm_a =
            CommitmentVar::new_input(ark_relations::ns!(cs, "cpwt::cm_a"), || Ok(&self.cm_a))?;

        let circuit_cm_z =
            CommitmentVar::new_input(ark_relations::ns!(cs, "cpwt::cm_z"), || Ok(&self.cm_z))?;

        let circuit_u =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cpwt::u"), || Ok(&self.u))?;

        let circuit_a =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cpwt::a"), || Ok(&self.a))?;

        let circuit_z =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "cpwt::z"), || Ok(&self.z))?;

        let circuit_o_u =
            RandomnessVar::new_witness(ark_relations::ns!(cs, "cpwt::o_u"), || Ok(&self.o_u))?;

        let circuit_o_a =
            RandomnessVar::new_witness(ark_relations::ns!(cs, "cpwt::o_a"), || Ok(&self.o_a))?;

        let circuit_o_z =
            RandomnessVar::new_witness(ark_relations::ns!(cs, "cpwt::o_z"), || Ok(&self.o_z))?;

        let two_bigint = ConstraintF::<C>::from_str("2").unwrap_or_default();
        let two = FpVar::new_constant(ark_relations::ns!(cs, "two"), two_bigint)?;

        let gadget = WTGadget::<C, GG>::new(
            circuit_pp,
            circuit_cm_u,
            circuit_cm_a,
            circuit_cm_z,
            circuit_u,
            circuit_a,
            circuit_z,
            circuit_o_u,
            circuit_o_a,
            circuit_o_z,
            two,
        );

        gadget.welltransform()
    }
}

#[cfg(test)]
mod well_transform {
    use super::{WellTransform, SHIFT_SIZE};
    use crate::core::cc_snark::{prepare_verifying_key, CcGroth16};
    use crate::core::pedersen::data_structure::{Commitment, Parameters, Plaintext, Randomness};
    use crate::core::pedersen::Pedersen;
    use crate::harisa::constants::*;
    use crate::ConstraintF;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::pairing::Pairing;
    use ark_ec::CurveGroup;
    use ark_r1cs_std::pairing::PairingVar;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng, One, UniformRand,
    };

    fn test_cp_wt<C: CurveGroup>(
        a_len: usize,
    ) -> (
        Parameters<C>,
        Commitment<C>,
        Commitment<C>,
        Commitment<C>,
        Plaintext<C>,
        Plaintext<C>,
        Plaintext<C>,
        Randomness<C>,
        Randomness<C>,
        Randomness<C>,
    ) {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let pp = Pedersen::<C>::setup(a_len, &mut rng).unwrap();

        let shift = C::ScalarField::from(2u128.pow(SHIFT_SIZE.try_into().unwrap()));

        let mut a_vec = Vec::new();
        let mut z_vec = Vec::new();
        let mut u_vec = Vec::new();

        for i in 0..a_len {
            let a_i = C::ScalarField::from(ODD_PRIME[3 * i]);
            a_vec.push(a_i);

            let z_i = C::ScalarField::from(ODD_PRIME[3 * i + 1]);
            z_vec.push(z_i);

            let u_i = a_i * shift + z_i;
            u_vec.push(u_i);
        }

        let a = Plaintext::<C>::from_plaintext_vec(a_vec);

        let (cm_a, o_a) = Pedersen::<C>::commit(pp.clone(), a.clone(), &mut rng).unwrap();

        let z = Plaintext::<C>::from_plaintext_vec(z_vec);

        let (cm_z, o_z) = Pedersen::<C>::commit(pp.clone(), z.clone(), &mut rng).unwrap();

        let u = Plaintext::<C>::from_plaintext_vec(u_vec);

        let (cm_u, o_u) = Pedersen::<C>::commit(pp.clone(), u.clone(), &mut rng).unwrap();

        (pp, cm_u, cm_a, cm_z, u, a, z, o_u, o_a, o_z)
    }

    const U_LEN: usize = 32;

    #[test]
    fn test_cp_wt_bn254() {
        use ark_ed_on_bn254::EdwardsProjective as C;
        test_cp_wt::<C>(U_LEN);
    }

    #[test]
    fn test_cp_wt_cc_groth16_bn254() {
        use crate::core::pedersen::Pedersen;
        use ark_bn254::Bn254;
        use ark_ed_on_bn254::{constraints::EdwardsVar as GG, EdwardsProjective as C};

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pp, cm_u, cm_a, cm_z, u, a, z, o_u, o_a, o_z) = test_cp_wt::<C>(U_LEN);

        let circuit = WellTransform::<C, GG>::new(pp, cm_u, cm_a, cm_z, u, a, z, o_u, o_a, o_z);

        let (ek, vk) =
            CcGroth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let pvk = prepare_verifying_key::<Bn254>(&vk);

        let proof = CcGroth16::<Bn254>::prove(&ek, circuit, &mut rng).unwrap();

        assert!(CcGroth16::<Bn254>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
    }

    #[test]
    fn test_cp_wt_bls12_381() {
        use ark_ed_on_bls12_381::EdwardsProjective as C;
        test_cp_wt::<C>(U_LEN);
    }

    #[test]
    fn test_cp_wt_cc_groth16_bls12_381() {
        use crate::core::pedersen::Pedersen;
        use ark_bls12_381::Bls12_381;
        use ark_ed_on_bls12_381::{constraints::EdwardsVar as GG, EdwardsProjective as C};

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pp, cm_u, cm_a, cm_z, u, a, z, o_u, o_a, o_z) = test_cp_wt::<C>(U_LEN);

        let circuit = WellTransform::<C, GG>::new(pp, cm_u, cm_a, cm_z, u, a, z, o_u, o_a, o_z);

        let (ek, vk) =
            CcGroth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);

        let proof = CcGroth16::<Bls12_381>::prove(&ek, circuit, &mut rng).unwrap();

        assert!(CcGroth16::<Bls12_381>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
    }
}
