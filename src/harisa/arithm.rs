use crate::core::pedersen::{
    circuit::{CommitmentVar, ParametersVar, PedersenGadget, PlaintextVar, RandomnessVar},
    data_structure::{Commitment, Parameters, Plaintext, Randomness},
};
use crate::ConstraintF;

use ark_ec::CurveGroup;
use ark_ff::One;
use ark_r1cs_std::{fields::fp::FpVar, pairing::PairingVar, prelude::*};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, SynthesisMode},
};
use std::{
    marker::PhantomData,
    ops::{AddAssign, Mul, MulAssign},
};

pub struct ArithmGadget<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    // statements
    pub pp: ParametersVar<C, GG>,
    pub cm_u: CommitmentVar<C, GG>,
    pub cm_sr: CommitmentVar<C, GG>,
    pub h: RandomnessVar<C, GG>,
    pub l: RandomnessVar<C, GG>,
    pub k: RandomnessVar<C, GG>,

    // witness
    pub u: PlaintextVar<C, GG>,
    pub s: RandomnessVar<C, GG>,
    pub r: RandomnessVar<C, GG>,
    pub o_u: RandomnessVar<C, GG>,
    pub o_sr: RandomnessVar<C, GG>,
}

impl<C, GG> ArithmGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn new(
        pp: ParametersVar<C, GG>,
        cm_u: CommitmentVar<C, GG>,
        cm_sr: CommitmentVar<C, GG>,
        h: RandomnessVar<C, GG>,
        l: RandomnessVar<C, GG>,
        k: RandomnessVar<C, GG>,

        u: PlaintextVar<C, GG>,
        s: RandomnessVar<C, GG>,
        r: RandomnessVar<C, GG>,
        o_u: RandomnessVar<C, GG>,
        o_sr: RandomnessVar<C, GG>,
    ) -> Self {
        Self {
            pp,
            cm_u,
            cm_sr,
            h,
            l,
            k,
            u,
            s,
            r,
            o_u,
            o_sr,
        }
    }

    fn cparithm(&self) -> Result<(), SynthesisError> {
        // 1. cm_u == COMM(u; o_u)
        let rand_u = self.o_u.rand.clone().to_bits_le()?;

        let mut computed_cm_u = self.pp.h.clone().scalar_mul_le(rand_u.clone().iter())?;

        for (g_i, u_i) in self.pp.g.clone().iter().zip(self.u.msg.clone().into_iter()) {
            let computed_cm_u_i = g_i.scalar_mul_le(u_i.to_bits_le()?.iter())?;

            computed_cm_u += computed_cm_u_i;
        }

        self.cm_u.cm.enforce_equal(&computed_cm_u)?;

        // 2. cm_sr == COMM(s, r; o_sr)
        let rand_sr = self.o_sr.rand.clone().to_bits_le()?;

        let mut computed_cm_sr = self.pp.h.clone().scalar_mul_le(rand_sr.clone().iter())?;

        let mut sr = vec![self.s.rand.clone(), self.r.rand.clone()];

        for (g_i, u_i) in self.pp.g.clone().iter().zip(sr.into_iter()) {
            let computed_cm_sr_i = g_i.scalar_mul_le(u_i.to_bits_le()?.iter())?;
            computed_cm_sr += computed_cm_sr_i;
        }

        self.cm_sr.cm.enforce_equal(&computed_cm_sr)?;

        // 3. k == s * h * u + r mod l
        let computed_k: FpVar<ConstraintF<C>> = self.compute_k();
        self.k.rand.enforce_equal(&computed_k)?;

        println!("k: \t{:?}", self.k.rand.value());
        println!("com_k: \t{:?}", computed_k.value());

        Ok(())
    }

    fn compute_k(&self) -> FpVar<ConstraintF<C>> {
        let mut computed_k = self.s.rand.clone() * self.h.rand.clone();

        for u_i in self.u.msg.clone().into_iter() {
            computed_k *= u_i;
        }

        computed_k += self.r.rand.clone();

        computed_k
    }
}

#[derive(Clone)]
pub struct ArithmCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    // statements
    pub pp: Parameters<C>,
    pub cm_u: Commitment<C>,
    pub cm_sr: Commitment<C>,
    pub h: Randomness<C>,
    pub l: Randomness<C>,
    pub k: Randomness<C>,

    // witness
    pub u: Plaintext<C>,
    pub s: Randomness<C>,
    pub r: Randomness<C>,
    pub o_u: Randomness<C>,
    pub o_sr: Randomness<C>,

    _curve: PhantomData<GG>,
}

impl<C, GG> ArithmCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    pub fn new(
        pp: Parameters<C>,
        cm_u: Commitment<C>,
        cm_sr: Commitment<C>,
        h: Randomness<C>,
        l: Randomness<C>,
        k: Randomness<C>,
        u: Plaintext<C>,
        s: Randomness<C>,
        r: Randomness<C>,
        o_u: Randomness<C>,
        o_sr: Randomness<C>,
    ) -> Self {
        Self {
            pp,
            cm_u,
            cm_sr,
            h,
            l,
            k,
            u,
            s,
            r,
            o_u,
            o_sr,
            _curve: PhantomData,
        }
    }
}

impl<C, GG> ConstraintSynthesizer<ConstraintF<C>> for ArithmCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        let circuit_pp = ParametersVar::new_input(ns!(cs, "cparithm::crs"), || Ok(&self.pp))?;

        let circuit_cm_u = CommitmentVar::new_input(ns!(cs, "cparithm::cm_u"), || Ok(&self.cm_u))?;

        let circuit_cm_sr =
            CommitmentVar::new_input(ns!(cs, "cparithm::cm_sr"), || Ok(&self.cm_sr))?;

        let circuit_h = RandomnessVar::new_input(ns!(cs, "cparithm::h"), || Ok(&self.h))?;

        let circuit_l = RandomnessVar::new_input(ns!(cs, "cparithm::l"), || Ok(&self.l))?;

        let circuit_k = RandomnessVar::new_input(ns!(cs, "cparithm::k"), || Ok(&self.k))?;

        let circuit_u = PlaintextVar::new_witness(ns!(cs, "cparithm::u"), || Ok(&self.u))?;

        let circuit_s = RandomnessVar::new_witness(ns!(cs, "cparithm::s"), || Ok(&self.s))?;

        let circuit_r = RandomnessVar::new_witness(ns!(cs, "cparithm::r"), || Ok(&self.r))?;

        let circuit_o_u = RandomnessVar::new_witness(ns!(cs, "cparithm::o_u"), || Ok(&self.o_u))?;

        let circuit_o_sr =
            RandomnessVar::new_witness(ns!(cs, "cparithm::o_sr"), || Ok(&self.o_sr))?;

        let gadget = ArithmGadget::<C, GG>::new(
            circuit_pp,
            circuit_cm_u,
            circuit_cm_sr,
            circuit_h,
            circuit_l,
            circuit_k,
            circuit_u,
            circuit_s,
            circuit_r,
            circuit_o_u,
            circuit_o_sr,
        );

        gadget.cparithm()
    }
}

#[cfg(test)]
mod arithm {
    use super::ArithmCircuit;
    use crate::core::cc_snark::{prepare_verifying_key, CcGroth16};
    use crate::core::pedersen::data_structure::{Commitment, Parameters, Plaintext, Randomness};
    use crate::core::pedersen::Pedersen;
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

    fn test_cp_arithm<C: CurveGroup>(
        u_len: usize,
    ) -> (
        Parameters<C>,
        Commitment<C>,
        Commitment<C>,
        Randomness<C>,
        Randomness<C>,
        Randomness<C>,
        Plaintext<C>,
        Randomness<C>,
        Randomness<C>,
        Randomness<C>,
        Randomness<C>,
    ) {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let pp = Pedersen::<C>::setup(u_len, &mut rng).unwrap();

        let h = Randomness::<C>::to_rand(C::ScalarField::rand(&mut rng));

        let field_s = C::ScalarField::rand(&mut rng);
        let field_r = C::ScalarField::rand(&mut rng);

        let s = Randomness::<C>::to_rand(field_s);
        let r = Randomness::<C>::to_rand(field_r);

        let (cm_sr, o_sr) = Pedersen::<C>::commit(
            pp.clone(),
            Plaintext::<C>::from_plaintext_vec(vec![field_s, field_r]),
            &mut rng,
        )
        .unwrap();

        let mut field_k = s.rand.clone() * h.rand.clone();

        let mut u_vec = Vec::new();

        for _ in 0..u_len {
            let u_i = C::ScalarField::rand(&mut rng);
            field_k *= u_i.clone();
            u_vec.push(u_i);
        }

        field_k += r.rand.clone();

        let k = Randomness::<C>::to_rand(field_k);

        let u = Plaintext::<C>::from_plaintext_vec(u_vec);

        let (cm_u, o_u) = Pedersen::<C>::commit(pp.clone(), u.clone(), &mut rng).unwrap();

        let l = Randomness::<C>::to_rand(C::ScalarField::rand(&mut rng));
        assert!(
            Pedersen::<C>::verify(pp.clone(), u.clone(), cm_u.clone(), o_u.clone()).unwrap(),
            "Invalid Commitment (u)"
        );
        assert!(
            Pedersen::<C>::verify(
                pp.clone(),
                Plaintext::<C>::from_plaintext_vec(vec![s.rand.clone(), r.rand.clone()]),
                cm_sr.clone(),
                o_sr.clone()
            )
            .unwrap(),
            "Invalid Commitment (sr)"
        );

        (pp, cm_u, cm_sr, h, l, k, u, s, r, o_u, o_sr)
    }

    #[test]
    fn test_cp_arithm_bn254() {
        use ark_ed_on_bn254::EdwardsProjective as C;
        test_cp_arithm::<C>(8);
    }

    #[test]
    fn test_cp_arithm_cc_groth16_bn254() {
        use crate::core::pedersen::Pedersen;
        use ark_bn254::{Bn254, Fr};
        use ark_ed_on_bn254::{constraints::EdwardsVar as GG, EdwardsProjective as C};

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let u_len = 8;

        let (pp, cm_u, cm_sr, h, l, k, u, s, r, o_u, o_sr) = test_cp_arithm::<C>(u_len);

        let circuit = ArithmCircuit::<C, GG>::new(pp, cm_u, cm_sr, h, l, k, u, s, r, o_u, o_sr);

        let (ek, vk) =
            CcGroth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);

        let proof = CcGroth16::<Bn254>::prove(&ek, circuit, &mut rng).unwrap();

        assert!(CcGroth16::<Bn254>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
    }

    #[test]
    fn test_cp_arithm_bls12_381() {
        use ark_ed_on_bls12_381::EdwardsProjective as C;
        test_cp_arithm::<C>(8);
    }

    #[test]
    fn test_cp_arithm_cc_groth16_bls12_381() {
        use crate::core::pedersen::Pedersen;
        use ark_bls12_381::Bls12_381;
        use ark_ed_on_bls12_381::{constraints::EdwardsVar as GG, EdwardsProjective as C};

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let u_len = 8;

        let (pp, cm_u, cm_sr, h, l, k, u, s, r, o_u, o_sr) = test_cp_arithm::<C>(u_len);

        let circuit = ArithmCircuit::<C, GG>::new(pp, cm_u, cm_sr, h, l, k, u, s, r, o_u, o_sr);

        let (ek, vk) =
            CcGroth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);

        let proof = CcGroth16::<Bls12_381>::prove(&ek, circuit, &mut rng).unwrap();

        assert!(CcGroth16::<Bls12_381>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
    }
}
// cargo test -r test_cp_arithm_cc_groth16_bn254 -- --nocapture
