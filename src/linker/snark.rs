use std::marker::PhantomData;

use crate::linker::Linker;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, One, Zero};

#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PP<
    G1: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
    G2: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
> {
    pub l: usize, // # of rows
    pub t: usize, // # of cols
    pub g1: G1,
    pub g2: G2,
}

impl<
        G1: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
        G2: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
    > PP<G1, G2>
{
    pub fn new(l: usize, t: usize, g1: &G1, g2: &G2) -> PP<G1, G2> {
        PP {
            l,
            t,
            g1: g1.clone(),
            g2: g2.clone(),
        }
    }
}

#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct EK<G1: Clone + Default + CanonicalSerialize + CanonicalDeserialize> {
    pub p: Vec<G1>,
}

#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VK<G2: Clone + Default + CanonicalSerialize + CanonicalDeserialize> {
    pub c: Vec<G2>,
    pub a: G2,
}

fn vec_to_g2<E: Pairing>(
    pp: &PP<E::G1Affine, E::G2Affine>,
    v: &Vec<E::ScalarField>,
) -> Vec<E::G2Affine> {
    v.iter()
        .map(|x| (pp.g2 * x).into_affine())
        .collect::<Vec<_>>()
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct LinkSnark<E: Pairing> {
    _curve: PhantomData<E>,
}

impl<E: Pairing> Linker<E> for LinkSnark<E> {
    type Instance = Vec<E::ScalarField>;
    type Witness = Vec<E::ScalarField>;

    type CM = PhantomData<E>;
    type EK = EK<E::G1Affine>;
    type VK = VK<E::G2Affine>;

    type CRS = Vec<Vec<E::G1Affine>>;
    type PP = PP<E::G1Affine, E::G2Affine>;
    type Proof = E::G1Affine;

    fn setup<R: Rng>(ck: &[<E as Pairing>::G1Affine], rng: &mut R) -> (Self::PP, Self::CRS) {
        // sparse matrix 생성
    }

    fn keygen<R: Rng>(pp: &Self::PP, crs: Self::CRS, rng: &mut R) -> (Self::EK, Self::VK) {
        // keygen => generator들...? (g, h) 생성해서 만들기
    }

    fn prove<R: Rng>(
        pp: &Self::PP,
        ek: &Self::EK,
        witness: Self::Witness,
        rng: &mut R,
    ) -> (Self::Proof, Self::CM) {
        (Self::inner_product(ek.p, witness.to_vec()), PhantomData)
    }

    fn verify(pp: &Self::PP, vk: &Self::VK, instance: &Self::Instance, prf: &Self::Proof) -> bool {
        assert_eq!(pp.l, instance.len());
        let mut g1 = vec![];
        let mut g2 = vec![];
        for i in 0..instance.len() {
            g1.push(E::G1Prepared::from(instance[i]));
            g2.push(E::G2Prepared::from(vk.c[i]));
        }
        g1.push(E::G1Prepared::from(*prf));
        g2.push(E::G2Prepared::from(-vk.a.into_group()));
        E::TargetField::one() == E::multi_pairing(g1.into_iter(), g2.into_iter()).0
    }
}

impl<E: Pairing> LinkSnark<E> {
    fn inner_product(w: Vec<E::G1Affine>, v: Vec<E::ScalarField>) -> E::G1Affine {
        assert_eq!(w.len(), v.len());
        let mut res = E::G1Affine::zero();

        for (w_i, v_i) in w.clone().iter().zip(v.clone().into_iter()) {
            let r_i = *w_i * v_i;
            res = (res + r_i).into();
        }

        res
    }
}
