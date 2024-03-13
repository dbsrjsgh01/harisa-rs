use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::*;

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<E: Pairing> {
    pub g: Vec<E::G1Affine>,
    pub h: E::G1Affine,
}

impl<E: Pairing> Default for Parameters<E> {
    fn default() -> Self {
        Self {
            g: Vec::new(),
            h: E::G1Affine::default(),
        }
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Plaintext<E: Pairing> {
    pub msg: Vec<E::ScalarField>,
}

impl<E: Pairing> Plaintext<E> {
    pub fn from_plaintext_vec(pt_vec: Vec<E::ScalarField>) -> Self {
        Self { msg: pt_vec }
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Randomness<E: Pairing> {
    pub rand: E::ScalarField,
}

impl<E: Pairing> Randomness<E> {
    pub fn to_rand(r: E::ScalarField) -> Self {
        Self { rand: r }
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Commitment<E: Pairing> {
    pub cm: E::G1Affine,
}
