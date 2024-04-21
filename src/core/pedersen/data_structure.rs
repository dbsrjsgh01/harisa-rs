use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::*;

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<C: CurveGroup> {
    pub g: Vec<C::Affine>,
    pub h: C::Affine,
}

impl<C: CurveGroup> Default for Parameters<C> {
    fn default() -> Self {
        Self {
            g: vec![C::Affine::default(), C::Affine::default()],
            h: C::Affine::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Plaintext<C: CurveGroup> {
    pub msg: Vec<C::ScalarField>,
}

impl<C: CurveGroup> Default for Plaintext<C> {
    fn default() -> Self {
        Self { msg: Vec::new() }
    }
}

impl<C: CurveGroup> Plaintext<C> {
    pub fn from_plaintext_vec(pt_vec: Vec<C::ScalarField>) -> Self {
        Self { msg: pt_vec }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Randomness<C: CurveGroup> {
    pub rand: C::ScalarField,
}

impl<C: CurveGroup> Default for Randomness<C> {
    fn default() -> Self {
        Self {
            rand: C::ScalarField::default(),
        }
    }
}

impl<C: CurveGroup> Randomness<C> {
    pub fn to_rand(r: C::ScalarField) -> Self {
        Self { rand: r }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment<C: CurveGroup> {
    pub cm: C::Affine,
}

impl<C: CurveGroup> Default for Commitment<C> {
    fn default() -> Self {
        Self {
            cm: C::Affine::default(),
        }
    }
}
