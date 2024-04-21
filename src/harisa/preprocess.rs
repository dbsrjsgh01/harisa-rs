use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_std::{rand::Rng, One, Zero};

pub fn preprocess<E: Pairing>(g: E::G1Affine, set: Vec<E::ScalarField>) -> Vec<E::G1Affine> {
    let mut tree = Vec::new();
    tree.push(g.clone());

    let mut right_set = set.clone();
    let mut set_size = set.len();

    if set_size > 1 {
        set_size >>= 1;
        let left_set: Vec<E::ScalarField> = right_set.drain(set_size..).collect();

        let left_res = g.clone() * mul_set::<E>(left_set.clone());
        preprocess::<E>(left_res.into(), right_set.clone());

        let right_res = g.clone() * mul_set::<E>(right_set);
        preprocess::<E>(right_res.into(), left_set);
    }

    tree
}

pub fn mul_set<E: Pairing>(set: Vec<E::ScalarField>) -> E::ScalarField {
    let res = set.iter().product();
    res
}

pub fn assemble<E: Pairing>(
    a: E::ScalarField,
    b: E::ScalarField,
    w_a: E::G1Affine,
    w_b: E::G1Affine,
) -> E::G1Affine {
    let (x, y) = extended_euclidean_algorithm::<E>(a, b);
    let res = w_a * y + w_b * x;
    res.into()
}

pub fn extended_euclidean_algorithm<E: Pairing>(
    a: E::ScalarField,
    b: E::ScalarField,
) -> (E::ScalarField, E::ScalarField) {
    let q = a / b;
    let r = a - b * q;
    if r == E::ScalarField::zero() {
        (E::ScalarField::one(), E::ScalarField::zero())
    } else {
        let (x, y) = extended_euclidean_algorithm::<E>(b, r);
        let new_y = x - y.clone() * q;

        (y, new_y.into())
    }
}
