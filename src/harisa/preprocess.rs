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
        let left = preprocess::<E>(left_res.into(), right_set.clone());

        let right_res = g.clone() * mul_set::<E>(right_set);
        let right = preprocess::<E>(right_res.into(), left_set);

        tree = [left, right].concat();
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

#[cfg(test)]
mod preprocess {
    use super::{assemble, mul_set, preprocess};
    use crate::harisa::constants::ODD_PRIME;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{CryptoRng, Rng, RngCore},
        UniformRand,
    };

    fn test_preprocess<E: Pairing>(n: usize) {
        let mut rng = ark_std::test_rng();

        let g = E::G1Affine::rand(&mut rng);

        let mut set = Vec::new();

        for i in 0..n {
            set.push(E::ScalarField::from(ODD_PRIME[rng.gen::<usize>() % 256]));
        }

        let tree = preprocess::<E>(g, set.clone());

        let total_mul = mul_set::<E>(set.clone());
        for i in 0..set.len() {
            let expr = total_mul / set[i];
            assert_eq!(tree[i], (g * expr).into(), "Not equal in elem {}", i);
        }
    }

    #[test]
    fn test_preprocess_bn254() {
        // use ark_ed_on_bn254::EdwardsProjective as E;
        use ark_bn254::Bn254 as E;

        test_preprocess::<E>(8)
    }
}
