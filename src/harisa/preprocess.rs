use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, BigInteger256, Field, PrimeField, UniformRand};
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;
use ark_std::{rand::Rng, One, Zero};
use num_bigint::BigInt;
use num_traits;
use std::mem::swap;

use crate::utils::Utils;

pub fn preprocess(g: BigInt, set: Vec<BigInt>) -> Vec<BigInt> {
    let mut tree = Vec::new();
    tree.push(g.clone());

    let mut right_set = set.clone();
    let mut set_size = set.len();

    if set_size > 1 {
        set_size >>= 1;
        let left_set: Vec<BigInt> = right_set.drain(set_size..).collect();

        let left_res = g.clone() * mul_set(left_set.clone());
        let left = preprocess(left_res.into(), right_set.clone());

        let right_res = g.clone() * mul_set(right_set);
        let right = preprocess(right_res.into(), left_set);

        tree = [left, right].concat();
    }

    tree
}

pub fn mul_set(set: Vec<BigInt>) -> BigInt {
    let res = set.iter().product();
    res
}

pub fn assemble(a: BigInt, b: BigInt, w_a: BigInt, w_b: BigInt) -> (BigInt, BigInt) {
    let (d, x, y) = extended_gcd(a.clone(), b.clone());
    let res = w_a * y + w_b * x;
    (res, a * b)
}

pub fn extended_euclidean_algorithm<E: Pairing>(
    a: E::ScalarField,
    b: E::ScalarField,
) -> (E::ScalarField, E::ScalarField) {
    if b == E::ScalarField::zero() {
        (E::ScalarField::one(), E::ScalarField::zero())
    } else {
        // 나눗셈, 나머지 구현 필요
        let (q, r) = Utils::<E>::div(a, b);
        let (x, y) = extended_euclidean_algorithm::<E>(b, r);
        let new_y = x - y.clone() * q;

        (y, new_y.into())
    }
}

// ext_gcd(modify)
pub fn extended_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut r) = (a, b);
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(), BigInt::one());

    while r != BigInt::zero() {
        let quotient = &old_r / &r;

        old_r -= &quotient * &r;
        swap(&mut old_r, &mut r);

        old_s -= &quotient * &s;
        swap(&mut old_s, &mut s);

        old_t -= &quotient * &t;
        swap(&mut old_t, &mut t);
    }

    (old_r, old_s, old_t)
}

pub fn from_scalar_field<F: PrimeField>(n: BigInt) -> F {
    // BigInt를 바이트 배열로 변환 (빅 엔디안)
    let (_, mut big_int_bytes) = n.to_bytes_be();
    while big_int_bytes.len() < 32 {
        big_int_bytes.insert(0, 0);
    }

    if big_int_bytes.len() > 32 {
        (_, big_int_bytes) = (n % BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap())
        .to_bytes_be();
    }

    assert!(
        big_int_bytes.len() == 32,
        "The byte representation must be 32 bytes long."
    );

    // 바이트 배열을 BigInteger256로 변환
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&big_int_bytes);

    // BigInteger256을 ScalarField로 변환
    F::from_be_bytes_mod_order(&bytes)
}

pub fn big_int_to_fr<E: Pairing>(x: BigInt, y: BigInt) -> (E::ScalarField, E::ScalarField) {
    fn big_int_to_scalar_field<F: PrimeField>(big_int: BigInt) -> F {
        // BigInt를 바이트 배열로 변환 (빅 엔디안)
        let (_, mut big_int_bytes) = big_int.to_bytes_be();
        while big_int_bytes.len() < 32 {
            big_int_bytes.insert(0, 0);
        }
        assert!(
            big_int_bytes.len() == 32,
            "The byte representation must be 32 bytes long."
        );

        // 바이트 배열을 BigInteger256로 변환
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&big_int_bytes);

        // BigInteger256을 ScalarField로 변환
        F::from_be_bytes_mod_order(&bytes)
    }

    let scalar_x = big_int_to_scalar_field::<E::ScalarField>(x);
    let scalar_y = big_int_to_scalar_field::<E::ScalarField>(y);

    (scalar_x, scalar_y)
}

#[cfg(test)]
mod preprocess {
    use std::clone;

    use super::{assemble, mul_set, preprocess};
    use crate::harisa::constants::ODD_PRIME;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{CryptoRng, Rng, RngCore},
        UniformRand,
    };
    use num_bigint::{BigInt, RandBigInt};

    fn test_preprocess(n: usize) {
        let mut rng = ark_std::test_rng();

        let g = BigInt::from_slice(num_bigint::Sign::NoSign, &[rng.gen::<u32>()]);

        let mut set = Vec::new();

        for i in 0..n {
            set.push(BigInt::from(ODD_PRIME[rng.gen::<usize>() % 256]));
        }

        let tree = preprocess(g.clone(), set.clone());

        let total_mul = mul_set(set.clone());
        for i in 0..set.len() {
            let expr = total_mul.clone() / set[i].clone();
            assert_eq!(tree[i], g.clone() * expr, "Not equal in elem {}", i);
        }
    }

    #[test]
    fn test_preprocess_with_elem() {
        test_preprocess(8)
    }

    #[test]
    fn test_ext_euclid() {
        use super::extended_euclidean_algorithm;
        use ark_bn254::{Bn254 as E, Fr as F};
        let a = F::from(161u64);
        let b = F::from(28u64);

        let (x, y) = extended_euclidean_algorithm::<E>(a, b);
        assert_eq!(y, F::from(6u64));
    }
}
