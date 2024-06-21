use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::SynthesisError;
use ark_std::{
    rand::{CryptoRng, Rng, RngCore},
    test_rng, One, UniformRand, Zero,
};
use num_bigint::{BigInt, RandBigInt};
use rand_core::SeedableRng;

/// Pedersen Commitment
pub fn pedersen<E: Pairing, R: Rng + RngCore + CryptoRng>(
    g: E::G1Affine,
    msg: Vec<E::ScalarField>,
    rng: &mut R,
) -> Result<(E::G1Affine, E::ScalarField), SynthesisError> {
    let h = E::G1Affine::rand(rng);
    let r = E::ScalarField::rand(rng);

    let mut cm = h * r;

    for m_i in msg.clone().iter() {
        cm += g * m_i;
    }

    Ok((cm.into(), r))
}

/// Miller-Rabin primality test
fn miller_rabin<R: Rng + CryptoRng + RngCore>(n: BigInt, k: usize) -> bool {
    // let mut d = n.clone() - 1;
    // let mut s = BigInt::zero();
    // while d % 2 == BigInt::zero() {
    //     d /= 2;
    //     s += 1;
    // }

    // for _ in 0..k {
    //     let mut a = RandBigInt::gen_bigint_range(&mut a, &BigInt::one(), n.clone() - 1);

    //     for
    // }

    true
}
