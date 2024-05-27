use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, PrimeField};
use ark_relations::r1cs::SynthesisError;
use ark_std::{
    rand::{CryptoRng, Rng, RngCore},
    test_rng, UniformRand,
};
use rand_core::SeedableRng;

pub struct Utils<E: Pairing> {
    _curve: PhantomData<E>,
}

impl<E: Pairing> Utils<E> {
    /// Pedersen Commitment
    pub fn pedersen<R: Rng + RngCore + CryptoRng>(
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
    fn miller_rabin<R: Rng + CryptoRng + RngCore>(input: usize, check_time: usize) -> bool {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let range = input - 3;

        let mut r: usize = 0;
        let mut d: usize = 0;

        let mut tmp = input.clone();

        while tmp % 2 == 1 {
            tmp /= 2;
            r += 1;
        }

        d = tmp;

        for i in 0..check_time {
            let a = rng.gen::<usize>() % range + 2;
            let mut x = a.pow(d.try_into().unwrap()) % input;
            if x == 1 || x == input - 1 {
                continue;
            }
            for j in 0..r - 1 {
                x = x.pow(2) % input;
                if x == 1 {
                    return false;
                }
                if x == input - 1 {
                    continue;
                }
                return false;
            }
        }

        true
    }
}
