use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, Field, PrimeField};
use ark_relations::r1cs::SynthesisError;
use ark_std::{
    rand::{CryptoRng, Rng, RngCore},
    test_rng, One, UniformRand, Zero,
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

    fn rem(a: E::ScalarField, b: E::ScalarField) -> E::ScalarField {
        let quot = a / b;
        a - quot * b
    }

    fn pow(a: E::ScalarField, b: E::ScalarField) -> E::ScalarField {
        let mut tmp = b;
        let mut res = a;
        let one = E::ScalarField::one();
        while tmp == one {
            tmp -= one;
            res *= a;
        }
        res
    }

    /// Miller-Rabin primality test
    fn miller_rabin<R: Rng + CryptoRng + RngCore>(
        input: E::ScalarField,
        check_time: usize,
    ) -> bool {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let range = input - E::ScalarField::from(3u64);

        let mut r: usize = 0;
        let mut d = E::ScalarField::zero();

        let one = E::ScalarField::one();
        let two = one + one;

        let mut tmp = input.clone();
        let mut tmp2 = tmp / two;

        while tmp == tmp2 * two + one {
            tmp = tmp2;
            tmp2 /= two;
            r += 1;
        }

        d = tmp;

        'check: for i in 0..check_time {
            let a = Self::rem(E::ScalarField::rand(&mut rng), range) + two;

            let mut x = Self::rem(Self::pow(a, d.try_into().unwrap()), input);

            if x == one || x + one == input {
                continue 'check;
            }

            for j in 0..r - 1 {
                x = x * x;
                x = Self::rem(x, input);
                if x == one {
                    return false;
                }
                if x + one == input {
                    continue 'check;
                }
                return false;
            }
        }

        true
    }

    pub fn set(n: usize) -> Vec<E::ScalarField> {
        use crate::harisa::constants::ODD_PRIME;

        let mut res = Vec::new();
        for i in 0..n {
            res.push(E::ScalarField::from(ODD_PRIME[i]));
        }

        res
    }
}
