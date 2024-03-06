pub mod circuit;
pub mod data_structure;
mod test;

use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_std::{rand::Rng, test_rng};

use self::data_structure::*;

pub type Error = Box<dyn ark_std::error::Error>;

pub struct Pedersen<E: Pairing> {
    pub msg: Vec<E::ScalarField>,
    pub rand: E::ScalarField,
}

impl<E: Pairing> Pedersen<E> {
    // setup
    pub fn setup<R: Rng>(n: usize, rng: &mut R) -> Result<Parameters<E>, Error> {
        let mut g = Vec::new();
        for i in 0..n {
            let g_i = E::G1Affine::rand(rng);
            g.push(g_i);
        }
        let h = E::G1Affine::rand(rng);

        Ok(Parameters { g, h })
    }

    // commit
    pub fn commit<R: Rng>(
        param: Parameters<E>,
        msg: Plaintext<E>,
        rng: &mut R,
    ) -> Result<(Commitment<E>, Randomness<E>), Error> {
        let r = E::ScalarField::rand(rng);
        let mut cm = param.h * r;
        for (g_i, m_i) in param.g.iter().zip(msg.msg.into_iter()) {
            cm = cm + (g_i.clone() * m_i.clone());
        }

        Ok((Commitment { cm: cm.into() }, Randomness { rand: r }))
    }

    pub fn verify(
        param: Parameters<E>,
        msg: Plaintext<E>,
        cm: Commitment<E>,
        rand: Randomness<E>,
    ) -> Result<bool, Error> {
        let r = rand.rand;
        let mut res = param.h * r;
        for (g_i, m_i) in param.g.iter().zip(msg.msg.into_iter()) {
            res = res + (g_i.clone() * m_i.clone());
        }

        Ok(cm.cm == res.into())
    }
}
