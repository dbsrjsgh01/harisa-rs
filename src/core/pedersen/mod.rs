pub mod circuit;
pub mod data_structure;
mod test;

use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::Rng;

use self::data_structure::*;

pub type Error = Box<dyn ark_std::error::Error>;
pub struct Pedersen<C: CurveGroup> {
    _curve: PhantomData<C>,
}

impl<C: CurveGroup> Pedersen<C> {
    pub fn setup<R: Rng>(n: usize, rng: &mut R) -> Result<Parameters<C>, Error> {
        let mut g = Vec::new();
        for i in 0..n {
            let g_i = C::Affine::rand(rng);
            g.push(g_i);
        }
        let h = C::Affine::rand(rng);

        Ok(Parameters { g, h })
    }

    pub fn commit<R: Rng>(
        param: Parameters<C>,
        msg: Plaintext<C>,
        rng: &mut R,
    ) -> Result<(Commitment<C>, Randomness<C>), Error> {
        let r = C::ScalarField::rand(rng);
        let mut cm = param.h * r;
        for (g_i, m_i) in param.g.iter().zip(msg.msg.into_iter()) {
            cm = cm + (g_i.clone() * m_i.clone());
        }

        Ok((Commitment { cm: cm.into() }, Randomness { rand: r }))
    }

    pub fn verify(
        param: Parameters<C>,
        msg: Plaintext<C>,
        cm: Commitment<C>,
        rand: Randomness<C>,
    ) -> Result<bool, Error> {
        let r = rand.rand;
        let mut res = param.h * r;
        for (g_i, m_i) in param.g.iter().zip(msg.msg.into_iter()) {
            res = res + (g_i.clone() * m_i.clone());
        }
        Ok(cm.cm == res.into())
    }
}
