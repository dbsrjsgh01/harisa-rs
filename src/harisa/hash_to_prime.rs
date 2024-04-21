use ark_ec::pairing::Pairing;
use ark_ff::{biginteger::BigInteger64 as B, BigInteger as _};

use ark_std::{
    cfg_into_iter, cfg_iter,
    ops::{AddAssign, Mul},
    vec::Vec,
};
use ark_std::{rand::Rng, One};

use ark_relations::r1cs::SynthesisError;

use ark_std::rand::{CryptoRng, RngCore, SeedableRng};
use ark_std::{test_rng, UniformRand};

pub fn hash_to_prime<E: Pairing, R: Rng + RngCore + CryptoRng>(
    input: Vec<E::G1Affine>,
    rand: Vec<E::ScalarField>,
    shift: usize,
    rng: &mut R,
) -> Result<E::ScalarField, SynthesisError> {
    // 기존 Harisa: Poseidon
    // 우리는? 그냥 bit transition & circuit에서 확인
    // 현재는 그냥 둬도 상관 없을듯

    // let mut v = Vec::new();
    // for (u_i, z_i) in input.clone().iter().zip(rand.clone().into_iter()) {
    //     let mut sh = B::one();
    //     sh.muln(shift as u32);
    //     let mut v_i = u_i * sh;
    //     v_i += z_i;

    //     v.push(v_i);
    // }

    // Ok(v)
    Ok(E::ScalarField::one())
}
