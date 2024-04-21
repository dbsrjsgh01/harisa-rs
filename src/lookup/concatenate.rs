use ark_ec::pairing::Pairing;
use ark_ff::One;
use ark_std::ops::{AddAssign, MulAssign};

pub fn concatenate<E: Pairing>(
    a: Vec<E::ScalarField>,
    z: Vec<E::ScalarField>,
    n: usize,
) -> Vec<E::ScalarField> {
    assert!(a.len() - z.len() > 0, "Too small random values");

    let mut u = Vec::new();
    let two = E::ScalarField::one() + E::ScalarField::one();
    let mut switch = E::ScalarField::one() + E::ScalarField::one();

    let mut n = n;
    while n > 1 {
        switch *= switch;
        if n % 2 == 1 {
            switch *= two;
        }
        n >>= 1;
    }

    for (a_i, z_i) in a.clone().iter().zip(z.clone().into_iter()) {
        let u_i = *a_i * switch + z_i;
        u.push(u_i);
    }

    u
}
