#![allow(
    dead_code,
    unused_imports,
    unused_mut,
    unused_variables,
    unused_macros,
    unused_assignments,
    unreachable_patterns
)]

pub mod core;
pub mod harisa;

pub use ark_crypto_primitives::*;
pub use ark_ec::*;
pub use ark_ff::*;
pub use ark_poly::*;

pub use pairing::*;

pub(crate) type BasePrimeField<E> =
    <<<E as Pairing>::G1 as CurveGroup>::BaseField as Field>::BasePrimeField;

#[macro_use]
extern crate ark_std;

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

pub use ark_std::{marker::PhantomData, vec::Vec};
