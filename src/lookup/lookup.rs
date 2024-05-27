use std::marker::PhantomData;

use crate::{
    cc_snark::{LibsnarkReduction, R1CSToQAP},
    harisa::Membership,
};

use ark_ec::pairing::Pairing;

pub struct HarisaPlus<E: Pairing, M: Membership<E>, QAP: R1CSToQAP = LibsnarkReduction> {
    _curve: PhantomData<(E, M, QAP)>,
}
