use crate::linker::{
    matrix::SparseMatrix,
    snark::{LinkSnark, PP},
};

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::SynthesisError;

use super::Linker;

pub fn generate_cp_arithm_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    let l = 3;
    let t = msg_len + 5;

    let mut snark_ck = snark_ck.clone();
    snark_ck.truncate(msg_len + 3);

    let mut crs = SparseMatrix::new(l, t);

    // cm_u
    crs.insert_row_slice(0, 0, &vec![ck[0]]);
    for i in 0..msg_len {
        crs.insert_row_slice(0, i + 3, &vec![ck[i + 1]]);
    }

    // cm_sr
    crs.insert_row_slice(1, 1, &vec![ck[0]]);
    crs.insert_row_slice(1, msg_len + 3, &vec![ck[1], ck[2]]);

    // snark_ck
    crs.insert_row_slice(l - 1, 2, &snark_ck);

    crs
}

pub fn generate_cp_bound_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    let l = 2;
    let t = msg_len + 2;

    let mut snark_ck = snark_ck.clone();
    snark_ck.truncate(msg_len + 1);

    let mut crs = SparseMatrix::new(l, t);

    // cm_u
    crs.insert_row_slice(0, 0, &vec![ck[0]]);
    for i in 0..msg_len {
        crs.insert_row_slice(0, i + 2, &vec![ck[i + 1]]);
    }

    // snark_ck
    crs.insert_row_slice(l - 1, 1, &snark_ck);

    crs
}

pub fn generate_cp_ctt_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    let l = 3;
    let t = 2 * msg_len + 3;

    let mut crs = SparseMatrix::new(l, t);

    // cm_u
    crs.insert_row_slice(0, 0, &vec![ck[0]]);
    for i in 0..msg_len {
        crs.insert_row_slice(0, i + 3, &vec![ck[i + 1]]);
    }

    // cm_a
    crs.insert_row_slice(1, 1, &vec![ck[0]]);
    for i in 0..msg_len {
        crs.insert_row_slice(1, i + 3 + msg_len, &vec![ck[i + 1]]);
    }

    // snark_ck
    crs.insert_row_slice(l - 1, 2, &snark_ck);

    crs
}

pub fn generate_cp_wt_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    let l = 4;
    let t = 3 * msg_len + 4;

    let mut crs = SparseMatrix::new(l, t);

    // cm_u
    crs.insert_row_slice(0, 0, &vec![ck[0]]);
    for i in 0..msg_len {
        crs.insert_row_slice(0, i + 4, &vec![ck[i + 1]]);
    }

    // cm_a
    crs.insert_row_slice(1, 1, &vec![ck[0]]);
    for i in 0..msg_len {
        crs.insert_row_slice(1, i + 4 + msg_len, &vec![ck[i + 1]]);
    }

    // cm_z
    crs.insert_row_slice(2, 2, &vec![ck[0]]);
    for i in 0..msg_len {
        crs.insert_row_slice(2, i + 4 + 2 * msg_len, &vec![ck[i + 1]]);
    }

    // snark_ck
    crs.insert_row_slice(l - 1, 3, &snark_ck);

    crs
}

pub fn generate_cp_witness<E: Pairing>(
    r: Vec<E::ScalarField>,
    u: Vec<E::ScalarField>,
    snark_witness: Vec<E::ScalarField>,
) -> Result<<LinkSnark<E> as Linker<E>>::Witness, SynthesisError> {
    let mut witness_vec = Vec::new();
    witness_vec.extend_from_slice(r.as_slice());
    witness_vec.extend_from_slice(snark_witness.as_slice());
    witness_vec.extend_from_slice(u.as_slice());

    Ok(witness_vec)
}

pub fn generate_cp_instance<E: Pairing>(
    cm: Vec<E::G1Affine>,
    snark_cm: E::G1Affine,
) -> Result<<LinkSnark<E> as Linker<E>>::Instance, SynthesisError> {
    let mut instance_vec = cm;

    instance_vec.push(snark_cm);

    Ok(instance_vec)
}
