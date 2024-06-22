use crate::linker::{
    matrix::SparseMatrix,
    snark::{LinkSnark, PP},
};

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::SynthesisError;

use super::Linker;

/**  Matrix 생성
*   g_1 g_2 ... g_m                                             h
*                   g_1 g_2 ... g_m                                 h
*                                   g_1 g_2 ... g_m                     h
*                                                   g_1 g_2                 h
*   g_1 g_2 ... g_m g_1 g_2 ... g_m g_1 g_2 ... g_m g_1 g_2 h'
*/
pub fn generate_cp_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    assert_eq!(msg_len, ck.len());

    let l = 5;
    let t = 3 * msg_len + 7;

    let mut crs = SparseMatrix::new(l, t);

    // g_i
    for i in 0..msg_len {
        crs.insert_row_slice(0, i, &ck);
        crs.insert_row_slice(1, msg_len + i, &ck);
        crs.insert_row_slice(2, 2 * msg_len + i, &ck);
        crs.insert_row_slice(4, i, &ck);
        crs.insert_row_slice(4, msg_len + i, &ck);
        crs.insert_row_slice(4, 2 * msg_len + i, &ck);
    }

    // sr
    crs.insert_row_slice(3, 3 * msg_len, &vec![ck[0], ck[1]]);
    crs.insert_row_slice(4, 3 * msg_len, &vec![ck[0], ck[1]]);

    // h
    crs.insert_row_slice(4, 3 * msg_len + 2, &vec![ck[5]]);
    crs.insert_row_slice(0, 3 * msg_len + 3, &vec![ck[5]]);
    crs.insert_row_slice(1, 3 * msg_len + 4, &vec![ck[5]]);
    crs.insert_row_slice(2, 3 * msg_len + 5, &vec![ck[5]]);
    crs.insert_row_slice(3, 3 * msg_len + 6, &vec![ck[5]]);

    crs
}

pub fn generate_cp_arithm_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    // assert_eq!(msg_len, ck.len());

    let l = 3;
    let t = msg_len + 5;

    let mut crs = SparseMatrix::new(l, t);

    // cm_u
    crs.insert_row_slice(0, 0, &vec![ck[0]]);
    for i in 0..msg_len {
        crs.insert_row_slice(0, i + 3, &vec![ck[1]]);
    }

    // cm_sr
    crs.insert_row_slice(1, 1, &vec![ck[0]]);
    crs.insert_row_slice(1, msg_len + 3, &vec![ck[0], ck[1]]);

    // snark_ck
    crs.insert_row_slice(l - 1, 2, &snark_ck);

    crs
}

pub fn generate_cp_bound_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    assert_eq!(msg_len, ck.len());

    let l = 2;
    let t = msg_len + 2;

    let mut crs = SparseMatrix::new(l, t);

    // cm_u
    crs.insert_row_slice(0, 0, &vec![ck[0]]);
    crs.insert_row_slice(0, 2, &vec![ck[1]]);

    // snark_ck
    crs.insert_row_slice(l - 1, 1, &snark_ck);

    crs
}

pub fn generate_cp_ctt_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    assert_eq!(msg_len, ck.len());

    let l = 3;
    let t = 2 * msg_len + 3;

    let mut crs = SparseMatrix::new(l, t);

    // cm_u
    crs.insert_row_slice(0, 0, &vec![ck[0]]);
    crs.insert_row_slice(0, 3, &vec![ck[1]]);

    // cm_a
    crs.insert_row_slice(1, 1, &vec![ck[0]]);
    crs.insert_row_slice(1, msg_len + 3, &vec![ck[1]]);

    // snark_ck
    crs.insert_row_slice(l - 1, 2, &snark_ck);

    crs
}

pub fn generate_cp_wt_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    assert_eq!(msg_len, ck.len());

    let l = 4;
    let t = 3 * msg_len + 4;

    let mut crs = SparseMatrix::new(l, t);

    // cm_u
    crs.insert_row_slice(0, 0, &vec![ck[0]]);
    crs.insert_row_slice(0, 4, &vec![ck[1]]);

    // cm_a
    crs.insert_row_slice(1, 1, &vec![ck[0]]);
    crs.insert_row_slice(1, msg_len + 4, &vec![ck[1]]);

    // cm_z
    crs.insert_row_slice(2, 2, &vec![ck[0]]);
    crs.insert_row_slice(2, 2 * msg_len + 4, &vec![ck[1]]);

    // snark_ck
    crs.insert_row_slice(l - 1, 3, &snark_ck);

    crs
}

pub fn generate_cp_arithm_witness<E: Pairing>(
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

pub fn generate_cp_arithm_instance<E: Pairing>(
    cm: Vec<E::G1Affine>,
    snark_cm: E::G1Affine,
) -> Result<<LinkSnark<E> as Linker<E>>::Instance, SynthesisError> {
    let mut instance_vec = cm;

    instance_vec.push(snark_cm);

    Ok(instance_vec)
}
