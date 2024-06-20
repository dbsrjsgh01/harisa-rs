use crate::linker::{
    matrix::SparseMatrix,
    snark::{LinkSnark, PP},
};

use ark_ec::pairing::Pairing;

/**  Matrix 생성
*   g_1 g_2 ... g_m                                             h
*                   g_1 g_2 ... g_m                                 h
*                                   g_1 g_2 ... g_m                     h
*                                                   g_1 g_2                 h
*   g_1 g_2 ... g_m g_1 g_2 ... g_m g_1 g_2 ... g_m g_1 g_2 h'
*/
pub fn generate_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
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
