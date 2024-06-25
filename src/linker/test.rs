use crate::{
    cc_snark::{prepare_verifying_key, CcGroth16},
    harisa::{arithm::ArithmCircuit, constants::ODD_PRIME},
    linker::{matrix::inner_product, snark::LinkSnark, Linker},
};

use ark_crypto_primitives::snark::SNARK;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::{
    rand::{CryptoRng, Rng, RngCore, SeedableRng},
    test_rng, One, UniformRand,
};

fn test_cp_arithm<F: PrimeField>(
    u_len: usize,
) -> (
    Option<F>,
    Option<F>,
    Option<F>,
    Option<Vec<F>>,
    Option<F>,
    Option<F>,
) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let h = F::rand(&mut rng);
    let l = F::one();
    let s = F::rand(&mut rng);
    let r = F::rand(&mut rng);
    let mut u = Vec::new();
    let mut k = s * h;
    for _ in 0..u_len {
        let u_i = F::from(ODD_PRIME[rng.gen::<usize>() % 256]);
        u.push(u_i);
        k *= u_i;
    }
    k += r;
    (Some(h), Some(l), Some(k), Some(u), Some(s), Some(r))
}

fn test_cp_arithm_with_linker<E: Pairing>(n: usize) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let arithm_circuit = ArithmCircuit::mock(n);

    let (cc_ek, cc_vk) = CcGroth16::<E>::circuit_specific_setup(arithm_circuit, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&cc_vk);

    let snark_ck = cc_ek.ck.as_slice().to_vec();

    let mut ck = Vec::with_capacity(2);
    for _ in 0..2 {
        ck.push(E::G1::rand(&mut rng).into_affine());
    }

    let (link_pp, link_crs) = LinkSnark::<E>::setup(n, ck.clone(), snark_ck, &mut rng);

    let (link_ek, link_vk) = LinkSnark::<E>::keygen(&link_pp, link_crs, &mut rng);

    let (h, l, k, u, s, r) = test_cp_arithm::<E::ScalarField>(n);

    let mut u_star = E::ScalarField::one();
    for u_i in u.clone().unwrap() {
        u_star *= u_i;
    }

    let o_u = E::ScalarField::rand(&mut rng);

    let cm_u = (ck[1] * u_star + ck[0] * o_u).into();

    let sr = s.unwrap() * r.unwrap();

    let o_sr = E::ScalarField::rand(&mut rng);

    let cm_sr = (ck[1] * sr + ck[0] * o_sr).into();

    let arithm_circuit = ArithmCircuit::<E::ScalarField>::new(
        h.unwrap(),
        l.unwrap(),
        k.unwrap(),
        u.clone().unwrap(),
        s.unwrap(),
        r.unwrap(),
    );

    let cc_prf = CcGroth16::<E>::prove(&cc_ek, arithm_circuit, &mut rng).unwrap();

    let snark_witness = [cc_prf.open];

    let test_result = inner_product::<E>(
        [
            snark_witness.clone().to_vec(),
            vec![h.unwrap(), l.unwrap(), k.unwrap()],
        ]
        .concat()
        .as_slice(),
        cc_ek.ck.as_slice(),
    );

    assert_eq!(test_result, cc_prf.cm); // instance들 check => assertion 통과

    let link_witness = LinkSnark::<E>::generate_witness(
        vec![o_u, o_sr],
        [u.unwrap(), vec![s.unwrap(), r.unwrap()]].concat(),
        snark_witness.to_vec(),
    );

    let (link_prf, link_cm) = LinkSnark::<E>::prove(&link_pp, &link_ek, link_witness, &mut rng);

    let link_instance =
        LinkSnark::<E>::generate_instance(vec![cm_u, cm_sr], cc_prf.clone().cm, link_cm);

    println!("lnk_prf: {:?}", link_prf);

    assert!(CcGroth16::<E>::verify_with_processed_vk(&pvk, &[], &cc_prf).unwrap());

    assert!(LinkSnark::<E>::verify(
        &link_pp,
        &link_vk,
        &link_instance,
        &link_prf
    ));
}

#[test]
fn test_cp_arithm_with_linker_bn254() {
    use ark_bn254::Bn254 as E;
    test_cp_arithm_with_linker::<E>(32);
}
