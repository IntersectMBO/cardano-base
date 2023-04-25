#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case)]

extern crate core;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use blst::min_sig::*;
use blst::BLST_ERROR;
use ff::Field;
use group::Group;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::io::prelude::*;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};

fn pairing_properties<R: RngCore>(mut rng: R) -> std::io::Result<()> {
    let P = G1Affine::from(G1Projective::random(&mut rng));
    let Q = G2Affine::from(G2Projective::random(&mut rng));

    let a = Scalar::random(&mut rng);
    let b = Scalar::random(&mut rng);
    let mut aplusb = Scalar::clone(&a);
    let mut atimesb = Scalar::clone(&a);

    aplusb.add_assign(&b);
    atimesb.mul_assign(&b);

    let aP = G1Affine::from(P.mul(a));
    let bQ = G2Affine::from(Q.mul(b));
    let bP = G1Affine::from(P.mul(b));
    let aQ = G2Affine::from(Q.mul(a));

    let aplusbP = G1Affine::from(P.mul(aplusb));
    let atimesbP = G1Affine::from(P.mul(atimesb));

    let hex_aP = hex::encode(aP.to_compressed());
    let hex_bQ = hex::encode(bQ.to_compressed());
    let hex_bP = hex::encode(bP.to_compressed());
    let hex_aQ = hex::encode(aQ.to_compressed());
    let hex_aplusbP = hex::encode(aplusbP.to_compressed());
    let hex_atimesbP = hex::encode(atimesbP.to_compressed());

    let mut file = File::create("pairing_test_vectors")?;
    file.write_all(hex_aP.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_bQ.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_bP.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_aQ.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_aplusbP.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_atimesbP.as_ref())?;
    Ok(())
}

fn ec_operations<R: RngCore>(mut rng: R) -> std::io::Result<()> {
    let scalar = Scalar::random(&mut rng);

    let G1_P = G1Affine::from(G1Projective::random(&mut rng));
    let G1_Q = G1Affine::from(G1Projective::random(&mut rng));
    let G1_ADD = G1Affine::from(G1Affine::clone(&G1_P).add(G1Projective::from(G1_Q)));
    let G1_SUB = G1Affine::from(G1Affine::clone(&G1_P).sub(G1Projective::from(G1_Q)));
    let G1_MUL = G1Affine::from(G1_Q.mul(scalar));
    let G1_NEG = G1_P.neg();

    let G2_P = G2Affine::from(G2Projective::random(&mut rng));
    let G2_Q = G2Affine::from(G2Projective::random(&mut rng));
    let G2_ADD = G2Affine::from(G2Affine::clone(&G2_P).add(G2Projective::from(G2_Q)));
    let G2_SUB = G2Affine::from(G2Affine::clone(&G2_P).sub(G2Projective::from(G2_Q)));
    let G2_MUL = G2Affine::from(G2_Q.mul(scalar));
    let G2_NEG = G2_P.neg();

    let hex_G1_P = hex::encode(G1_P.to_compressed());
    let hex_G1_Q = hex::encode(G1_Q.to_compressed());
    let hex_G1_ADD = hex::encode(G1_ADD.to_compressed());
    let hex_G1_SUB = hex::encode(G1_SUB.to_compressed());
    let hex_G1_MUL = hex::encode(G1_MUL.to_compressed());
    let hex_G1_NEG = hex::encode(G1_NEG.to_compressed());

    let hex_G2_P = hex::encode(G2_P.to_compressed());
    let hex_G2_Q = hex::encode(G2_Q.to_compressed());
    let hex_G2_ADD = hex::encode(G2_ADD.to_compressed());
    let hex_G2_SUB = hex::encode(G2_SUB.to_compressed());
    let hex_G2_MUL = hex::encode(G2_MUL.to_compressed());
    let hex_G2_NEG = hex::encode(G2_NEG.to_compressed());

    let mut file = File::create("ec_operations_test_vectors")?;
    file.write_all(hex_G1_P.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G1_Q.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G1_ADD.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G1_SUB.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G1_MUL.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G1_NEG.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G2_P.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G2_Q.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G2_ADD.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G2_SUB.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G2_MUL.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hex_G2_NEG.as_ref())?;

    Ok(())
}

fn serde<R: RngCore>(mut rng: R) -> std::io::Result<()> {
    //---- G1----
    let G1_P = G1Affine::from(G1Projective::random(&mut rng));
    let mut G1_bytes = G1_P.to_uncompressed();
    assert_eq!(
        G1Affine::from_uncompressed(&G1_bytes).is_some().unwrap_u8(),
        1
    );
    G1_bytes[4] ^= 1;
    assert_eq!(
        G1Affine::from_uncompressed(&G1_bytes).is_none().unwrap_u8(),
        1
    );

    let G1_uncomp_curve_hex = hex::encode(G1_bytes);

    let mut G1_compressed = G1_P.to_compressed();
    G1_compressed[4] ^= 1;
    assert_eq!(
        G1Affine::from_compressed(&G1_compressed)
            .is_none()
            .unwrap_u8(),
        1
    );

    let G1_comp_curve_hex = hex::encode(G1_compressed);

    let mut G1_random_bytes = [0u8; 48];
    for _ in 0..10 {
        rng.fill_bytes(&mut G1_random_bytes);
        G1_random_bytes[0] |= 0b10000000;
        G1_random_bytes[0] &= 0b10011111;
        let G1_try_out_group = G1Affine::from_compressed_unchecked(&G1_random_bytes);
        if G1_try_out_group.is_some().unwrap_u8() == 1
            && G1_try_out_group.unwrap().is_torsion_free().unwrap_u8() == 0
        {
            assert_eq!(
                G1Affine::from_compressed(&G1_random_bytes)
                    .is_none()
                    .unwrap_u8(),
                1
            );
            break;
        }
    }

    let G1_comp_group_hex = hex::encode(G1_random_bytes);

    let mut G1_affine_pt = G1Affine::default();
    for _ in 0..10 {
        rng.fill_bytes(&mut G1_random_bytes);
        G1_random_bytes[0] |= 0b10000000;
        G1_random_bytes[0] &= 0b10011111;
        let G1_try_out_group = G1Affine::from_compressed_unchecked(&G1_random_bytes);
        if G1_try_out_group.is_some().unwrap_u8() == 1
            && G1_try_out_group.unwrap().is_torsion_free().unwrap_u8() == 0
        {
            assert_eq!(
                G1Affine::from_compressed(&G1_random_bytes)
                    .is_none()
                    .unwrap_u8(),
                1
            );

            G1_affine_pt = G1Affine::from_compressed_unchecked(&G1_random_bytes).unwrap();
            break;
        }
    }

    let G1_uncomp_group_hex = hex::encode(G1_affine_pt.to_uncompressed());
    //-----------------------------------------------------------

    //---- G2----
    let G2_P = G2Affine::from(G2Projective::random(&mut rng));
    let mut G2_bytes = G2_P.to_uncompressed();
    assert_eq!(
        G2Affine::from_uncompressed(&G2_bytes).is_some().unwrap_u8(),
        1
    );
    G2_bytes[4] ^= 1;
    assert_eq!(
        G2Affine::from_uncompressed(&G2_bytes).is_none().unwrap_u8(),
        1
    );

    let G2_uncomp_curve_hex = hex::encode(G2_bytes);

    let mut G2_compressed = G2_P.to_compressed();
    G2_compressed[4] ^= 1;
    assert_eq!(
        G2Affine::from_compressed(&G2_compressed)
            .is_none()
            .unwrap_u8(),
        1
    );

    let G2_comp_curve_hex = hex::encode(G2_compressed);

    let mut G2_random_bytes = [0u8; 96];
    for _ in 0..10 {
        rng.fill_bytes(&mut G2_random_bytes);
        G2_random_bytes[0] |= 0b10000000;
        G2_random_bytes[0] &= 0b10011111;
        let G2_try_out_group = G2Affine::from_compressed_unchecked(&G2_random_bytes);
        if G2_try_out_group.is_some().unwrap_u8() == 1
            && G2_try_out_group.unwrap().is_torsion_free().unwrap_u8() == 0
        {
            assert_eq!(
                G2Affine::from_compressed(&G2_random_bytes)
                    .is_none()
                    .unwrap_u8(),
                1
            );
            break;
        }
    }

    let G2_comp_group_hex = hex::encode(G2_random_bytes);

    let mut G2_affine_pt = G2Affine::default();
    for _ in 0..100 {
        rng.fill_bytes(&mut G2_random_bytes);
        G2_random_bytes[0] |= 0b10000000;
        G2_random_bytes[0] &= 0b10011111;
        let G2_try_out_group = G2Affine::from_compressed_unchecked(&G2_random_bytes);
        if G2_try_out_group.is_some().unwrap_u8() == 1
            && G2_try_out_group.unwrap().is_torsion_free().unwrap_u8() == 0
        {
            assert_eq!(
                G2Affine::from_compressed(&G2_random_bytes)
                    .is_none()
                    .unwrap_u8(),
                1
            );

            G2_affine_pt = G2Affine::from_compressed_unchecked(&G2_random_bytes).unwrap();
            break;
        }
    }

    let G2_uncomp_group_hex = hex::encode(G2_affine_pt.to_uncompressed());
    //-----------------------------------------------------------

    let mut file = File::create("serde_test_vectors")?;
    file.write_all(G1_uncomp_curve_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(G1_comp_curve_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(G1_comp_group_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(G1_uncomp_group_hex.as_ref())?;
    file.write_all(b"\n")?;

    file.write_all(G2_uncomp_curve_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(G2_comp_curve_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(G2_comp_group_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(G2_uncomp_group_hex.as_ref())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn bls_sig_with_aug<R: RngCore>(mut rng: R) -> std::io::Result<()> {
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let aug = b"Random value for test aug";
    let msg = b"blst is such a blast";
    let sig = sk.sign(msg, dst, aug);

    let err = sig.verify(true, msg, dst, aug, &pk, true);
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS);

    let sig_hex = hex::encode(sig.to_bytes());
    let pk_hex = hex::encode(pk.to_bytes());
    let mut file = File::create("bls_sig_aug_test_vectors")?;
    file.write_all(sig_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(pk_hex.as_ref())?;

    Ok(())
}

fn bls_sig<R: RngCore>(mut rng: R) -> std::io::Result<()> {
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let msg = b"blst is such a blast";
    let sig = sk.sign(msg, dst, &[]);

    let err = sig.verify(true, msg, dst, &[], &pk, true);
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS);

    let sig_hex = hex::encode(sig.to_bytes());
    let pk_hex = hex::encode(pk.to_bytes());
    let mut file = File::create("bls_sig_test_vectors")?;
    file.write_all(sig_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(pk_hex.as_ref())?;

    Ok(())
}

fn main() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    pairing_properties(&mut rng).expect("Failed to create test vectors!");
    ec_operations(&mut rng).expect("Failed to create test vectors!");
    serde(&mut rng).expect("Failed to create test vectors!");
    bls_sig_with_aug(&mut rng).expect("Failed to create test vectors!");
    bls_sig(&mut rng).expect("Failed to create test vectors!");
}
