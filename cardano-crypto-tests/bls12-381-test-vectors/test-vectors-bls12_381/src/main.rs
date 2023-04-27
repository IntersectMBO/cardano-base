#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case)]

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use blst::min_sig::*;
use blst::BLST_ERROR;
use ff::Field;
use group::Group;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::io::prelude::*;

fn pairing_properties<R: RngCore>(mut rng: R) -> std::io::Result<()> {
    let P = G1Projective::random(&mut rng);
    let Q = G2Projective::random(&mut rng);

    let a = Scalar::random(&mut rng);
    let b = Scalar::random(&mut rng);
    let aplusb = a + b;
    let atimesb = a * b;

    let aP = a * P;
    let bQ = b * Q;
    let bP = b * P;
    let aQ = a * Q;

    let aplusbP = aplusb * P;
    let atimesbP = atimesb * P;
    let aplusbQ = aplusb * Q;
    let atimesbQ = atimesb * Q;

    write_hex_to_file(
        "pairing_test_vectors",
        &[
            [aP, bP, aplusbP, atimesbP].map(|a| hex::encode(G1Affine::from(a).to_compressed())), // COMMENT: Why we only test aplusb and atimesb in G1?
            [aQ, bQ, aplusbQ, atimesbQ].map(|a| hex::encode(G2Affine::from(a).to_compressed())),
        ]
        .concat(),
    )
}

fn ec_operations<R: RngCore>(mut rng: R) -> std::io::Result<()> {
    let scalar = Scalar::random(&mut rng);

    let G1_P = G1Projective::random(&mut rng);
    let G1_Q = G1Projective::random(&mut rng);
    let G1_ADD = G1_P + G1_Q;
    let G1_SUB = G1_P - G1_Q;
    let G1_MUL = scalar * G1_Q;
    let G1_NEG = -G1_P;

    let G2_P = G2Projective::random(&mut rng);
    let G2_Q = G2Projective::random(&mut rng);
    let G2_ADD = G2_P + G2_Q;
    let G2_SUB = G2_P + G2_Q;
    let G2_MUL = scalar * G2_Q;
    let G2_NEG = -G2_P;

    write_hex_to_file(
        "ec_operations_test_vectors",
        &[
            [G1_P, G1_Q, G1_ADD, G1_SUB, G1_MUL, G1_NEG]
                .map(|a| hex::encode(G1Affine::from(a).to_compressed())),
            [G2_P, G2_Q, G2_ADD, G2_SUB, G2_MUL, G2_NEG]
                .map(|a| hex::encode(G2Affine::from(a).to_compressed())),
        ]
        .concat(),
    )
}

fn serde<R: RngCore>(mut rng: R) -> std::io::Result<()> {
    // vector to store the hex strings of invalid points
    let mut hex_strings = Vec::new();

    //---- G1----
    let G1_P = G1Affine::from(G1Projective::random(&mut rng));
    let mut G1_bytes = G1_P.to_uncompressed();
    G1_bytes[4] ^= 1;
    assert_eq!(
        G1Affine::from_uncompressed(&G1_bytes).is_none().unwrap_u8(),
        1
    );

    hex_strings.push(hex::encode(G1_bytes));

    let mut G1_compressed = G1_P.to_compressed();
    G1_compressed[4] ^= 1;
    assert_eq!(
        G1Affine::from_compressed(&G1_compressed)
            .is_none()
            .unwrap_u8(),
        1
    );

    hex_strings.push(hex::encode(G1_compressed));

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
            hex_strings.push(hex::encode(G1_random_bytes)); // REMOVE THIS COMMENT: we need to encode within the loop, because if we reach 10 and haven't found anything, we would break and store the zero vector, which we don't want.
            break;
        }
    }

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

            let G1_affine_pt = G1Affine::from_compressed_unchecked(&G1_random_bytes).unwrap();
            hex_strings.push(hex::encode(G1_affine_pt.to_uncompressed()));
            break;
        }
    }
    //-----------------------------------------------------------

    //---- G2----
    let G2_P = G2Affine::from(G2Projective::random(&mut rng));
    let mut G2_bytes = G2_P.to_uncompressed();
    G2_bytes[4] ^= 1;
    assert_eq!(
        G2Affine::from_uncompressed(&G2_bytes).is_none().unwrap_u8(),
        1
    );

    hex_strings.push(hex::encode(G2_bytes));

    let mut G2_compressed = G2_P.to_compressed();
    G2_compressed[4] ^= 1;
    assert_eq!(
        G2Affine::from_compressed(&G2_compressed)
            .is_none()
            .unwrap_u8(),
        1
    );

    hex_strings.push(hex::encode(G2_compressed));

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
            hex_strings.push(hex::encode(G2_random_bytes));
            break;
        }
    }

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

            let G2_affine_pt = G2Affine::from_compressed_unchecked(&G2_random_bytes).unwrap();
            hex_strings.push(hex::encode(G2_affine_pt.to_uncompressed()));
            break;
        }
    }

    //-----------------------------------------------------------

    write_hex_to_file("serde_test_vectors", &hex_strings)
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

fn write_hex_to_file(file_name: &str, hex_strings: &[String]) -> std::io::Result<()> {
    let mut file = File::create(file_name)?;

    for string in hex_strings {
        file.write_all(string.as_ref())?;
        file.write_all(b"\n")?;
    }
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
