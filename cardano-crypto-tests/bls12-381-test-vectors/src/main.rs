#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case)]

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use blst::min_sig::*;
use blst::BLST_ERROR;
use ff::Field;
use group::{Curve, Group};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::io::prelude::*;
use sha2::{Digest, Sha256};

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
        "././test_vectors/pairing_test_vectors",
        &[
            [P, aP, bP, aplusbP, atimesbP].map(|a| hex::encode(G1Affine::from(a).to_compressed())),
            [Q, aQ, bQ, aplusbQ, atimesbQ].map(|a| hex::encode(G2Affine::from(a).to_compressed())),
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
    let G2_SUB = G2_P - G2_Q;
    let G2_MUL = scalar * G2_Q;
    let G2_NEG = -G2_P;

    write_hex_to_file(
        "././test_vectors/ec_operations_test_vectors",
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
    // Uncompressed not on curve
    let mut uncompressed_bytes = [0u8; 96];
    loop {
        rng.fill_bytes(&mut uncompressed_bytes);
        // We set the flags for the bytes
        uncompressed_bytes[0] &= 0b00011111; // Uncompressed point, not at infinity
        let G1_try_out_curve = G1Affine::from_uncompressed_unchecked(&uncompressed_bytes);
        if G1_try_out_curve.is_some().unwrap_u8() == 1 && G1_try_out_curve.unwrap().is_on_curve().unwrap_u8() == 0 {
            hex_strings.push(hex::encode(uncompressed_bytes));
            break;
        }
    }

    // Compressed not on curve
    let mut compressed_bytes = [0u8; 48];
    loop {
        rng.fill_bytes(&mut compressed_bytes);
        // We set the flags for the bytes
        compressed_bytes[0] |= 0b10000000;
        compressed_bytes[0] &= 0b10001111; // Compressed point, not at infinity. We don't care about the y sign (either both or neither will be on curve)
                                           // We unset the 4th bit to make sure that the x-coordinate is canonical
        if G1Affine::from_compressed_unchecked(&compressed_bytes).is_none().unwrap_u8() == 1 {
            hex_strings.push(hex::encode(compressed_bytes));
            break;
        }
    }

    // Compressed not in group
    loop {
        rng.fill_bytes(&mut compressed_bytes);
        // We set the flags for the bytes
        compressed_bytes[0] |= 0b10000000;
        compressed_bytes[0] &= 0b10011111; // Compressed point, not at infinity. We don't care about the y sign (either both or neither will be in group)
        let G1_try_out_group = G1Affine::from_compressed_unchecked(&compressed_bytes);
        if G1_try_out_group.is_some().unwrap_u8() == 1
            && G1_try_out_group.unwrap().is_torsion_free().unwrap_u8() == 0
        {
            hex_strings.push(hex::encode(compressed_bytes));
            break;
        }
    }

    // Uncompressed not in group
    loop {
        rng.fill_bytes(&mut compressed_bytes);
        // We set the flags for the bytes
        compressed_bytes[0] |= 0b10000000;
        compressed_bytes[0] &= 0b10011111; // Compressed point, not at infinity. We don't care about the y sign (either both or neither will be in group)
        let G1_try_out_group = G1Affine::from_compressed_unchecked(&compressed_bytes);
        if G1_try_out_group.is_some().unwrap_u8() == 1
            && G1_try_out_group.unwrap().is_torsion_free().unwrap_u8() == 0
        {
            hex_strings.push(hex::encode(G1_try_out_group.unwrap().to_uncompressed()));
            break;
        }
    }
    //-----------------------------------------------------------

    //---- G2----
    // Uncompressed not on curve
    let mut uncompressed_bytes = [0u8; 192];
    loop {
        rng.fill_bytes(&mut uncompressed_bytes);
        // We set the flags for the bytes
        uncompressed_bytes[0] &= 0b00011111; // Uncompressed point, not at infinity
        let G2_try_out_curve = G2Affine::from_uncompressed_unchecked(&uncompressed_bytes);
        if G2_try_out_curve.is_some().unwrap_u8() == 1 && G2_try_out_curve.unwrap().is_on_curve().unwrap_u8() == 0 {
            hex_strings.push(hex::encode(uncompressed_bytes));
            break;
        }
    }

    // Compressed not on curve
    let mut compressed_bytes = [0u8; 96];
    loop {
        rng.fill_bytes(&mut compressed_bytes);
        // We set the flags for the bytes
        compressed_bytes[0] |= 0b10000000;
        compressed_bytes[0] &= 0b10001111; // Compressed point, not at infinity. We don't care about the y sign (either both or neither will be in the curve)
                                           // We unset the fourth bit to make sure that the first `Fp` of the x coordinate is canonical
        compressed_bytes[48] &= 0b00001111; // We unset the fourth bit of the 48th byte to make sure that the second `Fp` of the x coordinate is canonical

        if G2Affine::from_compressed_unchecked(&compressed_bytes).is_none().unwrap_u8() == 1 {
            hex_strings.push(hex::encode(compressed_bytes));
            break;
        }
    }

    // Compressed not in group
    loop {
        rng.fill_bytes(&mut compressed_bytes);
        // We set the flags for the bytes
        compressed_bytes[0] |= 0b10000000;
        compressed_bytes[0] &= 0b10011111; // Compressed point, not at infinity. We don't care about the y sign (either both or neither will be in group)
        let G2_try_out_group = G2Affine::from_compressed_unchecked(&compressed_bytes);
        if G2_try_out_group.is_some().unwrap_u8() == 1
            && G2_try_out_group.unwrap().is_torsion_free().unwrap_u8() == 0
        {
            hex_strings.push(hex::encode(compressed_bytes));
            break;
        }
    }

    // Uncompressed not in group
    loop {
        rng.fill_bytes(&mut compressed_bytes);
        // We set the flags for the bytes
        compressed_bytes[0] |= 0b10000000;
        compressed_bytes[0] &= 0b10011111; // Compressed point, not at infinity. We don't care about the y sign (either both or neither will be in group)
        let G2_try_out_group = G2Affine::from_compressed_unchecked(&compressed_bytes);
        if G2_try_out_group.is_some().unwrap_u8() == 1
            && G2_try_out_group.unwrap().is_torsion_free().unwrap_u8() == 0
        {
            hex_strings.push(hex::encode(G2_try_out_group.unwrap().to_uncompressed()));
            break;
        }
    }

    //-----------------------------------------------------------

    write_hex_to_file("././test_vectors/serde_test_vectors", &hex_strings)
}

fn bls_sig_with_dst_aug<R: RngCore>(mut rng: R) -> std::io::Result<()> {
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = Scalar::random(rng);
    let pk = sk * G2Projective::generator();

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let aug = b"Random value for test aug. ";
    let msg = b"blst is such a blast";
    let mut concat_msg_aug = Vec::new();
    concat_msg_aug.extend_from_slice(aug);
    concat_msg_aug.extend_from_slice(msg);
    let hashed_msg = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        concat_msg_aug,
        dst,
    );

    let sig = sk * hashed_msg;

    let blst_sig = Signature::from_bytes(&sig.to_affine().to_compressed())
        .expect("Invalid conversion from zkcrypto to blst");
    let blst_pk = PublicKey::from_bytes(&pk.to_affine().to_compressed())
        .expect("Invalid conversion from zkcrypto to blst");
    let err = blst_sig.verify(true, msg, dst, aug, &blst_pk, true);
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS);

    let sig_hex = hex::encode(sig.to_affine().to_compressed());
    let pk_hex = hex::encode(pk.to_affine().to_compressed());
    let mut file = File::create("././test_vectors/bls_sig_aug_test_vectors")?;
    file.write_all(sig_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(pk_hex.as_ref())?;
    file.write_all(b"\n")?;

    Ok(())
}

fn h2c_large_dst<R: RngCore>(rng: &mut R) -> std::io::Result<()> {
    let msg = b"Testing large dst.";
    let mut large_dst = [0u8; 300];
    rng.fill_bytes(&mut large_dst);

    let hash_output = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        msg,
        &large_dst,
    );

    // Given that the DST is larger than 255 bytes, it will first be hashed. Here we test that we can perform that action
    // manually.
    // Sanity check
    let hashed_dst = Sha256::new().chain(b"H2C-OVERSIZE-DST-").chain(&large_dst).finalize();

    let manually_hashed_output = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        msg,
        &hashed_dst,
    );

    assert_eq!(hash_output, manually_hashed_output);

    // Sanity check with blst lib
    use blst::{blst_hash_to_g1, blst_p1, blst_p1_compress};

    let mut out = blst_p1::default();
    unsafe { blst_hash_to_g1(&mut out, msg.as_ptr(), msg.len(), hashed_dst.as_ptr(), hashed_dst.len(), hashed_dst.as_ptr(), 0) };

    let mut bytes = [0u8; 48];
    unsafe { blst_p1_compress(bytes.as_mut_ptr(), &out) }

    assert_eq!(bytes, hash_output.to_affine().to_compressed());

    let msg_hex = hex::encode(msg);
    let large_dst_hex = hex::encode(large_dst);
    let hash_output_hex = hex::encode(hash_output.to_affine().to_compressed());

    let mut file = File::create("././test_vectors/h2c_large_dst")?;
    file.write_all(msg_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(large_dst_hex.as_ref())?;
    file.write_all(b"\n")?;
    file.write_all(hash_output_hex.as_ref())?;
    file.write_all(b"\n")?;

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
    bls_sig_with_dst_aug(&mut rng).expect("Failed to create test vectors!");
    h2c_large_dst(&mut rng).expect("Failed to create large dst test vectors!");
}
