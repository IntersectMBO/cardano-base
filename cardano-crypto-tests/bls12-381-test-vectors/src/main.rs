#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case)]

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use blst::{min_pk, min_sig, BLST_ERROR};
use ff::Field;
use group::{Curve, Group};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;

// === BLS12-381 constants shared across generators ===
const DEFAULT_DST: &[u8] = b"BLS_DST_CARDANO_BASE_V1";
const DSIGN_MESSAGE: &[u8] = b"cardano-base bls12-381 dsign serde vector";
const SIGN_VERIFY_MESSAGE: &[u8] = b"cardano-base bls12-381 sign-verify golden vector";
const MAX_KEYGEN_SEARCH_ITERS: u64 = 1_000_000;

// === DSIGN profile types ===
/// Deterministic DSIGN profile with seed/keys reused across generators.
#[derive(Clone)]
struct DsignProfileCase {
    label: &'static str,
    seed: [u8; 32],
    sk: [u8; 32],
    vk: Vec<u8>,
}

/// Static seed templates describing the four golden-vector profiles.
struct SeedProfiles {
    vanilla: [u8; 32],
    low_entropy: [u8; 32],
    low_scalar_base: [u8; 32],
    high_scalar_base: [u8; 32],
}

/// Serde artifacts (sk/vk/sig/pop) derived from a DSIGN profile.
struct SerdeCase {
    label: &'static str,
    seed: [u8; 32],
    sk: [u8; 32],
    vk: Vec<u8>,
    sig: Vec<u8>,
    pop: Vec<u8>,
}

struct PopCase {
    label: &'static str,
    seed: [u8; 32],
    sk: [u8; 32],
    vk: Vec<u8>,
    pop: Vec<u8>,
}

struct VkAggregationCase {
    label: &'static str,
    input_vks: Vec<Vec<u8>>,
    aggregated_vk: Vec<u8>,
}

struct SigAggregationSigner {
    seed: [u8; 32],
    sk: [u8; 32],
    vk: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

struct SigAggregationCase {
    label: String,
    shared_message: Option<Vec<u8>>,
    signers: Vec<SigAggregationSigner>,
    aggregated_sig: Vec<u8>,
}

const VK_AGGREGATION_GROUPS: &[(&str, &[usize])] =
    &[("first_two", &[0, 1]), ("all_four", &[0, 1, 2, 3])];

fn build_distinct_message(label: &str, signer_index: usize) -> Vec<u8> {
    let mut message = SIGN_VERIFY_MESSAGE.to_vec();
    message.extend_from_slice(b"|");
    message.extend_from_slice(label.as_bytes());
    message.extend_from_slice(b"#");
    message.extend_from_slice(&(signer_index as u32).to_be_bytes());
    message
}

// === Seed helpers shared by all DSIGN generators ===
fn low_entropy_seed(last_byte: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[31] = last_byte;
    seed
}

fn minpk_seed_profiles() -> SeedProfiles {
    SeedProfiles {
        vanilla: [
            0xd4, 0x1e, 0xe4, 0xd1, 0x41, 0x0a, 0x01, 0x8a, 0x23, 0x48, 0xc2, 0xfc, 0x8a, 0x39,
            0x5a, 0xdc, 0xa8, 0x9d, 0x81, 0x21, 0x6b, 0xf2, 0x5c, 0xff, 0xd0, 0xfd, 0x9f, 0x55,
            0x95, 0x9a, 0x10, 0x3f,
        ],
        low_entropy: low_entropy_seed(0x01),
        low_scalar_base: [0x11u8; 32],
        high_scalar_base: [0xF1u8; 32],
    }
}

fn minsig_seed_profiles() -> SeedProfiles {
    SeedProfiles {
        vanilla: [
            0x42, 0x09, 0xfb, 0x4b, 0xeb, 0x16, 0x68, 0x37, 0x00, 0x55, 0x46, 0x03, 0x65, 0x2e,
            0x5d, 0x45, 0x42, 0xe1, 0x5b, 0x7a, 0x18, 0xed, 0xfd, 0x4c, 0x47, 0xbe, 0xd0, 0x8f,
            0xc6, 0x22, 0xce, 0x27,
        ],
        low_entropy: low_entropy_seed(0x02),
        low_scalar_base: [0x21u8; 32],
        high_scalar_base: [0xE1u8; 32],
    }
}

fn mix_counter(mut base: [u8; 32], counter: u64) -> [u8; 32] {
    let ctr_bytes = counter.to_be_bytes();
    let offset = base.len() - ctr_bytes.len();
    base[offset..].copy_from_slice(&ctr_bytes);
    base
}

fn is_low_scalar(sk: &[u8; 32]) -> bool {
    sk[0] == 0x00 && sk[1] <= 0x01
}

fn is_high_scalar(sk: &[u8; 32]) -> bool {
    sk[0] == 0x73 && sk[1] >= 0xE0
}

// === DSIGN keygen helpers and profile construction ===
fn minpk_keygen(seed: &[u8]) -> ([u8; 32], Vec<u8>) {
    let sk = min_pk::SecretKey::key_gen(seed, &[]).expect("minpk keygen failed");
    let vk = sk.sk_to_pk();
    (sk.to_bytes(), vk.to_bytes().to_vec())
}

fn minsig_keygen(seed: &[u8]) -> ([u8; 32], Vec<u8>) {
    let sk = min_sig::SecretKey::key_gen(seed, &[]).expect("minsig keygen failed");
    let vk = sk.sk_to_pk();
    (sk.to_bytes(), vk.to_bytes().to_vec())
}

fn build_dsign_profile_cases<F>(keygen: F, seeds: SeedProfiles) -> Vec<DsignProfileCase>
where
    F: Fn(&[u8]) -> ([u8; 32], Vec<u8>) + Copy,
{
    let mut cases = Vec::new();
    cases.push(case_from_seed("high_entropy", seeds.vanilla, keygen));
    cases.push(case_from_seed("low_entropy", seeds.low_entropy, keygen));
    cases.push(search_case(
        "low_scalar",
        seeds.low_scalar_base,
        keygen,
        is_low_scalar,
    ));
    cases.push(search_case(
        "high_scalar",
        seeds.high_scalar_base,
        keygen,
        is_high_scalar,
    ));
    cases
}

fn case_from_seed<F>(label: &'static str, seed: [u8; 32], keygen: F) -> DsignProfileCase
where
    F: Fn(&[u8]) -> ([u8; 32], Vec<u8>),
{
    let (sk, vk) = keygen(&seed);
    DsignProfileCase {
        label,
        seed,
        sk,
        vk,
    }
}

fn search_case<F, P>(
    label: &'static str,
    base_seed: [u8; 32],
    keygen: F,
    predicate: P,
) -> DsignProfileCase
where
    F: Fn(&[u8]) -> ([u8; 32], Vec<u8>) + Copy,
    P: Fn(&[u8; 32]) -> bool,
{
    for counter in 0..MAX_KEYGEN_SEARCH_ITERS {
        let candidate_seed = mix_counter(base_seed, counter);
        let (sk, vk) = keygen(&candidate_seed);
        if predicate(&sk) {
            return DsignProfileCase {
                label,
                seed: candidate_seed,
                sk,
                vk,
            };
        }
    }
    panic!(
        "Failed to find {} keygen case within {} iterations",
        label, MAX_KEYGEN_SEARCH_ITERS
    );
}

// === DSIGN profile writers & I/O helpers ===
fn append_keygen_case(
    lines: &mut Vec<String>,
    label: &str,
    seed: &[u8],
    sk_bytes: &[u8],
    vk_bytes: &[u8],
) {
    lines.push(format!("# case: {}", label));
    lines.push(format!("seed={}", hex::encode(seed)));
    lines.push(format!("sk={}", hex::encode(sk_bytes)));
    lines.push(format!("vk={}", hex::encode(vk_bytes)));
    lines.push(String::new());
}

fn write_dsign_profile_case_file(path: &str, cases: &[DsignProfileCase]) -> std::io::Result<()> {
    let mut lines = Vec::new();
    for case in cases {
        append_keygen_case(
            &mut lines,
            case.label,
            &case.seed,
            &case.sk,
            case.vk.as_slice(),
        );
    }
    write_hex_to_file(path, &lines)
}

fn write_sign_verify_case_file<F>(
    path: &str,
    cases: &[DsignProfileCase],
    signer: F,
) -> std::io::Result<()>
where
    F: Fn(&DsignProfileCase) -> Vec<u8>,
{
    let mut lines = Vec::new();
    for case in cases {
        lines.push(format!("# case: {}", case.label));
        lines.push(format!("seed={}", hex::encode(case.seed)));
        lines.push(format!("sk={}", hex::encode(case.sk)));
        lines.push(format!("vk={}", hex::encode(&case.vk)));
        lines.push(format!("msg={}", hex::encode(SIGN_VERIFY_MESSAGE)));
        let sig_bytes = signer(case);
        lines.push(format!("sig={}", hex::encode(sig_bytes)));
        lines.push(String::new());
    }
    write_hex_to_file(path, &lines)
}

fn write_serde_case_file(path: &str, cases: &[SerdeCase]) -> std::io::Result<()> {
    let mut lines = Vec::new();
    for case in cases {
        append_serde_case(&mut lines, case);
    }
    write_hex_to_file(path, &lines)
}

fn append_serde_case(lines: &mut Vec<String>, case: &SerdeCase) {
    lines.push(format!("# case: {}", case.label));
    lines.push(format!("seed={}", hex::encode(case.seed)));
    lines.push(format!("sk={}", hex::encode(case.sk)));
    lines.push(format!("vk={}", hex::encode(&case.vk)));
    lines.push(format!("sig={}", hex::encode(&case.sig)));
    lines.push(format!("pop={}", hex::encode(&case.pop)));
    lines.push(String::new());
}

fn append_pop_case(lines: &mut Vec<String>, case: &PopCase) {
    lines.push(format!("# case: {}", case.label));
    lines.push(format!("seed={}", hex::encode(case.seed)));
    lines.push(format!("sk={}", hex::encode(case.sk)));
    lines.push(format!("vk={}", hex::encode(&case.vk)));
    lines.push(format!("pop={}", hex::encode(&case.pop)));
    lines.push(String::new());
}

fn write_hex_to_file(file_name: &str, hex_strings: &[String]) -> std::io::Result<()> {
    let mut file = File::create(file_name)?;
    for string in hex_strings {
        file.write_all(string.as_ref())?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

fn write_vk_aggregation_case_file(path: &str, cases: &[VkAggregationCase]) -> std::io::Result<()> {
    let mut lines = Vec::new();
    for case in cases {
        lines.push(format!("# case: {}", case.label));
        for (idx, vk_bytes) in case.input_vks.iter().enumerate() {
            lines.push(format!("vk_{}={}", idx + 1, hex::encode(vk_bytes)));
        }
        lines.push(format!("agg_vk={}", hex::encode(&case.aggregated_vk)));
        lines.push(String::new());
    }
    write_hex_to_file(path, &lines)
}

fn write_sig_aggregation_case_file(
    path: &str,
    cases: &[SigAggregationCase],
) -> std::io::Result<()> {
    let mut lines = Vec::new();
    for case in cases {
        lines.push(format!("# case: {}", case.label));
        if let Some(message) = &case.shared_message {
            lines.push(format!("msg={}", hex::encode(message)));
        }
        for (idx, signer) in case.signers.iter().enumerate() {
            let prefix = format!("signer_{}", idx + 1);
            lines.push(format!("{}_seed={}", prefix, hex::encode(signer.seed)));
            lines.push(format!("{}_sk={}", prefix, hex::encode(signer.sk)));
            lines.push(format!("{}_vk={}", prefix, hex::encode(&signer.vk)));
            lines.push(format!("{}_msg={}", prefix, hex::encode(&signer.msg)));
            lines.push(format!("{}_sig={}", prefix, hex::encode(&signer.sig)));
        }
        lines.push(format!("agg_sig={}", hex::encode(&case.aggregated_sig)));
        lines.push(String::new());
    }
    write_hex_to_file(path, &lines)
}

// === POP derivation and serde artifact builders ===
fn secret_key_scalar(sk_bytes: [u8; 32]) -> Scalar {
    let mut le_bytes = sk_bytes;
    le_bytes.reverse();
    Scalar::from_bytes(&le_bytes).unwrap()
}

fn concat_pop_components(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(first.len() + second.len());
    out.extend_from_slice(first);
    out.extend_from_slice(second);
    out
}

fn derive_minpk_pop_bytes(sk: &min_pk::SecretKey, pk: &min_pk::PublicKey) -> Vec<u8> {
    // PoP μ1 follows the DSIGN interface: message is "PoP" || compressed_pk,
    // DST is DEFAULT_DST and augmentation is empty (the pin bytes are supplied here).
    let mut pin = b"PoP".to_vec();
    pin.extend_from_slice(&pk.to_bytes());
    let mu1 = sk.sign(&pin, DEFAULT_DST, &[]);
    assert_eq!(
        mu1.verify(true, &pin, DEFAULT_DST, &[], pk, true),
        BLST_ERROR::BLST_SUCCESS
    );
    let mu1_bytes = mu1.to_bytes();

    let scalar = secret_key_scalar(sk.to_bytes());
    let mu2_point = G2Projective::generator() * scalar;
    let mu2_bytes = G2Affine::from(mu2_point).to_compressed();

    concat_pop_components(&mu1_bytes, &mu2_bytes)
}

fn derive_minsig_pop_bytes(sk: &min_sig::SecretKey, pk: &min_sig::PublicKey) -> Vec<u8> {
    // Mirror the Haskell PoP semantics: sign "PoP" || compressed_pk with the default DST and empty aug.
    let mut pin = b"PoP".to_vec();
    pin.extend_from_slice(&pk.to_bytes());
    let mu1 = sk.sign(&pin, DEFAULT_DST, &[]);
    assert_eq!(
        mu1.verify(true, &pin, DEFAULT_DST, &[], pk, true),
        BLST_ERROR::BLST_SUCCESS
    );
    let mu1_bytes = mu1.to_bytes();

    let scalar = secret_key_scalar(sk.to_bytes());
    let mu2_point = G1Projective::generator() * scalar;
    let mu2_bytes = G1Affine::from(mu2_point).to_compressed();

    concat_pop_components(&mu1_bytes, &mu2_bytes)
}

fn build_minpk_sig_and_pop(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let sk = min_pk::SecretKey::key_gen(seed, &[]).expect("minpk keygen failed");
    let pk = sk.sk_to_pk();
    let sig = sk.sign(DSIGN_MESSAGE, DEFAULT_DST, &[]);
    assert_eq!(
        sig.verify(true, DSIGN_MESSAGE, DEFAULT_DST, &[], &pk, true),
        BLST_ERROR::BLST_SUCCESS
    );
    let pop = derive_minpk_pop_bytes(&sk, &pk);
    (sig.to_bytes().to_vec(), pop)
}

fn build_minsig_sig_and_pop(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let sk = min_sig::SecretKey::key_gen(seed, &[]).expect("minsig keygen failed");
    let pk = sk.sk_to_pk();
    let sig = sk.sign(DSIGN_MESSAGE, DEFAULT_DST, &[]);
    assert_eq!(
        sig.verify(true, DSIGN_MESSAGE, DEFAULT_DST, &[], &pk, true),
        BLST_ERROR::BLST_SUCCESS
    );
    let pop = derive_minsig_pop_bytes(&sk, &pk);
    (sig.to_bytes().to_vec(), pop)
}

fn build_serde_cases<F>(cases: Vec<DsignProfileCase>, build_artifacts: F) -> Vec<SerdeCase>
where
    F: Fn(&[u8; 32]) -> (Vec<u8>, Vec<u8>),
{
    cases
        .into_iter()
        .map(|case| {
            let (sig, pop) = build_artifacts(&case.seed);
            SerdeCase {
                label: case.label,
                seed: case.seed,
                sk: case.sk,
                vk: case.vk,
                sig,
                pop,
            }
        })
        .collect()
}

// === BLS12-381 DSIGN keygen/serde/sign-verify vector generators ===
fn generate_minpk_sign_verify_vectors(cases: &[DsignProfileCase]) -> std::io::Result<()> {
    write_sign_verify_case_file("././test_vectors/dsign_minpk_sign_verify", cases, |case| {
        let sk = min_pk::SecretKey::key_gen(&case.seed, &[]).expect("minpk keygen failed");
        debug_assert_eq!(sk.to_bytes(), case.sk);
        sk.sign(SIGN_VERIFY_MESSAGE, DEFAULT_DST, &[])
            .to_bytes()
            .to_vec()
    })
}

fn build_pop_cases<F>(cases: &[DsignProfileCase], pop_builder: F) -> Vec<PopCase>
where
    F: Fn(&[u8; 32]) -> Vec<u8>,
{
    cases
        .iter()
        .map(|case| PopCase {
            label: case.label,
            seed: case.seed,
            sk: case.sk,
            vk: case.vk.clone(),
            pop: pop_builder(&case.seed),
        })
        .collect()
}

fn write_pop_case_file(path: &str, cases: &[PopCase]) -> std::io::Result<()> {
    let mut lines = Vec::new();
    for case in cases {
        append_pop_case(&mut lines, case);
    }
    write_hex_to_file(path, &lines)
}

fn generate_minpk_pop_vectors(cases: &[DsignProfileCase]) -> std::io::Result<()> {
    let pop_cases = build_pop_cases(cases, |seed| {
        let sk = min_pk::SecretKey::key_gen(seed, &[]).expect("minpk keygen failed");
        let vk = sk.sk_to_pk();
        derive_minpk_pop_bytes(&sk, &vk)
    });
    write_pop_case_file("././test_vectors/dsign_minpk_pop", &pop_cases)
}

fn generate_minsig_pop_vectors(cases: &[DsignProfileCase]) -> std::io::Result<()> {
    let pop_cases = build_pop_cases(cases, |seed| {
        let sk = min_sig::SecretKey::key_gen(seed, &[]).expect("minsig keygen failed");
        let vk = sk.sk_to_pk();
        derive_minsig_pop_bytes(&sk, &vk)
    });
    write_pop_case_file("././test_vectors/dsign_minsig_pop", &pop_cases)
}

fn generate_minsig_sign_verify_vectors(cases: &[DsignProfileCase]) -> std::io::Result<()> {
    write_sign_verify_case_file("././test_vectors/dsign_minsig_sign_verify", cases, |case| {
        let sk = min_sig::SecretKey::key_gen(&case.seed, &[]).expect("minsig keygen failed");
        debug_assert_eq!(sk.to_bytes(), case.sk);
        sk.sign(SIGN_VERIFY_MESSAGE, DEFAULT_DST, &[])
            .to_bytes()
            .to_vec()
    })
}

// === DSIGN verification-key aggregation vectors ===
fn build_vk_aggregation_cases<F>(
    cases: &[DsignProfileCase],
    groupings: &[(&'static str, &'static [usize])],
    aggregate_fn: F,
) -> Vec<VkAggregationCase>
where
    F: Fn(&[Vec<u8>]) -> Vec<u8>,
{
    groupings
        .iter()
        .map(|&(label, indices)| {
            let mut inputs = Vec::new();
            for &index in indices {
                let case = cases.get(index).unwrap_or_else(|| {
                    panic!(
                        "Verification key index {} out of range for aggregation case {}",
                        index, label
                    )
                });
                inputs.push(case.vk.clone());
            }
            assert!(
                !inputs.is_empty(),
                "Aggregation case {} must include at least one verification key",
                label
            );
            let aggregated_vk = aggregate_fn(&inputs);
            VkAggregationCase {
                label,
                input_vks: inputs,
                aggregated_vk,
            }
        })
        .collect()
}

fn aggregate_minpk_verification_keys(vks: &[Vec<u8>]) -> Vec<u8> {
    let mut acc = G1Projective::identity();
    for vk in vks {
        let bytes: [u8; 48] = vk
            .as_slice()
            .try_into()
            .expect("MinPk verification keys must be 48 bytes");
        let affine = Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&bytes))
            .expect("Invalid MinPk verification key bytes");
        acc += G1Projective::from(affine);
    }
    G1Affine::from(acc).to_compressed().to_vec()
}

fn aggregate_minsig_verification_keys(vks: &[Vec<u8>]) -> Vec<u8> {
    let mut acc = G2Projective::identity();
    for vk in vks {
        let bytes: [u8; 96] = vk
            .as_slice()
            .try_into()
            .expect("MinSig verification keys must be 96 bytes");
        let affine = Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&bytes))
            .expect("Invalid MinSig verification key bytes");
        acc += G2Projective::from(affine);
    }
    G2Affine::from(acc).to_compressed().to_vec()
}

fn sum_minpk_signatures(signatures: &[Vec<u8>]) -> Vec<u8> {
    let mut acc = G2Projective::identity();
    for sig in signatures {
        let bytes: [u8; 96] = sig
            .as_slice()
            .try_into()
            .expect("MinPk signatures must be 96 bytes");
        let affine = Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&bytes))
            .expect("Invalid MinPk signature bytes");
        acc += G2Projective::from(affine);
    }
    G2Affine::from(acc).to_compressed().to_vec()
}

fn sum_minsig_signatures(signatures: &[Vec<u8>]) -> Vec<u8> {
    let mut acc = G1Projective::identity();
    for sig in signatures {
        let bytes: [u8; 48] = sig
            .as_slice()
            .try_into()
            .expect("MinSig signatures must be 48 bytes");
        let affine = Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&bytes))
            .expect("Invalid MinSig signature bytes");
        acc += G1Projective::from(affine);
    }
    G1Affine::from(acc).to_compressed().to_vec()
}

fn generate_minpk_vk_aggregation_vectors(cases: &[DsignProfileCase]) -> std::io::Result<()> {
    let vk_cases = build_vk_aggregation_cases(
        cases,
        VK_AGGREGATION_GROUPS,
        aggregate_minpk_verification_keys,
    );
    write_vk_aggregation_case_file("././test_vectors/dsign_minpk_vk_aggregation", &vk_cases)
}

fn generate_minsig_vk_aggregation_vectors(cases: &[DsignProfileCase]) -> std::io::Result<()> {
    let vk_cases = build_vk_aggregation_cases(
        cases,
        VK_AGGREGATION_GROUPS,
        aggregate_minsig_verification_keys,
    );
    write_vk_aggregation_case_file("././test_vectors/dsign_minsig_vk_aggregation", &vk_cases)
}

fn aggregate_minpk_signatures_same_msg(signatures: &[Vec<u8>]) -> Vec<u8> {
    sum_minpk_signatures(signatures)
}

fn aggregate_minsig_signatures_same_msg(signatures: &[Vec<u8>]) -> Vec<u8> {
    sum_minsig_signatures(signatures)
}

fn aggregate_minpk_signatures_distinct_msg(signatures: &[Vec<u8>]) -> Vec<u8> {
    sum_minpk_signatures(signatures)
}

fn aggregate_minsig_signatures_distinct_msg(signatures: &[Vec<u8>]) -> Vec<u8> {
    sum_minsig_signatures(signatures)
}

fn generate_minpk_sig_aggregation_vectors_same_msg(
    cases: &[DsignProfileCase],
) -> std::io::Result<()> {
    let mut agg_cases = Vec::new();
    for &(group_label, indices) in VK_AGGREGATION_GROUPS {
        let mut signers = Vec::new();
        let mut signatures = Vec::new();
        let mut vks = Vec::new();
        for &index in indices {
            let case = cases.get(index).unwrap_or_else(|| {
                panic!(
                    "Verification key index {} out of range for aggregation case {}",
                    index, group_label
                )
            });
            let sk = min_pk::SecretKey::key_gen(&case.seed, &[]).expect("minpk keygen failed");
            debug_assert_eq!(sk.to_bytes(), case.sk);
            let signer_msg = SIGN_VERIFY_MESSAGE.to_vec();
            let sig_bytes = sk.sign(&signer_msg, DEFAULT_DST, &[]).to_bytes().to_vec();
            signatures.push(sig_bytes.clone());
            vks.push(case.vk.clone());
            signers.push(SigAggregationSigner {
                seed: case.seed,
                sk: case.sk,
                vk: case.vk.clone(),
                msg: signer_msg,
                sig: sig_bytes,
            });
        }
        let aggregated_sig = aggregate_minpk_signatures_same_msg(&signatures);
        let aggregated_vk = aggregate_minpk_verification_keys(&vks);
        let agg_sig = min_pk::Signature::from_bytes(&aggregated_sig)
            .expect("Aggregated MinPk signature bytes invalid");
        let agg_vk = min_pk::PublicKey::from_bytes(&aggregated_vk)
            .expect("Aggregated MinPk verification key invalid");
        assert_eq!(
            agg_sig.verify(true, SIGN_VERIFY_MESSAGE, DEFAULT_DST, &[], &agg_vk, true),
            BLST_ERROR::BLST_SUCCESS
        );
        agg_cases.push(SigAggregationCase {
            label: format!("minpk_{}", group_label),
            shared_message: Some(SIGN_VERIFY_MESSAGE.to_vec()),
            signers,
            aggregated_sig,
        });
    }
    write_sig_aggregation_case_file("././test_vectors/dsign_minpk_sig_agg_same_msg", &agg_cases)
}

fn generate_minsig_sig_aggregation_vectors_same_msg(
    cases: &[DsignProfileCase],
) -> std::io::Result<()> {
    let mut agg_cases = Vec::new();
    for &(group_label, indices) in VK_AGGREGATION_GROUPS {
        let mut signers = Vec::new();
        let mut signatures = Vec::new();
        let mut vks = Vec::new();
        for &index in indices {
            let case = cases.get(index).unwrap_or_else(|| {
                panic!(
                    "Verification key index {} out of range for aggregation case {}",
                    index, group_label
                )
            });
            let sk = min_sig::SecretKey::key_gen(&case.seed, &[]).expect("minsig keygen failed");
            debug_assert_eq!(sk.to_bytes(), case.sk);
            let signer_msg = SIGN_VERIFY_MESSAGE.to_vec();
            let sig_bytes = sk.sign(&signer_msg, DEFAULT_DST, &[]).to_bytes().to_vec();
            signatures.push(sig_bytes.clone());
            vks.push(case.vk.clone());
            signers.push(SigAggregationSigner {
                seed: case.seed,
                sk: case.sk,
                vk: case.vk.clone(),
                msg: signer_msg,
                sig: sig_bytes,
            });
        }
        let aggregated_sig = aggregate_minsig_signatures_same_msg(&signatures);
        let aggregated_vk = aggregate_minsig_verification_keys(&vks);
        let agg_sig = min_sig::Signature::from_bytes(&aggregated_sig)
            .expect("Aggregated MinSig signature bytes invalid");
        let agg_vk = min_sig::PublicKey::from_bytes(&aggregated_vk)
            .expect("Aggregated MinSig verification key invalid");
        assert_eq!(
            agg_sig.verify(true, SIGN_VERIFY_MESSAGE, DEFAULT_DST, &[], &agg_vk, true),
            BLST_ERROR::BLST_SUCCESS
        );
        agg_cases.push(SigAggregationCase {
            label: format!("minsig_{}", group_label),
            shared_message: Some(SIGN_VERIFY_MESSAGE.to_vec()),
            signers,
            aggregated_sig,
        });
    }
    write_sig_aggregation_case_file("././test_vectors/dsign_minsig_sig_agg_same_msg", &agg_cases)
}

fn verify_minpk_distinct_messages(signers: &[SigAggregationSigner], aggregated_sig: &[u8]) {
    let agg_sig = min_pk::Signature::from_bytes(aggregated_sig)
        .expect("Aggregated MinPk signature bytes invalid");
    let public_keys: Vec<min_pk::PublicKey> = signers
        .iter()
        .map(|signer| {
            min_pk::PublicKey::from_bytes(&signer.vk).expect("Invalid MinPk verification key bytes")
        })
        .collect();
    let pk_refs: Vec<&min_pk::PublicKey> = public_keys.iter().collect();
    let msg_refs: Vec<&[u8]> = signers.iter().map(|signer| signer.msg.as_slice()).collect();
    let err = agg_sig.aggregate_verify(true, &msg_refs, DEFAULT_DST, &pk_refs, true);
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS);
}

fn verify_minsig_distinct_messages(signers: &[SigAggregationSigner], aggregated_sig: &[u8]) {
    let agg_sig = min_sig::Signature::from_bytes(aggregated_sig)
        .expect("Aggregated MinSig signature bytes invalid");
    let public_keys: Vec<min_sig::PublicKey> = signers
        .iter()
        .map(|signer| {
            min_sig::PublicKey::from_bytes(&signer.vk)
                .expect("Invalid MinSig verification key bytes")
        })
        .collect();
    let pk_refs: Vec<&min_sig::PublicKey> = public_keys.iter().collect();
    let msg_refs: Vec<&[u8]> = signers.iter().map(|signer| signer.msg.as_slice()).collect();
    let err = agg_sig.aggregate_verify(true, &msg_refs, DEFAULT_DST, &pk_refs, true);
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS);
}

fn generate_minpk_sig_aggregation_vectors_distinct_msg(
    cases: &[DsignProfileCase],
) -> std::io::Result<()> {
    let mut agg_cases = Vec::new();
    for &(group_label, indices) in VK_AGGREGATION_GROUPS {
        let mut signers = Vec::new();
        let mut signatures = Vec::new();
        for (signer_idx, &index) in indices.iter().enumerate() {
            let case = cases.get(index).unwrap_or_else(|| {
                panic!(
                    "Verification key index {} out of range for aggregation case {}",
                    index, group_label
                )
            });
            let sk = min_pk::SecretKey::key_gen(&case.seed, &[]).expect("minpk keygen failed");
            debug_assert_eq!(sk.to_bytes(), case.sk);
            let signer_msg = build_distinct_message(case.label, signer_idx);
            let sig_bytes = sk.sign(&signer_msg, DEFAULT_DST, &[]).to_bytes().to_vec();
            signatures.push(sig_bytes.clone());
            signers.push(SigAggregationSigner {
                seed: case.seed,
                sk: case.sk,
                vk: case.vk.clone(),
                msg: signer_msg,
                sig: sig_bytes,
            });
        }
        let aggregated_sig = aggregate_minpk_signatures_distinct_msg(&signatures);
        verify_minpk_distinct_messages(&signers, &aggregated_sig);
        agg_cases.push(SigAggregationCase {
            label: format!("minpk_{}_distinct_msg", group_label),
            shared_message: None,
            signers,
            aggregated_sig,
        });
    }
    write_sig_aggregation_case_file(
        "././test_vectors/dsign_minpk_sig_agg_distinct_msg",
        &agg_cases,
    )
}

fn generate_minsig_sig_aggregation_vectors_distinct_msg(
    cases: &[DsignProfileCase],
) -> std::io::Result<()> {
    let mut agg_cases = Vec::new();
    for &(group_label, indices) in VK_AGGREGATION_GROUPS {
        let mut signers = Vec::new();
        let mut signatures = Vec::new();
        for (signer_idx, &index) in indices.iter().enumerate() {
            let case = cases.get(index).unwrap_or_else(|| {
                panic!(
                    "Verification key index {} out of range for aggregation case {}",
                    index, group_label
                )
            });
            let sk = min_sig::SecretKey::key_gen(&case.seed, &[]).expect("minsig keygen failed");
            debug_assert_eq!(sk.to_bytes(), case.sk);
            let signer_msg = build_distinct_message(case.label, signer_idx);
            let sig_bytes = sk.sign(&signer_msg, DEFAULT_DST, &[]).to_bytes().to_vec();
            signatures.push(sig_bytes.clone());
            signers.push(SigAggregationSigner {
                seed: case.seed,
                sk: case.sk,
                vk: case.vk.clone(),
                msg: signer_msg,
                sig: sig_bytes,
            });
        }
        let aggregated_sig = aggregate_minsig_signatures_distinct_msg(&signatures);
        verify_minsig_distinct_messages(&signers, &aggregated_sig);
        agg_cases.push(SigAggregationCase {
            label: format!("minsig_{}_distinct_msg", group_label),
            shared_message: None,
            signers,
            aggregated_sig,
        });
    }
    write_sig_aggregation_case_file(
        "././test_vectors/dsign_minsig_sig_agg_distinct_msg",
        &agg_cases,
    )
}

// === Pairing / EC / curve serde / DST/AUG / H2C test vectors ===
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

fn curve_serde_vectors<R: RngCore>(mut rng: R) -> std::io::Result<()> {
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
        if G1_try_out_curve.is_some().unwrap_u8() == 1
            && G1_try_out_curve.unwrap().is_on_curve().unwrap_u8() == 0
        {
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
        if G1Affine::from_compressed_unchecked(&compressed_bytes)
            .is_none()
            .unwrap_u8()
            == 1
        {
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
        if G2_try_out_curve.is_some().unwrap_u8() == 1
            && G2_try_out_curve.unwrap().is_on_curve().unwrap_u8() == 0
        {
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

        if G2Affine::from_compressed_unchecked(&compressed_bytes)
            .is_none()
            .unwrap_u8()
            == 1
        {
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
    let hashed_msg =
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(concat_msg_aug, dst);

    let sig = sk * hashed_msg;

    let blst_sig = min_sig::Signature::from_bytes(&sig.to_affine().to_compressed())
        .expect("Invalid conversion from zkcrypto to blst");
    let blst_pk = min_sig::PublicKey::from_bytes(&pk.to_affine().to_compressed())
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

    let hash_output =
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, &large_dst);

    // Given that the DST is larger than 255 bytes, it will first be hashed. Here we test that we can perform that action
    // manually.
    // Sanity check
    let hashed_dst = Sha256::new()
        .chain(b"H2C-OVERSIZE-DST-")
        .chain(&large_dst)
        .finalize();

    let manually_hashed_output =
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, &hashed_dst);

    assert_eq!(hash_output, manually_hashed_output);

    // Sanity check with blst lib
    use blst::{blst_hash_to_g1, blst_p1, blst_p1_compress};

    let mut out = blst_p1::default();
    unsafe {
        blst_hash_to_g1(
            &mut out,
            msg.as_ptr(),
            msg.len(),
            hashed_dst.as_ptr(),
            hashed_dst.len(),
            hashed_dst.as_ptr(),
            0,
        )
    };

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

fn main() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    pairing_properties(&mut rng).expect("Failed to create test vectors!");
    ec_operations(&mut rng).expect("Failed to create test vectors!");
    curve_serde_vectors(&mut rng).expect("Failed to create test vectors!");
    bls_sig_with_dst_aug(&mut rng).expect("Failed to create test vectors!");
    h2c_large_dst(&mut rng).expect("Failed to create large dst test vectors!");
    let minpk_cases = build_dsign_profile_cases(minpk_keygen, minpk_seed_profiles());
    let minsig_cases = build_dsign_profile_cases(minsig_keygen, minsig_seed_profiles());
    write_dsign_profile_case_file("././test_vectors/dsign_minpk_keygen", &minpk_cases)
        .expect("Failed to create MinPk keygen vectors!");
    write_dsign_profile_case_file("././test_vectors/dsign_minsig_keygen", &minsig_cases)
        .expect("Failed to create MinSig keygen vectors!");
    let minpk_serde = build_serde_cases(minpk_cases.clone(), build_minpk_sig_and_pop);
    let minsig_serde = build_serde_cases(minsig_cases.clone(), build_minsig_sig_and_pop);
    write_serde_case_file("././test_vectors/dsign_minpk_serde", &minpk_serde)
        .expect("Failed to create MinPk DSIGN serde vectors!");
    write_serde_case_file("././test_vectors/dsign_minsig_serde", &minsig_serde)
        .expect("Failed to create MinSig DSIGN serde vectors!");
    generate_minpk_sign_verify_vectors(&minpk_cases)
        .expect("Failed to create MinPk DSIGN sign/verify vectors!");
    generate_minsig_sign_verify_vectors(&minsig_cases)
        .expect("Failed to create MinSig DSIGN sign/verify vectors!");
    generate_minpk_pop_vectors(&minpk_cases).expect("Failed to create MinPk PoP vectors!");
    generate_minsig_pop_vectors(&minsig_cases).expect("Failed to create MinSig PoP vectors!");
    generate_minpk_vk_aggregation_vectors(&minpk_cases)
        .expect("Failed to create MinPk verification key aggregation vectors!");
    generate_minsig_vk_aggregation_vectors(&minsig_cases)
        .expect("Failed to create MinSig verification key aggregation vectors!");
    generate_minpk_sig_aggregation_vectors_same_msg(&minpk_cases)
        .expect("Failed to create MinPk signature aggregation vectors!");
    generate_minsig_sig_aggregation_vectors_same_msg(&minsig_cases)
        .expect("Failed to create MinSig signature aggregation vectors!");
    generate_minpk_sig_aggregation_vectors_distinct_msg(&minpk_cases)
        .expect("Failed to create MinPk distinct-message aggregation vectors!");
    generate_minsig_sig_aggregation_vectors_distinct_msg(&minsig_cases)
        .expect("Failed to create MinSig distinct-message aggregation vectors!");
}
