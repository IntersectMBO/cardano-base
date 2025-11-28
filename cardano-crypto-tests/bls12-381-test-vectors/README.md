## Test vectors for BLS
This is a rust script to generate test vectors for the following:
- Using [bls12_381](https://github.com/zkcrypto/bls12_381)
  - Pairing properties
  - Elliptic curve operations
  - Deserialization/decompression
- Using [blst](https://github.com/supranational/blst) bindings from [bls12_381](https://github.com/zkcrypto/bls12_381) BLS signature with `aug` and `dst`.
  The results are in hex encoding and stored under the folder `test_vectors`.

### 1- Test vectors for pairing properties
The properties to be tested:
- `e([a]P, Q) = e(P, [a]Q)`
- `e([a]P, [b]Q) = e([b]P, [a]Q)`
- `e([a]P, [b]Q) = e([a * b]P, Q)`
- `e([a]P, Q) * e([b]P, Q) = e([a + b]P, Q)`
- `e([a]P, [b]Q) = e(P, [a * b]Q)`
- `e(P, [a]Q) * e(P, [b]Q) = e(P, [a + b]Q)`

The values used to generate test vectors:
```
a = 0x0e51216fa879b2ce727b596d065dd9b7fd8a84d94ffacf9ca30ad114304272d3 // scalar
b = 0x437c2d7d852637c2ef23645a5abcbb308d6150bfcccbf3a8fdbc9daaa91496ef // scalar
aplusb = 0x51cd4eed2d9fea91619ebdc7611a94e88aebd5991cc6c345a0c76ebed95709c2 // scalar
atimesb = 0x2d70bbc706812d56e805ae67934b3275ff67f304a76ea9b3c96d31b9c0d607ba // scalar
```

Order of the values printed on `pairing_test_vectors`:
- `P`
- `[a]P`
- `[b]P`
- `[a + b]P`
- `[a * b]P`
- `Q`
- `[a]Q`
- `[b]Q`
- `[a + b]Q`
- `[a * b]Q`



### 2- Test vectors for elliptic curve operations
Operations to be tested:
- Addition
- Subtraction
- Scalar multiplication
- Negation

The scalar used in scalar multiplication:
```
0x40df499974f62e2f268cd5096b0d952073900054122ffce0a27c9d96932891a5
```

Order of the values printed on `ec_operations_test_vectors`:

- `G1_P` - random point on `G_1`
- `G1_Q` - random point on `G_1`
- `G1_ADD = G1_P + G1_Q`
- `G1_SUB = G1_P - G1_Q`
- `G1_MULL = [scalar]G1_Q`
- `G1_NEG = -G1_P`
- `G2_P` - random point on `G_2`
- `G2_Q` - random point on `G_2`
- `G2_ADD = G2_P + G2_Q`
- `G2_SUB = G2_P - G2_Q`
- `G2_MULL = [scalar]G2_Q`
- `G2_NEG = -G2_P`


### 3- Test vectors for deserialization/decompression
- Point not in curve should fail deserialisation
- Point not in group should fail deserialisation
- Point not in curve should fail decompression
- Point not in group should fail decompression

Order of the values printed on `serde_test_vectors`:
- `G1_uncomp_not_on_curve`
- `G1_comp_not_on_curve`
- `G1_comp_not_on_group`
- `G1_uncomp_not_on_group`
- `G2_uncomp_not_on_curve`
- `G2_comp_not_on_curve`
- `G2_comp_not_on_group`
- `G2_uncomp_not_on_group`

### 4- BLS Signature
Test vectors for BLS signature, using `blst` bindings.

The explicit usage of `aug` is not allowed in Cardano-base bindings. Therefore, before verification, they need to be appended into the message by following [hash-to-curve](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve#name-expand_message) spec.

`DST` and `msg` values used to generate test vectors:

```rust
let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
let msg = b"blst is such a blast";
let aug = b"Random value for test aug";
```
Order of the values printed on the files `bls_sig_aug_test_vectors` (BLS signature with `aug`):

- `sig`
- `pk`

To validate these test vectors, one needs to proceed as follows:
```
let hashed_msg = HashToG1Curve(aug || msg, dst);

assert!(pairing(sig, G2Generator) ==  pairing(hashed_msg, pk))
```

### 5- Hash to curve with large DST
The plutus bindings bound the DST to be at most 255 bytes, following the standard draft specification. If
applications require a domain separation tag that is longer than 255 bytes, they should convert it to a smaller
DST following the instructions of the standard draft (see [section 5.3.3](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve#name-using-dsts-longer-than-255-)).

We create test vectors to ensure that hashing to a curve by first hashing a large DST with SHA256, and then
hashing to the curve works as expected. The test vectors of this file are stored in `h2c_large_dst` with the
following order:

- 'msg'
- 'large_dst'
- Compressed G1 'output'

To validate these test vectors, one needs to proceed as follows:

```
let hashed_dst = Sha256(b"H2C-OVERSIZE-DST-" | large_dst);

let hashed_output = HashToG1Curve(msg, hashed_dst);

let expected_output = G1FromCompressed(output);

assert!(expected_oputput == hashed_output);
```

### 6 – DSIGN Test Vectors (MinPk / MinSig)

This folder also contains a comprehensive suite of *deterministic golden test
vectors* for the BLS-based DSIGN implementations used in `cardano-crypto-class`.
These vectors allow cross-checking the Rust implementation (`blst` via
`bls12_381` crate) against the Haskell DSIGN bindings in `cardano-base`.

All vectors are hex-encoded and are grouped by DSIGN variant:

- `dsign_minpk_*` — DSIGN over MinPk (VK in G1, Sig in G2)
- `dsign_minsig_*` — DSIGN over MinSig (VK in G2, Sig in G1)

The generator produces vectors for **all major DSIGN operations**, ensuring
byte-for-byte compatibility between Rust and Haskell.

#### 6.1 – Contents of each DSIGN vector file

Each file contains the following fields in this fixed order:

1. **sk** – 32-byte secret key (IKM-derived, deterministic)  
2. **vk** – compressed verification key  
   - MinPk: G1 (48 bytes)  
   - MinSig: G2 (96 bytes)  
3. **sig** – compressed signature  
   - MinPk: G2 (96 bytes)  
   - MinSig: G1 (48 bytes)  
4. **pop** – encoded proof-of-possession  
   - MinPk: `mu1 || mu2` (G2||G2 = 192 bytes)  
   - MinSig: `mu1 || mu2` (G1||G1 = 96 bytes)

These vectors are used in Haskell tests to validate *serialization,
deserialization, and correctness of keygen, signing, verification, and PoP*.

---

#### 6.2 – Serialization / Deserialization Vectors

We generate deterministic round-trip serde vectors for all DSIGN artifacts:

- Secret keys  
- Verification keys  
- Signatures  
- Proof-of-possession values  

These vectors confirm that compressed encodings match across both Rust and
Haskell implementations, and that invalid encodings are rejected correctly.

---

#### 6.3 – Deterministic Key Generation

The following values are produced deterministically for each test case:

- Secret key (from IKM)  
- Verification key (`sk * Generator`)  
- Proof of possession (`PoP = Sign(sk, vk)`)  

These vectors allow Haskell tests to assert:

- Same IKM ⇒ same `sk`, `vk`, `pop`  
- Cross-language determinism (Rust ↔ Haskell)  
- Correct group placement and byte encoding of keys

---

#### 6.4 – Signature Generation (Sign)

For each message and DSIGN context:

- `sig = Sign(sk, msg, dst, aug)` is computed deterministically  
- The vectors include both MinPk and MinSig outputs  
- `dst` and `aug` are handled according to the CFRG BLS specifications

These vectors allow Haskell to verify:

- Deterministic signing  
- Matching compressed encodings vs. Rust  
- Proper DST/AUG expansion (following hash-to-curve rules)

---

#### 6.5 – Proof of Possession (PoP)

The generator produces golden PoP values:

- MinPk PoP: signature over `vk` in G2  
- MinSig PoP: signature over `vk` in G1  

Each PoP is deterministic and stored as the concatenation of two compressed
group elements (`mu1 || mu2`), validating:

- Correct implementation of PoP construction  
- Correct subgroup membership  
- Exact byte-level compatibility with `blst`

---

#### 6.6 – Verification Key Aggregation

We include deterministic vectors for:

- Aggregation of verification keys over G1 (MinPk)  
- Aggregation over G2 (MinSig)

Each test case provides:

- Individual `vk_i` values  
- Aggregated `agg_vk = Σ vk_i` (compressed)

These support:

- Deterministic group operations  
- Correctness of Haskell’s aggregation implementation  
- Matching compressed encodings vs. Rust

---

#### 6.7 – Signature Aggregation (Same Message)

We generate vectors for aggregation of signatures **on the same message**:

- Multiple secret keys sign the *same* `msg`  
- The final aggregated signature is:  
  `agg_sig = Σ sig_i`

Stored values:

- Individual signatures (`sig_i`)  
- Aggregated signature (`agg_sig`)

The vectors ensure:

- Group-law correctness  
- Deterministic aggregation across Rust & Haskell  
- Correct compressed G1/G2 encodings

---

#### 6.8 – Signature Aggregation (Distinct Messages)

We also generate vectors for multi-message aggregation:

- Each signer uses a distinct message `msg_i`  
- Aggregation is still linear:
  `agg_sig = Σ sig_i`

These vectors are essential for verifying:

- Distinct-message correctness  
- Proper hashing to curve with the right DST/AUG  
- Deterministic multi-message behavior  
- Exact compressed output consistency

---

#### Summary

These DSIGN test vectors collectively cover:

- Serde (sk, vk, sig, pop)  
- Deterministic key generation  
- Signing correctness  
- Proof-of-possession  
- Verification key aggregation  
- Signature aggregation (same and distinct messages)  

They ensure byte-accurate compatibility between Rust’s `blst` implementation and
the Haskell DSIGN modules in `cardano-base`, and are used as the basis for
golden-vector tests in the Haskell test suite.
