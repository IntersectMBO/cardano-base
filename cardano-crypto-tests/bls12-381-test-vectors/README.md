## Test vectors for BLS
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
P = 840463aa2f2cda89985b1f3f5eb43b9c29809765d2747d60734b19d6f90610effdfc500af7d458a3e78cee0945ddc669 // G1 point
Q = b67029fbf3ab8e62ab6b499f541537fc07d9466e668392df2bc19762d7dc48b64be09a448cd46dbfe21819a91cd0ab3205f1316ad1cc32853f3f1a1d06497f5cfbc2d753dfc01bff177adeb93f24d452045435dc6eb29f5610b66cd0dd3fb352 // G2 point
a = 0x0e51216fa879b2ce727b596d065dd9b7fd8a84d94ffacf9ca30ad114304272d3 // scalar
b = 0x437c2d7d852637c2ef23645a5abcbb308d6150bfcccbf3a8fdbc9daaa91496ef // scalar
aplusb = 0x51cd4eed2d9fea91619ebdc7611a94e88aebd5991cc6c345a0c76ebed95709c2 // scalar
atimesb = 0x2d70bbc706812d56e805ae67934b3275ff67f304a76ea9b3c96d31b9c0d607ba // scalar
```

Order of the values printed on `pairing_test_vectors`:
- `[a]P`    
- `[b]P`
- `[a + b]P`
- `[a * b]P`
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
