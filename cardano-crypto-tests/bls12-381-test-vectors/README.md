## Test vectors for BLS
### 1- Test vectors for pairing properties
- `e([a]P, Q) = e(P, [a]Q)`
- `e([a]P, [b]Q) = e([b]P, [a]Q)`
- `e([a]P, [b]Q) = e([a * b]P, Q)`
- `e([a]P, Q) * e([b]P, Q) = e([a + b]P, Q)`

Order of the values printed on `pairing_test_vectors`:
- `[a]P`    
- `[b]Q`
- `[b]P`
- `[a]Q`
- `[a + b]P`
- `[a * b]P`


### 2- Test vectors for elliptic curve operations
Operations to be tested:
- Addition - `P + Q`
- Subtraction - `P - Q`
- Scalar multiplication - `[scalar]Q`
- Negation - `-P`

Order of the values printed on `ec_operations_test_vectors`:
- `P \in G_1` 
- `Q \in G_1`
- `P + Q \in G_1`
- `P - Q \in G_1`
- `[scalar]Q \in G_1`
- `-P \in G_1`
- `P \in G_2`
- `Q \in G_2`
- `P + Q \in G_2`
- `P - Q \in G_2`
- `[scalar]Q \in G_2`
- `-P \in G_2`


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

The explicit usage of `DST` and `aug` is not allowed in Cardano-base bindings. Therefore, before verification, they need to be appended into the message by following [hash-to-curve](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve#name-expand_message) spec.

`DST` and `msg` values used to generate test vectors:

```rust
let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
let msg = b"blst is such a blast";
let aug = b"Random value for test aug";
```
Order of the values printed on the files `bls_sig_aug_test_vectors` (BLS signature with `aug`) and `bls_sig_test_vectors` (BLS signature without `aug`):

- `sig`
- `pk`


