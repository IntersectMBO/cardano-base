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
- `G1_uncomp_curve`: G1 point uncompressed is on curve?
- `G1_comp_curve`: G1 point compressed is on curve?
- `G1_comp_group`: G1 point compressed is on group?
- `G1_uncomp_group`: G1 point uncompressed is on group?
- `G2_uncomp_curve`: G2 point uncompressed is on curve?
- `G2_comp_curve`: G2 point compressed is on curve?
- `G2_comp_group`: G2 point compressed is on group?
- `G2_uncomp_group`: G2 point uncompressed is on group?

### 4- BLS Signature
Test vectors for BLS signature, using `blst` bindings.

**a. BLS signature with `aug`:** Order of the values printed on `bls_sig_aug_test_vectors`:
- `sig`
- `pk`

**b. BLS signature without `aug`:** Order of the values printed on `bls_sig_test_vectors`:
- `sig`
- `pk`
