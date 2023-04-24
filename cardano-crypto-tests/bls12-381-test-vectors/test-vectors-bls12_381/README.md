## Print order
### `pairing_test_vectors`:
- `$a \times P$`    
- `$b \times Q$`
- `$b \times P$`
- `$a \times Q$`
- `$(a+b) \times P$`
- `$(a\times b) \times P$`


### `ec_operations_test_vectors`:
- `$P \in G_1$` 
- `$Q \in G_1$`
- `$P + Q \in G_1$`
- `$P - Q \in G_1$`
- `$scalar \times Q \in G_1$`
- `$-P \in G_1$`
- `$P \in G_2$`
- `$Q \in G_2$`
- `$P + Q \in G_2$`
- `$P - Q \in G_2$`
- `$scalar \times Q \in G_2$`
- `$-P \in G_2$`


### `serde_test_vectors`:
- `$G1_uncompressed$` on curve?
- `$G1_compressed$` on curve?
- `G1_point` in group?
- `$G2_uncompressed$` on curve?
- `$G2_compressed$` on curve?
- `G2_point` in group?
