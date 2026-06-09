# cardano-crypto-leios

Data types for Leios protocol artifacts as specified in
[CIP-0164](https://github.com/cardano-scaling/CIPs/blob/leios/CIP-0164/README.md):

- `EbHash` — hash of the RB header that announced an endorser block (`hash32`).
- `LeiosCert` — an aggregated BLS certificate over committee votes for an EB.

Both `cardano-ledger` (which embeds `LeiosCert` in the Dijkstra-era block body)
and `ouroboros-consensus` (which validates and resolves CertRBs) depend on this
package so they agree on the type.
