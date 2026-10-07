# cardano-crypto-peras

This package provides concrete definitions for the Peras-specific components
needed by layers other than Consensus:

- **Peras certificates**: these need to be stored in blocks in order to
  coordinate the end of a cooldown. Since this addition ultimately affects
  block sizes (and block size checks live in Ledger), the best place to store
  these certificates is at the Ledger level.
- **Peras votes**: the individual, per-committee-member votes that
  certificates aggregate.

Base types live in `Cardano.Crypto.Peras`, certificates in
`Cardano.Crypto.Peras.Cert`, and votes in `Cardano.Crypto.Peras.Vote`. This
package does not provide CBOR instances for these types (matching
`cardano-crypto-leios`): `EncCBOR`/`DecCBOR` instances are provided by
`cardano-ledger-binary` instead.
