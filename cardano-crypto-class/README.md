# cardano-crypto-class

This package defines type classes and mock instances for the following cryptographic primitives:

  - A digital signature scheme

  - An aggregatable signature scheme

  - A cryptographic hashing function

  - A key-evolving signature scheme

  - A verifiable random function

It also provides bindings to concrete primitives, including BLS12-381
elliptic-curve operations (via [blst](https://github.com/supranational/blst))
and the Poseidon permutation over the BLS12-381 scalar field
(`Cardano.Crypto.Poseidon`, backed by a vendored C implementation from
Nomadic Labs' [ocaml-bls12-381-hash](https://gitlab.com/nomadic-labs/cryptography/ocaml-bls12-381-hash);
see the haddocks of `Cardano.Crypto.Poseidon.Internal` for the full
C contract and design rationale).
