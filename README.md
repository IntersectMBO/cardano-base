# cardano-base

A collection of miscellaneous packages used by Cardano that cover:

* cryptography
* serialization
* slotting

Each sub-project has its own README:

* [`cardano-binary`](./cardano-binary): CBOR serialisation types and typeclasses.
* [`cardano-crypto-class`](./cardano-crypto-class): Abstract cryptographic interfaces.
* [`cardano-crypto-praos`](./cardano-crypto-praos): Concrete VRF implementation for Ouroboros Praos.
* [`cardano-slotting`](./cardano-slotting): Key slotting and real-time conversion types.
* [`cardano-strict-containers`](./cardano-strict-containers): Strict variants of standard containers to avoid space leaks.
* [`base-deriving-via`](./base-deriving-via): General hooks and newtypes for `DerivingVia`.
* [`orphans-deriving-via`](./orphans-deriving-via): Orphan instances for deriving via hooks.
* [`heapwords`](./heapwords): Tooling for measuring in-memory representation size of data structures.
* [`measures`](./measures): Abstractions for measured quantities.

Haddocks for all packages from the `master` branch can be found at
[base.cardano.intersectmbo.org](https://base.cardano.intersectmbo.org/)

All releases for packages found in this repository are recorded in the
[Cardano Haskell package repository](https://github.com/intersectmbo/cardano-haskell-packages)

## Developer Onboarding Path

If you are new to the `cardano-base` packages, here is the recommended path to familiarize yourself with the codebase:

1. **Serialization First:** Start with `cardano-binary` to understand how data moves across the network and is stored on-chain using CBOR.
2. **Cryptographic Foundations:** Read `cardano-crypto-class` to learn the interfaces for hashing, signing, and VRFs, without getting bogged down in implementation details.
3. **Advanced Crypto:** Dive into `cardano-crypto-praos` for the concrete VRF implementations, or explore `cardano-crypto-peras` if looking at specific protocol details.
4. **Time & Slots:** Review `cardano-slotting` to understand how time is handled in Ouroboros.
5. **Memory & Optimization:** Look at `cardano-strict-containers` for avoiding space leaks, and `heapwords` for profiling data sizes.
6. **Derivation Tooling:** Check out `base-deriving-via` to see how boilerplate is minimized across the project.

## Integration Guide

These packages are designed to work together to form the foundational layer of a Cardano node.

* **Binary + Crypto:** Hash algorithms in `cardano-crypto-class` use `cardano-binary`'s `ToCBOR` instances to compute hashes over structured data (`hashWithSerialiser toCBOR`).
* **Binary + Slotting:** Slotting types (`SlotNo`, `EpochNo`) provide `ToCBOR`/`FromCBOR` instances ensuring temporal data can be serialized.
* **Crypto + Slotting:** The Praos VRF (`cardano-crypto-praos`) evaluates over a combination of epoch predictability and slot numbers, linking cryptographics directly to `cardano-slotting`.
* **Memory Optimization:** All components prefer the strict collections from `cardano-strict-containers` to prevent unintended thunk build-ups, and `heapwords` can be used to write tests confirming the layout size of cryptographic and time-based structures.

## Building

### Quick Start with `nix` (Recommended)

With nix it is as easy as:

```shellsession
$ nix develop
...
$ cabal build all
```

### Without `nix`

**IMPORTANT**: This project requires custom versions of cryptographic libraries with VRF support.

See **[INSTALL.md](INSTALL.md)** for detailed installation instructions including:

- Pre-built binaries for macOS, Linux, and Windows
- Building from source
- Environment setup
- Troubleshooting

Quick overview of required dependencies:

* **libsodium-vrf** - Custom fork with VRF batch verification ([source](https://github.com/input-output-hk/libsodium/tree/iquerejeta/vrf_batchverify))
* **libsecp256k1** - With Schnorr signature support
* **libblst** - BLS12-381 implementation

Pre-built binaries available at: <https://github.com/input-output-hk/iohk-nix/releases/latest>

## GHC

Default version of GHC used in `nix` is `9.6.7`. The project is tested with GHC versions `9.6.7`, `9.8.4`, `9.10.2`, and `9.12.2`.

### Testing

This is a command to run test suites for all packages:

```shellsession
$ cabal test all
```

The test suites use [hspec](https://hspec.github.io/),
which allows for running specific tests.
This is done by passing the `--match` flag to the test program, followed by a pattern.
You can alternatively use the `HSPEC_MATCH` environment variable with a pattern.
For example, the `cardano-crypto-class` tests can be run with:

```shellsession
$ cabal test cardano-crypto-class --test-option=--match='blake2b_256'
```

or

```shellsession
$ HSPEC_MATCH='blake2b_256' cabal test cardano-crypto-class
```

