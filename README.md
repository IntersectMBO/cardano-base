# cardano-base

A collection of miscellaneous packages used by Cardano that cover:

* cryptography
* serialization
* slotting

Each sub-project has its own README.

Haddocks for all packages from the `master` branch can be found at
[base.cardano.intersectmbo.org](https://base.cardano.intersectmbo.org/)

All releases for packages found in this repository are recorded in the
[Cardano Haskell package repository](https://github.com/intersectmbo/cardano-haskell-packages)

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

