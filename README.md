# cardano-base

A collection of miscellaneous packages used by Cardano that cover:

* cryptography
* serialization
* slotting

Each sub-project has its own README.

Haddocks for all packages from the `master` branch can be found at
[base.cardano.intersectmbo.org](https://base.cardano.intersectmbo.org/)

All releases for packages found in this repository are recorded in [Cardano Haskell
package repository](https://github.com/intersectmbo/cardano-haskell-packages)

## Building

### Quick Start with `nix` (Recommended)

With nix it is as easy as:

```
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

Pre-built binaries available at: https://github.com/input-output-hk/iohk-nix/releases/latest


## GHC

Default version of GHC used in `nix` is `9.6.7`. The project is tested with GHC versions `9.6.7`, `9.8.4`, `9.10.2`, and `9.12.2`.


### Testing

This is a command to run test suites for all packages:

```
$ cabal build all
```

The test suites use [Tasty](https://github.com/feuerbach/tasty),
which allows for running specific tests.
This is done by passing the `-p` flag to the test program, followed by an `awk` pattern.
You can alternatively use the `TASTY_PATTERN` environment variable with a pattern.
For example, the `cardano-crypto-tests` can be run with:

```shell
$ cabal test cardano-crypto-tests --test-options '-p blake2b_256'
```

or

```shell
$ TASTY_PATTERN="blake2b_256" cabal test cardano-crypto-tests
```

