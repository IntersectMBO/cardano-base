# cardano-base

A collection of miscellaneous packages used by Cardano that cover:

* cryptography
* serialization
* slotting

Each sub-project has its own README.

Haddock for all packages from master branch can be found here:
[https://input-output-hk.github.io/cardano-base](https://input-output-hk.github.io/cardano-base/)

All releases for packages found in this repository are recorded in [Cardano Haskell
package repository](https://github.com/input-output-hk/cardano-haskell-packages)

## Building

### With `nix`

With nix it is as easy as:

```
$ nix develop
...
$ cabal build all
```

### Without `nix`

Crypotgraphic depencencies needed for building Haskell packages:

* [`libsodium`](https://github.com/jedisct1/libsodium)
* [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1)
* [`libblst`](https://github.com/supranational/blst)

We provide packaged versions for common Operating Systems for all of the above
dependencies: [Download](https://github.com/input-output-hk/iohk-nix/releases/latest)


## GHC

Default version of GHC used in `nix` is `9.2.7`, but we do support other GHC versions
`8.10.7` and `9.6.1`.


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

