# cardano-crypto-praos

This package implements Haskell FFI wrappers around the VRF (verifiable random
function) implemented in libsodium.

## Libsodium Dependency

This package depends on a custom fork of the `libsodium` C library, found at

<https://github.com/input-output-hk/libsodium/tree/iquerejeta/vrf_batchverify>

### Usage with `cabal`

#### Using external libsodium

- Clone out the above-mentioned libsodium fork
- Build and install this `libsodium` version (make sure `pkgconfig` can find it)
- Cabal should now pick up this version

#### Using internal C code

The `cbits` directory contains the C code that's needed to implement
the custom VRF code, disable the `external-libsodium-vrf` flag to let
GHC build those directly. This still requires a working libsodium
installation.

```shellsession
$ cabal build -f-external-libsodium-vrf
```

### Usage with Nix

To build entirely with nix:

```shellsession
$ nix build .#cardano-crypto-praos:lib:cardano-crypto-praos
```

To build using nix+cabal:

```shellsession
$ nix develop
...
$ cabal update
...
$ cabal build cardano-crypto-praos
```

However, `cabal update` is needed only when `index-state` was updated in `cabal.project`.
