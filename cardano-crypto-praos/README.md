# cardano-crypto-praos

This package implements Haskell FFI wrappers around the VRF (verifiable random
function) implemented in libsodium.

## Libsodium Dependency

This package depends on a custom fork of the `libsodium` C library, found at

https://github.com/input-output-hk/libsodium/tree/iquerejeta/vrf_batchverify

### Usage with `cabal`

#### Using external libsodium

- Clone out the above-mentioned libsodium fork
- Build and install this `libsodium` version (make sure `pkgconfig` can find
  it)
- Cabal should now pick up this version

#### Using internal C code

The `cbits` directory contains the C code that's needed to implement
the custom VRF code, disable the `external-libsodium-vrf` flag to let
GHC build those directly. This still requires a working libsodium
installation.

```
cabal build -f-external-libsodium-vrf
```

### Usage with Nix

To build fully with nix:
> nix-build default.nix -A haskellPackages.cardano-crypto-praos
To use nix+cabal:
> nix-shell --run "cabal build cardano-crypto-praos"
