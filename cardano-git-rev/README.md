# Cardano Git Rev

This package exposes functions to provide git information for `cardano-node`.

`cardano-node` support building via `nix` and `cabal`

When building with `nix` the git executable and git metadata isn't available so the
git revision is embedded as a series of 40 zeros during the build. After the nix build
is finished the executable is patched with the correct git sha. See [set-git-rev.hs][set-git-rev.hs]

[set-git-rev.hs]: https://github.com/input-output-hk/iohk-nix/blob/master/overlays/haskell-nix-extra/utils/set-git-rev.hs
