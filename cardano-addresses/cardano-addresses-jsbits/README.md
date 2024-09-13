# GHCJS Build of cardano-addresses

How to build `cardano-addresses` library, executables, and tests with
ghcjs.

## With Nix

Build and run CLI:

```terminal
$ nix build .#ghc810-javascript-unknown-ghcjs:cardano-addresses-cli:exe:cardano-address
$ ./result/bin/cardano-address --help
$ ./result/bin/cardano-address recovery-phrase generate
```

Execute library unit tests:
```terminal
$ nix build .#checks.x86_64-linux.ghc810-javascript-unknown-ghcjs:cardano-addresses:test:unit
$ cat result/test-stdout
```

## With Cabal in nix-shell

Note: The package `cardano-addresses-jsbits` depends on the file `jsbits/cardano-crypto.js`. In order to build it manually, we need to generate that first, and put it in `cardano-addresses/cardano-addresses-jsbits/jsbits/`. We can do that easily with nix. For example, in linux we may write:

```terminal
nix build .#jsbits.x86_64-linux
mkdir cardano-addresses/cardano-addresses-jsbits/jsbits/
cp result/jsbits/cardano-crypto.js  cardano-addresses/cardano-addresses-jsbits/jsbits/
```

The `nix-shell` development environment provides
`js-unknown-ghcjs-cabal`, which is a cross-compiling Cabal for ghcjs.

Build and run CLI:

```terminal
$ nix develop .#ghc810-javascript-unknown-ghcjs
$ js-unknown-ghcjs-cabal --builddir=dist-ghcjs build all
...
$ js-unknown-ghcjs-cabal --builddir=dist-ghcjs run cardano-addresses-cli:exe:cardano-address
...
$ node dist-ghcjs/build/js-ghcjs/ghcjs-8.10.7/cardano-addresses-cli-3.12.0/x/cardano-address/build/cardano-address/cardano-address.jsexe/all.js recovery-phrase generate
indoor apology bracket motor lecture logic range elder lizard resemble penalty can normal pond couch corn forget snow hard setup fire actual plate earth
```

### Limitations

1. `js-unknown-ghcjs-cabal run` doesn't work ghcjs code needs to be
   interpreted with `nodejs`.

2. We needed to add dummy calls to `Cardano.Address.Jsbits.addJsbitsDependency`
   to ensure that ghcjs linked in the emscripten-compiled crypto code.

## Without Nix

This is more difficult because you need to manually install correct
versions of build tools and dependencies.

Use the script `jsbits/emscripten/build.sh` to make
`cardano-crypto.js` and then install the `cardano-addresses-jsbits`
library with ghcjs Cabal.
