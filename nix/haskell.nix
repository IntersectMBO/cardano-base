############################################################################
# Builds Haskell packages with Haskell.nix
############################################################################
{ lib
, stdenv
, haskell-nix
, buildPackages
, config ? {}
# GHC attribute name
, compiler ? config.haskellNix.compiler or "ghc8107"
# Enable profiling
, profiling ? config.haskellNix.profiling or false
}:
let

  src = haskell-nix.haskellLib.cleanGit {
      name = "cardano-base-src";
      src = ../.;
  };

  # This creates the Haskell package set.
  # https://input-output-hk.github.io/haskell.nix/user-guide/projects/
  pkgSet = haskell-nix.cabalProject ({pkgs, ...}: {
    inherit src;
    compiler-nix-name = compiler;
    cabalProjectLocal = lib.optionalString pkgs.stdenv.hostPlatform.isGhcjs ''
      allow-newer:
             stm:base
    '';
    modules = [

      # Allow reinstallation of Win32
      { nonReinstallablePkgs =
        [ "rts" "ghc-heap" "ghc-prim" "integer-gmp" "integer-simple" "base"
          "deepseq" "array" "ghc-boot-th" "pretty" "template-haskell"
          # ghcjs custom packages
          "ghcjs-prim" "ghcjs-th"
          "ghc-boot"
          "ghc" "array" "binary" "bytestring" "containers"
          "filepath" "ghc-boot" "ghc-compact" "ghc-prim"
          # "ghci" "haskeline"
          "hpc"
          "mtl" "parsec" "text" "transformers"
          "xhtml"
          # "stm" "terminfo"
        ];
      }
      {
        # Packages we wish to ignore version bounds of.
        # This is similar to jailbreakCabal, however it
        # does not require any messing with cabal files.
        packages.katip.doExactConfig = true;

        # split data output for ekg to reduce closure size
        packages.ekg.components.library.enableSeparateDataOutput = true;
        packages.binary.configureFlags = [ "--ghc-option=-Werror" ];
        #packages.binary/test.configureFlags = [ "--ghc-option=-Werror" ];
        packages.cardano-crypto-class.configureFlags = [ "--ghc-option=-Werror" ];
        packages.cardano-crypto-class.components.library.pkgconfig = lib.mkForce [[ buildPackages.libsodium-vrf ]];
        packages.slotting.configureFlags = [ "--ghc-option=-Werror" ];
        enableLibraryProfiling = profiling;
      }
      (lib.optionalAttrs stdenv.hostPlatform.isWindows {
        # Disable cabal-doctest tests by turning off custom setups
        packages.comonad.package.buildType = lib.mkForce "Simple";
        packages.distributive.package.buildType = lib.mkForce "Simple";
        packages.lens.package.buildType = lib.mkForce "Simple";
        packages.nonempty-vector.package.buildType = lib.mkForce "Simple";
        packages.semigroupoids.package.buildType = lib.mkForce "Simple";

        # Make sure we use a buildPackages version of happy
        packages.pretty-show.components.library.build-tools = [ buildPackages.haskell-nix.haskellPackages.happy ];

        # Remove hsc2hs build-tool dependencies (suitable version will be available as part of the ghc derivation)
        packages.Win32.components.library.build-tools = lib.mkForce [];
        packages.terminal-size.components.library.build-tools = lib.mkForce [];
        packages.network.components.library.build-tools = lib.mkForce [];
      })
      ({ pkgs, ... }: lib.mkIf (pkgs.stdenv.hostPlatform.isGhcjs) {
        packages =
          let
            runEmscripten = ''
              patchShebangs jsbits/emscripten/build.sh
              (cd jsbits/emscripten && PATH=${
                  # The extra buildPackages here is for closurecompiler.
                  # Without it we get `unknown emulation for platform: js-unknown-ghcjs` errors.
                  lib.makeBinPath (with pkgs.buildPackages.buildPackages;
                    [ emscripten closurecompiler coreutils python2 ])
                }:$PATH ./build.sh)
            '';
            libsodium-vrf = pkgs.libsodium-vrf.overrideAttrs (attrs: {
              nativeBuildInputs = attrs.nativeBuildInputs or [ ] ++ (with pkgs.buildPackages.buildPackages; [ emscripten python2 ]);
              prePatch = ''
                export HOME=$(mktemp -d)
                export PYTHON=${pkgs.buildPackages.buildPackages.python2}/bin/python
              '' + attrs.prePatch or "";
              configurePhase = ''
                emconfigure ./configure --prefix=$out --enable-minimal --disable-shared --without-pthreads --disable-ssp --disable-asm --disable-pie CFLAGS=-Os
              '';
              CC = "emcc";
            });
          in
          {
            cardano-crypto-praos.components.library.pkgconfig = lib.mkForce [ [ libsodium-vrf ] ];
            cardano-crypto-class.components.library.pkgconfig = lib.mkForce [ [ libsodium-vrf ] ];
            cardano-crypto-class.components.library.build-tools = with pkgs.buildPackages.buildPackages; [ emscripten python2 ];
            cardano-crypto-class.components.library.preConfigure = ''
              ls -l
              emcc $(js-unknown-ghcjs-pkg-config --libs --cflags libsodium) jsbits/libsodium.c -o jsbits/libsodium.js -s WASM=0 \
                -s "EXTRA_EXPORTED_RUNTIME_METHODS=['printErr']" \
                -s "EXPORTED_FUNCTIONS=['_malloc', '_free', '_crypto_generichash_blake2b', '_crypto_generichash_blake2b_final', '_crypto_generichash_blake2b_init', '_crypto_generichash_blake2b_update', '_crypto_hash_sha256', '_crypto_hash_sha256_final', '_crypto_hash_sha256_init', '_crypto_hash_sha256_update', '_crypto_sign_ed25519_detached', '_crypto_sign_ed25519_seed_keypair', '_crypto_sign_ed25519_sk_to_pk', '_crypto_sign_ed25519_sk_to_seed', '_crypto_sign_ed25519_verify_detached', '_sodium_compare', '_sodium_free', '_sodium_init', '_sodium_malloc', '_sodium_memzero']"
            '';
            # cryptonite.components.library.preConfigure = runEmscripten;
          };
      })
    ];
  });
in
  pkgSet
