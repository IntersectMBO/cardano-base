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
  pkgSet = haskell-nix.cabalProject {
    inherit src;
    compiler-nix-name = compiler;
    modules = [

      {
        # Packages we wish to ignore version bounds of.
        # This is similar to jailbreakCabal, however it
        # does not require any messing with cabal files.
        packages.katip.doExactConfig = true;

        # split data output for ekg to reduce closure size
        packages.ekg.components.library.enableSeparateDataOutput = true;
        packages.cardano-binary.configureFlags = [ "--ghc-option=-Werror" ];
        packages.cardano-crypto-class.configureFlags = [ "--ghc-option=-Werror" ];
        # We need to override the pkgconfig libraries so that we can provide our fork of
        # libsodium instead of the one from nixpkgs, which is what haskell.nix would
        # otherwise choose. Unfortunately, this means that we also override any other 
        # pkgconfig libraries that haskell.nix would pick for us. So we also need to 
        # manually include those here.
        packages.cardano-crypto-class.components.library.pkgconfig = lib.mkForce [[ buildPackages.libsodium-vrf buildPackages.secp256k1 ]];
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
    ];
  };
in
  pkgSet
