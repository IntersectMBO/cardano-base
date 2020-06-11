############################################################################
# Builds Haskell packages with Haskell.nix
############################################################################
{ lib
, stdenv
, haskell-nix
, buildPackages
, pkgs
, config ? {}
# GHC attribute name
, compiler ? config.haskellNix.compiler or "ghc865"
# Enable profiling
, profiling ? config.haskellNix.profiling or false
}:
let

  # This creates the Haskell package set.
  # https://input-output-hk.github.io/haskell.nix/user-guide/projects/
  pkgSet = haskell-nix.cabalProject {
    src = haskell-nix.haskellLib.cleanGit { src = ../.; name = "cardano-base"; };
    compiler-nix-name = compiler;
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
        packages.slotting.configureFlags = [ "--ghc-option=-Werror" ];
        enableLibraryProfiling = profiling;
      }
      (lib.optionalAttrs stdenv.hostPlatform.isWindows {

        # This is a bit fragile but will work for now.  In haskell.nix we only
        # collect the .dll's as referenced in the package database files, this
        # means that for rust libraries we will miss them.  Thus we are copying
        # them here.  This however means we'd have to do this by hand for each
        # rust dependency.  Not ideal.  Maybe haskell.nix should walk
        # dependencies, I'm not certain about the implications there though.
        #
        # TODO: figure out why rust won't build window static libs.
        #
        packages.cardano-crypto-class.components.tests.test-crypto.postInstall = ''
        echo "Symlink kes-mmm-sumed25519 .dlls ..."
        for p in ${lib.concatStringsSep " " [ pkgs.kes_mmm_sumed25519_c ]}; do
          find "$p" -iname '*.dll' -exec ln -s {} $out/bin \;
        done
        '';

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
