{ system, compiler, flags, pkgs, hsPkgs, pkgconfPkgs, ... }:
  {
    flags = { development = false; };
    package = {
      specVersion = "1.10";
      identifier = { name = "cardano-prelude-test"; version = "0.1.0.0"; };
      license = "MIT";
      copyright = "2018 IOHK";
      maintainer = "operations@iohk.io";
      author = "IOHK";
      homepage = "";
      url = "";
      synopsis = "Utility types and functions for testing Cardano";
      description = "Utility types and functions for testing Cardano";
      buildType = "Simple";
      };
    components = {
      "library" = {
        depends = [
          (hsPkgs.base)
          (hsPkgs.aeson)
          (hsPkgs.aeson-pretty)
          (hsPkgs.attoparsec)
          (hsPkgs.base16-bytestring)
          (hsPkgs.bytestring)
          (hsPkgs.canonical-json)
          (hsPkgs.cardano-prelude)
          (hsPkgs.containers)
          (hsPkgs.cryptonite)
          (hsPkgs.formatting)
          (hsPkgs.hedgehog)
          (hsPkgs.hspec)
          (hsPkgs.pretty-show)
          (hsPkgs.QuickCheck)
          (hsPkgs.quickcheck-instances)
          (hsPkgs.text)
          (hsPkgs.template-haskell)
          (hsPkgs.time)
          ];
        };
      };
    } // {
    src = (pkgs.lib).mkDefault (pkgs.fetchgit {
      url = "https://github.com/input-output-hk/cardano-prelude";
      rev = "1fc576f290d24738fa70d90027e6774e3ae88c99";
      sha256 = "17fwmwkcyqwhl4bq1rj3z2xnl0r9j4pz6ay5p3c49s2zg9rapwp5";
      });
    postUnpack = "sourceRoot+=/test; echo source root reset to \$sourceRoot";
    }