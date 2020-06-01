{ lib, callPackage, cardanoBaseHaskellPackages }:
let
  sources = import ./sources.nix;
  naersk = callPackage sources.naersk {};
  kesSrc = cardanoBaseHaskellPackages.kes-mmm-sumed.src;
  stripLastElement = input: lib.concatStringsSep "/" (lib.init (lib.splitString "/" input));
in
naersk.buildPackage {
  root = stripLastElement kesSrc;
  copyBins = true;
  copyTarget = false;
  copyLibs = true;
}
