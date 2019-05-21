with import ../../lib.nix;
with pkgs;

let
  stack-pkgs = import ./.stack-pkgs.nix;
  compiler = (stack-pkgs.extras {}).compiler.nix-name;

in haskell.lib.buildStackProject {
  name = "cardano-base-env";
  buildInputs = [ zlib openssl gmp libffi git ];
  ghc = haskell.packages.${compiler}.ghc;
}
