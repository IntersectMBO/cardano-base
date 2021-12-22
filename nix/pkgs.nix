{ sources }:
# our packages overlay
pkgs: _: with pkgs; {
  cardanoBaseHaskellPackages = import ./haskell.nix {
    inherit config
      sources
      lib
      stdenv
      haskell-nix
      buildPackages
      ;
  };

}
