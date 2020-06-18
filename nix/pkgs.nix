# our packages overlay
pkgs: _: with pkgs; {
  cardanoBaseHaskellPackages = import ./haskell.nix {
    inherit config
      lib
      stdenv
      haskell-nix
      buildPackages
      ;
  };

  libsodium = pkgs.callPackage ./pkgs/libsodium {};
}
