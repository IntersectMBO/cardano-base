# This file is used by nix-shell.
{ config ? {}
, sourcesOverride ? {}
, withHoogle ? false
, pkgs ? import ./nix {
    inherit config sourcesOverride;
  }
}:
with pkgs;
let
  inherit (pkgs.haskell-nix) haskellLib;

  # This provides a development environment that can be used with nix-shell or
  # lorri. See https://input-output-hk.github.io/haskell.nix/tutorials/development.html
  shell = cardanoBaseHaskellPackages.shellFor {
    name = "cabal-dev-shell";

    # These programs will be available inside the nix-shell.
    nativeBuildInputs = with buildPackages; with haskellPackages; [
      cabal-install
      ghcid
      gitAndTools.git
      hlint
      weeder
      nix
      niv
      pkgconfig
      sqlite-interactive
    ];

    tools = {
      haskell-language-server = "latest";
    };

    inherit withHoogle;
  };

  devops = pkgs.stdenv.mkDerivation {
    name = "devops-shell";
    buildInputs = [
      niv
    ];
    shellHook = ''
      echo "DevOps Tools" \
      | ${figlet}/bin/figlet -f banner -c \
      | ${lolcat}/bin/lolcat

      echo "NOTE: you may need to export GITHUB_TOKEN if you hit rate limits with niv"
      echo "Commands:
        * niv update <package> - update package

      "
    '';
  };

in

 shell // { inherit devops; }
