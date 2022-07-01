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
  # This provides a development environment that can be used with nix-shell or
  # lorri. See https://input-output-hk.github.io/haskell.nix/tutorials/development.html
  shell = cardanoBaseHaskellPackages.shellFor {
    name = "cabal-dev-shell";

    # These programs will be available inside the nix-shell.
    buildInputs = with haskellPackages; [
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
      cabal = "3.6.2.0";
      haskell-language-server = "latest";
    };

    # Prevents cabal from choosing alternate plans, so that
    # *all* dependencies are provided by Nix.
    exactDeps = false;

    NIX_SSL_CERT_FILE = "/etc/ssl/certs/ca-bundle.crt";
    SSL_CERT_FILE = "/etc/ssl/certs/ca-bundle.crt";

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
