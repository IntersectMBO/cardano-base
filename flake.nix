{
  description = "cardano-base";

  inputs = {
    haskellNix.url = "github:input-output-hk/haskell.nix";
    # allow us to independently update hackageNix
    haskellNix.inputs.hackage.follows = "hackageNix";
    nixpkgs.follows = "haskellNix/nixpkgs-unstable";
    iohkNix.url = "github:input-output-hk/iohk-nix";
    flake-utils.url = "github:hamishmack/flake-utils/hkm/nested-hydraJobs";

    hackageNix = {
      url = "github:input-output-hk/hackage.nix";
      flake = false;
    };

    CHaP = {
      url = "github:intersectmbo/cardano-haskell-packages?ref=repo";
      flake = false;
    };

    # non-flake nix compatibility
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };

    pre-commit-hooks.url = "github:cachix/pre-commit-hooks.nix";
  };

  outputs = inputs: let
    supportedSystems = [
      "x86_64-linux"
      "x86_64-darwin"
      # "aarch64-linux" - disable these temporarily because the build is broken
      "aarch64-darwin"
    ];
  in
    inputs.flake-utils.lib.eachSystem supportedSystems (
      system: let
        # setup our nixpkgs with the haskell.nix overlays, and the iohk-nix
        # overlays...
        nixpkgs = import inputs.nixpkgs {
          overlays = [
            # iohkNix.overlays.crypto provide libsodium-vrf, libblst and libsecp256k1.
            inputs.iohkNix.overlays.crypto
            # haskellNix.overlay can be configured by later overlays, so need to come before them.
            inputs.haskellNix.overlay
            # configure haskell.nix to use iohk-nix crypto librairies.
            inputs.iohkNix.overlays.haskell-nix-crypto
          ];
          inherit system;
          inherit (inputs.haskellNix) config;
        };
        inherit (nixpkgs) lib;

        # see flake `variants` below for alternative compilers
        defaultCompiler = "ghc966";
        fourmoluVersion = "0.16.2.0";
        # We use cabalProject' to ensure we don't build the plan for
        # all systems.
        cabalProject = nixpkgs.haskell-nix.cabalProject' ({config, ...}: {
          src = ./.;
          name = "cardano-base";
          compiler-nix-name = lib.mkDefault defaultCompiler;

          # CHaP input map, so we can find CHaP packages (needs to be more
          # recent than the index-state we set!). Can be updated with
          #
          #  nix flake lock --update-input CHaP
          #
          inputMap = {
            "https://chap.intersectmbo.org/" = inputs.CHaP;
          };
          cabalProjectLocal = ''
            repository cardano-haskell-packages-local
              url: file:${inputs.CHaP}
              secure: True
            active-repositories: hackage.haskell.org, cardano-haskell-packages-local
          '';

          shell = {
            # force LANG to be UTF-8, otherwise GHC might choke on UTF encoded data.
            shellHook = ''
              export LANG=en_US.UTF-8
              export LC_ALL=en_US.UTF-8
            '' + lib.optionalString (nixpkgs.glibcLocales != null && nixpkgs.stdenv.hostPlatform.libc == "glibc") ''
              export LOCALE_ARCHIVE="${nixpkgs.glibcLocales}/lib/locale/locale-archive"
            '';

            # tools we want in our shell, from hackage
            tools =
              {
                cabal = "3.12.1.0";
                ghcid = "0.8.9";
              }
              // lib.optionalAttrs (config.compiler-nix-name == defaultCompiler) {
                # tools that work only with default compiler
                fourmolu = fourmoluVersion;
                hlint = "3.8";
                haskell-language-server = "2.9.0.0";
                cabal-gild = "1.5.0.1";
              };

            # and from nixpkgs or other inputs
            nativeBuildInputs = with nixpkgs;
              [
                haskellPackages.implicit-hie
              ];
            # disable Hoogle until someone request it
            withHoogle = false;
            # Skip cross compilers for the shell
            crossPlatforms = _: [];
          };
          flake = {
            # on linux, build/test other supported compilers
            variants = lib.genAttrs ["ghc8107"] (compiler-nix-name: {
              inherit compiler-nix-name;
            });
            # we also want cross compilation to windows.
            crossPlatforms = p: lib.optional (system == "x86_64-linux" && config.compiler-nix-name != "ghc8107") p.mingwW64;
          };

          # package customizations as needed. Where cabal.project is not
          # specific enough, or doesn't allow setting these.
          modules = [
            ({pkgs, ...}: {
              # Packages that are not always in the plan need to be listed so that haskell.nix does not
              # complain about overrides on packages that do not exist.
              package-keys = ["katip" "ekg" "slotting" "lens" "nonempty-vector"];

              # Packages we wish to ignore version bounds of.
              # This is similar to jailbreakCabal, however it
              # does not require any messing with cabal files.
              packages.katip.doExactConfig = true;

              # split data output for ekg to reduce closure size
              packages.ekg.components.library.enableSeparateDataOutput = true;
              packages.cardano-binary.configureFlags = [ "--ghc-option=-Werror" ];
              packages.cardano-crypto-class.configureFlags = [ "--ghc-option=-Werror" ];
              packages.slotting.configureFlags = [ "--ghc-option=-Werror" ];
            })
            ({pkgs, ...}: with pkgs; nixpkgs.lib.mkIf stdenv.hostPlatform.isWindows {
              packages.text.flags.simdutf = false;
              # Disable cabal-doctest tests by turning off custom setups
              packages.comonad.package.buildType = lib.mkForce "Simple";
              packages.distributive.package.buildType = lib.mkForce "Simple";
              packages.lens.package.buildType = lib.mkForce "Simple";
              packages.nonempty-vector.package.buildType = lib.mkForce "Simple";
              packages.semigroupoids.package.buildType = lib.mkForce "Simple";

              # Make sure we use a buildPackages version of happy
              # packages.pretty-show.components.library.build-tools = [ (pkgsBuildBuild.haskell-nix.tool compiler-nix-name "happy" "1.20.1.1") ];

              # Remove hsc2hs build-tool dependencies (suitable version will be available as part of the ghc derivation)
              packages.Win32.components.library.build-tools = lib.mkForce [];
              packages.terminal-size.components.library.build-tools = lib.mkForce [];
              packages.network.components.library.build-tools = lib.mkForce [];
            })
          ];
        });
        # ... and construct a flake from the cabal project
        flake = cabalProject.flake {};
      in
        lib.recursiveUpdate flake rec {
          project = cabalProject;
          # add a required job, that's basically all hydraJobs.
          hydraJobs =
            nixpkgs.callPackages inputs.iohkNix.utils.ciJobsAggregates
            {
              ciJobs =
                flake.hydraJobs
                // {
                  # This ensure hydra send a status for the required job (even if no change other than commit hash)
                  revision = nixpkgs.writeText "revision" (inputs.self.rev or "dirty");
                };
            };
          legacyPackages = {
            inherit cabalProject nixpkgs;
            # also provide hydraJobs through legacyPackages to allow building without system prefix:
            inherit hydraJobs;
          };

          devShells = let
            mkDevShells = p: {
              # `nix develop .#profiling` (or `.#ghc966.profiling): a shell with profiling enabled
              profiling = (p.appendModule {modules = [{enableLibraryProfiling = true;}];}).shell;
              # `nix develop .#pre-commit` (or `.#ghc966.pre-commit): a shell with pre-commit enabled
              pre-commit = let
                pre-commit-check = inputs.pre-commit-hooks.lib.${system}.run {
                  src = ./.;
                  hooks = {
                    fourmolu.enable = true;
                  };
                  tools = {
                    fourmolu = p.tool "fourmolu" fourmoluVersion;
                  };
                };
              in
                p.shell.overrideAttrs (old: {
                  shellHook = old.shellHook + pre-commit-check.shellHook;
              });
            };
          in
            mkDevShells cabalProject
            # Additional shells for every GHC version supported by haskell.nix, eg. `nix develop .#ghc8107`
            // lib.mapAttrs (compiler-nix-name: _: let
              p = cabalProject.appendModule {inherit compiler-nix-name;};
            in
              p.shell // (mkDevShells p))
            nixpkgs.haskell-nix.compiler;
          # formatter used by nix fmt
          formatter = nixpkgs.alejandra;
        }
    );

  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    ];
    allow-import-from-derivation = true;
  };
}
