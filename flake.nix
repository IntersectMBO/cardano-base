{
  inputs = {
    haskellNix.url = "github:input-output-hk/haskell.nix";
    haskellNix.inputs.tullia.follows = "tullia";
    nixpkgs.follows = "haskellNix/nixpkgs-unstable";
    iohkNix.url = "github:input-output-hk/iohk-nix";
    flake-utils.url = "github:hamishmack/flake-utils/hkm/nested-hydraJobs";

    CHaP.url = "github:input-output-hk/cardano-haskell-packages?ref=repo";
    CHaP.flake = false;

    # cicero
    tullia.url = "github:input-output-hk/tullia";
  };

  outputs = inputs:
    let
      profiling = false;
      supportedSystems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
       ]; in
    inputs.flake-utils.lib.eachSystem supportedSystems (system:
      let
        # setup our nixpkgs with the haskell.nix overlays, and the iohk-nix
        # overlays...
        nixpkgs = import inputs.nixpkgs {
          overlays = [inputs.haskellNix.overlay] ++ builtins.attrValues inputs.iohkNix.overlays;
          inherit system;
          inherit (inputs.haskellNix) config;
        };
        # ... and construct a flake from the cabal.project file.
        # We use cabalProject' to ensure we don't build the plan for
        # all systems.
        flake = (nixpkgs.haskell-nix.cabalProject' rec {
          src = ./.;
          name = "cardano-base";
          compiler-nix-name = "ghc927";

          # CHaP input map, so we can find CHaP packages (needs to be more
          # recent than the index-state we set!). Can be updated with
          #
          #  nix flake lock --update-input CHaP
          #
          inputMap = {
            "https://input-output-hk.github.io/cardano-haskell-packages" = inputs.CHaP;
          };

          # tools we want in our shell
          shell.tools = {
            cabal = "3.10.1.0";
            ghcid = "0.8.8";
            haskell-language-server = "latest";
            hlint = {};
            weeder = "2.4.1";
          };
          # Now we use pkgsBuildBuild, to make sure that even in the cross
          # compilation setting, we don't run into issues where we pick tools
          # for the target.
          shell.buildInputs = with nixpkgs.pkgsBuildBuild; [
            gitAndTools.git
            sqlite-interactive
          ];
          shell.withHoogle = true;

          # package customizations as needed. Where cabal.project is not
          # specific enough, or doesn't allow setting these.
          modules = [
            ({pkgs, ...}: {
              # Packages we wish to ignore version bounds of.
              # This is similar to jailbreakCabal, however it
              # does not require any messing with cabal files.
              packages.katip.doExactConfig = true;

              # split data output for ekg to reduce closure size
              packages.ekg.components.library.enableSeparateDataOutput = true;
              packages.cardano-binary.configureFlags = [ "--ghc-option=-Werror" ];
              packages.cardano-crypto-class.configureFlags = [ "--ghc-option=-Werror" ];
              packages.slotting.configureFlags = [ "--ghc-option=-Werror" ];
              enableLibraryProfiling = profiling;
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
        }).flake (
          # we also want cross compilation to windows.
          nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          crossPlatforms = p: [p.mingwW64];
        })
        # add cicero logic.
        // (let actionCiInputName = "GitHub event"; in inputs.tullia.fromSimple system {
          tasks =  {
            ci = { config, lib, ... }: {
              preset = {
                nix.enable = true;
                github.ci = {
                  # Tullia tasks can run locally or on Cicero.
                  # When no facts are present we know that we are running locally and vice versa.
                  # When running locally, the current directory is already bind-mounted into the container,
                  # so we don't need to fetch the source from GitHub and we don't want to report a GitHub status.
                  enable = config.actionRun.facts != {};
                  repository = "input-output-hk/cardano-base";
                  remote = config.preset.github.lib.readRepository actionCiInputName null;
                  revision = config.preset.github.lib.readRevision actionCiInputName null;
                };
              };


              command.text = config.preset.github.status.lib.reportBulk {
                bulk.text = ''
                  nix eval .#hydraJobs --apply __attrNames --json |
                  nix-systems -i |
                  jq 'with_entries(select(.value))' # filter out systems that we cannot build for
                '';
                each.text = ''nix build -L .#hydraJobs."$1".required'';
                skippedDescription = lib.escapeShellArg "No nix builder for this system";
              };

              memory = 1024 * 8;
              nomad.driver = "exec";
              nomad.resources.cpu = 10000;
            };
          };

          actions = {
            "cardano-base/ci" = {
              task = "ci";
              io = ''
                // This is a CUE expression that defines what events trigger a new run of this action.
                // There is no documentation for this yet. Ask SRE if you have trouble changing this.
                let github = {
                  #input: "${actionCiInputName}"
                  #repo: "input-output-hk/cardano-base"
                }

                #lib.merge
                #ios: [
                  {#lib.io.github_push, github, #default_branch: true},
                  {#lib.io.github_pr,   github},
                ]
              '';
            };
          };
        });
      in nixpkgs.lib.recursiveUpdate flake {
        # add a required job, that's basically all hydraJobs.
        hydraJobs = nixpkgs.callPackages inputs.iohkNix.utils.ciJobsAggregates
          { ciJobs = flake.hydraJobs; };
      }
    );

  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
      # drop this, once we stop needing it; when we have stable aarch64-darwin
      # builds
      "https://cache.zw3rk.com"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "loony-tools:pr9m4BkM/5/eSTZlkQyRt57Jz7OMBxNSUiMC4FkcNfk="
    ];
    allow-import-from-derivation = true;
  };
}
