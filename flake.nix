{
  description = "cardano-base";

  inputs = {
    haskellNix.url = "github:input-output-hk/haskell.nix";
    nixpkgs.follows = "haskellNix/nixpkgs-unstable";
    iohkNix.url = "github:input-output-hk/iohk-nix";
    flake-utils.url = "github:hamishmack/flake-utils/hkm/nested-hydraJobs";

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
    lib = inputs.nixpkgs.lib;
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
        cabalProject = nixpkgs.haskell-nix.cabalProject' ({config, ...}:
        let
        isCrossBuild = nixpkgs.hostPlatform != nixpkgs.buildPlatform;
        compareGhc = builtins.compareVersions nixpkgs.buildPackages.haskell-nix.compiler.${config.compiler-nix-name}.version;
        in {
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
              };

            # and from nixpkgs or other inputs
            nativeBuildInputs = with nixpkgs;
              [
                haskellPackages.implicit-hie
              ];
            # disable Hoogle until someone request it
            withHoogle = false;
            crossPlatforms = p: lib.optional (compareGhc "9.0" < 0) p.ghcjs;
          };

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
            })
            ({pkgs, ...}: with pkgs; lib.mkIf stdenv.hostPlatform.isWindows {
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

            # GHCJS build configuration
            ({ config, pkgs, ... }:
              let
                # Run the script to build the C sources from cryptonite and cardano-crypto
                # and place the result in jsbits/cardano-crypto.js
                jsbits = pkgs.runCommand "cardano-addresses-jsbits" { } ''
                  script=$(mktemp -d)
                  cp -r ${cardano-addresses/cardano-addresses-jsbits/emscripten}/* $script
                  ln -s ${pkgs.srcOnly {name = "cryptonite-src"; src = config.packages.cryptonite.src;}}/cbits $script/cryptonite
                  ln -s ${pkgs.srcOnly {name = "cardano-crypto-src"; src = config.packages.cardano-crypto.src;}}/cbits $script/cardano-crypto
                  patchShebangs $script/build.sh
                  (cd $script && PATH=${
                      # The extra buildPackages here is for closurecompiler.
                      # Without it we get `unknown emulation for platform: js-unknown-ghcjs` errors.
                      lib.makeBinPath (with pkgs.buildPackages.buildPackages;
                        [emscripten closurecompiler coreutils])
                    }:$PATH ./build.sh)
                  mkdir -p $out
                  cp $script/cardano-crypto.js $out
                '';
                addJsbits = ''
                  mkdir -p jsbits
                  cp ${jsbits}/* jsbits
                '';
              in
              lib.mkIf (pkgs.stdenv.hostPlatform.isGhcjs) {
                reinstallableLibGhc = false;
      
                # TODO replace this with `zlib` build with `emcc` if possible.
                # Replace zlib with a derivation including just the header files
                packages.digest.components.library.libs = lib.mkForce [(
                  pkgs.pkgsBuildBuild.runCommand "zlib" { nativeBuildInputs = [ pkgs.pkgsBuildBuild.xorg.lndir ]; } ''
                    mkdir -p $out/include
                    lndir ${pkgs.pkgsBuildBuild.lib.getDev pkgs.pkgsBuildBuild.zlib}/include $out/include
                '')];
                # Prevent downstream packages from looking for zlib
                packages.digest.components.library.postInstall = ''
                  sed -i 's/^extra-libraries: *z//g' $out/package.conf.d/digest-*.conf
                '';
                # Prevent errors from missing zlib function _adler32
                packages.cardano-addresses.configureFlags = [ "--gcc-options=-Wno-undefined" ];
                packages.cardano-addresses-cli.configureFlags = [ "--gcc-options=-Wno-undefined" ];
                packages.cardano-addresses-jsapi.configureFlags = [ "--gcc-options=-Wno-undefined" ];
      
                packages.cardano-addresses-cli.components.library.build-tools = [ pkgs.buildPackages.buildPackages.gitMinimal ];
                packages.cardano-addresses-jsapi.components.library.build-tools = [ pkgs.buildPackages.buildPackages.gitMinimal ];
                packages.cardano-addresses-jsbits.components.library.preConfigure = addJsbits;
                packages.cardano-addresses-cli.components.tests.unit.preCheck = ''
                  export CARDANO_ADDRESSES_CLI="${config.hsPkgs.cardano-addresses-cli.components.exes.cardano-address}/bin"
                '';
                packages.cardano-addresses-cli.components.tests.unit.build-tools = pkgs.lib.mkForce [
                  config.hsPkgs.buildPackages.hspec-discover.components.exes.hspec-discover
                  pkgs.buildPackages.nodejs
               ];
             })
            ({ pkgs, ... }: lib.mkIf (!pkgs.stdenv.hostPlatform.isGhcjs) {
                # Disable jsapi-test on jsaddle/native. It's not working yet.
                packages.cardano-addresses-jsapi.components.tests.jsapi-test.preCheck = ''
                  echo "Tests disabled on non-ghcjs"
                  exit 0
                '';
              })
          ];
          # ... and construct a flake from the cabal project
          flake = {
            # on linux, build/test other supported compilers
            variants = lib.optionalAttrs (system == "x86_64-linux")
              # on linux, build/test other supported compilers
              (lib.genAttrs ["ghc8107" "ghc982"] (compiler-nix-name: {
                inherit compiler-nix-name;
              }));
            crossPlatforms = p:
              lib.optional (system == "x86_64-linux" && builtins.elem config.compiler-nix-name ["ghc8107"]) p.ghcjs ++
              lib.optional (system == "x86_64-linux" && config.compiler-nix-name == defaultCompiler) p.mingwW64;
          };
        });
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
          docker = { cardano-address =
                       let cardano-address-pkg = flake.packages."cardano-addresses-cli:exe:cardano-address";
                       in nixpkgs.dockerTools.buildLayeredImage {
                            name = "cardano-address";
                            tag = "latest";
                            contents = [ cardano-address-pkg ];
                            config.Cmd = [ "cardano-address" ];
                          };
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
