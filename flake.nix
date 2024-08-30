{
  inputs = {
    haskellNix.url = "github:input-output-hk/haskell.nix";
    nixpkgs.follows = "haskellNix/nixpkgs-unstable";
    iohkNix.url = "github:input-output-hk/iohk-nix";
    flake-utils.url = "github:hamishmack/flake-utils/hkm/nested-hydraJobs";

    CHaP.url = "github:intersectmbo/cardano-haskell-packages?ref=repo";
    CHaP.flake = false;

    # non-flake nix compatibility
    flake-compat.url = "github:edolstra/flake-compat";
    flake-compat.flake = false;
  };

  outputs = inputs:
    let
      lib = inputs.nixpkgs.lib;
      profiling = false;
      supportedSystems = [
        "x86_64-linux"
        "x86_64-darwin"
        # not supported on ci.iog.io right now
        #"aarch64-linux"
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

        defaultCompilerVersion = "ghc928";

        # ... and construct a flake from the cabal.project file.
        # We use cabalProject' to ensure we don't build the plan for
        # all systems.
        flake = (nixpkgs.haskell-nix.cabalProject' ({config, ...}:
        let 
          isCrossBuild = nixpkgs.hostPlatform != nixpkgs.buildPlatform;
          compareGhc = builtins.compareVersions nixpkgs.buildPackages.haskell-nix.compiler.${config.compiler-nix-name}.version;
        in {
          src = ./.;
          name = "cardano-base";
          compiler-nix-name = lib.mkDefault defaultCompilerVersion;

          # CHaP input map, so we can find CHaP packages (needs to be more
          # recent than the index-state we set!). Can be updated with
          #
          #  nix flake lock --update-input CHaP
          #
          inputMap = {
            "https://chap.intersectmbo.org/" = inputs.CHaP;
          };

          # tools we want in our shell
          shell = {
            crossPlatforms = p: lib.optional (compareGhc "9.0" < 0) p.ghcjs;
            tools = ({
              cabal = "3.10.1.0";
              ghcid = "0.8.8";
              haskell-language-server = if compareGhc "9" < 0
                                        then { src = nixpkgs.buildPackages.haskell-nix.sources."hls-2.2"; }
                                        else "latest";
            } // (lib.optionalAttrs (compareGhc "9.0" >= 0) {
              # ghc 9.2.8 comes with base 4.16.
              # this disqualifies weeder > 2.4.1
              # and hlint > 3.6.1
               hlint = "3.6.1";
               weeder = "2.4.1";
            }));
            # Now we use pkgsBuildBuild, to make sure that even in the cross
            # compilation setting, we don't run into issues where we pick tools
            # for the target.
            buildInputs = with nixpkgs.pkgsBuildBuild; [
              gitAndTools.git
              sqlite-interactive
            ];
            withHoogle = compareGhc "9.0" >= 0;
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
              enableLibraryProfiling = profiling;
            })

            ({pkgs, ...}: with pkgs; lib.mkIf isCrossBuild {
              packages.text.flags.simdutf = false;
              # Disable cabal-doctest tests by turning off custom setups
              packages.pretty-simple.package.buildType = lib.mkForce "Simple";
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
                packages.cardano-addresses-jsbits.components.library.postPatch = addJsbits;
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
          flake = {
          # on linux, build/test other supported compilers
          variants = lib.optionalAttrs (system == "x86_64-linux")
            # on linux, build/test other supported compilers
            (lib.genAttrs ["ghc810"] (compiler-nix-name: {
              inherit compiler-nix-name;
            }));
          crossPlatforms = p:
            lib.optional (system == "x86_64-linux" && builtins.elem config.compiler-nix-name ["ghc8107"]) p.ghcjs ++
            lib.optional (system == "x86_64-linux" && config.compiler-nix-name == defaultCompilerVersion) p.mingwW64;
          };
        })).flake {};
        cardano-addresses-js = nixpkgs.callPackage ./nix/cardano-addresses-js.nix { cardano-addresses-jsapi = flake.packages."ghc810-javascript-unknown-ghcjs:cardano-addresses-jsapi:exe:cardano-addresses-jsapi".package; };
        cardano-addresses-demo-js = nixpkgs.callPackage ./nix/cardano-addresses-demo-js.nix { inherit cardano-addresses-js; };
        cardano-addresses-js-shell = nixpkgs.callPackage ./nix/cardano-addresses-js-shell.nix { inherit cardano-addresses-js;};
      in lib.recursiveUpdate flake {
        # add a required job, that's basically all hydraJobs.
        hydraJobs = nixpkgs.callPackages inputs.iohkNix.utils.ciJobsAggregates
          { ciJobs = flake.hydraJobs; };
        docker = { cardano-address =
                     let cardano-address-pkg = flake.packages."cardano-addresses-cli:exe:cardano-address";
                     in nixpkgs.dockerTools.buildLayeredImage {
                          name = "cardano-address";
                          tag = "latest";
                          contents = [ cardano-address-pkg ];
                          config.Cmd = [ "cardano-address" ];
                        };
                 };
        jsbits = nixpkgs.srcOnly flake.packages."ghc810-javascript-unknown-ghcjs:cardano-addresses-jsbits:lib:cardano-addresses-jsbits";
        packages = { inherit cardano-addresses-js; inherit cardano-addresses-demo-js; inherit cardano-addresses-js-shell; };
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
