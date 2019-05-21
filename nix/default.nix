{
  extras = hackage:
    {
      packages = {
        "base58-bytestring" = (((hackage.base58-bytestring)."0.1.0").revisions).default;
        "hedgehog" = (((hackage.hedgehog)."1.0").revisions).default;
        "micro-recursion-schemes" = (((hackage.micro-recursion-schemes)."5.0.2.2").revisions).default;
        "streaming-binary" = (((hackage.streaming-binary)."0.3.0.1").revisions).default;
        "transformers" = (((hackage.transformers)."0.5.6.2").revisions).default;
        "process" = (((hackage.process)."1.6.5.0").revisions).default;
        } // {
        cardano-binary = ./cardano-binary.nix;
        cardano-binary-test = ./cardano-binary-test.nix;
        cardano-prelude = ./cardano-prelude.nix;
        cardano-prelude-test = ./cardano-prelude-test.nix;
        cborg = ./cborg.nix;
        cardano-crypto = ./cardano-crypto.nix;
        canonical-json = ./canonical-json.nix;
        };
      compiler.version = "8.6.4";
      compiler.nix-name = "ghc864";
      };
  resolver = "lts-13.16";
  compiler = "ghc-8.6.4";
  }