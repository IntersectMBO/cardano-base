{
  cell,
  inputs,
}:

import "${inputs.self}/release.nix" {
  cardano-base = inputs.self;
  supportedSystems = [inputs.nixpkgs.system];
}
