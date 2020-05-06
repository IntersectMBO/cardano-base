module Cardano.Crypto.Hash.NeverUsed (NeverHash) where

import Cardano.Crypto.Hash.Class

-- | HASH never used
--
-- Will throw a runtime exception when trying to hash something.
data NeverHash

instance HashAlgorithm NeverHash where
  hashAlgorithmName _ = "never"
  sizeHash _ = 0
  digest = error "HASH not available"
