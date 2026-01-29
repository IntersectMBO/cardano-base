{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the SHA3_512 hashing algorithm.
module Cardano.Crypto.Hash.SHA3_512 (
  SHA3_512,
)
where

import Cardano.Crypto.Hash.Class
import qualified Data.ByteArray as BA
import qualified "crypton" Crypto.Hash as H

data SHA3_512

instance HashAlgorithm SHA3_512 where
  type HashSize SHA3_512 = 64
  hashAlgorithmName _ = "sha3-512"
  digest _ = convert . H.hash

convert :: H.Digest H.SHA3_512 -> ByteString
convert = BA.convert
