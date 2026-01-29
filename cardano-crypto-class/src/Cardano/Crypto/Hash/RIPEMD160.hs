{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the RIPEMD-160 hashing algorithm.
module Cardano.Crypto.Hash.RIPEMD160 (
  RIPEMD160,
)
where

import Cardano.Crypto.Hash.Class
import qualified Data.ByteArray as BA
import qualified "crypton" Crypto.Hash as H

data RIPEMD160

instance HashAlgorithm RIPEMD160 where
  type HashSize RIPEMD160 = 20
  hashAlgorithmName _ = "RIPEMD160"
  digest _ = convert . H.hash

convert :: H.Digest H.RIPEMD160 -> ByteString
convert = BA.convert
