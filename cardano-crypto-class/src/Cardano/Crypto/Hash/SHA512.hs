{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the SHA512 hashing algorithm.
module Cardano.Crypto.Hash.SHA512 (
  SHA512,
)
where

import Cardano.Crypto.Hash.Class
import qualified Data.ByteArray as BA
import qualified "crypton" Crypto.Hash as H

data SHA512

instance HashAlgorithm SHA512 where
  type SizeHash SHA512 = 64
  hashAlgorithmName _ = "sha512"
  digest _ = convert . H.hash

convert :: H.Digest H.SHA512 -> ByteString
convert = BA.convert
