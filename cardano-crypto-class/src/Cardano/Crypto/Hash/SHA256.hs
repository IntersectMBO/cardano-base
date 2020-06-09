{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the SHA256 hashing algorithm.
module Cardano.Crypto.Hash.SHA256
  ( SHA256
  )
where

import Cardano.Crypto.Hash.Class
import qualified "cryptonite" Crypto.Hash as H
import qualified Data.ByteArray as BA

data SHA256

instance HashAlgorithm SHA256 where
  type SizeHash SHA256 = 32
  hashAlgorithmName _ = "sha256"
  digest _ = convert . H.hash

convert :: H.Digest H.SHA256 -> ByteString
convert = BA.convert
