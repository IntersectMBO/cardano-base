{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the MD5 hashing algorithm.
module Cardano.Crypto.Hash.MD5
  ( MD5
  )
where

import Cardano.Crypto.Hash.Class
import qualified "cryptonite" Crypto.Hash as H
import qualified Data.ByteArray as BA

data MD5

instance HashAlgorithm MD5 where
  type SizeHash MD5 = 16
  hashAlgorithmName _ = "md5"
  digest _ = convert . H.hash

convert :: H.Digest H.MD5 -> ByteString
convert = BA.convert
