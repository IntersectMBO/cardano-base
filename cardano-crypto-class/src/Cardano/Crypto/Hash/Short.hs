{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of short hashing algorithm, suitable for testing as
-- it's not very collision-resistant.
module Cardano.Crypto.Hash.Short
  ( ShortHash
  )
where

import Cardano.Crypto.Hash.Class
import qualified "cryptonite" Crypto.Hash as H
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B

data ShortHash

instance HashAlgorithm ShortHash where
  type SizeHash ShortHash = 8
  hashAlgorithmName _ = "md5_short"
  digest p =
    B.take (fromIntegral (sizeHash p)) .
      BA.convert .
      H.hash @ByteString @H.MD5 -- Internally, treat it like MD5.
