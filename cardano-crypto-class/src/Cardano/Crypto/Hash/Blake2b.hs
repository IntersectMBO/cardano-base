{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeApplications #-}

-- | Implementation of the Blake2b hashing algorithm, with various sizes.
module Cardano.Crypto.Hash.Blake2b
  ( Blake2b_224
  , Blake2b_256
  )
where

import Cardano.Crypto.Hash.Class
import qualified "cryptonite" Crypto.Hash as H
import qualified Data.ByteArray as BA

data Blake2b_224
data Blake2b_256

instance HashAlgorithm Blake2b_224 where
  byteCount _ = 28
  digest _ = BA.convert . H.hash @_ @H.Blake2b_224

instance HashAlgorithm Blake2b_256 where
  byteCount _ = 32
  digest _ = BA.convert . H.hash @_ @H.Blake2b_256
