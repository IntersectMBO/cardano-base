{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Implementation of short hashing algorithm, suitable for testing as
-- it's not very collision-resistant.
module Cardano.Crypto.Hash.Short
  ( ShortHash
  , MD5Prefix
  )
where

import Cardano.Crypto.Hash.Class
import qualified "cryptonite" Crypto.Hash as H
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B

import GHC.TypeLits (Nat, KnownNat, CmpNat, natVal)
import Data.Proxy (Proxy (..))

type ShortHash = MD5Prefix 8

data MD5Prefix (n :: Nat)

instance (KnownNat n, CmpNat n 33 ~ 'LT) => HashAlgorithm (MD5Prefix n) where
  hashAlgorithmName p = "md5_prefix_" <> show (sizeHash p)
  sizeHash _ = fromIntegral $ natVal (Proxy :: Proxy n)
  digest p =
    B.take (fromIntegral (sizeHash p)) .
      BA.convert .
      H.hash @ByteString @H.MD5 -- Internally, treat it like MD5.
