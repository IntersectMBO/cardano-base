{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- | Implementation of short hashing algorithm, suitable for testing.
module Cardano.Crypto.Hash.Short (
  ShortHash,
  Blake2bPrefix,
)
where

import Cardano.Crypto.Hash.Blake2b (blake2b_libsodium)
import Cardano.Crypto.Hash.Class

import Data.Proxy (Proxy (..))
import GHC.TypeLits (CmpNat, KnownNat, Nat, natVal)

type ShortHash = Blake2bPrefix 8

data Blake2bPrefix (n :: Nat)

instance (KnownNat n, CmpNat n 33 ~ 'LT) => HashAlgorithm (Blake2bPrefix n) where
  type HashSize (Blake2bPrefix n) = n
  hashAlgorithmName _ = "blake2b_prefix_" <> show (natVal (Proxy :: Proxy n))
  digest _ = blake2b_libsodium (fromIntegral @Integer @Int (natVal (Proxy :: Proxy n)))
