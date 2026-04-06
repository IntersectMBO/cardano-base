{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.PackedBytes (
  AnyPackedBytes (..),
  genPackedBytes,
) where

import Cardano.Crypto.PackedBytes
import Control.Monad.Trans.Fail.String (errorFail)
import Data.Proxy
import Data.Reflection (reifyNat)
import GHC.TypeLits
import Test.Cardano.Base.Bytes (genShortByteString)
import Test.QuickCheck

instance KnownNat n => Arbitrary (PackedBytes n) where
  arbitrary = genPackedBytes (Proxy @n)

genPackedBytes :: KnownNat n => proxy n -> Gen (PackedBytes n)
genPackedBytes proxy =
  errorFail . packShortByteString <$> genShortByteString (fromInteger (natVal proxy))

data AnyPackedBytes where
  AnyPackedBytes :: KnownNat n => PackedBytes n -> AnyPackedBytes

instance Show AnyPackedBytes where
  show (AnyPackedBytes pb) = show pb

instance Arbitrary AnyPackedBytes where
  arbitrary = do
    NonNegative n <- arbitrary
    reifyNat n (fmap AnyPackedBytes . genPackedBytes)
