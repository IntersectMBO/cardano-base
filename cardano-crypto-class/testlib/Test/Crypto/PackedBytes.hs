{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Test.Crypto.PackedBytes where

import Cardano.Crypto.PackedBytes
import Control.Monad.Trans.Fail.String (errorFail)
import Data.Proxy
import GHC.TypeLits
import Test.Cardano.Base.Bytes (genShortByteString)
import Test.QuickCheck

instance KnownNat n => Arbitrary (PackedBytes n) where
  arbitrary =
    errorFail . packShortByteString <$> genShortByteString (fromInteger (natVal (Proxy @n)))
