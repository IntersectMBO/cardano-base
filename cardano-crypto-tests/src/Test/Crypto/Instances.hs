{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.Instances () where

import qualified Cardano.Crypto.Libsodium as NaCl
import Cardano.Crypto.PinnedSizedBytes
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (..))
import GHC.TypeLits (KnownNat, natVal)
import Test.QuickCheck (Arbitrary (..), vectorOf)

instance KnownNat n => Arbitrary (NaCl.MLockedSizedBytes n) where
  arbitrary = NaCl.mlsbFromByteString . BS.pack <$> vectorOf size arbitrary
    where
      size :: Int
      size = fromInteger (natVal (Proxy :: Proxy n))

instance KnownNat n => Arbitrary (PinnedSizedBytes n) where
  arbitrary = psbFromBytes <$> vectorOf size arbitrary
    where
      size :: Int
      size = fromInteger (natVal (Proxy :: Proxy n))
