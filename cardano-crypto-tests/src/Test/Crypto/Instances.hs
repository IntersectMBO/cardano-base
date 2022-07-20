{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Test.Crypto.Instances () where

import Data.Maybe (mapMaybe)
import GHC.Exts (fromListN, toList, fromList)
import Data.Proxy (Proxy (Proxy))
import GHC.TypeLits (KnownNat, natVal)
import Test.QuickCheck (Arbitrary (arbitrary, shrink))
import qualified Data.ByteString as BS
import qualified Test.QuickCheck.Gen as Gen
import qualified Cardano.Crypto.Libsodium as NaCl
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbFromByteStringCheck,
  psbToByteString,
  )

instance KnownNat n => Arbitrary (NaCl.MLockedSizedBytes n) where
    arbitrary = NaCl.mlsbFromByteString . BS.pack <$> Gen.vectorOf size arbitrary
      where
        size :: Int
        size = fromInteger (natVal (Proxy :: Proxy n))

instance KnownNat n => Arbitrary (PinnedSizedBytes n) where
    arbitrary = do
      let size :: Int = fromIntegral . natVal $ Proxy @n
      Gen.suchThatMap (fromListN size <$> Gen.vectorOf size arbitrary) 
                      psbFromByteStringCheck
    shrink psb = case toList . psbToByteString $ psb of 
      bytes -> mapMaybe (psbFromByteStringCheck . fromList) . shrink $ bytes
