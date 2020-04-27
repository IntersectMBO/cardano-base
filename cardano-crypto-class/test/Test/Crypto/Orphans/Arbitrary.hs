{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE ScopedTypeVariables  #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
module Test.Crypto.Orphans.Arbitrary
  ( arbitrarySeedOfSize
  )
where

import Cardano.Binary (ToCBOR (..))
import Cardano.Crypto.DSIGN (DSIGNAlgorithm (..))
import Cardano.Crypto.Hash (Hash, HashAlgorithm (..), hash)
import Cardano.Crypto.VRF (VRFAlgorithm (..))
import Cardano.Crypto.Seed
import Data.ByteString as BS (pack)
import Data.Proxy (Proxy (..))
import Numeric.Natural (Natural)
import Data.Word (Word64)
import Test.Crypto.Util (TestSeed (..), withTestSeed)
import Test.QuickCheck (Arbitrary (..), Gen, arbitraryBoundedIntegral, vector)

instance Arbitrary TestSeed where
  arbitrary =
    (\w1 w2 w3 w4 w5 -> TestSeed (w1, w2, w3, w4, w5)) <$>
      gen <*>
      gen <*>
      gen <*>
      gen <*>
      gen
    where
      gen :: Gen Word64
      gen = arbitraryBoundedIntegral
  shrink = const []

arbitrarySeedOfSize :: Natural -> Gen Seed
arbitrarySeedOfSize sz =
  (mkSeedFromBytes . BS.pack) <$> vector (fromIntegral sz)

instance DSIGNAlgorithm v => Arbitrary (SignKeyDSIGN v) where
  arbitrary = genKeyDSIGN <$> arbitrarySeedOfSize seedSize
    where
      seedSize = seedSizeDSIGN (Proxy :: Proxy v)
  shrink = const []

instance (ToCBOR a, Arbitrary a, HashAlgorithm h) => Arbitrary (Hash h a) where
  arbitrary = hash <$> arbitrary
  shrink = const []

instance DSIGNAlgorithm v => Arbitrary (VerKeyDSIGN v) where
  arbitrary = deriveVerKeyDSIGN <$> arbitrary
  shrink = const []

instance (Cardano.Crypto.DSIGN.Signable v Int, DSIGNAlgorithm v, ContextDSIGN v ~ ())
  => Arbitrary (SigDSIGN v) where
  arbitrary = do
    a <- arbitrary :: Gen Int
    sk <- arbitrary
    return $ signDSIGN () a sk
  shrink = const []

instance VRFAlgorithm v => Arbitrary (SignKeyVRF v) where
  arbitrary = do
    seed <- arbitrary
    return $ withTestSeed seed genKeyVRF
  shrink = const []

instance VRFAlgorithm v => Arbitrary (VerKeyVRF v) where
  arbitrary = deriveVerKeyVRF <$> arbitrary
  shrink = const []

instance (Cardano.Crypto.VRF.Signable v Int, VRFAlgorithm v, ContextVRF v ~ ())
  => Arbitrary (CertVRF v) where
  arbitrary = do
    a <- arbitrary :: Gen Int
    sk <- arbitrary
    seed <- arbitrary
    return $ withTestSeed seed $ fmap snd $ evalVRF () a sk
  shrink = const []
