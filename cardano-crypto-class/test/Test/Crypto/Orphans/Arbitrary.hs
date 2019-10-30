{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TypeFamilies         #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
module Test.Crypto.Orphans.Arbitrary
  (
  )
where

import Cardano.Binary (ToCBOR (..))
import Cardano.Crypto.DSIGN (DSIGNAlgorithm (..))
import Cardano.Crypto.Hash (Hash, HashAlgorithm (..), hash)
import Cardano.Crypto.VRF (VRFAlgorithm (..))
import Data.Word (Word64)
import Test.Crypto.Util (Seed (..), withSeed)
import Test.QuickCheck (Arbitrary (..), Gen, arbitraryBoundedIntegral)

instance Arbitrary Seed where
  arbitrary =
    (\w1 w2 w3 w4 w5 -> Seed (w1, w2, w3, w4, w5)) <$>
      gen <*>
      gen <*>
      gen <*>
      gen <*>
      gen
    where
      gen :: Gen Word64
      gen = arbitraryBoundedIntegral
  shrink = const []

instance DSIGNAlgorithm v => Arbitrary (SignKeyDSIGN v) where
  arbitrary = do
    seed <- arbitrary
    return $ withSeed seed genKeyDSIGN
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
    seed <- arbitrary
    return $ withSeed seed $ signDSIGN () a sk
  shrink = const []

instance VRFAlgorithm v => Arbitrary (SignKeyVRF v) where
  arbitrary = do
    seed <- arbitrary
    return $ withSeed seed genKeyVRF
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
    return $ withSeed seed $ fmap snd $ evalVRF () a sk
  shrink = const []
