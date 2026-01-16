{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.Instances (
  withMLSBFromPSB,
  withMLockedSeedFromPSB,
) where

import Cardano.Crypto.Libsodium
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.PinnedSizedBytes
import Cardano.Crypto.Util
import Cardano.Crypto.VRF.Class
import Control.Monad.Class.MonadST
import Control.Monad.Class.MonadThrow
import Data.Maybe (mapMaybe)
import Data.Proxy (Proxy (Proxy))
import GHC.Exts (fromList, fromListN, toList)
import GHC.TypeLits (KnownNat, natVal)
import Test.Cardano.Base.Bytes (genByteArray)
import Test.Crypto.Util (Message, arbitrarySeedOfSize)
import Test.QuickCheck (Arbitrary (..), Gen)
import qualified Test.QuickCheck.Gen as Gen

-- We cannot allow this instance, because it doesn't guarantee timely
-- forgetting of the MLocked memory, and in a QuickCheck context, where
-- tens of thousands of these values may be generated, waiting for GC to clean
-- up after us could have us run over our mlock quota.
--
-- Instead, use 'arbitrary' to generate a suitably sized PinnedSizedBytes
-- value, and then mlsbFromPSB or withMLSBFromPSB to convert it to an
-- MLockedSizedBytes value.
--
-- instance KnownNat n => Arbitrary (MLockedSizedBytes n) where
--     arbitrary = unsafePerformIO . mlsbFromByteString . BS.pack <$> vectorOf size arbitrary
--       where
--         size :: Int
--         size = fromInteger (natVal (Proxy :: Proxy n))

mlsbFromPSB :: (MonadST m, KnownNat n) => PinnedSizedBytes n -> m (MLockedSizedBytes n)
mlsbFromPSB = mlsbFromByteString . psbToByteString

withMLSBFromPSB ::
  (MonadST m, MonadThrow m, KnownNat n) => PinnedSizedBytes n -> (MLockedSizedBytes n -> m a) -> m a
withMLSBFromPSB psb =
  bracket
    (mlsbFromPSB psb)
    mlsbFinalize

mlockedSeedFromPSB :: (MonadST m, KnownNat n) => PinnedSizedBytes n -> m (MLockedSeed n)
mlockedSeedFromPSB = fmap MLockedSeed . mlsbFromPSB

withMLockedSeedFromPSB ::
  (MonadST m, MonadThrow m, KnownNat n) => PinnedSizedBytes n -> (MLockedSeed n -> m a) -> m a
withMLockedSeedFromPSB psb =
  bracket
    (mlockedSeedFromPSB psb)
    mlockedSeedFinalize

instance KnownNat n => Arbitrary (PinnedSizedBytes n) where
  arbitrary = do
    let size = fromIntegral @Integer @Int . natVal $ Proxy @n
    Gen.suchThatMap
      (fromListN size <$> Gen.vectorOf size arbitrary)
      psbFromByteStringCheck
  shrink psb = case toList . psbToByteString $ psb of
    bytes -> mapMaybe (psbFromByteStringCheck . fromList) . shrink $ bytes

instance VRFAlgorithm v => Arbitrary (OutputVRF v) where
  arbitrary = do
    let n = fromIntegral @Word @Int (sizeOutputVRF (Proxy @v))
    OutputVRF <$> genByteArray n

instance VRFAlgorithm v => Arbitrary (VerKeyVRF v) where
  arbitrary = deriveVerKeyVRF <$> arbitrary

instance VRFAlgorithm v => Arbitrary (SignKeyVRF v) where
  arbitrary = genKeyVRF <$> arbitrarySeedOfSize seedSize
    where
      seedSize = seedSizeVRF (Proxy :: Proxy v)

instance
  ( VRFAlgorithm v
  , ContextVRF v ~ ()
  , Signable v ~ SignableRepresentation
  ) =>
  Arbitrary (CertVRF v)
  where
  arbitrary = do
    a <- arbitrary :: Gen Message
    sk <- arbitrary
    return $ snd $ evalVRF () a sk

instance
  (ContextVRF v ~ (), Signable v ~ SignableRepresentation, VRFAlgorithm v) =>
  Arbitrary (CertifiedVRF v a)
  where
  arbitrary = CertifiedVRF <$> arbitrary <*> genCertVRF
    where
      genCertVRF :: Gen (CertVRF v)
      genCertVRF = arbitrary
