{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Test.Crypto.Instances
( withMLSBFromPSB
, withMLockedSeedFromPSB
) where

import Data.Maybe (mapMaybe)
import GHC.Exts (fromListN, toList, fromList)
import Data.Proxy (Proxy (Proxy))
import GHC.TypeLits (KnownNat, natVal)
import Test.QuickCheck (Arbitrary (..))
import qualified Test.QuickCheck.Gen as Gen
import Cardano.Crypto.MonadMLock
import Cardano.Crypto.MLockedSeed
import Control.Monad.Class.MonadThrow
import Control.Monad.Class.MonadST

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

mlsbFromPSB :: (MonadMLock m, MonadST m, KnownNat n) => PinnedSizedBytes n -> m (MLockedSizedBytes m n)
mlsbFromPSB = mlsbFromByteString . psbToByteString

withMLSBFromPSB :: (MonadMLock m, MonadST m, MonadThrow m, KnownNat n) => PinnedSizedBytes n -> (MLockedSizedBytes m n -> m a) -> m a
withMLSBFromPSB psb =
  bracket
    (mlsbFromPSB psb)
    mlsbFinalize

mlockedSeedFromPSB :: (MonadMLock m, MonadST m, KnownNat n) => PinnedSizedBytes n -> m (MLockedSeed m n)
mlockedSeedFromPSB = fmap MLockedSeed . mlsbFromPSB

withMLockedSeedFromPSB :: (MonadMLock m, MonadST m, MonadThrow m, KnownNat n) => PinnedSizedBytes n -> (MLockedSeed m n -> m a) -> m a
withMLockedSeedFromPSB psb =
  bracket
    (mlockedSeedFromPSB psb)
    mlockedSeedFinalize

instance KnownNat n => Arbitrary (PinnedSizedBytes n) where
    arbitrary = do
      let size :: Int = fromIntegral . natVal $ Proxy @n
      Gen.suchThatMap (fromListN size <$> Gen.vectorOf size arbitrary)
                      psbFromByteStringCheck
    shrink psb = case toList . psbToByteString $ psb of
      bytes -> mapMaybe (psbFromByteStringCheck . fromList) . shrink $ bytes
