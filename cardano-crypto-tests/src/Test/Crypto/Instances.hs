{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Test.Crypto.Instances
( withMLSBFromPSB
) where

import Data.Maybe (mapMaybe)
import GHC.Exts (fromListN, toList, fromList)
import Data.Proxy (Proxy (Proxy))
import GHC.TypeLits (KnownNat, natVal)
import Test.QuickCheck (Arbitrary (..))
-- import qualified Data.ByteString as BS
import qualified Test.QuickCheck.Gen as Gen
import qualified Cardano.Crypto.Libsodium as NaCl
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbFromByteStringCheck,
  psbToByteString,
  )
import Test.Crypto.RunIO (RunIO (..))
import Control.Monad.IO.Class (MonadIO (..))
import Control.Exception (bracket)

-- We cannot allow this instance, because it doesn't guarantee timely
-- forgetting of the MLocked memory.
-- Instead, use 'arbitrary' to generate a suitably sized PinnedSizedBytes
-- value, and then mlsbFromPSB or withMLSBFromPSB to convert it to an
-- MLockedSizedBytes value.
--
-- instance KnownNat n => Arbitrary (NaCl.MLockedSizedBytes n) where
--     arbitrary = unsafePerformIO . NaCl.mlsbFromByteString . BS.pack <$> vectorOf size arbitrary
--       where
--         size :: Int
--         size = fromInteger (natVal (Proxy :: Proxy n))

mlsbFromPSB :: KnownNat n => PinnedSizedBytes n -> IO (NaCl.MLockedSizedBytes n)
mlsbFromPSB = NaCl.mlsbFromByteString . psbToByteString

withMLSBFromPSB :: (KnownNat n, MonadIO m, RunIO m) => PinnedSizedBytes n -> (NaCl.MLockedSizedBytes n -> m a) -> m a
withMLSBFromPSB psb action = liftIO $ do
  bracket
    (mlsbFromPSB psb)
    NaCl.mlsbFinalize
    (io . action)

instance KnownNat n => Arbitrary (PinnedSizedBytes n) where
    arbitrary = do
      let size :: Int = fromIntegral . natVal $ Proxy @n
      Gen.suchThatMap (fromListN size <$> Gen.vectorOf size arbitrary)
                      psbFromByteStringCheck
    shrink psb = case toList . psbToByteString $ psb of
      bytes -> mapMaybe (psbFromByteStringCheck . fromList) . shrink $ bytes
