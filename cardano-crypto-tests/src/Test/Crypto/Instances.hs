{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Test.Crypto.Instances
( withMLSBFromPSB
) where

import Data.Proxy (Proxy (..))
import GHC.TypeLits (KnownNat, natVal)
import Test.QuickCheck (Arbitrary (..), vectorOf)

import qualified Cardano.Crypto.Libsodium as NaCl
import Cardano.Crypto.PinnedSizedBytes
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

mlsbFromPSB :: (KnownNat n) => PinnedSizedBytes n -> IO (NaCl.MLockedSizedBytes n)
mlsbFromPSB = NaCl.mlsbFromByteString . psbToByteString

withMLSBFromPSB :: (KnownNat n, MonadIO m, RunIO m) => PinnedSizedBytes n -> (NaCl.MLockedSizedBytes n -> m a) -> m a
withMLSBFromPSB psb action = liftIO $ do
  bracket
    (mlsbFromPSB psb)
    NaCl.mlsbFinalize
    (io . action)

instance KnownNat n => Arbitrary (PinnedSizedBytes n) where
    arbitrary = psbFromBytes <$> vectorOf size arbitrary
      where
        size :: Int
        size = fromInteger (natVal (Proxy :: Proxy n))
