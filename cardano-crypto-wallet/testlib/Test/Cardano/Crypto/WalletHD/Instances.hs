{-# OPTIONS_GHC -Wno-orphans #-}

-- | QuickCheck 'Arbitrary' instances for wallet types.
--
-- 'Arbitrary' 'EncryptedKey' always produces v2 envelopes wrapped with the
-- empty passphrase so that tests can call passphrase-dependent operations
-- without tracking a per-key passphrase.
module Test.Cardano.Crypto.WalletHD.Instances () where

import Control.Monad (replicateM)
import qualified Data.ByteString as BS
import System.IO.Unsafe (unsafePerformIO)
import Test.QuickCheck

import Cardano.Crypto.WalletHD.Encrypted

instance Arbitrary DerivationScheme where
  arbitrary = elements [DerivationScheme1, DerivationScheme2]

-- | Generates a v2-wrapped 'EncryptedKey' from a random 32-byte seed and
-- chain code, always encrypted with the empty passphrase.
instance Arbitrary EncryptedKey where
  arbitrary = do
    seed <- BS.pack <$> replicateM 32 arbitrary
    cc <- BS.pack <$> replicateM 32 arbitrary
    case unsafePerformIO (encryptedCreate seed (BS.empty :: BS.ByteString) cc) of
      Right k -> pure k
      Left _ -> arbitrary
