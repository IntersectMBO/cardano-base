{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE StandaloneDeriving #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Cardano.Crypto.Orphans () where

import qualified Data.ByteString as BS

import Cardano.Prelude (CanonicalExamples (..), Generic)
import Cardano.Prelude.CanonicalExamples.Orphans ()

import Crypto.Error (CryptoFailable(..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448

deriving instance Generic RSA.PublicKey
instance CanonicalExamples RSA.PublicKey

deriving instance Generic RSA.PrivateKey
instance CanonicalExamples RSA.PrivateKey

instance CanonicalExamples Ed448.SecretKey where
  canonicalExamples = case Ed448.secretKey bs of
      CryptoFailed err -> error (show err)
      CryptoPassed a   -> return [a]
    where
      bs = BS.pack $ replicate Ed448.secretKeySize 0

instance CanonicalExamples Ed448.PublicKey where
  canonicalExamples = fmap Ed448.toPublic <$> canonicalExamples

instance CanonicalExamples Ed448.Signature where
  canonicalExamples = do
    secret <- canonicalExamples
    public <- canonicalExamples
    bs <- canonicalExamples
    return $ Ed448.sign <$> secret <*> public <*> (bs :: [BS.ByteString])

instance CanonicalExamples Ed25519.SecretKey where
  canonicalExamples = case Ed25519.secretKey bs of
      CryptoFailed err -> error (show err)
      CryptoPassed a   -> return [a]
    where
      bs = BS.pack $ replicate Ed25519.secretKeySize 0

instance CanonicalExamples Ed25519.PublicKey where
  canonicalExamples = fmap Ed25519.toPublic <$> canonicalExamples

instance CanonicalExamples Ed25519.Signature where
  canonicalExamples = do
    secret <- canonicalExamples
    public <- canonicalExamples
    bs <- canonicalExamples
    return $ Ed25519.sign <$> secret <*> public <*> (bs :: [BS.ByteString])

