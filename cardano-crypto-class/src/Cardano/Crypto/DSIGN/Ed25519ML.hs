{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}

-- | Ed25519 digital signatures.
module Cardano.Crypto.DSIGN.Ed25519ML
  ( Ed25519DSIGNM
  , SigDSIGNM (..)
  , SignKeyDSIGNM (..)
  , VerKeyDSIGNM (..)
  )
where

import Control.DeepSeq (NFData)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)
import GHC.IO.Exception (ioException)
import Control.Monad (unless)
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.Ptr (castPtr, nullPtr)
import qualified Data.ByteString as BS
-- import qualified Data.ByteString.Unsafe as BS

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Foreign
import Cardano.Crypto.PinnedSizedBytes
import Cardano.Crypto.Libsodium.C
-- import Cardano.Crypto.Libsodium.Memory.Internal
import Cardano.Crypto.Libsodium (MLockedSizedBytes)
-- import Cardano.Crypto.Libsodium.MLockedBytes
import Cardano.Crypto.MonadSodium (MonadSodium (..))

import Cardano.Crypto.DSIGNM.Class
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (SignableRepresentation(..))


data Ed25519DSIGNM

instance NoThunks (VerKeyDSIGNM Ed25519DSIGNM)
instance NoThunks (SignKeyDSIGNM Ed25519DSIGNM)
instance NoThunks (SigDSIGNM Ed25519DSIGNM)

-- | Convert C-style return code / errno error reporting into Haskell
-- exceptions.
--
-- Runs an IO action (which should be some FFI call into C) that returns a
-- result code; if the result code returned is nonzero, fetch the errno, and
-- throw a suitable IO exception.
cOrError :: String -> String -> IO Int -> IO ()
cOrError contextDesc cFunName action = do
  res <- action
  unless (res == 0) $ do
      errno <- getErrno
      ioException $ errnoToIOError (contextDesc ++ ": " ++ cFunName) errno Nothing Nothing

instance DSIGNMAlgorithm Ed25519DSIGNM where
    type SeedSizeDSIGNM Ed25519DSIGNM = CRYPTO_SIGN_ED25519_SEEDBYTES
    -- | Ed25519 key size is 32 octets
    -- (per <https://tools.ietf.org/html/rfc8032#section-5.1.6>)
    type SizeVerKeyDSIGNM  Ed25519DSIGNM = CRYPTO_SIGN_ED25519_PUBLICKEYBYTES
    -- | Ed25519 secret key size is 32 octets; however, libsodium packs both
    -- the secret key and the public key into a 64-octet compound and exposes
    -- that as the secret key; the actual 32-octet secret key is called
    -- \"seed\" in libsodium. For backwards compatibility reasons and
    -- efficiency, we use the 64-octet compounds internally (this is what
    -- libsodium expects), but we only serialize the 32-octet secret key part
    -- (the libsodium \"seed\").
    type SizeSignKeyDSIGNM Ed25519DSIGNM = CRYPTO_SIGN_ED25519_SEEDBYTES
    -- | Ed25519 signature size is 64 octets
    type SizeSigDSIGNM     Ed25519DSIGNM = CRYPTO_SIGN_ED25519_BYTES

    --
    -- Key and signature types
    --

    newtype VerKeyDSIGNM Ed25519DSIGNM = VerKeyEd25519DSIGNM (PinnedSizedBytes (SizeVerKeyDSIGNM Ed25519DSIGNM))
        deriving (Show, Eq, Generic)
        deriving newtype NFData

    -- Note that the size of the internal key data structure is the SECRET KEY
    -- bytes as per libsodium, while the declared key size (for serialization)
    -- is libsodium's SEED bytes. We expand 32-octet keys to 64-octet ones
    -- during deserialization, and we delete the 32 octets that contain the
    -- public key from the secret key before serializing.
    newtype SignKeyDSIGNM Ed25519DSIGNM = SignKeyEd25519DSIGNM (MLockedSizedBytes CRYPTO_SIGN_ED25519_SECRETKEYBYTES)
        deriving (Show, Eq, Generic)
        deriving newtype NFData

    newtype SigDSIGNM Ed25519DSIGNM = SigEd25519DSIGNM (PinnedSizedBytes (SizeSigDSIGNM Ed25519DSIGNM))
        deriving (Show, Eq, Generic)
        deriving newtype NFData

    --
    -- Metadata and basic key operations
    --

    algorithmNameDSIGNM _ = "ed25519-ml"

    deriveVerKeyDSIGNM (SignKeyEd25519DSIGNM sk) =
      VerKeyEd25519DSIGNM <$> do
        mlsbUseAsSizedPtr sk $ \skPtr ->
          allocaSized $ \seedPtr ->
          psbCreateSized $ \pkPtr -> do
              cOrError "deriveVerKeyDSIGNM @Ed25519DSIGNM" "c_crypto_sign_ed25519_sk_to_seed"
                $ c_crypto_sign_ed25519_sk_to_seed seedPtr skPtr
              cOrError "deriveVerKeyDSIGNM @Ed25519DSIGNM" "c_crypto_sign_ed25519_seed_keypair"
                $ c_crypto_sign_ed25519_seed_keypair pkPtr skPtr seedPtr


    --
    -- Core algorithm operations
    --

    type Signable Ed25519DSIGNM = SignableRepresentation

    signDSIGNM () a (SignKeyEd25519DSIGNM sk) =
      let bs = getSignableRepresentation a
      in SigEd25519DSIGNM <$> do
          BS.useAsCStringLen bs $ \(ptr, len) -> 
            mlsbUseAsSizedPtr sk $ \skPtr ->
            allocaSized $ \pkPtr -> do
                cOrError "signDSIGNM @Ed25519DSIGNM" "c_crypto_sign_ed25519_sk_to_pk"
                  $ c_crypto_sign_ed25519_sk_to_pk pkPtr skPtr
                psbCreateSized $ \sigPtr -> do
                  cOrError "signDSIGNM @Ed25519DSIGNM" "c_crypto_sign_ed25519_detached"
                    $ c_crypto_sign_ed25519_detached sigPtr nullPtr (castPtr ptr) (fromIntegral len) skPtr

    verifyDSIGNM () (VerKeyEd25519DSIGNM vk) a (SigEd25519DSIGNM sig) =
        let bs = getSignableRepresentation a
        in unsafeDupablePerformIO $
          BS.useAsCStringLen bs $ \(ptr, len) ->
          psbUseAsSizedPtr vk $ \vkPtr ->
          psbUseAsSizedPtr sig $ \sigPtr -> do
              res <- c_crypto_sign_ed25519_verify_detached sigPtr (castPtr ptr) (fromIntegral len) vkPtr
              if res == 0
              then return (Right ())
              else do
                  -- errno <- getErrno
                  return (Left  "Verification failed")

    --
    -- Key generation
    --

    genKeyDSIGNM seed = SignKeyEd25519DSIGNM <$> do
          sk <- mlsbNew
          mlsbUseAsSizedPtr sk $ \skPtr ->
            BS.useAsCStringLen (getSeedBytes $ seed) $ \(seedPtr, _) ->
            allocaSized $ \pkPtr -> do
                cOrError "genKeyDSIGNM @Ed25519DSIGNM" "c_crypto_sign_ed25519_seed_keypair"
                  $ c_crypto_sign_ed25519_seed_keypair pkPtr skPtr (SizedPtr . castPtr $ seedPtr)
          return sk

    --
    -- raw serialise/deserialise
    --

    rawSerialiseVerKeyDSIGNM   (VerKeyEd25519DSIGNM vk) = psbToByteString vk
    rawSerialiseSigDSIGNM      (SigEd25519DSIGNM sig) = psbToByteString sig

    rawDeserialiseVerKeyDSIGNM  = fmap VerKeyEd25519DSIGNM . psbFromByteStringCheck
    rawDeserialiseSigDSIGNM     = fmap SigEd25519DSIGNM . psbFromByteStringCheck


instance ToCBOR (VerKeyDSIGNM Ed25519DSIGNM) where
  toCBOR = encodeVerKeyDSIGNM
  encodedSizeExpr _ = encodedVerKeyDSIGNMSizeExpr

instance FromCBOR (VerKeyDSIGNM Ed25519DSIGNM) where
  fromCBOR = decodeVerKeyDSIGNM

-- instance ToCBOR (SignKeyDSIGNM Ed25519DSIGNM) where
--   toCBOR = encodeSignKeyDSIGNM
--   encodedSizeExpr _ = encodedSignKeyDESIGNSizeExpr
-- 
-- instance FromCBOR (SignKeyDSIGNM Ed25519DSIGNM) where
--   fromCBOR = decodeSignKeyDSIGNM

instance ToCBOR (SigDSIGNM Ed25519DSIGNM) where
  toCBOR = encodeSigDSIGNM
  encodedSizeExpr _ = encodedSigDSIGNMSizeExpr

instance FromCBOR (SigDSIGNM Ed25519DSIGNM) where
  fromCBOR = decodeSigDSIGNM
