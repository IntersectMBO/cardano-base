{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

-- | Ed25519 digital signatures.
module Cardano.Crypto.DSIGN.Ed25519
  ( Ed25519DSIGN
  , SigDSIGN (..)
  , SignKeyDSIGN (..)
  , VerKeyDSIGN (..)
  )
where

import Cardano.Binary
  ( Decoder
  , Encoding
  , FromCBOR (..)
  , ToCBOR (..)
  , serialize
  )
import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Seed
import Cardano.Prelude (NFData, NoUnexpectedThunks, UseIsNormalForm(..))
import Crypto.Error (CryptoFailable (..))
import Crypto.PubKey.Ed25519 as Ed25519
import Data.ByteArray (ByteArrayAccess, convert)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (toStrict)
import GHC.Generics (Generic)

data Ed25519DSIGN

instance DSIGNAlgorithm Ed25519DSIGN where

    --
    -- Key and signature types
    --

    newtype VerKeyDSIGN Ed25519DSIGN = VerKeyEd25519DSIGN PublicKey
        deriving (Show, Eq, Generic, ByteArrayAccess)
        deriving newtype NFData
        deriving NoUnexpectedThunks via UseIsNormalForm PublicKey

    newtype SignKeyDSIGN Ed25519DSIGN = SignKeyEd25519DSIGN SecretKey
        deriving (Show, Eq, Generic, ByteArrayAccess)
        deriving newtype NFData
        deriving NoUnexpectedThunks via UseIsNormalForm SecretKey

    newtype SigDSIGN Ed25519DSIGN = SigEd25519DSIGN Signature
        deriving (Show, Eq, Generic, ByteArrayAccess)
        deriving NoUnexpectedThunks via UseIsNormalForm Signature

    --
    -- Metadata and basic key operations
    --

    deriveVerKeyDSIGN (SignKeyEd25519DSIGN sk) = VerKeyEd25519DSIGN $ toPublic sk

    -- | Ed25519 key size is 32 octets
    -- (per <https://tools.ietf.org/html/rfc8032#section-5.1.6>)
    abstractSizeVKey _ = 32

    -- | Ed25519 signature size is 64 octets
    abstractSizeSig  _ = 64

    --
    -- Core algorithm operations
    --

    type Signable Ed25519DSIGN = ToCBOR

    signDSIGN () a (SignKeyEd25519DSIGN sk) =
        let vk = toPublic sk
            bs = toStrict $ serialize a
         in SigEd25519DSIGN $ sign sk vk bs

    verifyDSIGN () (VerKeyEd25519DSIGN vk) a (SigEd25519DSIGN sig) =
        if verify vk (toStrict $ serialize a) sig
          then Right ()
          else Left "Verification failed"

    --
    -- Key generation
    --

    seedSizeDSIGN _  = 32
    genKeyDSIGN seed =
        let sk = runMonadRandomWithSeed seed Ed25519.generateSecretKey
         in SignKeyEd25519DSIGN sk

    --
    -- raw serialise/deserialise
    --

    rawSerialiseVerKeyDSIGN   = convert
    rawSerialiseSignKeyDSIGN  = convert
    rawSerialiseSigDSIGN      = convert

    rawDeserialiseVerKeyDSIGN  = fmap VerKeyEd25519DSIGN
                               . cryptoFailableToMaybe . Ed25519.publicKey
    rawDeserialiseSignKeyDSIGN = fmap SignKeyEd25519DSIGN
                               . cryptoFailableToMaybe . Ed25519.secretKey
    rawDeserialiseSigDSIGN     = fmap SigEd25519DSIGN
                               . cryptoFailableToMaybe . Ed25519.signature

    --
    -- CBOR encoding/decoding
    --

    encodeVerKeyDSIGN = toCBOR
    encodeSignKeyDSIGN = toCBOR
    encodeSigDSIGN = toCBOR

    decodeVerKeyDSIGN = fromCBOR
    decodeSignKeyDSIGN = fromCBOR
    decodeSigDSIGN = fromCBOR


instance ToCBOR (VerKeyDSIGN Ed25519DSIGN) where
  toCBOR = encodeBA

instance FromCBOR (VerKeyDSIGN Ed25519DSIGN) where
  fromCBOR = VerKeyEd25519DSIGN <$> decodeBA publicKey

instance ToCBOR (SignKeyDSIGN Ed25519DSIGN) where
  toCBOR = encodeBA

instance FromCBOR (SignKeyDSIGN Ed25519DSIGN) where
  fromCBOR = SignKeyEd25519DSIGN <$> decodeBA secretKey

instance ToCBOR (SigDSIGN Ed25519DSIGN) where
  toCBOR = encodeBA

instance FromCBOR (SigDSIGN Ed25519DSIGN) where
  fromCBOR = SigEd25519DSIGN <$> decodeBA signature

encodeBA :: ByteArrayAccess ba => ba -> Encoding
encodeBA ba = let bs = convert ba :: ByteString in toCBOR bs

decodeBA :: forall a s. (ByteString -> CryptoFailable a) -> Decoder s a
decodeBA f = do
  bs <- fromCBOR :: Decoder s ByteString
  case f bs of
    CryptoPassed a -> return a
    CryptoFailed e -> fail $ "decodeBA: " ++ show e

cryptoFailableToMaybe :: CryptoFailable a -> Maybe a
cryptoFailableToMaybe (CryptoPassed a) = Just a
cryptoFailableToMaybe (CryptoFailed _) = Nothing
