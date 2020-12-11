{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
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

import Control.DeepSeq (NFData)
import Data.ByteArray as BA (ByteArrayAccess, convert)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks, InspectHeap(..))

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Crypto.Error (CryptoFailable (..))
import Crypto.PubKey.Ed25519 as Ed25519

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (SignableRepresentation(..))


data Ed25519DSIGN

instance DSIGNAlgorithm Ed25519DSIGN where
    type SeedSizeDSIGN Ed25519DSIGN = 32
    -- | Ed25519 key size is 32 octets
    -- (per <https://tools.ietf.org/html/rfc8032#section-5.1.6>)
    type SizeVerKeyDSIGN  Ed25519DSIGN = 32
    type SizeSignKeyDSIGN Ed25519DSIGN = 32
    -- | Ed25519 signature size is 64 octets
    type SizeSigDSIGN     Ed25519DSIGN = 64

    --
    -- Key and signature types
    --

    newtype VerKeyDSIGN Ed25519DSIGN = VerKeyEd25519DSIGN PublicKey
        deriving (Show, Eq, Generic, ByteArrayAccess)
        deriving newtype NFData
        deriving NoThunks via InspectHeap PublicKey

    newtype SignKeyDSIGN Ed25519DSIGN = SignKeyEd25519DSIGN SecretKey
        deriving (Show, Eq, Generic, ByteArrayAccess)
        deriving newtype NFData
        deriving NoThunks via InspectHeap SecretKey

    newtype SigDSIGN Ed25519DSIGN = SigEd25519DSIGN Signature
        deriving (Show, Eq, Generic, ByteArrayAccess)
        deriving NoThunks via InspectHeap Signature
        deriving newtype NFData

    --
    -- Metadata and basic key operations
    --

    algorithmNameDSIGN _ = "ed25519"

    deriveVerKeyDSIGN (SignKeyEd25519DSIGN sk) = VerKeyEd25519DSIGN $ toPublic sk


    --
    -- Core algorithm operations
    --

    type Signable Ed25519DSIGN = SignableRepresentation

    signDSIGN () a (SignKeyEd25519DSIGN sk) =
        let vk = toPublic sk
            bs = getSignableRepresentation a
         in SigEd25519DSIGN $ sign sk vk bs

    verifyDSIGN () (VerKeyEd25519DSIGN vk) a (SigEd25519DSIGN sig) =
        if verify vk (getSignableRepresentation a) sig
          then Right ()
          else Left "Verification failed"

    --
    -- Key generation
    --

    genKeyDSIGN seed =
        let sk = runMonadRandomWithSeed seed Ed25519.generateSecretKey
         in SignKeyEd25519DSIGN sk

    --
    -- raw serialise/deserialise
    --

    rawSerialiseVerKeyDSIGN   = BA.convert
    rawSerialiseSignKeyDSIGN  = BA.convert
    rawSerialiseSigDSIGN      = BA.convert

    rawDeserialiseVerKeyDSIGN  = fmap VerKeyEd25519DSIGN
                               . cryptoFailableToMaybe . Ed25519.publicKey
    rawDeserialiseSignKeyDSIGN = fmap SignKeyEd25519DSIGN
                               . cryptoFailableToMaybe . Ed25519.secretKey
    rawDeserialiseSigDSIGN     = fmap SigEd25519DSIGN
                               . cryptoFailableToMaybe . Ed25519.signature


instance ToCBOR (VerKeyDSIGN Ed25519DSIGN) where
  toCBOR = encodeVerKeyDSIGN
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN Ed25519DSIGN) where
  fromCBOR = decodeVerKeyDSIGN

instance ToCBOR (SignKeyDSIGN Ed25519DSIGN) where
  toCBOR = encodeSignKeyDSIGN
  encodedSizeExpr _ = encodedSignKeyDESIGNSizeExpr

instance FromCBOR (SignKeyDSIGN Ed25519DSIGN) where
  fromCBOR = decodeSignKeyDSIGN

instance ToCBOR (SigDSIGN Ed25519DSIGN) where
  toCBOR = encodeSigDSIGN
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN Ed25519DSIGN) where
  fromCBOR = decodeSigDSIGN


cryptoFailableToMaybe :: CryptoFailable a -> Maybe a
cryptoFailableToMaybe (CryptoPassed a) = Just a
cryptoFailableToMaybe (CryptoFailed _) = Nothing
