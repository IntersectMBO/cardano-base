{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Ed448 digital signatures.
module Cardano.Crypto.DSIGN.Ed448 (
  Ed448DSIGN,
  SigDSIGN (..),
  SignKeyDSIGN (..),
  VerKeyDSIGN (..),
)
where

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
 )
import Control.DeepSeq (NFData)
import Data.ByteArray as BA (ByteArrayAccess, convert)
import GHC.Generics (Generic)
import NoThunks.Class (InspectHeap (..), NoThunks)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Crypto.Error (CryptoFailable (..))
import Crypto.PubKey.Ed448 as Ed448

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (SignableRepresentation (..))

data Ed448DSIGN

instance DSIGNAlgorithm Ed448DSIGN where
  type SeedSizeDSIGN Ed448DSIGN = 57

  --
  -- Key and signature types
  --

  newtype VerKeyDSIGN Ed448DSIGN = VerKeyEd448DSIGN PublicKey
    deriving (Show, Eq, Generic, ByteArrayAccess)
    deriving newtype (NFData)
    deriving (NoThunks) via InspectHeap PublicKey

  newtype SignKeyDSIGN Ed448DSIGN = SignKeyEd448DSIGN SecretKey
    deriving (Show, Eq, Generic, ByteArrayAccess)
    deriving newtype (NFData)
    deriving (NoThunks) via InspectHeap SecretKey

  newtype SigDSIGN Ed448DSIGN = SigEd448DSIGN Signature
    deriving (Show, Eq, Generic, ByteArrayAccess)
    deriving (NoThunks) via InspectHeap Signature

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGN _ = "ed448"

  deriveVerKeyDSIGN (SignKeyEd448DSIGN sk) = VerKeyEd448DSIGN $ toPublic sk

  --
  -- Core algorithm operations
  --

  type Signable Ed448DSIGN = SignableRepresentation

  signDSIGN () a (SignKeyEd448DSIGN sk) =
    let vk = toPublic sk
        bs = getSignableRepresentation a
     in SigEd448DSIGN $ sign sk vk bs

  verifyDSIGN () (VerKeyEd448DSIGN vk) a (SigEd448DSIGN sig) =
    if verify vk (getSignableRepresentation a) sig
      then Right ()
      else Left "Verification failed"

  --
  -- Key generation
  --

  genKeyDSIGN seed =
    let sk = runMonadRandomWithSeed seed Ed448.generateSecretKey
     in SignKeyEd448DSIGN sk

instance ToCBOR (VerKeyDSIGN Ed448DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN Ed448DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN Ed448DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN Ed448DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN Ed448DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN Ed448DSIGN) where
  fromCBOR = decodeFixedSized

instance FixedSizeCodec (VerKeyDSIGN Ed448DSIGN) where
  type FixedSize (VerKeyDSIGN Ed448DSIGN) = 57
  rawEncodeFixedSized (VerKeyEd448DSIGN vk) = BA.convert vk
  rawDecodeFixedSized bs = VerKeyEd448DSIGN <$> liftCryptoFailable (Ed448.publicKey bs)
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyDSIGN Ed448DSIGN) where
  type FixedSize (SignKeyDSIGN Ed448DSIGN) = 57
  rawEncodeFixedSized (SignKeyEd448DSIGN sk) = BA.convert sk
  rawDecodeFixedSized bs = SignKeyEd448DSIGN <$> liftCryptoFailable (Ed448.secretKey bs)
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SigDSIGN Ed448DSIGN) where
  type FixedSize (SigDSIGN Ed448DSIGN) = 114
  rawEncodeFixedSized (SigEd448DSIGN sig) = BA.convert sig
  rawDecodeFixedSized bs = SigEd448DSIGN <$> liftCryptoFailable (Ed448.signature bs)
  {-# INLINE rawDecodeFixedSized #-}

liftCryptoFailable :: MonadFail m => CryptoFailable a -> m a
liftCryptoFailable (CryptoPassed a) = pure a
liftCryptoFailable (CryptoFailed a) = fail $ show a
