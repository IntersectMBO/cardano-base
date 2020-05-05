{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Abstract Verifiable Random Functions.
module Cardano.Crypto.VRF.Class
  ( VRFAlgorithm (..)
  , CertifiedVRF (..)
  , evalCertified
  , verifyCertified
  )
where

import Cardano.Binary
  ( Decoder
  , Encoding
  , FromCBOR (..)
  , ToCBOR (..)
  , encodeListLen
  , enforceSize
  , decodeBytes
  , encodeBytes
  , serializeEncoding'
  , decodeFullDecoder
  )
import Cardano.Crypto.Util (Empty)
import Cardano.Crypto.Seed (Seed)
import Cardano.Crypto.Hash.Class (HashAlgorithm, Hash, hashRaw)
import Cardano.Prelude (NoUnexpectedThunks)
import Crypto.Random (MonadRandom)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy as LBS (fromStrict)
import Data.Kind (Type)
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack
import Numeric.Natural


class ( Typeable v
      , Show (VerKeyVRF v)
      , Eq (VerKeyVRF v)
      , Show (SignKeyVRF v)
      , Show (CertVRF v)
      , Eq (CertVRF v)
      , NoUnexpectedThunks (CertVRF    v)
      , NoUnexpectedThunks (VerKeyVRF  v)
      , NoUnexpectedThunks (SignKeyVRF v)
      )
      => VRFAlgorithm v where


  --
  -- Key and signature types
  --

  data VerKeyVRF  v :: Type
  data SignKeyVRF v :: Type
  data CertVRF    v :: Type


  --
  -- Metadata and basic key operations
  --

  algorithmNameVRF :: proxy v -> String

  deriveVerKeyVRF :: SignKeyVRF v -> VerKeyVRF v

  hashVerKeyVRF :: HashAlgorithm h => VerKeyVRF v -> Hash h (VerKeyVRF v)
  hashVerKeyVRF = hashRaw rawSerialiseVerKeyVRF


  --
  -- Core algorithm operations
  --

  -- | Context required to run the VRF algorithm
  --
  -- Unit by default (no context required)
  type ContextVRF v :: Type
  type ContextVRF v = ()

  type Signable v :: Type -> Constraint
  type Signable c = Empty

  evalVRF
    :: (MonadRandom m, HasCallStack, Signable v a)
    => ContextVRF v
    -> a
    -> SignKeyVRF v
    -> m (Natural, CertVRF v)

  verifyVRF
    :: (HasCallStack, Signable v a)
    => ContextVRF v
    -> VerKeyVRF v
    -> a
    -> (Natural, CertVRF v)
    -> Bool

  maxVRF :: proxy v -> Natural


  --
  -- Key generation
  --

  genKeyVRF :: Seed -> SignKeyVRF v

  -- | The upper bound on the 'Seed' size needed by 'genKeyVRF'
  seedSizeVRF :: proxy v -> Word


  --
  -- Serialisation/(de)serialisation in raw format, no extra tags
  --
  -- default implementations in terms of the CBOR encode/decode
  --

  rawSerialiseVerKeyVRF :: VerKeyVRF v -> ByteString
  rawSerialiseVerKeyVRF = serializeEncoding' . encodeVerKeyVRF

  rawSerialiseSignKeyVRF :: SignKeyVRF v -> ByteString
  rawSerialiseSignKeyVRF = serializeEncoding' . encodeSignKeyVRF

  rawSerialiseCertVRF :: CertVRF v -> ByteString
  rawSerialiseCertVRF = serializeEncoding' . encodeCertVRF

  rawDeserialiseVerKeyVRF :: ByteString -> Maybe (VerKeyVRF v)
  rawDeserialiseVerKeyVRF =
      either (const Nothing) Just
    . decodeFullDecoder
        "rawDeserialiseVerKeyVRF"
        decodeVerKeyVRF
    . LBS.fromStrict

  rawDeserialiseSignKeyVRF :: ByteString -> Maybe (SignKeyVRF v)
  rawDeserialiseSignKeyVRF =
      either (const Nothing) Just
    . decodeFullDecoder
        "rawDeserialiseVerKeyVRF"
        decodeSignKeyVRF
    . LBS.fromStrict

  rawDeserialiseCertVRF :: ByteString -> Maybe (CertVRF v)
  rawDeserialiseCertVRF =
      either (const Nothing) Just
    . decodeFullDecoder
        "rawDeserialiseVerKeyVRF"
        decodeCertVRF
    . LBS.fromStrict


  --
  -- Convenient CBOR encoding/decoding
  --
  -- default implementations in terms of the raw (de)serialise
  --

  encodeVerKeyVRF :: VerKeyVRF v -> Encoding
  encodeVerKeyVRF = encodeBytes . rawSerialiseVerKeyVRF

  encodeSignKeyVRF :: SignKeyVRF v -> Encoding
  encodeSignKeyVRF = encodeBytes . rawSerialiseSignKeyVRF

  encodeCertVRF :: CertVRF v -> Encoding
  encodeCertVRF = encodeBytes . rawSerialiseCertVRF

  decodeVerKeyVRF :: Decoder s (VerKeyVRF v)
  decodeVerKeyVRF = do
    bs <- decodeBytes
    case rawDeserialiseVerKeyVRF bs of
      Nothing -> fail "decodeVerKeyVRF: cannot decode key"
      Just vk -> return vk

  decodeSignKeyVRF :: Decoder s (SignKeyVRF v)
  decodeSignKeyVRF = do
    bs <- decodeBytes
    case rawDeserialiseSignKeyVRF bs of
      Nothing -> fail "decodeSignKeyVRF: cannot decode key"
      Just vk -> return vk

  decodeCertVRF :: Decoder s (CertVRF v)
  decodeCertVRF = do
    bs <- decodeBytes
    case rawDeserialiseCertVRF bs of
      Nothing -> fail "decodeCertVRF: cannot decode key"
      Just vk -> return vk


  {-# MINIMAL
        algorithmNameVRF
      , deriveVerKeyVRF
      , evalVRF
      , verifyVRF
      , maxVRF
      , genKeyVRF
      , seedSizeVRF
      , (rawSerialiseVerKeyVRF    | encodeVerKeyVRF)
      , (rawSerialiseSignKeyVRF   | encodeSignKeyVRF)
      , (rawSerialiseCertVRF      | encodeCertVRF)
      , (rawDeserialiseVerKeyVRF  | decodeVerKeyVRF)
      , (rawDeserialiseSignKeyVRF | decodeSignKeyVRF)
      , (rawDeserialiseCertVRF    | decodeCertVRF)
    #-}


data CertifiedVRF v a
  = CertifiedVRF
      { certifiedNatural :: Natural
      , certifiedProof :: CertVRF v
      }
  deriving Generic

deriving instance VRFAlgorithm v => Show (CertifiedVRF v a)
deriving instance VRFAlgorithm v => Eq   (CertifiedVRF v a)

instance VRFAlgorithm v => NoUnexpectedThunks (CertifiedVRF v a)
  -- use generic instance

instance (VRFAlgorithm v, Typeable a) => ToCBOR (CertifiedVRF v a) where
  toCBOR cvrf =
    encodeListLen 2 <>
      toCBOR (certifiedNatural cvrf) <>
      encodeCertVRF (certifiedProof cvrf)

instance (VRFAlgorithm v, Typeable a) => FromCBOR (CertifiedVRF v a) where
  fromCBOR =
    CertifiedVRF <$
      enforceSize "CertifiedVRF" 2 <*>
      fromCBOR <*>
      decodeCertVRF

evalCertified
  :: (VRFAlgorithm v, MonadRandom m, Signable v a)
  => ContextVRF v
  -> a
  -> SignKeyVRF v
  -> m (CertifiedVRF v a)
evalCertified ctxt a key = uncurry CertifiedVRF <$> evalVRF ctxt a key

verifyCertified
  :: (VRFAlgorithm v, Signable v a)
  => ContextVRF v
  -> VerKeyVRF v
  -> a
  -> CertifiedVRF v a
  -> Bool
verifyCertified ctxt vk a CertifiedVRF {..} = verifyVRF ctxt vk a (certifiedNatural, certifiedProof)
