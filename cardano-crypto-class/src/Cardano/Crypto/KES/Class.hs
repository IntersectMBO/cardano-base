{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Abstract key evolving signatures.
module Cardano.Crypto.KES.Class
  ( KESAlgorithm (..)
  , SignedKES (..)
  , Period
  , signedKES
  , verifySignedKES
  , encodeSignedKES
  , decodeSignedKES
  )
where

import Cardano.Binary (Decoder, decodeBytes, Encoding, encodeBytes,
                       serializeEncoding', decodeFullDecoder)
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (Empty)
import Cardano.Crypto.Hash.Class (HashAlgorithm, Hash, hashRaw)
import Cardano.Prelude (NoUnexpectedThunks)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy as LBS (fromStrict)
import Data.Kind (Type)
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack


class ( Typeable v
      , Show (VerKeyKES v)
      , Eq (VerKeyKES v)
      , Show (SignKeyKES v)
      , Show (SigKES v)
      , Eq (SigKES v)
      , NoUnexpectedThunks (SigKES     v)
      , NoUnexpectedThunks (SignKeyKES v)
      , NoUnexpectedThunks (VerKeyKES  v)
      )
      => KESAlgorithm v where


  --
  -- Key and signature types
  --

  data VerKeyKES  v :: Type
  data SignKeyKES v :: Type
  data SigKES     v :: Type


  --
  -- Metadata and basic key operations
  --

  algorithmNameKES :: proxy v -> String

  deriveVerKeyKES :: SignKeyKES v -> VerKeyKES v

  hashVerKeyKES :: HashAlgorithm h => VerKeyKES v -> Hash h (VerKeyKES v)
  hashVerKeyKES = hashRaw rawSerialiseVerKeyKES

  sizeVerKeyKES  :: proxy v -> Word
  sizeSignKeyKES :: proxy v -> Word
  sizeSigKES     :: proxy v -> Word


  --
  -- Core algorithm operations
  --

  -- | Context required to run the KES algorithm
  --
  -- Unit by default (no context required)
  type ContextKES v :: Type
  type ContextKES v = ()

  type Signable v :: Type -> Constraint
  type Signable v = Empty

  signKES
    :: (Signable v a, HasCallStack)
    => ContextKES v
    -> Period
    -> a
    -> SignKeyKES v
    -> SigKES v

  verifyKES
    :: (Signable v a, HasCallStack)
    => ContextKES v
    -> VerKeyKES v
    -> Period
    -> a
    -> SigKES v
    -> Either String ()

  -- | Update the KES signature key to the specified period. The intended
  -- behavior is to return `Nothing` in the case that the key cannot be evolved
  -- that far.
  --
  -- The precondition is that the current KES period of the input key is before
  -- the target period.
  -- The postcondition is that in case a key is returned, its current KES period
  -- corresponds to the target KES period.
  updateKES
    :: HasCallStack
    => ContextKES v
    -> SignKeyKES v
    -> Period
    -> Maybe (SignKeyKES v)

  -- | Return the current KES period of a KES signing key.
  totalPeriodsKES
    :: proxy v -> Period


  --
  -- Key generation
  --

  genKeyKES :: Seed -> SignKeyKES v

  -- | The upper bound on the 'Seed' size needed by 'genKeyKES'
  seedSizeKES :: proxy v -> Word


  --
  -- Serialisation/(de)serialisation in raw format, no extra tags
  --
  -- default implementations in terms of the CBOR encode/decode
  --

  rawSerialiseVerKeyKES :: VerKeyKES v -> ByteString
  rawSerialiseVerKeyKES = serializeEncoding' . encodeVerKeyKES

  rawSerialiseSignKeyKES :: SignKeyKES v -> ByteString
  rawSerialiseSignKeyKES = serializeEncoding' . encodeSignKeyKES

  rawSerialiseSigKES :: SigKES v -> ByteString
  rawSerialiseSigKES = serializeEncoding' . encodeSigKES

  rawDeserialiseVerKeyKES :: ByteString -> Maybe (VerKeyKES v)
  rawDeserialiseVerKeyKES =
      either (const Nothing) Just
    . decodeFullDecoder
        "rawDeserialiseVerKeyKES"
        decodeVerKeyKES
    . LBS.fromStrict

  rawDeserialiseSignKeyKES :: ByteString -> Maybe (SignKeyKES v)
  rawDeserialiseSignKeyKES =
      either (const Nothing) Just
    . decodeFullDecoder
        "rawDeserialiseVerKeyKES"
        decodeSignKeyKES
    . LBS.fromStrict

  rawDeserialiseSigKES :: ByteString -> Maybe (SigKES v)
  rawDeserialiseSigKES =
      either (const Nothing) Just
    . decodeFullDecoder
        "rawDeserialiseVerKeyKES"
        decodeSigKES
    . LBS.fromStrict


  --
  -- Convenient CBOR encoding/decoding
  --
  -- default implementations in terms of the raw (de)serialise
  --

  encodeVerKeyKES :: VerKeyKES v -> Encoding
  encodeVerKeyKES = encodeBytes . rawSerialiseVerKeyKES

  encodeSignKeyKES :: SignKeyKES v -> Encoding
  encodeSignKeyKES = encodeBytes . rawSerialiseSignKeyKES

  encodeSigKES :: SigKES v -> Encoding
  encodeSigKES = encodeBytes . rawSerialiseSigKES

  decodeVerKeyKES :: Decoder s (VerKeyKES v)
  decodeVerKeyKES = do
    bs <- decodeBytes
    case rawDeserialiseVerKeyKES bs of
      Nothing -> fail "decodeVerKeyKES: cannot decode key"
      Just vk -> return vk

  decodeSignKeyKES :: Decoder s (SignKeyKES v)
  decodeSignKeyKES = do
    bs <- decodeBytes
    case rawDeserialiseSignKeyKES bs of
      Nothing -> fail "decodeSignKeyKES: cannot decode key"
      Just vk -> return vk

  decodeSigKES :: Decoder s (SigKES v)
  decodeSigKES = do
    bs <- decodeBytes
    case rawDeserialiseSigKES bs of
      Nothing -> fail "decodeSigKES: cannot decode key"
      Just vk -> return vk


  {-# MINIMAL
        algorithmNameKES
      , deriveVerKeyKES
      , sizeVerKeyKES
      , sizeSignKeyKES
      , sizeSigKES
      , signKES
      , verifyKES
      , updateKES
      , totalPeriodsKES
      , genKeyKES
      , seedSizeKES
      , (rawSerialiseVerKeyKES    | encodeVerKeyKES)
      , (rawSerialiseSignKeyKES   | encodeSignKeyKES)
      , (rawSerialiseSigKES       | encodeSigKES)
      , (rawDeserialiseVerKeyKES  | decodeVerKeyKES)
      , (rawDeserialiseSignKeyKES | decodeSignKeyKES)
      , (rawDeserialiseSigKES     | decodeSigKES)
    #-}

-- | The KES period. The KES evolution index.
--
type Period = Word

newtype SignedKES v a = SignedKES {getSig :: SigKES v}
  deriving Generic

deriving instance KESAlgorithm v => Show (SignedKES v a)
deriving instance KESAlgorithm v => Eq   (SignedKES v a)

instance KESAlgorithm v => NoUnexpectedThunks (SignedKES v a)
  -- use generic instance

signedKES
  :: (KESAlgorithm v, Signable v a)
  => ContextKES v
  -> Period
  -> a
  -> SignKeyKES v
  -> SignedKES v a
signedKES ctxt time a key = SignedKES (signKES ctxt time a key)

verifySignedKES
  :: (KESAlgorithm v, Signable v a)
  => ContextKES v
  -> VerKeyKES v
  -> Period
  -> a
  -> SignedKES v a
  -> Either String ()
verifySignedKES ctxt vk j a (SignedKES sig) = verifyKES ctxt vk j a sig

encodeSignedKES :: KESAlgorithm v => SignedKES v a -> Encoding
encodeSignedKES (SignedKES s) = encodeSigKES s

decodeSignedKES :: KESAlgorithm v => Decoder s (SignedKES v a)
decodeSignedKES = SignedKES <$> decodeSigKES
