{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Abstract digital signatures.
module Cardano.Crypto.DSIGN.Class
  ( DSIGNAlgorithm (..)
  , SignedDSIGN (..)
  , signedDSIGN
  , verifySignedDSIGN
  , encodeSignedDSIGN
  , decodeSignedDSIGN
  , Seed
  )
where

import Cardano.Binary (Decoder, decodeBytes, Encoding, encodeBytes,
                       serializeEncoding', decodeFullDecoder)
import Cardano.Crypto.Util (Empty)
import Cardano.Prelude (NoUnexpectedThunks)
import Cardano.Crypto.Seed
import Cardano.Crypto.Hash.Class (HashAlgorithm, Hash, hashRaw)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy as LBS (fromStrict)
import Data.Kind (Type)
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack
import Numeric.Natural


class ( Typeable v
      , Show (VerKeyDSIGN v)
      , Eq (VerKeyDSIGN v)
      , Show (SignKeyDSIGN v)
      , Show (SigDSIGN v)
      , Eq (SigDSIGN v)
      , NoUnexpectedThunks (SigDSIGN     v)
      , NoUnexpectedThunks (SignKeyDSIGN v)
      , NoUnexpectedThunks (VerKeyDSIGN  v)
      )
      => DSIGNAlgorithm v where


  --
  -- Key and signature types
  --

  data VerKeyDSIGN  v :: Type
  data SignKeyDSIGN v :: Type
  data SigDSIGN     v :: Type


  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGN :: proxy v -> String

  deriveVerKeyDSIGN :: SignKeyDSIGN v -> VerKeyDSIGN v

  hashVerKeyDSIGN :: HashAlgorithm h => VerKeyDSIGN v -> Hash h (VerKeyDSIGN v)
  hashVerKeyDSIGN = hashRaw rawSerialiseVerKeyDSIGN

  -- | Abstract sizes for verification keys and signatures, specifies an upper
  -- bound on the real byte sizes.
  abstractSizeVKey :: proxy v -> Natural
  abstractSizeSig  :: proxy v -> Natural


  --
  -- Core algorithm operations
  --

  -- | Context required to run the DSIGN algorithm
  --
  -- Unit by default (no context required)
  type ContextDSIGN v :: Type
  type ContextDSIGN v = ()

  type Signable v :: Type -> Constraint
  type Signable v = Empty

  signDSIGN
    :: (Signable v a, HasCallStack)
    => ContextDSIGN v
    -> a
    -> SignKeyDSIGN v
    -> SigDSIGN v

  verifyDSIGN
    :: (Signable v a, HasCallStack)
    => ContextDSIGN v
    -> VerKeyDSIGN v
    -> a
    -> SigDSIGN v
    -> Either String ()


  --
  -- Key generation
  --

  genKeyDSIGN :: Seed -> SignKeyDSIGN v

  -- | The upper bound on the 'Seed' size needed by 'genKeyDSIGN'
  seedSizeDSIGN :: proxy v -> Natural


  --
  -- Serialisation/(de)serialisation in raw format, no extra tags
  --
  -- default implementations in terms of the CBOR encode/decode
  --

  rawSerialiseVerKeyDSIGN :: VerKeyDSIGN v -> ByteString
  rawSerialiseVerKeyDSIGN = serializeEncoding' . encodeVerKeyDSIGN

  rawSerialiseSignKeyDSIGN :: SignKeyDSIGN v -> ByteString
  rawSerialiseSignKeyDSIGN = serializeEncoding' . encodeSignKeyDSIGN

  rawSerialiseSigDSIGN :: SigDSIGN v -> ByteString
  rawSerialiseSigDSIGN = serializeEncoding' . encodeSigDSIGN

  rawDeserialiseVerKeyDSIGN :: ByteString -> Maybe (VerKeyDSIGN v)
  rawDeserialiseVerKeyDSIGN =
      either (const Nothing) Just
    . decodeFullDecoder
        "rawDeserialiseVerKeyDSIGN"
        decodeVerKeyDSIGN
    . LBS.fromStrict

  rawDeserialiseSignKeyDSIGN :: ByteString -> Maybe (SignKeyDSIGN v)
  rawDeserialiseSignKeyDSIGN =
      either (const Nothing) Just
    . decodeFullDecoder
        "rawDeserialiseVerKeyDSIGN"
        decodeSignKeyDSIGN
    . LBS.fromStrict

  rawDeserialiseSigDSIGN :: ByteString -> Maybe (SigDSIGN v)
  rawDeserialiseSigDSIGN =
      either (const Nothing) Just
    . decodeFullDecoder
        "rawDeserialiseVerKeyDSIGN"
        decodeSigDSIGN
    . LBS.fromStrict


  --
  -- Convenient CBOR encoding/decoding
  --
  -- default implementations in terms of the raw (de)serialise
  --

  encodeVerKeyDSIGN :: VerKeyDSIGN v -> Encoding
  encodeVerKeyDSIGN = encodeBytes . rawSerialiseVerKeyDSIGN

  encodeSignKeyDSIGN :: SignKeyDSIGN v -> Encoding
  encodeSignKeyDSIGN = encodeBytes . rawSerialiseSignKeyDSIGN

  encodeSigDSIGN :: SigDSIGN v -> Encoding
  encodeSigDSIGN = encodeBytes . rawSerialiseSigDSIGN

  decodeVerKeyDSIGN :: Decoder s (VerKeyDSIGN v)
  decodeVerKeyDSIGN = do
    bs <- decodeBytes
    case rawDeserialiseVerKeyDSIGN bs of
      Nothing -> fail "decodeVerKeyDSIGN: cannot decode key"
      Just vk -> return vk

  decodeSignKeyDSIGN :: Decoder s (SignKeyDSIGN v)
  decodeSignKeyDSIGN = do
    bs <- decodeBytes
    case rawDeserialiseSignKeyDSIGN bs of
      Nothing -> fail "decodeSignKeyDSIGN: cannot decode key"
      Just vk -> return vk

  decodeSigDSIGN :: Decoder s (SigDSIGN v)
  decodeSigDSIGN = do
    bs <- decodeBytes
    case rawDeserialiseSigDSIGN bs of
      Nothing -> fail "decodeSigDSIGN: cannot decode key"
      Just vk -> return vk


  {-# MINIMAL
        algorithmNameDSIGN
      , deriveVerKeyDSIGN
      , abstractSizeVKey
      , abstractSizeSig
      , signDSIGN
      , verifyDSIGN
      , genKeyDSIGN
      , seedSizeDSIGN
      , (rawSerialiseVerKeyDSIGN    | encodeVerKeyDSIGN)
      , (rawSerialiseSignKeyDSIGN   | encodeSignKeyDSIGN)
      , (rawSerialiseSigDSIGN       | encodeSigDSIGN)
      , (rawDeserialiseVerKeyDSIGN  | decodeVerKeyDSIGN)
      , (rawDeserialiseSignKeyDSIGN | decodeSignKeyDSIGN)
      , (rawDeserialiseSigDSIGN     | decodeSigDSIGN)
    #-}


newtype SignedDSIGN v a = SignedDSIGN (SigDSIGN v)
  deriving Generic

deriving instance DSIGNAlgorithm v => Show (SignedDSIGN v a)
deriving instance DSIGNAlgorithm v => Eq   (SignedDSIGN v a)

instance DSIGNAlgorithm v => NoUnexpectedThunks (SignedDSIGN v a)
  -- use generic instance

signedDSIGN
  :: (DSIGNAlgorithm v, Signable v a)
  => ContextDSIGN v
  -> a
  -> SignKeyDSIGN v
  -> SignedDSIGN v a
signedDSIGN ctxt a key = SignedDSIGN (signDSIGN ctxt a key)

verifySignedDSIGN
  :: (DSIGNAlgorithm v, Signable v a, HasCallStack)
  => ContextDSIGN v
  -> VerKeyDSIGN v
  -> a
  -> SignedDSIGN v a
  -> Either String ()
verifySignedDSIGN ctxt key a (SignedDSIGN s) = verifyDSIGN ctxt key a s

encodeSignedDSIGN :: DSIGNAlgorithm v => SignedDSIGN v a -> Encoding
encodeSignedDSIGN (SignedDSIGN s) = encodeSigDSIGN s

decodeSignedDSIGN :: DSIGNAlgorithm v => Decoder s (SignedDSIGN v a)
decodeSignedDSIGN = SignedDSIGN <$> decodeSigDSIGN
