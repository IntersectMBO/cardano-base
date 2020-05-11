{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Abstract digital signatures.
module Cardano.Crypto.DSIGN.Class
  (
    -- * DSIGN algorithm class
    DSIGNAlgorithm (..)
  , Seed

    -- * 'SignedDSIGN' wrapper
  , SignedDSIGN (..)
  , signedDSIGN
  , verifySignedDSIGN

    -- * CBOR encoding and decoding
  , encodeVerKeyDSIGN
  , decodeVerKeyDSIGN
  , encodeSignKeyDSIGN
  , decodeSignKeyDSIGN
  , encodeSigDSIGN
  , decodeSigDSIGN
  , encodeSignedDSIGN
  , decodeSignedDSIGN
  )
where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Kind (Type)
import Data.Proxy (Proxy(..))
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack

import Cardano.Prelude (CanonicalExamples, NoUnexpectedThunks)
import Cardano.Binary (Decoder, decodeBytes, Encoding, encodeBytes)

import Cardano.Crypto.Util (Empty)
import Cardano.Crypto.Seed
import Cardano.Crypto.Hash.Class (HashAlgorithm, Hash, hashRaw)



class ( Typeable v
      , Show (VerKeyDSIGN v)
      , Eq (VerKeyDSIGN v)
      , Show (SignKeyDSIGN v)
      , Show (SigDSIGN v)
      , Eq (SigDSIGN v)
      , NoUnexpectedThunks (SigDSIGN     v)
      , NoUnexpectedThunks (SignKeyDSIGN v)
      , NoUnexpectedThunks (VerKeyDSIGN  v)
      , CanonicalExamples (SigDSIGN     v)
      , CanonicalExamples (SignKeyDSIGN v)
      , CanonicalExamples (VerKeyDSIGN  v)
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
  seedSizeDSIGN :: proxy v -> Word


  --
  -- Serialisation/(de)serialisation in fixed-size raw format
  --

  sizeVerKeyDSIGN  :: proxy v -> Word
  sizeSignKeyDSIGN :: proxy v -> Word
  sizeSigDSIGN     :: proxy v -> Word

  rawSerialiseVerKeyDSIGN    :: VerKeyDSIGN  v -> ByteString
  rawSerialiseSignKeyDSIGN   :: SignKeyDSIGN v -> ByteString
  rawSerialiseSigDSIGN       :: SigDSIGN     v -> ByteString

  rawDeserialiseVerKeyDSIGN  :: ByteString -> Maybe (VerKeyDSIGN  v)
  rawDeserialiseSignKeyDSIGN :: ByteString -> Maybe (SignKeyDSIGN v)
  rawDeserialiseSigDSIGN     :: ByteString -> Maybe (SigDSIGN     v)


--
-- Convenient CBOR encoding/decoding
--
-- Implementations in terms of the raw (de)serialise
--

encodeVerKeyDSIGN :: DSIGNAlgorithm v => VerKeyDSIGN v -> Encoding
encodeVerKeyDSIGN = encodeBytes . rawSerialiseVerKeyDSIGN

encodeSignKeyDSIGN :: DSIGNAlgorithm v => SignKeyDSIGN v -> Encoding
encodeSignKeyDSIGN = encodeBytes . rawSerialiseSignKeyDSIGN

encodeSigDSIGN :: DSIGNAlgorithm v => SigDSIGN v -> Encoding
encodeSigDSIGN = encodeBytes . rawSerialiseSigDSIGN

decodeVerKeyDSIGN :: forall v s. DSIGNAlgorithm v => Decoder s (VerKeyDSIGN v)
decodeVerKeyDSIGN = do
    bs <- decodeBytes
    case rawDeserialiseVerKeyDSIGN bs of
      Just vk -> return vk
      Nothing
        | actual /= expected
                    -> fail ("decodeVerKeyDSIGN: wrong length, expected " ++
                             show expected ++ " bytes but got " ++ show actual)
        | otherwise -> fail "decodeVerKeyDSIGN: cannot decode key"
        where
          expected = fromIntegral (sizeVerKeyDSIGN (Proxy :: Proxy v))
          actual   = BS.length bs

decodeSignKeyDSIGN :: forall v s. DSIGNAlgorithm v => Decoder s (SignKeyDSIGN v)
decodeSignKeyDSIGN = do
    bs <- decodeBytes
    case rawDeserialiseSignKeyDSIGN bs of
      Just sk -> return sk
      Nothing
        | actual /= expected
                    -> fail ("decodeSignKeyDSIGN: wrong length, expected " ++
                             show expected ++ " bytes but got " ++ show actual)
        | otherwise -> fail "decodeSignKeyDSIGN: cannot decode key"
        where
          expected = fromIntegral (sizeSignKeyDSIGN (Proxy :: Proxy v))
          actual   = BS.length bs

decodeSigDSIGN :: forall v s. DSIGNAlgorithm v => Decoder s (SigDSIGN v)
decodeSigDSIGN = do
    bs <- decodeBytes
    case rawDeserialiseSigDSIGN bs of
      Just sig -> return sig
      Nothing
        | actual /= expected
                    -> fail ("decodeSigDSIGN: wrong length, expected " ++
                             show expected ++ " bytes but got " ++ show actual)
        | otherwise -> fail "decodeSigDSIGN: cannot decode signature"
        where
          expected = fromIntegral (sizeSigDSIGN (Proxy :: Proxy v))
          actual   = BS.length bs


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
