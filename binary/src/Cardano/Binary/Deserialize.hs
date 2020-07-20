{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeApplications      #-}

-- | Deserialization primitives built on top of the @FromCBOR@ typeclass

module Cardano.Binary.Deserialize
  (
  -- * Unsafe deserialization
    unsafeDeserialize
  , unsafeDeserialize'
  , CBOR.Write.toStrictByteString

  -- * Backward-compatible functions
  , decodeFull
  , decodeFull'
  , decodeFullDecoder

  -- * CBOR in CBOR
  , decodeNestedCbor
  , decodeNestedCborBytes
  )
where

import Cardano.Prelude

import qualified Codec.CBOR.Decoding as D
import qualified Codec.CBOR.Read as Read
import qualified Codec.CBOR.Write as CBOR.Write
import Control.Exception.Safe (impureThrow)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Internal as BSL

import Cardano.Binary.FromCBOR (DecoderError(..), FromCBOR(..))


-- | Deserialize a Haskell value from the external binary representation
--   (which must have been made using 'serialize' or related function).
--
--   /Throws/: @'Read.DeserialiseFailure'@ if the given external
--   representation is invalid or does not correspond to a value of the
--   expected type.
unsafeDeserialize :: FromCBOR a => LByteString -> a
unsafeDeserialize =
  either impureThrow identity . bimap fst fst . deserialiseDecoder fromCBOR

-- | Strict variant of 'deserialize'.
unsafeDeserialize' :: FromCBOR a => ByteString -> a
unsafeDeserialize' = unsafeDeserialize . BSL.fromStrict

-- | Deserialize a Haskell value from the external binary representation,
--   failing if there are leftovers. In a nutshell, the `full` here implies
--   the contract of this function is that what you feed as input needs to
--   be consumed entirely.
decodeFull :: forall a . FromCBOR a => LByteString -> Either DecoderError a
decodeFull = decodeFullDecoder (label $ Proxy @a) fromCBOR

decodeFull' :: forall a . FromCBOR a => ByteString -> Either DecoderError a
decodeFull' = decodeFull . BSL.fromStrict

decodeFullDecoder
  :: Text
  -- ^ Label for error reporting
  -> (forall s . D.Decoder s a)
  -- ^ The parser for the @ByteString@ to decode. It should decode the given
  -- @ByteString@ into a value of type @a@
  -> LByteString
  -- ^ The @ByteString@ to decode
  -> Either DecoderError a
decodeFullDecoder lbl decoder bs0 = case deserialiseDecoder decoder bs0 of
  Right (x, leftover) -> if BS.null leftover
    then pure x
    else Left $ DecoderErrorLeftover lbl leftover
  Left (e, _) -> Left $ DecoderErrorDeserialiseFailure lbl e

-- | Deserialise a 'LByteString' incrementally using the provided 'Decoder'
deserialiseDecoder
  :: (forall s . D.Decoder s a)
  -> LByteString
  -> Either (Read.DeserialiseFailure, ByteString) (a, ByteString)
deserialiseDecoder decoder bs0 =
  runST (supplyAllInput bs0 =<< Read.deserialiseIncremental decoder)

supplyAllInput
  :: LByteString
  -> Read.IDecode s a
  -> ST s (Either (Read.DeserialiseFailure, ByteString) (a, ByteString))
supplyAllInput bs' (Read.Done bs _ x) =
  return (Right (x, bs <> BSL.toStrict bs'))
supplyAllInput bs (Read.Partial k) = case bs of
  BSL.Chunk chunk bs' -> k (Just chunk) >>= supplyAllInput bs'
  BSL.Empty           -> k Nothing >>= supplyAllInput BSL.Empty
supplyAllInput _ (Read.Fail bs _ exn) = return (Left (exn, bs))


--------------------------------------------------------------------------------
-- Nested CBOR-in-CBOR
-- https://tools.ietf.org/html/rfc7049#section-2.4.4.1
--------------------------------------------------------------------------------

-- | Remove the the semantic tag 24 from the enclosed CBOR data item,
-- failing if the tag cannot be found.
decodeNestedCborTag :: D.Decoder s ()
decodeNestedCborTag = do
  t <- D.decodeTag
  when (t /= 24) $ cborError $ DecoderErrorUnknownTag
    "decodeNestedCborTag"
    (fromIntegral t)

-- | Remove the the semantic tag 24 from the enclosed CBOR data item,
-- decoding back the inner `ByteString` as a proper Haskell type.
-- Consume its input in full.
decodeNestedCbor :: FromCBOR a => D.Decoder s a
decodeNestedCbor = do
  bs <- decodeNestedCborBytes
  toCborError $ decodeFull' bs

-- | Like `decodeKnownCborDataItem`, but assumes nothing about the Haskell
-- type we want to deserialise back, therefore it yields the `ByteString`
-- Tag 24 surrounded (stripping such tag away).
--
-- In CBOR notation, if the data was serialised as:
--
-- >>> 24(h'DEADBEEF')
--
-- then `decodeNestedCborBytes` yields the inner 'DEADBEEF', unchanged.
decodeNestedCborBytes :: D.Decoder s ByteString
decodeNestedCborBytes = do
  decodeNestedCborTag
  D.decodeBytes

