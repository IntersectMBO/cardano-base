{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}

-- | Serialization primitives built on top of the @ToCBOR@ typeclass

module Cardano.Binary.Serialize
  ( serialize
  , serialize'
  , serializeBuilder
  , serializeEncoding
  , serializeEncoding'

  -- * CBOR in CBOR
  , encodeNestedCbor
  , encodeNestedCborBytes
  , nestedCborSizeExpr
  , nestedCborBytesSizeExpr
  )
where

import Prelude hiding ((.))

import qualified Codec.CBOR.Write as CBOR.Write
import Control.Category ((.))
import qualified Data.ByteString as BS
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString.Builder.Extra as Builder
import qualified Data.ByteString.Lazy as BSL

import Cardano.Binary.ToCBOR
  (Encoding, Size, ToCBOR(..), apMono, encodeTag, withWordSize)


-- | Serialize a Haskell value with a 'ToCBOR' instance to an external binary
--   representation.
--
--   The output is represented as a lazy 'LByteString' and is constructed
--   incrementally.
serialize :: ToCBOR a => a -> BSL.ByteString
serialize = serializeEncoding . toCBOR

-- | Serialize a Haskell value to an external binary representation.
--
--   The output is represented as a strict 'ByteString'.
serialize' :: ToCBOR a => a -> BS.ByteString
serialize' = BSL.toStrict . serialize

-- | Serialize into a Builder. Useful if you want to throw other ByteStrings
--   around it.
serializeBuilder :: ToCBOR a => a -> Builder
serializeBuilder = CBOR.Write.toBuilder . toCBOR

-- | Serialize a Haskell value to an external binary representation using the
--   provided CBOR 'Encoding'
--
--   The output is represented as an 'LByteString' and is constructed
--   incrementally.
serializeEncoding :: Encoding -> BSL.ByteString
serializeEncoding =
  Builder.toLazyByteStringWith strategy mempty . CBOR.Write.toBuilder
  where
    -- 1024 is the size of the first buffer, 4096 is the size of subsequent
    -- buffers. Chosen because they seem to give good performance. They are not
    -- sacred.
        strategy = Builder.safeStrategy 1024 4096

-- | A strict version of 'serializeEncoding'
serializeEncoding' :: Encoding -> BS.ByteString
serializeEncoding' = BSL.toStrict . serializeEncoding


--------------------------------------------------------------------------------
-- Nested CBOR-in-CBOR
-- https://tools.ietf.org/html/rfc7049#section-2.4.4.1
--------------------------------------------------------------------------------

-- | Encode and serialise the given `a` and sorround it with the semantic tag 24
--   In CBOR diagnostic notation:
--   >>> 24(h'DEADBEEF')
encodeNestedCbor :: ToCBOR a => a -> Encoding
encodeNestedCbor = encodeNestedCborBytes . serialize

-- | Like `encodeNestedCbor`, but assumes nothing about the shape of
--   input object, so that it must be passed as a binary `ByteString` blob. It's
--   the caller responsibility to ensure the input `ByteString` correspond
--   indeed to valid, previously-serialised CBOR data.
encodeNestedCborBytes :: BSL.ByteString -> Encoding
encodeNestedCborBytes x = encodeTag 24 <> toCBOR x

nestedCborSizeExpr :: Size -> Size
nestedCborSizeExpr x = 2 + apMono "withWordSize" withWordSize x + x

nestedCborBytesSizeExpr :: Size -> Size
nestedCborBytesSizeExpr x = 2 + apMono "withWordSize" withWordSize x + x

