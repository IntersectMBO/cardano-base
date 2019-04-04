{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveFunctor      #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE Rank2Types         #-}
{-# LANGUAGE TypeFamilies       #-}

module Cardano.Binary.Annotated
  ( Annotated(..)
  , ByteSpan(..)
  , Decoded(..)
  , annotatedDecoder
  , slice
  , fromCBORAnnotated
  , decodeFullAnnotatedBytes
  )
where

import Cardano.Prelude

import Codec.CBOR.Read (ByteOffset)
import Data.Aeson (FromJSON(..), ToJSON(..))
import qualified Data.ByteString.Lazy as BSL
import Data.Kind (Type)

import Cardano.Binary.Deserialize (decodeFullDecoder)
import Cardano.Binary.FromCBOR
  (Decoder, DecoderError, FromCBOR(..), decodeWithByteSpan)


-- | Extract a substring of a given ByteString corresponding to the offsets.
slice :: BSL.ByteString -> ByteSpan -> LByteString
slice bytes (ByteSpan start end) =
  BSL.take (end - start) $ BSL.drop start bytes

-- | A pair of offsets delimiting the beginning and end of a substring of a ByteString
data ByteSpan = ByteSpan !ByteOffset !ByteOffset

data Annotated b a = Annotated { unAnnotated :: !b, annotation :: !a }
  deriving (Eq, Show, Functor, Generic)
  deriving anyclass NFData

instance Bifunctor Annotated where
  first f (Annotated b a) = Annotated (f b) a
  second = fmap

instance (Eq a, Ord b) => Ord (Annotated b a) where
  compare = compare `on` unAnnotated

instance ToJSON b => ToJSON (Annotated b a) where
  toJSON = toJSON . unAnnotated

instance FromJSON b => FromJSON (Annotated b ()) where
  parseJSON j = flip Annotated () <$> parseJSON j

-- | A decoder for a value paired with an annotation specifying the start and end
-- of the consumed bytes.
annotatedDecoder :: Decoder s a -> Decoder s (Annotated a ByteSpan)
annotatedDecoder d = decodeWithByteSpan d
  <&> \(x, start, end) -> Annotated x (ByteSpan start end)

-- | A decoder for a value paired with an annotation specifying the start and end
-- of the consumed bytes.
fromCBORAnnotated :: FromCBOR a => Decoder s (Annotated a ByteSpan)
fromCBORAnnotated = annotatedDecoder fromCBOR

-- | Decodes a value from a ByteString, requiring that the full ByteString is consumed, and
-- replaces ByteSpan annotations with the corresponding substrings of the input string.
decodeFullAnnotatedBytes
  :: Functor f
  => Text
  -> (forall s . Decoder s (f ByteSpan))
  -> LByteString
  -> Either DecoderError (f ByteString)
decodeFullAnnotatedBytes lbl decoder bytes =
  fmap (BSL.toStrict . slice bytes) <$> decodeFullDecoder lbl decoder bytes

class Decoded t where
  type BaseType t :: Type
  recoverBytes :: t -> ByteString

instance Decoded (Annotated b ByteString) where
  type BaseType (Annotated b ByteString) = b
  recoverBytes = annotation
