{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveFunctor      #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE Rank2Types         #-}
{-# LANGUAGE TypeFamilies       #-}
{-# LANGUAGE TypeApplications   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Cardano.Binary.Annotated
  ( Annotated(..)
  , ByteSpan(..)
  , Decoded(..)
  , annotationBytes
  , annotatedDecoder
  , slice
  , fromCBORAnnotated
  , decodeFullAnnotatedBytes
  , reAnnotate
  , Annotator (..)
  , annotatorSlice
  , decodeAnnotator
  , withSlice
  , FullByteString (..)
  )
where

import Cardano.Prelude

import Codec.CBOR.Read (ByteOffset)
import Data.Aeson (FromJSON(..), ToJSON(..))
import qualified Data.ByteString.Lazy as BSL

import Cardano.Binary.Deserialize (decodeFullDecoder)
import Cardano.Binary.FromCBOR
  (Decoder, DecoderError, FromCBOR(..), decodeWithByteSpan)
import Cardano.Binary.ToCBOR
  (ToCBOR)
import Cardano.Binary.Serialize (serialize')



-- | Extract a substring of a given ByteString corresponding to the offsets.
slice :: BSL.ByteString -> ByteSpan -> LByteString
slice bytes (ByteSpan start end) =
  BSL.take (end - start) $ BSL.drop start bytes

-- | A pair of offsets delimiting the beginning and end of a substring of a ByteString
data ByteSpan = ByteSpan !ByteOffset !ByteOffset
  deriving (Generic, Show)

-- Used for debugging purposes only.
instance ToJSON ByteSpan where

data Annotated b a = Annotated { unAnnotated :: !b, annotation :: !a }
  deriving (Eq, Show, Functor, Generic)
  deriving anyclass (NFData, NoUnexpectedThunks)

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

annotationBytes :: Functor f => LByteString -> f ByteSpan -> f ByteString
annotationBytes bytes = fmap (BSL.toStrict . slice bytes)

-- | Decodes a value from a ByteString, requiring that the full ByteString is consumed, and
-- replaces ByteSpan annotations with the corresponding substrings of the input string.
decodeFullAnnotatedBytes
  :: Functor f
  => Text
  -> (forall s . Decoder s (f ByteSpan))
  -> LByteString
  -> Either DecoderError (f ByteString)
decodeFullAnnotatedBytes lbl decoder bytes =
  annotationBytes bytes <$> decodeFullDecoder lbl decoder bytes

-- | Reconstruct an annotation by re-serialising the payload to a ByteString.
reAnnotate :: ToCBOR a => Annotated a b -> Annotated a ByteString
reAnnotate (Annotated x _) = Annotated x (serialize' x)

class Decoded t where
  type BaseType t :: Type
  recoverBytes :: t -> ByteString

instance Decoded (Annotated b ByteString) where
  type BaseType (Annotated b ByteString) = b
  recoverBytes = annotation

-------------------------------------------------------------------------
-- Annotator
-------------------------------------------------------------------------

-- | This marks the entire bytestring used during decoding, rather than the
-- | piece we need to finish constructing our value.
newtype FullByteString = Full LByteString

-- | A value of type `Annotator a` is one that needs access to the entire
-- | bytestring used during decoding to finish construction.
newtype Annotator a = Annotator { runAnnotator :: FullByteString -> a }
  deriving newtype (Monad, Applicative, Functor)

-- | The argument is a decoder for a annotator that needs access to the bytes that
-- | were decoded. This function constructs and supplies the relevant piece.
annotatorSlice :: Decoder s (Annotator (LByteString -> a)) -> Decoder s (Annotator a)
annotatorSlice dec = do
  (k,bytes) <- withSlice dec
  pure $ k <*> bytes

-- | Pairs the decoder result with an annotator.
withSlice :: Decoder s a -> Decoder s (a, Annotator LByteString)
withSlice dec = do
  (r, start, end) <- decodeWithByteSpan dec
  return $ (r, Annotator $ sliceOffsets start end)
  where
  sliceOffsets :: ByteOffset -> ByteOffset -> FullByteString -> LByteString
  sliceOffsets start end (Full b) = (BSL.take (end - start) . BSL.drop start) b

-- | Supplies the bytestring argument to both the decoder and the produced annotator.
decodeAnnotator :: Text -> (forall s. Decoder s (Annotator a)) -> LByteString -> Either DecoderError a
decodeAnnotator label' decoder bytes =
  (\x -> runAnnotator x (Full bytes)) <$> decodeFullDecoder label' decoder bytes
