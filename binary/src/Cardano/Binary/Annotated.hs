{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveFunctor      #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE Rank2Types         #-}
{-# LANGUAGE TypeFamilies       #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | The CBOR class 'FromCBOR' does not support access to the original bytestring that is being deserialized.
--   The 'Annotated' module recovers this ability by introducing several newtypes types that,
--   along with some new operations, recover this ability.
--
-- 1. 'ByteSpan'  A pair of indexes into a bytestring, indicating a substring.
-- 2. 'Annotated'  Used in practice to pair a value with a 'ByteSpan'.
-- 3. 'FullByteString' A newtype (around a bytestring) used to store the original bytestring being deserialized.
-- 4. 'Annotator' An explict reader monad whose environment is a 'FullByteString'
--
-- The basic idea is, for a given type @t@, where we need the original bytestring, either
--
-- 1. To complete the deserialization, or
-- 2. To combine the deserialized answer with the original bytestring.
--
-- We should proceed as follows: Define instances
-- @(FromCBOR (Annotator t))@ instead of @(FromCBOR t)@. When making this instance we may freely use
-- that both 'Decoder' and 'Annotator' are both monads, and that functions 'withSlice' and 'annotatorSlice'
-- provide access to the original bytes, or portions thereof, inside of decoders.
-- Then, to actually decode a value of type @t@, we use something similar to the following code fragment.
--
-- @
-- howToUseFullBytes bytes = do
--   Annotator f <- decodeFullDecoder \"DecodingAnnotator\" (fromCBOR :: forall s. Decoder s (Annotator t)) bytes
--   pure (f (Full bytes))
-- @
-- Decode the bytes to get an @(Annotator f)@ where f is a function that when given original bytes produces a value of type @t@, then apply @f@ to @(Full bytes)@ to get the answer.
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
  , serializeEncoding
  , encodePreEncoded
  )
where

import Prelude

import Codec.CBOR.Read (ByteOffset)
import Data.Aeson (FromJSON(..), ToJSON(..))
import qualified Data.ByteString.Lazy as BSL

import Cardano.Binary.Deserialize (decodeFullDecoder)
import Cardano.Binary.FromCBOR
  (Decoder, DecoderError, FromCBOR(..), decodeWithByteSpan)
import Cardano.Binary.ToCBOR
  (ToCBOR(..))
import Cardano.Binary.Serialize (serialize',serializeEncoding)
import Codec.CBOR.Encoding(encodePreEncoded)
import Control.DeepSeq (NFData)
import Data.Bifunctor (Bifunctor (first, second))
import qualified Data.ByteString as BS
import Data.Function (on)
import Data.Functor ((<&>))
import Data.Kind (Type)
import Data.Text (Text)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

-- | Extract a substring of a given ByteString corresponding to the offsets.
slice :: BSL.ByteString -> ByteSpan -> BSL.ByteString
slice bytes (ByteSpan start end) =
  BSL.take (end - start) $ BSL.drop start bytes

-- | A pair of offsets delimiting the beginning and end of a substring of a ByteString
data ByteSpan = ByteSpan !ByteOffset !ByteOffset
  deriving (Generic, Show)

-- Used for debugging purposes only.
instance ToJSON ByteSpan where

data Annotated b a = Annotated { unAnnotated :: !b, annotation :: !a }
  deriving (Eq, Show, Functor, Generic)
  deriving anyclass (NFData, NoThunks)

instance Bifunctor Annotated where
  first f (Annotated b a) = Annotated (f b) a
  second = fmap

instance (Eq a, Ord b) => Ord (Annotated b a) where
  compare = compare `on` unAnnotated

instance ToJSON b => ToJSON (Annotated b a) where
  toJSON = toJSON . unAnnotated
  toEncoding = toEncoding . unAnnotated

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

annotationBytes :: Functor f => BSL.ByteString -> f ByteSpan -> f BS.ByteString
annotationBytes bytes = fmap (BSL.toStrict . slice bytes)

-- | Decodes a value from a ByteString, requiring that the full ByteString is consumed, and
-- replaces ByteSpan annotations with the corresponding substrings of the input string.
decodeFullAnnotatedBytes
  :: Functor f
  => Text
  -> (forall s . Decoder s (f ByteSpan))
  -> BSL.ByteString
  -> Either DecoderError (f BS.ByteString)
decodeFullAnnotatedBytes lbl decoder bytes =
  annotationBytes bytes <$> decodeFullDecoder lbl decoder bytes

-- | Reconstruct an annotation by re-serialising the payload to a ByteString.
reAnnotate :: ToCBOR a => Annotated a b -> Annotated a BS.ByteString
reAnnotate (Annotated x _) = Annotated x (serialize' x)

class Decoded t where
  type BaseType t :: Type
  recoverBytes :: t -> BS.ByteString

instance Decoded (Annotated b BS.ByteString) where
  type BaseType (Annotated b BS.ByteString) = b
  recoverBytes = annotation

-------------------------------------------------------------------------
-- Annotator
-------------------------------------------------------------------------

-- | This marks the entire bytestring used during decoding, rather than the
--   piece we need to finish constructing our value.
newtype FullByteString = Full BSL.ByteString

-- | A value of type @(Annotator a)@ is one that needs access to the entire
--   bytestring used during decoding to finish construction of a vaue of type @a@. A typical use
--   is some type that stores the bytes that were used to deserialize it.
--   For example the type @Inner@ below is constructed using the helper function @makeInner@
--   which serializes and stores its bytes (using 'serializeEncoding').
--   Note how we build the
--   'Annotator' by abstracting over the full bytes, and
--   using those original bytes to fill the bytes field of the constructor @Inner@.
--   The 'ToCBOR' instance just reuses the stored bytes to produce an encoding
--   (using 'encodePreEncoded').
--
-- @
-- data Inner = Inner Int Bool LByteString
--
-- makeInner :: Int -> Bool -> Inner
-- makeInner i b = Inner i b (serializeEncoding (toCBOR i <> toCBOR b))
--
-- instance ToCBOR Inner where
--   toCBOR (Inner _ _ bytes) = encodePreEncoded bytes
--
-- instance FromCBOR (Annotator Inner) where
--   fromCBOR = do
--      int <- fromCBOR
--      trueOrFalse <- fromCBOR
--      pure (Annotator (\(Full bytes) -> Inner int trueOrFalse bytes))
-- @
--
-- if an @Outer@ type has a field of type @Inner@, with a @(ToCBOR (Annotator Inner))@ instance,
-- the @Outer@ type must also have a @(ToCBOR (Annotator Outer))@ instance.
-- The key to writing that instance is to use the operation @withSlice@ which returns a pair.
-- The first component is an @Annotator@ that can build @Inner@, the second is an @Annotator@ that given the
-- full bytes, extracts just the bytes needed to decode @Inner@.
--
-- @
-- data Outer = Outer Text Inner
--
-- instance ToCBOR Outer where
--   toCBOR (Outer t i) = toCBOR t <> toCBOR i
--
-- instance FromCBOR (Annotator Outer) where
--   fromCBOR = do
--     t <- fromCBOR
--     (Annotator mkInner, Annotator extractInnerBytes) <- withSlice fromCBOR
--     pure (Annotator (\ full -> Outer t (mkInner (Full (extractInnerBytes full)))))
-- @
--
newtype Annotator a = Annotator { runAnnotator :: FullByteString -> a }
  deriving newtype (Monad, Applicative, Functor)

-- | The argument is a decoder for a annotator that needs access to the bytes that
-- | were decoded. This function constructs and supplies the relevant piece.
annotatorSlice :: Decoder s (Annotator (BSL.ByteString -> a)) -> Decoder s (Annotator a)
annotatorSlice dec = do
  (k,bytes) <- withSlice dec
  pure $ k <*> bytes

-- | Pairs the decoder result with an annotator that can be used to construct the exact bytes used to decode the result.
withSlice :: Decoder s a -> Decoder s (a, Annotator BSL.ByteString)
withSlice dec = do
  (r, start, end) <- decodeWithByteSpan dec
  return (r, Annotator $ sliceOffsets start end)
  where
  sliceOffsets :: ByteOffset -> ByteOffset -> FullByteString -> BSL.ByteString
  sliceOffsets start end (Full b) = (BSL.take (end - start) . BSL.drop start) b

-- | Supplies the bytestring argument to both the decoder and the produced annotator.
decodeAnnotator :: Text -> (forall s. Decoder s (Annotator a)) -> BSL.ByteString -> Either DecoderError a
decodeAnnotator label' decoder bytes =
  (\x -> runAnnotator x (Full bytes)) <$> decodeFullDecoder label' decoder bytes
