{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveFunctor      #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE Rank2Types         #-}
{-# LANGUAGE TypeFamilies       #-}
{-# LANGUAGE TypeApplications   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Cardano.Binary.Annotated
  ( Annotated(..)
  , ByteSpan(..)
  , Decoded(..)
  , annotatedDecoder
  , slice
  , fromCBORAnnotated
  , decodeFullAnnotatedBytes
  , reAnnotate
  , AnnotatedDecoder
  , FromCBORAnnotated (..)
  , decodeAnnotated
  , withSlice
  , withSlice'
  , liftByteSpanDecoder
  , decodeAnnotatedDecoder
  , fromCBOREmptyAnnotation
  )
where

import Cardano.Prelude

import Codec.CBOR.Read (ByteOffset)
import Data.Aeson (FromJSON(..), ToJSON(..))
import qualified Data.ByteString.Lazy as BSL
import Data.Kind (Type)

import Cardano.Binary.Deserialize (decodeFullDecoder)
import Cardano.Binary.FromCBOR
  (Decoder, DecoderError, FromCBOR(..), decodeWithByteSpan, decodeListWith, fromCBORMaybe)
import Cardano.Binary.ToCBOR
  (ToCBOR)
import Cardano.Binary.Serialize (serialize')



-- | Extract a substring of a given ByteString corresponding to the offsets.
slice :: BSL.ByteString -> ByteSpan -> LByteString
slice bytes (ByteSpan start end) =
  BSL.take (end - start) $ BSL.drop start bytes

-- | A pair of offsets delimiting the beginning and end of a substring of a ByteString
data ByteSpan = ByteSpan !ByteOffset !ByteOffset

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
-- Annotated Decoder
-------------------------------------------------------------------------


-- | An AnnotatedDecoder produces a value which needs a reference to the original ByteString to be
-- constructed.
type AnnotatedDecoder s a = ReaderT LByteString (Decoder s) a

decodeAnnotated :: forall a. (Typeable a , FromCBORAnnotated a)
  => LByteString
  -> Either DecoderError a
decodeAnnotated = decodeAnnotatedDecoder (show . typeRep $ Proxy @a) fromCBORAnnotated'

decodeAnnotatedDecoder :: Text -> (forall s. AnnotatedDecoder s a) -> LByteString -> Either DecoderError a
decodeAnnotatedDecoder label' decoder bytes =
  decodeFullDecoder label' (runReaderT decoder bytes) bytes

liftByteSpanDecoder :: Functor f => Decoder s (f ByteSpan) -> AnnotatedDecoder s (f ByteString)
liftByteSpanDecoder decoder = ReaderT $ \bytes ->
  decoder <&> \fbs -> BSL.toStrict . slice bytes <$> fbs

-- | Inserts the decoded segment
withSlice :: AnnotatedDecoder s (LByteString -> a) -> AnnotatedDecoder s a
withSlice decoder = ReaderT $ \bytes -> do
  (x, start, end) <- decodeWithByteSpan $ runReaderT decoder bytes
  pure $ x $ sliceOffsets start end bytes
  where
  sliceOffsets :: ByteOffset -> ByteOffset -> LByteString -> LByteString
  sliceOffsets start end = BSL.take (end - start) . BSL.drop start

-- | Equivalent to withSlice for strict ByteStrings
withSlice' :: AnnotatedDecoder s (ByteString -> a) -> AnnotatedDecoder s a
withSlice' = withSlice . fmap (. BSL.toStrict)

fromCBOREmptyAnnotation :: FromCBORAnnotated a => Decoder s a
fromCBOREmptyAnnotation = runReaderT fromCBORAnnotated' mempty

class FromCBORAnnotated a where
  fromCBORAnnotated' :: AnnotatedDecoder s a

instance (FromCBOR a) => FromCBORAnnotated (Annotated a ByteString) where
  fromCBORAnnotated' = withSlice' $ Annotated <$> lift fromCBOR

instance FromCBORAnnotated a => FromCBORAnnotated [a] where
  fromCBORAnnotated' = ReaderT $ \bytes -> decodeListWith (runReaderT fromCBORAnnotated' bytes)

instance FromCBORAnnotated a => FromCBORAnnotated (Maybe a) where
  fromCBORAnnotated' = ReaderT $ \bytes -> fromCBORMaybe (runReaderT fromCBORAnnotated' bytes)
