{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveFunctor      #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia        #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE InstanceSigs       #-}
{-# LANGUAGE PatternSynonyms    #-}
{-# LANGUAGE Rank2Types         #-}
{-# LANGUAGE TypeFamilies       #-}
{-# LANGUAGE TypeApplications   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}

module Cardano.Binary.Annotated
  ( Annotated(..)
  , Decoded(..)
  , reAnnotate
  , AnnotatedDecoder
    ( unwrapAnn )
  , pattern AnnotatedDecoder
  , liftAnn
  , withAnnotation
  , withAnnotation'
  , withSlice'
  , FromCBORAnnotated (..)
  , decodeAnnotated
  , decodeAnnotatedDecoder
  , fromCBOREmptyAnnotation
  , WrappedDecoder(..)
  , decodeWrapped
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
  (ToCBOR(..), encodePreEncoded)
import Cardano.Binary.Serialize (serialize')

-------------------------------------------------------------------------
-- Annotated Wrapper
-------------------------------------------------------------------------
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

instance Typeable b => ToCBOR (Annotated b ByteString) where
  toCBOR = encodePreEncoded . annotation

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

-- | An AnnotatedDecoder produces a value which needs a reference to the
-- original ByteString to be constructed. For example, consider
--
-- `data Foo = Foo Int ByteString`
--
-- where the ByteString is expected to be the serialized form of Foo.
--
-- The pattern `AnnotatedDecoder` takes care that the bytes provided are the
-- correct ones.
newtype AnnotatedDecoder s a
  = UnsafeAnnotatedDecoder (Decoder s (LByteString -> a))
  deriving (Functor)

liftAnn :: Decoder s a -> AnnotatedDecoder s a
liftAnn dec = withAnnotation $ const <$> dec

instance Applicative (AnnotatedDecoder s) where
  pure x = withAnnotation $ const <$> pure x
  (AnnotatedDecoder a) <*> (AnnotatedDecoder b) =
    withAnnotation $ (<*>) <$> a <*> b

{-# COMPLETE AnnotatedDecoder #-}
pattern AnnotatedDecoder
  :: forall a s. Decoder s (LByteString -> a)
  -> AnnotatedDecoder s a
pattern AnnotatedDecoder { unwrapAnn }
  <- UnsafeAnnotatedDecoder unwrapAnn
  where
    AnnotatedDecoder dec =
      let
        sliceOffsets :: ByteOffset -> ByteOffset -> LByteString -> LByteString
        sliceOffsets start end = BSL.take (end - start) . BSL.drop start
        decoderWithSlice = do
          (x, start, end) <- decodeWithByteSpan dec
          return $ x . sliceOffsets start end
      in UnsafeAnnotatedDecoder decoderWithSlice

decodeAnnotated :: forall a. (Typeable a , FromCBORAnnotated a)
  => LByteString
  -> Either DecoderError a
decodeAnnotated = decodeAnnotatedDecoder (show . typeRep $ Proxy @a) fromCBORAnnotated

decodeAnnotatedDecoder :: Text -> (forall s. AnnotatedDecoder s a) -> LByteString -> Either DecoderError a
decodeAnnotatedDecoder label' decoder bytes =
  (\x -> x bytes) <$> decodeFullDecoder label' (unwrapAnn decoder) bytes

withSlice' :: forall s a. AnnotatedDecoder s (ByteString -> a) -> AnnotatedDecoder s a
withSlice' (AnnotatedDecoder d) = withAnnotation $ do
  d1 <- d
  return $ \bytes -> d1 bytes (BSL.toStrict bytes)

-- | Wrap a plain decoder into an annotated one.
withAnnotation :: forall s a. Decoder s (LByteString -> a) -> AnnotatedDecoder s a
withAnnotation = AnnotatedDecoder

-- | Strict variant of 'withAnnotation'.
withAnnotation' :: forall s a. Decoder s (ByteString -> a) -> AnnotatedDecoder s a
withAnnotation' dec = withAnnotation $ do
  res <- dec
  return $ \bytes -> res (BSL.toStrict bytes)

class FromCBORAnnotated a where
  fromCBORAnnotated :: forall s. AnnotatedDecoder s a

instance (FromCBOR a) => FromCBORAnnotated (Annotated a ByteString) where
  fromCBORAnnotated = withAnnotation' $ Annotated <$> fromCBOR

instance FromCBORAnnotated a => FromCBORAnnotated [a] where
  fromCBORAnnotated = withAnnotation $ do
    xs <- decodeListWith (unwrapAnn fromCBORAnnotated)
    return $ \bytes -> fmap (\x -> x bytes) xs

instance FromCBORAnnotated a => FromCBORAnnotated (Maybe a) where
  fromCBORAnnotated = withAnnotation $ do
    xs <- fromCBORMaybe (unwrapAnn fromCBORAnnotated)
    return $ \bytes -> fmap (\x -> x bytes) xs

fromCBOREmptyAnnotation :: FromCBORAnnotated a => Decoder s a
fromCBOREmptyAnnotation = (\x -> x mempty) <$> unwrapAnn fromCBORAnnotated

-------------------------------------------------------------------------
-- Wrapped Decoder
-------------------------------------------------------------------------

-- | Wrap both annotated and plain decoders
data WrappedDecoder a =
    Ann !(forall s. AnnotatedDecoder s a)
  | Plain !(forall s. Decoder s a)
  deriving Functor

deriving via OnlyCheckIsWHNF "WrappedDecoder" (WrappedDecoder a)
  instance NoUnexpectedThunks (WrappedDecoder a)

decodeWrapped
  :: forall a
  . (Typeable a)
  => WrappedDecoder a
  -> BSL.ByteString
  -> Either DecoderError a
decodeWrapped (Ann ad) = decodeAnnotatedDecoder (show . typeRep $ Proxy @a) ad
decodeWrapped (Plain d) = decodeFullDecoder (show . typeRep $ Proxy @a) d
