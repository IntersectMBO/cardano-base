{-# LANGUAGE GADTs               #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Cardano.Binary.Helpers.CanonicalTestable
  ( CanonicalTestable (..)
  , TypeTerm (..)
  , encodeCanonical
  )
where

import Cardano.Prelude

import Cardano.Binary
  ( Encoding
  , ToCBOR(..)
  )
import Codec.CBOR.FlatTerm (FlatTerm, toFlatTerm)

newtype TypeTerm = TypeTerm [FlatTerm]
    deriving (Show, Eq)

data CanonicalTestable where
  WithCBOR :: forall a. (ToCBOR a, CanonicalExamples a) =>
      Proxy a -> CanonicalTestable
  Explicit :: forall a. CanonicalExamples a =>
      (a -> Encoding) -> CanonicalTestable
  WithCBORSized :: forall a. (ToCBOR a, CanonicalExamplesSized a) =>
      Proxy a -> Args -> CanonicalTestable
  ExplicitSized :: forall a. CanonicalExamplesSized a =>
      (a -> Encoding) -> Args -> CanonicalTestable

encodeCanonical :: CanonicalTestable -> TypeTerm
encodeCanonical (WithCBOR (Proxy :: Proxy a)) = TypeTerm $
    toFlatTerm . toCBOR <$> (unsafeGetCanonicalExamples :: [a])
encodeCanonical (Explicit enc) = TypeTerm $
    toFlatTerm . enc <$> unsafeGetCanonicalExamples
encodeCanonical (WithCBORSized (Proxy :: Proxy a) args) = TypeTerm $
    toFlatTerm . toCBOR <$> (getCanonicalExamplesSized args :: [a])
encodeCanonical (ExplicitSized enc args) = TypeTerm $
    toFlatTerm . enc <$> getCanonicalExamplesSized args
