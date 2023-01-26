{-# LANGUAGE CPP                       #-}
{-# LANGUAGE ConstrainedClassMethods   #-}
{-# LANGUAGE DeriveFunctor             #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE MultiWayIf                #-}
{-# LANGUAGE NumDecimals               #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE Rank2Types                #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE TypeApplications          #-}

module Cardano.Binary.EncCBOR
  ( EncCBOR(..)
  , module E
  , encMaybe
  , encNullMaybe
  , encSeq
  )
where

import Prelude hiding ((.))

import Codec.CBOR.Encoding as E
import Codec.CBOR.ByteArray.Sliced as BAS
import Control.Category (Category((.)))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BS.Lazy
import qualified Data.ByteString.Short as SBS
import Data.ByteString.Short.Internal (ShortByteString (SBS))
import qualified Data.Primitive.ByteArray as Prim
import qualified Data.Sequence as Seq
import Data.Fixed (E12, Fixed(..), Nano, Pico, resolution)
import Data.Foldable (toList, foldMap')
import Data.Int (Int32, Int64)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.Map as M
import Data.Ratio ( Ratio, denominator, numerator )
import qualified Data.Set as S
import Data.Tagged (Tagged(..))
import qualified Data.Text as Text
import Data.Time.Calendar.OrdinalDate ( toOrdinalDate )
import Data.Time.Clock (NominalDiffTime, UTCTime(..), diffTimeToPicoseconds)
import Data.Typeable ( Typeable, Proxy(..) )
import qualified Data.Vector as Vector
import qualified Data.Vector.Generic as Vector.Generic
import Data.Void (Void, absurd)
import Data.Word ( Word8, Word16, Word32, Word64 )
import Numeric.Natural (Natural)

class Typeable a => EncCBOR a where
  encCBOR :: a -> Encoding

--------------------------------------------------------------------------------
-- Primitive types
--------------------------------------------------------------------------------

instance EncCBOR () where
  encCBOR = const E.encodeNull

instance EncCBOR Bool where
  encCBOR = E.encodeBool


--------------------------------------------------------------------------------
-- Numeric data
--------------------------------------------------------------------------------

instance EncCBOR Integer where
  encCBOR = E.encodeInteger

instance EncCBOR Word where
  encCBOR = E.encodeWord

instance EncCBOR Word8 where
  encCBOR = E.encodeWord8

instance EncCBOR Word16 where
  encCBOR = E.encodeWord16

instance EncCBOR Word32 where
  encCBOR = E.encodeWord32

instance EncCBOR Word64 where
  encCBOR = E.encodeWord64

instance EncCBOR Int where
  encCBOR = E.encodeInt

instance EncCBOR Int32 where
  encCBOR = E.encodeInt32

instance EncCBOR Int64 where
  encCBOR = E.encodeInt64

instance EncCBOR Float where
  encCBOR = E.encodeFloat

instance EncCBOR Double where
  encCBOR = E.encodeDouble

instance EncCBOR a => EncCBOR (Ratio a) where
  encCBOR r = E.encodeListLen 2 <> encCBOR (numerator r) <> encCBOR (denominator r)

instance EncCBOR Nano where
  encCBOR (MkFixed nanoseconds) = encCBOR nanoseconds

instance EncCBOR Pico where
  encCBOR (MkFixed picoseconds) = encCBOR picoseconds

-- | For backwards compatibility we round pico precision to micro
instance EncCBOR NominalDiffTime where
  encCBOR = encCBOR . (`div` 1e6) . toPicoseconds
   where
    toPicoseconds :: NominalDiffTime -> Integer
    toPicoseconds t =
      numerator (toRational t * toRational (resolution $ Proxy @E12))

instance EncCBOR Natural where
  encCBOR = encCBOR . toInteger

instance EncCBOR Void where
  encCBOR = absurd


--------------------------------------------------------------------------------
-- Tagged
--------------------------------------------------------------------------------

instance (Typeable s, EncCBOR a) => EncCBOR (Tagged s a) where
  encCBOR (Tagged a) = encCBOR a


--------------------------------------------------------------------------------
-- Containers
--------------------------------------------------------------------------------

instance (EncCBOR a, EncCBOR b) => EncCBOR (a,b) where
  encCBOR (a, b) = E.encodeListLen 2 <> encCBOR a <> encCBOR b

instance (EncCBOR a, EncCBOR b, EncCBOR c) => EncCBOR (a,b,c) where
  encCBOR (a, b, c) = E.encodeListLen 3 <> encCBOR a <> encCBOR b <> encCBOR c

instance (EncCBOR a, EncCBOR b, EncCBOR c, EncCBOR d) => EncCBOR (a,b,c,d) where
  encCBOR (a, b, c, d) =
    E.encodeListLen 4 <> encCBOR a <> encCBOR b <> encCBOR c <> encCBOR d

instance
  (EncCBOR a, EncCBOR b, EncCBOR c, EncCBOR d, EncCBOR e)
  => EncCBOR (a, b, c, d, e)
 where
  encCBOR (a, b, c, d, e) =
    E.encodeListLen 5
      <> encCBOR a
      <> encCBOR b
      <> encCBOR c
      <> encCBOR d
      <> encCBOR e

instance
  (EncCBOR a, EncCBOR b, EncCBOR c, EncCBOR d, EncCBOR e, EncCBOR f, EncCBOR g)
  => EncCBOR (a, b, c, d, e, f, g)
  where
  encCBOR (a, b, c, d, e, f, g) =
    E.encodeListLen 7
      <> encCBOR a
      <> encCBOR b
      <> encCBOR c
      <> encCBOR d
      <> encCBOR e
      <> encCBOR f
      <> encCBOR g

instance EncCBOR BS.ByteString where
  encCBOR = E.encodeBytes

instance EncCBOR Text.Text where
  encCBOR = E.encodeString

instance EncCBOR SBS.ShortByteString where
  encCBOR sbs@(SBS ba) =
    E.encodeByteArray $ BAS.SBA (Prim.ByteArray ba) 0 (SBS.length sbs)

instance EncCBOR BS.Lazy.ByteString where
  encCBOR = encCBOR . BS.Lazy.toStrict

instance EncCBOR a => EncCBOR [a] where
  encCBOR xs = E.encodeListLenIndef <> foldr (\x r -> encCBOR x <> r) E.encodeBreak xs

instance (EncCBOR a, EncCBOR b) => EncCBOR (Either a b) where
  encCBOR (Left  x) = E.encodeListLen 2 <> E.encodeWord 0 <> encCBOR x
  encCBOR (Right x) = E.encodeListLen 2 <> E.encodeWord 1 <> encCBOR x

instance EncCBOR a => EncCBOR (NonEmpty a) where
  encCBOR = encCBOR . toList

instance EncCBOR a => EncCBOR (Maybe a) where
  encCBOR = encMaybe encCBOR

instance EncCBOR a => EncCBOR (Seq.Seq a) where
  encCBOR = encSeq encCBOR

encSeq :: (a -> Encoding) -> Seq.Seq a -> Encoding
encSeq encValue f = variableListLenEncoding (Seq.length f) (foldMap' encValue f)
{-# INLINE encSeq #-}

exactListLenEncoding :: Int -> Encoding -> Encoding
exactListLenEncoding len contents =
  encodeListLen (fromIntegral len :: Word) <> contents
{-# INLINE exactListLenEncoding #-}

-- | Conditionally use variable length encoding for list like structures with length
-- larger than 23, otherwise use exact list length encoding.
variableListLenEncoding ::
  -- | Number of elements in the encoded data structure.
  Int ->
  -- | Encoding for the actual data structure
  Encoding ->
  Encoding
variableListLenEncoding len contents =
  if len <= lengthThreshold
    then exactListLenEncoding len contents
    else encodeListLenIndef <> contents <> encodeBreak
  where
    lengthThreshold = 23
{-# INLINE variableListLenEncoding #-}

encMaybe :: (a -> Encoding) -> Maybe a -> Encoding
encMaybe encodeA = \case
  Nothing -> E.encodeListLen 0
  Just x  -> E.encodeListLen 1 <> encodeA x

-- | Alternative way to encode a Maybe type.
--
-- /Note/ - this is not the default method for encoding `Maybe`, use `encodeMaybe` instead
encNullMaybe :: (a -> Encoding) -> Maybe a -> Encoding
encNullMaybe encodeValue = \case
  Nothing -> encodeNull
  Just x -> encodeValue x

encodeContainerSkel
  :: (Word -> E.Encoding)
  -> (container -> Int)
  -> (accumFunc -> E.Encoding -> container -> E.Encoding)
  -> accumFunc
  -> container
  -> E.Encoding
encodeContainerSkel encodeLen size foldFunction f c =
  encodeLen (fromIntegral (size c)) <> foldFunction f mempty c
{-# INLINE encodeContainerSkel #-}

encodeMapSkel
  :: (EncCBOR k, EncCBOR v)
  => (m -> Int)
  -> ((k -> v -> E.Encoding -> E.Encoding) -> E.Encoding -> m -> E.Encoding)
  -> m
  -> E.Encoding
encodeMapSkel size foldrWithKey = encodeContainerSkel
  E.encodeMapLen
  size
  foldrWithKey
  (\k v b -> encCBOR k <> encCBOR v <> b)
{-# INLINE encodeMapSkel #-}

instance (EncCBOR k, EncCBOR v) => EncCBOR (M.Map k v) where
  encCBOR = encodeMapSkel M.size M.foldrWithKey

encodeSetSkel
  :: EncCBOR a
  => (s -> Int)
  -> ((a -> E.Encoding -> E.Encoding) -> E.Encoding -> s -> E.Encoding)
  -> s
  -> E.Encoding
encodeSetSkel size foldFunction = mappend encodeSetTag . encodeContainerSkel
  E.encodeListLen
  size
  foldFunction
  (\a b -> encCBOR a <> b)
{-# INLINE encodeSetSkel #-}

-- We stitch a `258` in from of a (Hash)Set, so that tools which
-- programmatically check for canonicity can recognise it from a normal
-- array. Why 258? This will be formalised pretty soon, but IANA allocated
-- 256...18446744073709551615 to "First come, first served":
-- https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml Currently `258` is
-- the first unassigned tag and as it requires 2 bytes to be encoded, it sounds
-- like the best fit.
setTag :: Word
setTag = 258

encodeSetTag :: E.Encoding
encodeSetTag = E.encodeTag setTag

instance EncCBOR a => EncCBOR (S.Set a) where
  encCBOR = encodeSetSkel S.size S.foldr

-- | Generic encoder for vectors. Its intended use is to allow easy
-- definition of 'Serialise' instances for custom vector
encodeVector :: (EncCBOR a, Vector.Generic.Vector v a) => v a -> E.Encoding
encodeVector = encodeContainerSkel
  E.encodeListLen
  Vector.Generic.length
  Vector.Generic.foldr
  (\a b -> encCBOR a <> b)
{-# INLINE encodeVector #-}


instance (EncCBOR a) => EncCBOR (Vector.Vector a) where
  encCBOR = encodeVector
  {-# INLINE encCBOR #-}


--------------------------------------------------------------------------------
-- Time
--------------------------------------------------------------------------------

instance EncCBOR UTCTime where
  encCBOR (UTCTime day timeOfDay) = mconcat [
      encodeListLen 3
    , encodeInteger year
    , encodeInt dayOfYear
    , encodeInteger timeOfDayPico
    ]
    where
      (year, dayOfYear) = toOrdinalDate day
      timeOfDayPico = diffTimeToPicoseconds timeOfDay
