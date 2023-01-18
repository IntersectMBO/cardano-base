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
  ( ToCBOR(..)
  , module E
  , toCBORMaybe
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
import Data.Fixed (E12, Fixed(..), Nano, Pico, resolution)
import Data.Foldable (toList)
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

class Typeable a => ToCBOR a where
  toCBOR :: a -> Encoding

--------------------------------------------------------------------------------
-- Primitive types
--------------------------------------------------------------------------------

instance ToCBOR () where
  toCBOR = const E.encodeNull

instance ToCBOR Bool where
  toCBOR = E.encodeBool


--------------------------------------------------------------------------------
-- Numeric data
--------------------------------------------------------------------------------

instance ToCBOR Integer where
  toCBOR = E.encodeInteger

instance ToCBOR Word where
  toCBOR = E.encodeWord

instance ToCBOR Word8 where
  toCBOR = E.encodeWord8

instance ToCBOR Word16 where
  toCBOR = E.encodeWord16

instance ToCBOR Word32 where
  toCBOR = E.encodeWord32

instance ToCBOR Word64 where
  toCBOR = E.encodeWord64

instance ToCBOR Int where
  toCBOR = E.encodeInt

instance ToCBOR Float where
  toCBOR = E.encodeFloat

instance ToCBOR Int32 where
  toCBOR = E.encodeInt32

instance ToCBOR Int64 where
  toCBOR = E.encodeInt64

instance ToCBOR a => ToCBOR (Ratio a) where
  toCBOR r = E.encodeListLen 2 <> toCBOR (numerator r) <> toCBOR (denominator r)

instance ToCBOR Nano where
  toCBOR (MkFixed nanoseconds) = toCBOR nanoseconds

instance ToCBOR Pico where
  toCBOR (MkFixed picoseconds) = toCBOR picoseconds

-- | For backwards compatibility we round pico precision to micro
instance ToCBOR NominalDiffTime where
  toCBOR = toCBOR . (`div` 1e6) . toPicoseconds
   where
    toPicoseconds :: NominalDiffTime -> Integer
    toPicoseconds t =
      numerator (toRational t * toRational (resolution $ Proxy @E12))

instance ToCBOR Natural where
  toCBOR = toCBOR . toInteger

instance ToCBOR Void where
  toCBOR = absurd


--------------------------------------------------------------------------------
-- Tagged
--------------------------------------------------------------------------------

instance (Typeable s, ToCBOR a) => ToCBOR (Tagged s a) where
  toCBOR (Tagged a) = toCBOR a


--------------------------------------------------------------------------------
-- Containers
--------------------------------------------------------------------------------

instance (ToCBOR a, ToCBOR b) => ToCBOR (a,b) where
  toCBOR (a, b) = E.encodeListLen 2 <> toCBOR a <> toCBOR b

instance (ToCBOR a, ToCBOR b, ToCBOR c) => ToCBOR (a,b,c) where
  toCBOR (a, b, c) = E.encodeListLen 3 <> toCBOR a <> toCBOR b <> toCBOR c

instance (ToCBOR a, ToCBOR b, ToCBOR c, ToCBOR d) => ToCBOR (a,b,c,d) where
  toCBOR (a, b, c, d) =
    E.encodeListLen 4 <> toCBOR a <> toCBOR b <> toCBOR c <> toCBOR d

instance
  (ToCBOR a, ToCBOR b, ToCBOR c, ToCBOR d, ToCBOR e)
  => ToCBOR (a, b, c, d, e)
 where
  toCBOR (a, b, c, d, e) =
    E.encodeListLen 5
      <> toCBOR a
      <> toCBOR b
      <> toCBOR c
      <> toCBOR d
      <> toCBOR e

instance
  (ToCBOR a, ToCBOR b, ToCBOR c, ToCBOR d, ToCBOR e, ToCBOR f, ToCBOR g)
  => ToCBOR (a, b, c, d, e, f, g)
  where
  toCBOR (a, b, c, d, e, f, g) =
    E.encodeListLen 7
      <> toCBOR a
      <> toCBOR b
      <> toCBOR c
      <> toCBOR d
      <> toCBOR e
      <> toCBOR f
      <> toCBOR g

instance ToCBOR BS.ByteString where
  toCBOR = E.encodeBytes

instance ToCBOR Text.Text where
  toCBOR = E.encodeString

instance ToCBOR SBS.ShortByteString where
  toCBOR sbs@(SBS ba) =
    E.encodeByteArray $ BAS.SBA (Prim.ByteArray ba) 0 (SBS.length sbs)

instance ToCBOR BS.Lazy.ByteString where
  toCBOR = toCBOR . BS.Lazy.toStrict

instance ToCBOR a => ToCBOR [a] where
  toCBOR xs = E.encodeListLenIndef <> foldr (\x r -> toCBOR x <> r) E.encodeBreak xs

instance (ToCBOR a, ToCBOR b) => ToCBOR (Either a b) where
  toCBOR (Left  x) = E.encodeListLen 2 <> E.encodeWord 0 <> toCBOR x
  toCBOR (Right x) = E.encodeListLen 2 <> E.encodeWord 1 <> toCBOR x

instance ToCBOR a => ToCBOR (NonEmpty a) where
  toCBOR = toCBOR . toList

instance ToCBOR a => ToCBOR (Maybe a) where
  toCBOR = toCBORMaybe toCBOR

toCBORMaybe :: (a -> Encoding) -> Maybe a -> Encoding
toCBORMaybe encodeA = \case
  Nothing -> E.encodeListLen 0
  Just x  -> E.encodeListLen 1 <> encodeA x

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
  :: (ToCBOR k, ToCBOR v)
  => (m -> Int)
  -> ((k -> v -> E.Encoding -> E.Encoding) -> E.Encoding -> m -> E.Encoding)
  -> m
  -> E.Encoding
encodeMapSkel size foldrWithKey = encodeContainerSkel
  E.encodeMapLen
  size
  foldrWithKey
  (\k v b -> toCBOR k <> toCBOR v <> b)
{-# INLINE encodeMapSkel #-}

instance (ToCBOR k, ToCBOR v) => ToCBOR (M.Map k v) where
  toCBOR = encodeMapSkel M.size M.foldrWithKey

encodeSetSkel
  :: ToCBOR a
  => (s -> Int)
  -> ((a -> E.Encoding -> E.Encoding) -> E.Encoding -> s -> E.Encoding)
  -> s
  -> E.Encoding
encodeSetSkel size foldFunction = mappend encodeSetTag . encodeContainerSkel
  E.encodeListLen
  size
  foldFunction
  (\a b -> toCBOR a <> b)
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

instance ToCBOR a => ToCBOR (S.Set a) where
  toCBOR = encodeSetSkel S.size S.foldr

-- | Generic encoder for vectors. Its intended use is to allow easy
-- definition of 'Serialise' instances for custom vector
encodeVector :: (ToCBOR a, Vector.Generic.Vector v a) => v a -> E.Encoding
encodeVector = encodeContainerSkel
  E.encodeListLen
  Vector.Generic.length
  Vector.Generic.foldr
  (\a b -> toCBOR a <> b)
{-# INLINE encodeVector #-}


instance (ToCBOR a) => ToCBOR (Vector.Vector a) where
  toCBOR = encodeVector
  {-# INLINE toCBOR #-}


--------------------------------------------------------------------------------
-- Time
--------------------------------------------------------------------------------

instance ToCBOR UTCTime where
  toCBOR (UTCTime day timeOfDay) = mconcat [
      encodeListLen 3
    , encodeInteger year
    , encodeInt dayOfYear
    , encodeInteger timeOfDayPico
    ]
    where
      (year, dayOfYear) = toOrdinalDate day
      timeOfDayPico = diffTimeToPicoseconds timeOfDay
