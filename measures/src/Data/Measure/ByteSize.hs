{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DerivingVia                #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeApplications           #-}

-- | A measure for practical byte sizes.
--
-- 'ByteSize' is for summation, which might overflow. The other types are for
-- storing, serializing, comparing, etc the results of calculations that did
-- not overflow.
--
-- Import this module qualified.
--
-- > import           Data.Measure.ByteSize (ByteSize)
-- > import qualified Data.Measure.ByteSize as ByteSize
module Data.Measure.ByteSize (
    ByteSize,
    -- * Observers
    compare,
    isOverflowed,
    -- * Safe result types
    ByteSize8 (ByteSize8, unByteSize8),
    ByteSize16 (ByteSize16, unByteSize16),
    ByteSize32 (ByteSize32, unByteSize32),
    ByteSize64 (ByteSize64, unByteSize64),
    -- * Conversions
    ByteSizeFrom,
    ByteSizePartialFrom,
    ByteSizeTo,
    from,
    partialFrom,
    partialFromDefault,
    to,
    -- * Unstable and unsafe
    unsafeCoercionWord64,
  ) where

import           Cardano.Binary (FromCBOR, ToCBOR)
import           Control.DeepSeq (NFData)
import           Data.Coerce (coerce)
import           Data.DerivingVia (InstantiatedAt (InstantiatedAt))
import           Data.Int (Int8, Int16, Int32, Int64)
import           Data.Maybe.Strict (StrictMaybe (..))
import           Data.Measure (BoundedMeasure, Measure)
import qualified Data.Measure as Measure
import           Data.Type.Coercion (Coercion (Coercion))
import           Data.Word (Word8, Word16, Word32, Word64)
import           GHC.Generics (Generic)
#if __GLASGOW_HASKELL__ < 900
-- Use the GHC version here because this is compiler dependent, and only indirectly lib dependent.
import           GHC.Natural (Natural)
#endif
import           NoThunks.Class (NoThunks,
                     OnlyCheckWhnfNamed (OnlyCheckWhnfNamed))
import           Prelude hiding (compare, fromInteger, toInteger)
import qualified Prelude
import           Quiet (Quiet (Quiet))

-- | A measure of byte size
--
-- INVARIANT @   0   <=   x   <=   2^64 - 2   @
--
-- Note well that the uppermost value is reserved for representing overflow:
-- there's a minus 2 in the invariant instead of the usual minus 1.
--
-- This type supports exactly one binary operator, checked addition, via
-- 'Semigroup'. (Recall that 'Data.Semigroup.stimes' automatically derives
-- non-negative integer scaling from 'Semigroup'.)
--
-- Given that the estimated total global data storage in 2024 is merely 5000
-- times the maximum representable value of this type, this representation
-- should suffice for the chain's actual needs for a long time. It's only bugs
-- and/or attack vectors that will incur overflows here. Even so, it's
-- important to detect and handle those cases.
--
-- No 'Eq' and 'Ord'. This is not a /saturated arithmetic/ type, and so two
-- overflows are not considered equivalent. This prohibits lawful instances of
-- 'Eq' and 'Ord' (eg this type's arithmetic comparisons are not reflexive).
--
-- No 'Enum' or 'Num'. We do not support 'Num' because we don't want all those
-- operators. Moreover, we don't want bare literals, so no 'Enum'. Literals
-- must explicitly include a constructor, such as @ByteSize.'from'@ or
-- @ByteSize.'maybeByteSizeFrom'@.
--
-- We in particular exclude subtraction because a representation of both
-- underflows and overflows would in turn require a representation for the sum
-- of those, which could not be usefully ordered --- it's essentially NaN. Such
-- an indeterminate would make it confusing to write (useful) monotonic
-- predicates over this type, eg when using it as a measure in finger trees.
--
-- No 'FromCBOR' and 'ToCBOR'. Every measure being sent across the network
-- should fit in a smaller type ('ByteSize8', 'ByteSize16', or 'ByteSize32'),
-- moreover, those types do not need to represent an overflow.
--
-- TODO pointer tagging might achieve comparable performance without reserving
-- the @2^63 - 1@ value, which is likely to cause /some/ confusion. But then it
-- would no longer be compatible with the @UNPACK@ pragma, for example.
newtype ByteSize = ByteSize Word64   -- ^ See the type's Haddock.
  deriving stock   (Read, Show)
  deriving newtype (NFData)
  deriving         (Bounded, Monoid, Semigroup)
           via         InstantiatedAt Measure ByteSize
  deriving         (NoThunks)
           via         OnlyCheckWhnfNamed "ByteSize" ByteSize

-- | Not part of the stable interface! Use at your own risk.
unsafeCoercionWord64 :: Coercion ByteSize Word64
unsafeCoercionWord64 = Coercion

-- | This sentinel value represents the result of overflow.
sentinel :: Word64
sentinel = maxBound

instance Measure ByteSize where
    max = coerce $ max @Word64
    min = coerce $ min @Word64

    plus (ByteSize x) (ByteSize y) =
        let !z = x + y
        in
        -- obviously equivalent to sentinel <= x + y, but avoids boundaries
        ByteSize $ if sentinel - x <= y then sentinel else z

    zero = ByteSize 0

instance BoundedMeasure ByteSize where
    maxBound = ByteSize sentinel

--------------------------------------------------------------------------------
-- Observers
--------------------------------------------------------------------------------

isOverflowed :: ByteSize -> Bool
isOverflowed (ByteSize x) = x == sentinel

-- | Returns 'SNothing' if and only if both values were overflowed.
compare :: ByteSize -> ByteSize -> StrictMaybe Ordering
compare (ByteSize x) (ByteSize y) = case Prelude.compare x y of
    LT -> SJust LT
    EQ -> if x == sentinel then SNothing else SJust EQ
    GT -> SJust GT

--------------------------------------------------------------------------------
-- Safe result types
--------------------------------------------------------------------------------

-- | The types 'ByteSize8', 'ByteSize16', 'ByteSize32', and 'ByteSize64' safely
-- capture the result of 'ByteSize' calculations that did not overflow
-- 'ByteSize' /and/ fit in the type.
--
-- They intentionally have no operators! All calculations should be done in
-- 'ByteSize'.
newtype ByteSize8 = ByteSize8 { unByteSize8 :: Word8 }
    -- ^ See the type's Haddock.
  deriving stock   (Generic)
  deriving stock   (Eq, Ord)
  deriving newtype (Bounded)
  deriving newtype (NFData)
  deriving newtype (FromCBOR, ToCBOR)
  deriving         (Read, Show)
           via         Quiet ByteSize8
  deriving         (NoThunks)
           via         OnlyCheckWhnfNamed "ByteSize8" ByteSize8

-- | See the documentation on 'ByteSize8'.
newtype ByteSize16 = ByteSize16 { unByteSize16 :: Word16 }
    -- ^ See the documentation on 'ByteSize8'.
  deriving stock   (Generic)
  deriving stock   (Eq, Ord)
  deriving newtype (Bounded)
  deriving newtype (NFData)
  deriving newtype (FromCBOR, ToCBOR)
  deriving         (Read, Show)
           via         Quiet ByteSize16
  deriving         (NoThunks)
           via         OnlyCheckWhnfNamed "ByteSize16" ByteSize16

-- | See the documentation on 'ByteSize8'
newtype ByteSize32 = ByteSize32 { unByteSize32 :: Word32 }
    -- ^ See the documentation on 'ByteSize8'.
  deriving stock   (Generic)
  deriving stock   (Eq, Ord)
  deriving newtype (Bounded)
  deriving newtype (NFData)
  deriving newtype (FromCBOR, ToCBOR)
  deriving         (Read, Show)
           via         Quiet ByteSize32
  deriving         (NoThunks)
           via         OnlyCheckWhnfNamed "ByteSize32" ByteSize32

-- | See the documentation on 'ByteSize8'
newtype ByteSize64 = ByteSize64 { unByteSize64 :: Word64 }
    -- ^ See the documentation on 'ByteSize8'.
  deriving stock   (Generic)
  deriving stock   (Eq, Ord)
  deriving newtype (Bounded)
  deriving newtype (NFData)
  deriving newtype (FromCBOR, ToCBOR)
  deriving         (Read, Show)
           via         Quiet ByteSize64
  deriving         (NoThunks)
           via         OnlyCheckWhnfNamed "ByteSize64" ByteSize64

--------------------------------------------------------------------------------
-- Conversions
--------------------------------------------------------------------------------

-- | Types where every value can be decidably classified as one of the following.
--
--   - An integer within the INVARIANT interval of 'ByteSize'.
--   - An integer greater than the INVARIANT interval of 'ByteSize'.
--   - Neither of those. For example, negative numbers, fractions, orange, etc.
--
-- Law: 'partialFrom' returns 'SNothing' only in the third case above.
--
-- Law: 'partialFrom' returns 'SJust' an overflow if and only if the second
-- case above.
class ByteSizePartialFrom a where
    -- | See 'ByteSizePartialFrom'.
    partialFrom :: a -> StrictMaybe ByteSize

partialFromDefault :: ByteSizeFrom a => a -> StrictMaybe ByteSize
partialFromDefault = SJust . from

-- | Law: @'partialFrom' = 'SJust' . 'from'@
class ByteSizePartialFrom a => ByteSizeFrom a where
    -- | See 'ByteSizeFrom'.
    from :: a -> ByteSize

-- | Returns 'SNothing' if and only if the 'ByteSize' cannot fit in the other
-- type, assuming an overflowed 'ByteSize' cannot fit into any type.
--
-- Because 'from' and 'partialFrom' might overflow, which loses information, it
-- is not required that @'partialFrom' x >>= 'to' = 'SJust' x@; 'to' is not
-- quite an inverse of 'from' and 'partialFrom'.
--
-- Law: @'to' x = 'SJust' y@ implies @'SJust' x = 'partialFrom' y@.
class ByteSizePartialFrom a => ByteSizeTo a where
    -- | See 'ByteSizeTo'.
    to :: ByteSize -> StrictMaybe a

instance ByteSizePartialFrom ByteSize8 where partialFrom = partialFromDefault
instance ByteSizeFrom        ByteSize8 where from        = from . unByteSize8
instance ByteSizeTo          ByteSize8 where to          = fmap ByteSize8 . to

instance ByteSizePartialFrom ByteSize16 where partialFrom = partialFromDefault
instance ByteSizeFrom        ByteSize16 where from        = from . unByteSize16
instance ByteSizeTo          ByteSize16 where to          = fmap ByteSize16 . to

instance ByteSizePartialFrom ByteSize32 where partialFrom = partialFromDefault
instance ByteSizeFrom        ByteSize32 where from        = from . unByteSize32
instance ByteSizeTo          ByteSize32 where to          = fmap ByteSize32 . to

instance ByteSizePartialFrom ByteSize64 where partialFrom = partialFromDefault
instance ByteSizeFrom        ByteSize64 where from        = from . unByteSize64
-- | NB the result will never be @'SJust' 'maxBound'@.
instance ByteSizeTo          ByteSize64 where to          = fmap ByteSize64 . to

instance ByteSizePartialFrom Word where partialFrom = partialFromDefault
instance ByteSizeFrom        Word where from        = ByteSize . fromIntegral
instance ByteSizeTo          Word where to          = toSmallerBoundedIntegral   -- also works if its bigger, ie Word64

instance ByteSizePartialFrom Word8 where partialFrom = partialFromDefault
instance ByteSizeFrom        Word8 where from        = fromSmallerUnsignedIntegral
instance ByteSizeTo          Word8 where to          = toSmallerBoundedIntegral

instance ByteSizePartialFrom Word16 where partialFrom = partialFromDefault
instance ByteSizeFrom        Word16 where from        = fromSmallerUnsignedIntegral
instance ByteSizeTo          Word16 where to          = toSmallerBoundedIntegral

instance ByteSizePartialFrom Word32 where partialFrom = partialFromDefault
instance ByteSizeFrom        Word32 where from        = fromSmallerUnsignedIntegral
instance ByteSizeTo          Word32 where to          = toSmallerBoundedIntegral

instance ByteSizePartialFrom Word64 where partialFrom = partialFromDefault
instance ByteSizeFrom        Word64 where from        = coerce
-- | NB the result will never be @'SJust' 'maxBound'@.
instance ByteSizeTo          Word64 where to          = toBiggerIntegral

instance ByteSizePartialFrom Natural where partialFrom = partialFromDefault
instance ByteSizeFrom        Natural where
    from a =
        ByteSize
      $ if fromIntegral sentinel <= a then sentinel else fromIntegral a
instance ByteSizeTo          Natural where to = toBiggerIntegral

instance ByteSizePartialFrom Integer where
    partialFrom a =
        if a < 0 || fromIntegral sentinel <= a then SNothing else
        SJust $ ByteSize $ Prelude.fromInteger a
instance ByteSizeTo          Integer where to = toBiggerIntegral

instance ByteSizePartialFrom Int where partialFrom = fromSmallerSignedIntegral
instance ByteSizeTo          Int where to          = toSmallerBoundedIntegral   -- even Int64 is smaller

instance ByteSizePartialFrom Int8 where partialFrom = fromSmallerSignedIntegral
instance ByteSizeTo          Int8 where to          = toSmallerBoundedIntegral

instance ByteSizePartialFrom Int16 where partialFrom = fromSmallerSignedIntegral
instance ByteSizeTo          Int16 where to          = toSmallerBoundedIntegral

instance ByteSizePartialFrom Int32 where partialFrom = fromSmallerSignedIntegral
instance ByteSizeTo          Int32 where to          = toSmallerBoundedIntegral

instance ByteSizePartialFrom Int64 where partialFrom = fromSmallerSignedIntegral
instance ByteSizeTo          Int64 where to          = toSmallerBoundedIntegral

fromSmallerUnsignedIntegral :: Integral a => a -> ByteSize
fromSmallerUnsignedIntegral = ByteSize . fromIntegral

fromSmallerSignedIntegral :: Integral a => a -> StrictMaybe ByteSize
fromSmallerSignedIntegral a =
    if a < 0 then SNothing else SJust $ ByteSize $ fromIntegral a

toBiggerIntegral :: Integral a => ByteSize -> StrictMaybe a
toBiggerIntegral (ByteSize x) =
    if sentinel == x then SNothing else SJust $ fromIntegral x

toSmallerBoundedIntegral :: forall a. (Bounded a, Integral a) => ByteSize -> StrictMaybe a
toSmallerBoundedIntegral (ByteSize x) =
    if overflow || tooBig then SNothing else SJust $ fromIntegral x
  where
    !tooBig   = fromIntegral (maxBound :: a) < x
    !overflow = sentinel == x
