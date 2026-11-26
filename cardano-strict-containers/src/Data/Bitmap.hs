{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | A compact bitmap over a 'ByteArray' based on the Leios certificate signers
-- bitfield representation (CIP-164).
--
-- A @'Bitmap' n@ can hold the indices @[0, n)@: @n@ is its /capacity/, an
-- upper bound fixed by the type, not its /population/, the number of indices
-- actually set ('numSetBits').
--
-- NOTE: this module is meant to be imported qualified.
module Data.Bitmap (
  NumBits,
  Bitmap,
  fromIndices,
  fromByteArray,
  toByteArray,
  toIndices,
  maxSetIndex,
  numSetBits,
  sizeInBytes,
) where

import Control.DeepSeq (NFData)
import Control.Monad (forM_)
import Data.Array.Byte (ByteArray)
import Data.Bits (countTrailingZeros, popCount, setBit, testBit)
import Data.IntSet (IntSet)
import qualified Data.IntSet as IntSet
import Data.Primitive.ByteArray (
  cloneByteArray,
  fillByteArray,
  indexByteArray,
  newByteArray,
  readByteArray,
  runByteArray,
  sizeofByteArray,
  writeByteArray,
 )
import Data.Proxy (Proxy (..))
import Data.Word (Word8)
import GHC.Generics (Generic)
import GHC.TypeNats (KnownNat, natVal)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import Numeric.Natural (Natural)

-- | The kind of a bitmap's capacity in bits.
type NumBits = Natural

type role Bitmap nominal

-- | A bitmap with capacity for the indices @[0, n)@, MSB-first: bit @i@ is bit
-- @7 - (i mod 8)@ of byte @i \`div\` 8@.
--
-- The capacity @n@ only bounds the bitmap. Bytes past the end read as zero, so
-- a bitmap takes as many bytes as its highest set index needs: at most
-- @⌈n/8⌉@, never a trailing zero byte, and none at all when empty. Equal
-- bitmaps thus have equal bytes.
--
-- The constructor is hidden so every 'Bitmap' upholds this; build one with
-- 'fromIndices' or 'fromByteArray'.
newtype Bitmap (n :: NumBits) = Bitmap ByteArray
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NFData)
  deriving (NoThunks) via OnlyCheckWhnfNamed "Bitmap" (Bitmap n)

-- | The capacity of a @'Bitmap' n@ in bits: @n@, not the number of set bits.
capacity :: KnownNat n => proxy n -> Int
capacity = fromIntegral . natVal

-- | Number of bits set in the bitmap, its population.
numSetBits :: Bitmap n -> Int
numSetBits (Bitmap ba) =
  sum
    [ popCount (indexByteArray ba i :: Word8)
    | i <- [0 .. sizeofByteArray ba - 1]
    ]

-- | Number of bytes the bitmap occupies.
sizeInBytes :: Bitmap n -> Int
sizeInBytes = sizeofByteArray . toByteArray

-- | The bitmap's bytes, as 'fromByteArray' adopts them.
toByteArray :: Bitmap n -> ByteArray
toByteArray (Bitmap ba) = ba

-- | Adopt the bytes of a bitmap, as read off the wire, if they fit the
-- capacity @n@: at most @⌈n/8⌉@ bytes and no bit set at index @n@ or above.
-- Trailing zero bytes are accepted and dropped.
fromByteArray :: forall n. KnownNat n => ByteArray -> Maybe (Bitmap n)
fromByteArray ba
  | size > nBytes = Nothing
  | maybe False (>= n) (maxSetIndexIn ba used) = Nothing
  | used == size = Just (Bitmap ba)
  | otherwise = Just (Bitmap (cloneByteArray ba 0 used))
  where
    n = capacity (Proxy @n)
    nBytes = (n + 7) `quot` 8
    size = sizeofByteArray ba
    used = dropTrailingZeros size
    dropTrailingZeros k
      | k > 0 && indexByteArray @Word8 ba (k - 1) == 0 = dropTrailingZeros (k - 1)
      | otherwise = k

-- | The highest index set, or 'Nothing' when the bitmap is empty. O(1), so a
-- bound can be checked before decoding any index.
maxSetIndex :: Bitmap n -> Maybe Int
maxSetIndex (Bitmap ba) = maxSetIndexIn ba (sizeofByteArray ba)

-- | The highest index set in the first @used@ bytes, the last of which must
-- be non-zero.
maxSetIndexIn :: ByteArray -> Int -> Maybe Int
maxSetIndexIn ba used
  | used == 0 = Nothing
  | otherwise = Just (8 * used - 1 - countTrailingZeros (indexByteArray @Word8 ba (used - 1)))

-- | Construct a bitmap with the given indices set. Indices outside the
-- capacity @[0, n)@ are ignored.
fromIndices :: forall n. KnownNat n => IntSet -> Bitmap n
fromIndices indices = Bitmap $ runByteArray $ do
  mba <- newByteArray nBytes
  fillByteArray mba 0 nBytes 0
  forM_ (IntSet.toList inCapacity) $ \i -> do
    let byteIx = i `quot` 8
        bitIx = 7 - i `rem` 8
    w <- readByteArray @Word8 mba byteIx
    writeByteArray mba byteIx (w `setBit` bitIx)
  pure mba
  where
    inCapacity =
      IntSet.takeWhileAntitone (< capacity (Proxy @n)) $
        IntSet.dropWhileAntitone (< 0) indices
    -- Up to the byte holding the highest index in capacity.
    nBytes = case fst <$> IntSet.maxView inCapacity of
      Nothing -> 0
      Just i -> i `quot` 8 + 1

-- | The indices set in the bitmap.
toIndices :: Bitmap n -> IntSet
toIndices (Bitmap ba) =
  IntSet.fromDistinctAscList
    [ i
    | byteIx <- [0 .. sizeofByteArray ba - 1]
    , let w = indexByteArray ba byteIx :: Word8
    , bitIx <- [0 .. 7]
    , testBit w (7 - bitIx)
    , let i = byteIx * 8 + bitIx
    ]
