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
  numSetBits,
  sizeInBytes,
) where

import Control.DeepSeq (NFData)
import Control.Monad (forM_, when)
import Data.Array.Byte (ByteArray)
import Data.Bits (countTrailingZeros, popCount, setBit, shiftR, testBit, (.&.))
import Data.List (dropWhileEnd)
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
  | used > 0 && highestIndex >= n = Nothing
  | used == size = Just (Bitmap ba)
  | otherwise = Just (Bitmap (cloneByteArray ba 0 used))
  where
    n = capacity (Proxy @n)
    nBytes = (n + 7) `quot` 8
    size = sizeofByteArray ba
    used = length (dropWhileEnd (== 0) [indexByteArray @Word8 ba i | i <- [0 .. size - 1]])
    highestIndex = 8 * used - 1 - countTrailingZeros (indexByteArray @Word8 ba (used - 1))

-- | Construct a bitmap with the given indices set. Indices outside the
-- capacity @[0, n)@ are ignored.
fromIndices :: forall n. KnownNat n => [Int] -> Bitmap n
fromIndices flipped = Bitmap $ runByteArray $ do
  mba <- newByteArray nBytes
  fillByteArray mba 0 nBytes 0
  forM_ flipped $ \i ->
    when (i >= 0 && i < n) $ do
      let byteIx = i `shiftR` 3
          bitIx = 7 - (i .&. 7)
      w <- readByteArray @Word8 mba byteIx
      writeByteArray mba byteIx (w `setBit` bitIx)
  pure mba
  where
    n = capacity (Proxy @n)
    -- Only as many bytes as the highest index in capacity needs.
    nBytes = maximum (0 : [i `shiftR` 3 + 1 | i <- flipped, i >= 0, i < n])

-- | The indices set in the bitmap, in ascending order.
toIndices :: Bitmap n -> [Int]
toIndices (Bitmap ba) =
  [ i
  | byteIx <- [0 .. sizeofByteArray ba - 1]
  , let w = indexByteArray ba byteIx :: Word8
  , bitIx <- [0 .. 7]
  , testBit w (7 - bitIx)
  , let i = byteIx * 8 + bitIx
  ]
