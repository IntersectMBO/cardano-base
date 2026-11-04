{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeApplications #-}

-- | A compact bitmap over a 'ByteArray' based on the Leios certificate signers
-- bitfield representation (CIP-164)
--
-- NOTE: this module is meant to be imported qualified.
module Data.Bitmap (
  Bitmap (..),
  numBytes,
  sizeInBytes,
  fromIndices,
  toIndices,
  numSetBits,
  wellFormed,
) where

import Control.DeepSeq (NFData)
import Control.Monad (forM_, when)
import Data.Array.Byte (ByteArray)
import Data.Bits (complement, popCount, setBit, shiftR, testBit, unsafeShiftL, (.&.))
import Data.Primitive.ByteArray (
  fillByteArray,
  indexByteArray,
  newByteArray,
  readByteArray,
  runByteArray,
  sizeofByteArray,
  writeByteArray,
 )
import Data.Word (Word8)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

-- | A bitmap over a number of indexes known to its users: @⌈n/8⌉@ bytes,
-- MSB-first, bit @i@ set iff index @i@ is set.
newtype Bitmap = Bitmap {bitmapBytes :: ByteArray}
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NFData)
  deriving (NoThunks) via OnlyCheckWhnfNamed "Bitmap" Bitmap

-- | The number of indexes set (flipped to 1) in the bitmap.
numSetBits :: Bitmap -> Int
numSetBits (Bitmap ba) =
  sum
    [ popCount (indexByteArray ba i :: Word8)
    | i <- [0 .. sizeofByteArray ba - 1]
    ]

-- | The number of bytes of a bitmap over the given number of indexes.
numBytes :: Int -> Int
numBytes n = (n + 7) `quot` 8

-- | The number of bytes of a bitmap.
sizeInBytes :: Bitmap -> Int
sizeInBytes = sizeofByteArray . bitmapBytes

lastByteMask :: Int -> Word8
lastByteMask n =
  complement (fromIntegral ((1 :: Int) `unsafeShiftL` (7 - (n - 1) `rem` 8)) - 1)

-- | Construct a bitmap over the given number of indexes from a list of indexes
-- that should be set (flipped to 1).
fromIndices :: Int -> [Int] -> Bitmap
fromIndices n flipped = Bitmap $ runByteArray $ do
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
    nBytes = numBytes (max 0 n)

-- | Retrieve all indexes that are set (flipped to 1) in a bitmap over the given
-- number of indexes, in ascending order.
toIndices :: Int -> Bitmap -> [Int]
toIndices n (Bitmap ba) =
  [ i
  | byteIx <- [0 .. sizeofByteArray ba - 1]
  , let w = indexByteArray ba byteIx :: Word8
  , bitIx <- [0 .. 7]
  , let i = byteIx * 8 + bitIx
  , i < n
  , testBit w (7 - bitIx)
  ]

-- | Whether a bitmap is well-formed over the given number of indexes: it has
-- the expected length and no bit set beyond the last index.
wellFormed :: Int -> Bitmap -> Bool
wellFormed n (Bitmap ba)
  | n <= 0 = False
  | sizeofByteArray ba /= numBytes n = False
  | indexByteArray @Word8 ba (numBytes n - 1) .&. complement (lastByteMask n) /= 0 = False
  | otherwise = True
