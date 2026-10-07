{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | A compact bitmap representation using serialisation-ready ByteStrings.
--
-- Adapted from @Cardano.Leios.BitMapPV@ in the @leios-wfa-ls-demo@ package.
--
-- NOTE: this module is meant to be imported qualified.
module Data.Bitmap (
  Bitmap (..),
  numBytes,
  fromIndices,
  toIndices,
  numSetBits,
  wellFormed,
) where

import Control.DeepSeq (NFData)
import Control.Monad (forM_, when)
import Data.Bits (
  clearBit,
  complement,
  countLeadingZeros,
  popCount,
  unsafeShiftL,
  (.&.),
  (.|.),
 )
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Internal as ByteString
import Data.Word (Word8)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Storable (peekByteOff, pokeByteOff)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

-- | A bitmap over a number of indexes known to its users: @⌈n/8⌉@ bytes,
-- MSB-first, bit @i@ set iff index @i@ is set.
newtype Bitmap = Bitmap {bitmapBytes :: ByteString}
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NFData)
  deriving (NoThunks) via OnlyCheckWhnfNamed "Bitmap" Bitmap

-- | The number of indexes set (flipped to 1) in the bitmap.
numSetBits :: Bitmap -> Int
numSetBits (Bitmap arr) =
  sum
    [ popCount (ByteString.index arr i)
    | i <- [0 .. ByteString.length arr - 1]
    ]

-- | The number of bytes of a bitmap over the given number of indexes.
numBytes :: Int -> Int
numBytes n = (n + 7) `quot` 8

lastByteMask :: Int -> Word8
lastByteMask n =
  complement (fromIntegral ((1 :: Int) `unsafeShiftL` (7 - (n - 1) `rem` 8)) - 1)

-- | Construct a bitmap over the given number of indexes from a list of indexes
-- that should be set (flipped to 1).
fromIndices :: Int -> [Int] -> Bitmap
fromIndices n flipped =
  Bitmap $
    ByteString.unsafeCreate nBytes $ \ptr -> do
      fillBytes ptr 0 nBytes
      forM_ flipped $ \i -> do
        when (i >= 0 && i <= maxI) $ do
          let !byteIx = i `quot` 8
          let !bitIx = 7 - i `rem` 8
          let !mask = bitMask bitIx
          w <- peekByteOff ptr byteIx :: IO Word8
          pokeByteOff ptr byteIx (w .|. mask)
  where
    !maxI = n - 1
    !nBytes = numBytes n

    bitMask k = fromIntegral ((1 :: Int) `unsafeShiftL` k)

-- | Retrieve all indexes that are set (flipped to 1) in a bitmap over the given
-- number of indexes, in ascending order.
toIndices :: Int -> Bitmap -> [Int]
toIndices n (Bitmap bitmap) =
  goBytes 0
  where
    !maxI = n - 1
    !nBytes = ByteString.length bitmap

    goBytes !byteIx
      | byteIx >= nBytes = []
      | otherwise =
          let !w = ByteString.index bitmap byteIx
           in goBits (byteIx * 8) w <> goBytes (byteIx + 1)

    goBits !_ 0 = []
    goBits !base !w =
      let !bitIx = countLeadingZeros w
          !i = base + bitIx
          !w' = clearBit w (7 - bitIx)
       in if i <= maxI
            then i : goBits base w'
            else []

-- | Whether a bitmap is well-formed over the given number of indexes: it has
-- the expected length and no bit set beyond the last index.
wellFormed :: Int -> Bitmap -> Bool
wellFormed n (Bitmap bs)
  | n <= 0 = False
  | ByteString.length bs /= numBytes n = False
  | ByteString.last bs .&. complement (lastByteMask n) /= 0 = False
  | otherwise = True
