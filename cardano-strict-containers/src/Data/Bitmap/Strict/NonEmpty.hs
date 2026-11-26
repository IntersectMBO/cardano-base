{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE TypeApplications #-}

-- | A compact, non-empty bitmap over a 'ByteArray' based on the Leios
-- certificate signers bitfield representation (CIP-164).
--
-- A 'NonEmptyBitmap' of @n@ bits is well-formed by construction: it is stored
-- in exactly @⌈n/8⌉@ bytes, MSB-first (index @i@ is bit @7 - i mod 8@ of byte
-- @i div 8@), its padding bits after the last index are zero, and at least one
-- of its bits is set. A bitmap that may be empty can live in
-- @Data.Bitmap.Strict@ if the need arises.
--
-- NOTE: this module is meant to be imported qualified.
module Data.Bitmap.Strict.NonEmpty (
  NonEmptyBitmap,
  mkNonEmptyBitmap,
  bitmapRawByteArray,
  bitmapNumBits,
  fromIndices,
  toIndices,
  toIndicesPrefix,
  numSetBits,
) where

import Control.DeepSeq (NFData)
import Control.Monad (forM_, unless, when)
import Data.Array.Byte (ByteArray)
import Data.Bits (complement, popCount, setBit, shiftR, testBit, unsafeShiftL, (.&.))
import Data.Foldable (find)
import Data.Foldable1 (Foldable1)
import Data.IntSet (IntSet)
import qualified Data.IntSet as IntSet
import Data.IntSet.NonEmpty (NEIntSet)
import qualified Data.IntSet.NonEmpty as NEIntSet
import Data.List.NonEmpty (nonEmpty)
import Data.Primitive.ByteArray (
  fillByteArray,
  indexByteArray,
  newByteArray,
  readByteArray,
  runByteArray,
  sizeofByteArray,
  writeByteArray,
 )
import Data.Word (Word16, Word8)
import GHC.Generics (Generic)
import GHC.Stack (HasCallStack)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

-- | A non-empty bitmap over a fixed number of bits: bit @i@ set iff index @i@
-- is set.
data NonEmptyBitmap = NonEmptyBitmap
  { bitmapBytes :: !ByteArray
  , bitmapBits :: !Int
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass (NFData)
  deriving (NoThunks) via OnlyCheckWhnfNamed "NonEmptyBitmap" NonEmptyBitmap

-- | Construct a bitmap from a 'ByteArray' and the number of bits used in it.
mkNonEmptyBitmap ::
  MonadFail m =>
  -- | Number of bits, at least 1
  Int ->
  -- | Size of this byte array must accommodate exact number of bits, with no
  -- more than 7 bits of wasted space, which themselves must be set to 0. At
  -- least one of the other bits must be set to 1
  ByteArray ->
  m NonEmptyBitmap
mkNonEmptyBitmap n ba = do
  when (n < 1) $
    fail $
      "NonEmptyBitmap: number of bits must be positive, got " <> show n
  unless (sizeofByteArray ba == nBytes) $
    fail $
      "NonEmptyBitmap: expected "
        <> show nBytes
        <> " bytes for "
        <> show n
        <> " bits, got "
        <> show (sizeofByteArray ba)
  unless (indexByteArray @Word8 ba (nBytes - 1) .&. complement (lastByteMask n) == 0) $
    fail $
      "NonEmptyBitmap: padding bits after bit " <> show (n - 1) <> " are not zero"
  let bm = NonEmptyBitmap ba n
  when (numSetBits bm == 0) $
    fail "NonEmptyBitmap: no bit is set"
  pure bm
  where
    nBytes = numBytesFromBits n

-- | The bytes of a bitmap.
bitmapRawByteArray :: NonEmptyBitmap -> ByteArray
bitmapRawByteArray = bitmapBytes

-- | The number of bits of a bitmap.
bitmapNumBits :: NonEmptyBitmap -> Int
bitmapNumBits = bitmapBits

-- | The number of indices set (flipped to 1) in the bitmap: at least 1.
numSetBits :: NonEmptyBitmap -> Int
numSetBits (NonEmptyBitmap ba _) =
  sum
    [ popCount (indexByteArray ba i :: Word8)
    | i <- [0 .. sizeofByteArray ba - 1]
    ]

-- | Number of bytes necessary to store the supplied number of bits.
numBytesFromBits :: Int -> Int
numBytesFromBits n = (n + 7) `quot` 8

-- | The bits of the last byte that hold indices, for @n > 0@ bits.
lastByteMask :: Int -> Word8
lastByteMask n =
  complement (fromIntegral ((1 :: Int) `unsafeShiftL` (7 - (n - 1) `rem` 8)) - 1)

-- | Construct a bitmap of the given number of bits from the indices that should
-- be set (flipped to 1). Fails if an index is not below the number of bits.
-- Duplicate indices set the same bit.
fromIndices ::
  (Foldable1 f, MonadFail m) =>
  -- | Number of bits
  Int ->
  f Word16 ->
  m NonEmptyBitmap
fromIndices n flipped = do
  forM_ (find ((>= n) . fromIntegral @Word16 @Int) flipped) $ \i ->
    fail $
      "NonEmptyBitmap.fromIndices: index " <> show i <> " is not below " <> show n <> " bits"
  pure $ NonEmptyBitmap bytes n
  where
    nBytes = numBytesFromBits n
    bytes = runByteArray $ do
      mba <- newByteArray nBytes
      fillByteArray mba 0 nBytes 0
      forM_ flipped $ \i16 -> do
        let i = fromIntegral @Word16 @Int i16
            byteIx = i `shiftR` 3
            bitIx = 7 - (i .&. 7)
        w <- readByteArray @Word8 mba byteIx
        writeByteArray mba byteIx (w `setBit` bitIx)
      pure mba

-- | Retrieve all indices that are set (flipped to 1) in a bitmap.
toIndices :: NonEmptyBitmap -> NEIntSet
toIndices bm =
  case nonEmpty (ascIndices (bitmapBits bm) bm) of
    Just is -> NEIntSet.fromDistinctAscList is
    Nothing -> error "NonEmptyBitmap.toIndices: no bit is set, which breaks the invariant"

-- | Retrieve the indices that are set (flipped to 1) among the first @k@ bits of
-- a bitmap. It is an error to request a negative number of bits or more bits
-- than the bitmap has.
toIndicesPrefix :: HasCallStack => Int -> NonEmptyBitmap -> IntSet
toIndicesPrefix k bm
  | k < 0 = error $ "NonEmptyBitmap.toIndicesPrefix: requested a negative number of bits: " <> show k
  | k > bitmapBits bm =
      error $
        "NonEmptyBitmap.toIndicesPrefix: requested more bits than available: "
          <> show k
          <> " vs "
          <> show (bitmapBits bm)
  | otherwise = IntSet.fromDistinctAscList (ascIndices k bm)

-- | The indices set among the first @k@ bits, in ascending order.
ascIndices :: Int -> NonEmptyBitmap -> [Int]
ascIndices k (NonEmptyBitmap ba _) =
  [ i
  | byteIx <- [0 .. numBytesFromBits k - 1]
  , let w = indexByteArray ba byteIx :: Word8
  , bitIx <- [0 .. 7]
  , let i = byteIx * 8 + bitIx
  , i < k
  , testBit w (7 - bitIx)
  ]
