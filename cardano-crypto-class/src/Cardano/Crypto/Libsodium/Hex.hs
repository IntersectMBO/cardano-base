{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Hex decoding straight into mlocked memory.
--
-- The decoders in this module read hex digits from a caller-supplied buffer
-- and write the decoded bytes into a freshly allocated mlocked buffer. The
-- decoded bytes never pass through the GHC heap: there is no intermediate
-- 'ByteString' and the loop keeps only the current pair of digits in
-- registers. This is what makes the functions suitable for loading secret key
-- material (such as a KES signing key) from a hex-encoded file.
--
-- The caller owns the returned buffer and must release it with
-- 'finalizeMLockedForeignPtr', which erases it. On a decode error the partially
-- filled buffer is erased and released before the error is returned, and the
-- error itself never carries any of the input.
module Cardano.Crypto.Libsodium.Hex (
  HexDecodeError (..),
  hexDecodeToMLocked,
  hexDecodeByteStringToMLocked,
) where

import Control.Monad.Class.MonadST (MonadST)
import Data.Bits (shiftL, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString.Unsafe as BS
import Data.Word (Word8)
import Foreign.C.Types (CSize)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)

import Cardano.Crypto.Libsodium.Memory (
  MLockedAllocator (..),
  MLockedForeignPtr,
  finalizeMLockedForeignPtr,
  mlockedMalloc,
  withMLockedForeignPtr,
  zeroMem,
 )
import Cardano.Crypto.Libsodium.Memory.Internal (unsafeIOToMonadST)

-- | Why a hex decode failed. Deliberately carries positions and lengths only,
-- never the input, so it can be logged safely.
data HexDecodeError
  = -- | The input has an odd number of bytes; the field is that length.
    HexOddLength !Int
  | -- | The byte at this offset of the input is not a hex digit.
    HexInvalidByteAt !Int
  deriving (Show, Eq)

-- | Decode @len@ bytes of hex digits starting at the given pointer into a fresh
-- mlocked buffer. Both upper- and lower-case digits are accepted. On success
-- the buffer holds exactly @len / 2@ bytes, which is also returned.
hexDecodeToMLocked ::
  MonadST m =>
  Ptr Word8 ->
  Int ->
  m (Either HexDecodeError (MLockedForeignPtr Word8, Int))
hexDecodeToMLocked src len = unsafeIOToMonadST (hexDecodeToMLockedIO src len)

-- | 'hexDecodeToMLocked' over the bytes of a 'ByteString'. The 'ByteString'
-- itself lives on the heap, so prefer 'hexDecodeToMLocked' when the hex text
-- can be kept out of the heap altogether.
hexDecodeByteStringToMLocked ::
  MonadST m =>
  ByteString ->
  m (Either HexDecodeError (MLockedForeignPtr Word8, Int))
hexDecodeByteStringToMLocked bs =
  unsafeIOToMonadST $
    BS.unsafeUseAsCStringLen bs $ \(ptr, len) ->
      hexDecodeToMLockedIO (castPtr ptr) len

hexDecodeToMLockedIO ::
  Ptr Word8 ->
  Int ->
  IO (Either HexDecodeError (MLockedForeignPtr Word8, Int))
hexDecodeToMLockedIO src len
  | odd len = return (Left (HexOddLength len))
  | otherwise = do
      let outLen = len `div` 2
      fptr <- mlAllocate mlockedMalloc (fromIntegral @Int @CSize outLen)
      firstBad <- withMLockedForeignPtr fptr $ \dst -> decodeLoop dst 0
      if firstBad < 0
        then return (Right (fptr, outLen))
        else do
          withMLockedForeignPtr fptr $ \dst ->
            zeroMem dst (fromIntegral @Int @CSize outLen)
          finalizeMLockedForeignPtr fptr
          return (Left (HexInvalidByteAt firstBad))
  where
    -- Returns the offset of the first non-hex byte, or -1 when all of the
    -- input decoded.
    decodeLoop :: Ptr Word8 -> Int -> IO Int
    decodeLoop dst !i
      | i >= len = return (-1)
      | otherwise = do
          hi <- nibble <$> peekByteOff src i
          lo <- nibble <$> peekByteOff src (i + 1)
          if
            | hi == invalidNibble -> return i
            | lo == invalidNibble -> return (i + 1)
            | otherwise -> do
                pokeByteOff dst (i `div` 2) ((hi `shiftL` 4) .|. lo)
                decodeLoop dst (i + 2)

-- | Sentinel returned by 'nibble' for a byte that is not a hex digit. Hex
-- digits decode to values below 16, so this never collides.
invalidNibble :: Word8
invalidNibble = 0xff

nibble :: Word8 -> Word8
nibble w
  | w >= 0x30 && w <= 0x39 = w - 0x30 -- '0'..'9'
  | w >= 0x61 && w <= 0x66 = w - 0x61 + 10 -- 'a'..'f'
  | w >= 0x41 && w <= 0x46 = w - 0x41 + 10 -- 'A'..'F'
  | otherwise = invalidNibble
