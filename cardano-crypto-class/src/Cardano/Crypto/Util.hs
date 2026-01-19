{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UnboxedTuples #-}

module Cardano.Crypto.Util (
  Empty,
  SignableRepresentation (..),
  getRandomWord64,

  -- * Simple serialisation used in mock instances
  readBinaryWord64,
  writeBinaryWord64,
  readBinaryNatural,
  writeBinaryNatural,
  splitsAt,

  -- * Low level conversions
  bytesToInteger,
  bytesToNatural,
  naturalToBytes,
  byteArrayToNatural,
  naturalToByteArray,
  byteArrayToInteger,

  -- * ByteString manipulation
  slice,

  -- * Base16 conversion
  decodeHexByteString,
  decodeHexString,
  decodeHexStringQ,
)
where

import Control.Monad (unless)
import Data.Array.Byte (ByteArray (..))
import Data.Bifunctor (first)
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as BSC8
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Short as SBS
import Data.Char (isAscii)
import Data.MemPack.Buffer (byteArrayFromShortByteString)
import Data.Word
import Language.Haskell.TH
import Numeric.Natural

import Foreign.ForeignPtr (withForeignPtr)
import GHC.Exts (Addr#, Int#, Word#, sizeofByteArray#)
import qualified GHC.Exts as GHC
import qualified GHC.Natural as GHC

import Crypto.Random (MonadRandom (..))

import GHC.IO (unsafeDupablePerformIO)
import GHC.Num.Integer (integerFromAddr, integerFromByteArray)

class Empty a
instance Empty a

--
-- Signable
--

-- | A class of types that have a representation in bytes that can be used
-- for signing and verifying.
class SignableRepresentation a where
  getSignableRepresentation :: a -> ByteString

instance SignableRepresentation ByteString where
  getSignableRepresentation = id

--
-- Random source used in some mock instances
--

getRandomWord64 :: MonadRandom m => m Word64
getRandomWord64 = readBinaryWord64 <$> getRandomBytes 8

--
-- Really simple serialisation used in some mock instances
--

readBinaryWord64 :: ByteString -> Word64
readBinaryWord64 =
  BS.foldl' (\acc w8 -> unsafeShiftL acc 8 + fromIntegral @Word8 @Word64 w8) 0

readBinaryNatural :: ByteString -> Natural
readBinaryNatural =
  BS.foldl' (\acc w8 -> unsafeShiftL acc 8 + fromIntegral @Word8 @Natural w8) 0

writeBinaryWord64 :: Word64 -> ByteString
writeBinaryWord64 =
  BS.reverse
    . fst
    . BS.unfoldrN 8 (\w -> Just (fromIntegral @Word64 @Word8 w, unsafeShiftR w 8))

writeBinaryNatural :: Int -> Natural -> ByteString
writeBinaryNatural bytes =
  BS.reverse
    . fst
    . BS.unfoldrN bytes (\w -> Just (fromIntegral @Natural @Word8 w, unsafeShiftR w 8))

splitsAt :: [Int] -> ByteString -> [ByteString]
splitsAt = go 0
  where
    go !_ [] bs
      | BS.null bs = []
      | otherwise = [bs]
    go !off (sz : szs) bs
      | BS.length bs >= sz = BS.take sz bs : go (off + sz) szs (BS.drop sz bs)
      | otherwise = []

-- | Create a 'Natural' out of a 'ByteString', in big endian.
bytesToNatural :: ByteString -> Natural
bytesToNatural = GHC.naturalFromInteger . bytesToInteger

-- | Create a 'Natural' out of a 'ByteArray', in big endian.
byteArrayToNatural :: ByteArray -> Natural
byteArrayToNatural = GHC.naturalFromInteger . byteArrayToInteger

-- | The inverse of 'bytesToNatural'. Note that this is a naive implementation
-- and only suitable for tests.
naturalToBytes :: Int -> Natural -> ByteString
naturalToBytes = writeBinaryNatural

-- | The inverse of 'bytesToNatural'. Note that this is a naive implementation
-- and only suitable for tests.
naturalToByteArray :: Int -> Natural -> ByteArray
naturalToByteArray numBytes = byteArrayFromShortByteString . SBS.toShort . writeBinaryNatural numBytes

-- | Create a 'Integer' out of a 'ByteString', in big endian.
bytesToInteger :: ByteString -> Integer
bytesToInteger (BS.PS fp (GHC.I# off#) (GHC.I# len#)) =
  -- This should be safe since we're simply reading from ByteString (which is
  -- immutable) and GMP allocates a new memory for the Integer, i.e., there is
  -- no mutation involved.
  unsafeDupablePerformIO $
    withForeignPtr fp $ \(GHC.Ptr addr#) ->
      let addrOff# = addr# `GHC.plusAddr#` off#
       in -- The last parmaeter (`1#`) tells the import function to use big
          -- endian encoding.
          importIntegerFromAddr addrOff# (GHC.int2Word# len#) 1#
  where
    importIntegerFromAddr :: Addr# -> Word# -> Int# -> IO Integer
    importIntegerFromAddr addr sz = integerFromAddr sz addr

-- | Create a 'Integer' out of a 'ByteArray', in big endian.
byteArrayToInteger :: ByteArray -> Integer
byteArrayToInteger (ByteArray ba#) =
  -- The last parmaeter (`1#`) tells the import function to use big
  -- endian encoding. The one before last (`0#`) is the offset
  integerFromByteArray (GHC.int2Word# (sizeofByteArray# ba#)) ba# (GHC.int2Word# 0#) 1#

slice :: Word -> Word -> ByteString -> ByteString
slice offset size =
  BS.take (fromIntegral @Word @Int size)
    . BS.drop (fromIntegral @Word @Int offset)

-- | Decode base16 ByteString, while ensuring expected length.
decodeHexByteString :: ByteString -> Int -> Either String ByteString
decodeHexByteString bsHex lenExpected = do
  bs <- first ("Malformed hex: " ++) $ BS16.decode bsHex
  let lenActual = BS.length bs
  unless (lenExpected == lenActual) $
    Left $
      "Expected in decoded form to be: "
        ++ show lenExpected
        ++ " bytes, but got: "
        ++ show lenActual
  pure bs

-- | Decode base16 String, while ensuring expected length. Unlike
-- `decodeHexByteString` this function expects a '0x' prefix.
decodeHexString :: String -> Int -> Either String ByteString
decodeHexString hexStr' lenExpected = do
  let hexStr =
        case hexStr' of
          '0' : 'x' : str -> str
          str -> str
  unless (all isAscii hexStr) $ Left $ "Input string contains invalid characters: " ++ hexStr
  decodeHexByteString (BSC8.pack hexStr) lenExpected

-- | Decode a `String` with Hex characters, while ensuring expected length.
decodeHexStringQ :: String -> Int -> Q Exp
decodeHexStringQ hexStr n = do
  case decodeHexString hexStr n of
    Left err -> fail $ "<decodeHexByteString>: " ++ err
    Right _ -> [|either error id (decodeHexString hexStr n)|]
