{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
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
  bytesToNatural,
  naturalToBytes,

  -- * ByteString manipulation
  slice,

  -- * Base16 conversion
  decodeHexByteString,
  decodeHexString,
  decodeHexStringQ,
)
where

import Control.Monad (unless)
import Data.Bifunctor (first)
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as BSC8
import qualified Data.ByteString.Internal as BS
import Data.Char (isAscii)
import Data.Word
import Language.Haskell.TH
import Numeric.Natural

import Foreign.ForeignPtr (withForeignPtr)
import GHC.Exts (Addr#, Int#, Word#)
import qualified GHC.Exts as GHC
import qualified GHC.Natural as GHC

import Crypto.Random (MonadRandom (..))

import GHC.IO (unsafeDupablePerformIO)
import GHC.Num.Integer (integerFromAddr)

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
  BS.foldl' (\acc w8 -> unsafeShiftL acc 8 + fromIntegral w8) 0

readBinaryNatural :: ByteString -> Natural
readBinaryNatural =
  BS.foldl' (\acc w8 -> unsafeShiftL acc 8 + fromIntegral w8) 0

writeBinaryWord64 :: Word64 -> ByteString
writeBinaryWord64 =
  BS.reverse
    . fst
    . BS.unfoldrN 8 (\w -> Just (fromIntegral w, unsafeShiftR w 8))

writeBinaryNatural :: Int -> Natural -> ByteString
writeBinaryNatural bytes =
  BS.reverse
    . fst
    . BS.unfoldrN bytes (\w -> Just (fromIntegral w, unsafeShiftR w 8))

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
--
-- This is fast enough to use in production.
bytesToNatural :: ByteString -> Natural
bytesToNatural = GHC.naturalFromInteger . bytesToInteger

-- | The inverse of 'bytesToNatural'. Note that this is a naive implementation
-- and only suitable for tests.
naturalToBytes :: Int -> Natural -> ByteString
naturalToBytes = writeBinaryNatural

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

slice :: Word -> Word -> ByteString -> ByteString
slice offset size =
  BS.take (fromIntegral size)
    . BS.drop (fromIntegral offset)

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
