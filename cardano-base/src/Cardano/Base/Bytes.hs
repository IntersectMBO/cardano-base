{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}

module Cardano.Base.Bytes (
  byteArrayToByteString,
  byteStringToByteArray,
  slice,
  splitsAt,
)
where

import Data.Array.Byte (ByteArray (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Short as SBS
import Data.MemPack.Buffer (
  byteArrayFromShortByteString,
  byteArrayToShortByteString,
  pinnedByteArrayToForeignPtr
 )
import Data.Primitive.ByteArray (isByteArrayPinned, sizeofByteArray)

byteArrayToByteString :: ByteArray -> ByteString
byteArrayToByteString ba@(ByteArray ba#)
  | isByteArrayPinned ba =
    BS.fromForeignPtr (pinnedByteArrayToForeignPtr ba#) 0 (sizeofByteArray ba)
  | otherwise = SBS.fromShort (byteArrayToShortByteString ba)
{-# INLINE byteArrayToByteString #-}

byteStringToByteArray :: ByteString -> ByteArray
byteStringToByteArray = byteArrayFromShortByteString . SBS.toShort
{-# INLINE byteStringToByteArray #-}

slice :: Word -> Word -> ByteString -> ByteString
slice offset size =
  BS.take (fromIntegral size)
    . BS.drop (fromIntegral offset)

splitsAt :: [Int] -> ByteString -> [ByteString]
splitsAt = go 0
  where
    go !_ [] bs
      | BS.null bs = []
      | otherwise = [bs]
    go !off (sz : szs) bs
      | BS.length bs >= sz = BS.take sz bs : go (off + sz) szs (BS.drop sz bs)
      | otherwise = []
