{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TypeApplications #-}

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
import qualified Data.ByteString.Short as SBS
import Data.MemPack.Buffer (
  byteArrayFromShortByteString,
  byteArrayToShortByteString,
 )

byteArrayToByteString :: ByteArray -> ByteString
byteArrayToByteString = SBS.fromShort . byteArrayToShortByteString
{-# INLINE byteArrayToByteString #-}

byteStringToByteArray :: ByteString -> ByteArray
byteStringToByteArray = byteArrayFromShortByteString . SBS.toShort
{-# INLINE byteStringToByteArray #-}

slice :: Word -> Word -> ByteString -> ByteString
slice offset size =
  BS.take (fromIntegral @Word @Int size)
    . BS.drop (fromIntegral @Word @Int offset)

splitsAt :: [Int] -> ByteString -> [ByteString]
splitsAt = go 0
  where
    go !_ [] bs
      | BS.null bs = []
      | otherwise = [bs]
    go !off (sz : szs) bs
      | BS.length bs >= sz = BS.take sz bs : go (off + sz) szs (BS.drop sz bs)
      | otherwise = []
