{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE FlexibleInstances #-}

{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
module Cardano.Crypto.Util
  ( Empty
  , getRandomWord64

    -- * Simple serialisation used in mock instances
  , readBinaryWord64
  , writeBinaryWord64
  , readBinaryNatural
  , writeBinaryNatural
  , splitsAt
  )
where

import           Data.Word
import           Numeric.Natural
import           Data.Bits
import qualified Data.ByteString as BS
import           Data.ByteString (ByteString)

import           Crypto.Random (MonadRandom (..))


class Empty a
instance Empty a


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
    BS.reverse . fst
  . BS.unfoldrN 8 (\w -> Just (fromIntegral w, unsafeShiftR w 8))

writeBinaryNatural :: Int -> Natural -> ByteString
writeBinaryNatural bytes =
    BS.reverse . fst
  . BS.unfoldrN bytes (\w -> Just (fromIntegral w, unsafeShiftR w 8))

splitsAt :: [Int] -> ByteString -> [ByteString]
splitsAt szs0 bs0 =
    go 0 szs0 bs0
  where
    go !_   [] bs
      | BS.null bs         = []
      | otherwise          = [bs]

    go !off (sz:szs) bs
      | BS.length bs >= sz = BS.take sz bs : go (off+sz) szs (BS.drop sz bs)
      | otherwise          = []
