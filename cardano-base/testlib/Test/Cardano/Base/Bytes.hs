{-# LANGUAGE CPP #-}

module Test.Cardano.Base.Bytes (
  genByteArray,
  genByteString,
  genLazyByteString,
  genShortByteString,
) where

import Data.Array.Byte (ByteArray)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
#if MIN_VERSION_bytestring(0,11,1)
import qualified Data.ByteString.Short as SBS
#else
import qualified Data.ByteString.Short.Internal as SBS
#endif
import Data.MemPack.Buffer (byteArrayFromShortByteString)
#if MIN_VERSION_random(1,3,0)
import System.Random.Stateful (
  runStateGen_,
  uniformByteStringM,
  uniformShortByteStringM,
 )
#else
import System.Random.Stateful (
  StatefulGen (..),
  runStateGen_,
  uniformByteStringM,
 )
#endif
import Test.QuickCheck
import Test.QuickCheck.Gen (Gen (MkGen))

genByteArray :: Int -> Gen ByteArray
genByteArray n = byteArrayFromShortByteString <$> genShortByteString n

genByteString :: Int -> Gen BS.ByteString
genByteString n = MkGen $ \r _ -> runStateGen_ r $ uniformByteStringM n

genLazyByteString :: Int -> Gen BSL.ByteString
genLazyByteString n = BSL.fromStrict <$> genByteString n

genShortByteString :: Int -> Gen SBS.ShortByteString
#if MIN_VERSION_random(1,3,0)
genShortByteString n = MkGen $ \r _ -> runStateGen_ r $ uniformShortByteStringM n
#else
genShortByteString n = MkGen $ \r _ -> runStateGen_ r $ uniformShortByteString n
#endif
