{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the Blake2b hashing algorithm, with various sizes.
module Cardano.Crypto.Hash.Blake2b
  ( Blake2b_224
  , Blake2b_256
  , blake2b_libsodium -- Used for Hash.Short
  )
where

import Control.Monad (unless)
import Cardano.Crypto.Libsodium.C (c_crypto_generichash_blake2b)

import Cardano.Crypto.Hash.Class (HashAlgorithm (..), SizeHash, hashAlgorithmName, digest)
import Foreign.Ptr (castPtr, nullPtr)
import Foreign.C.Error (errnoToIOError, getErrno)
import GHC.IO.Exception (ioException)

import           Control.DeepSeq (NFData)
import qualified Data.ByteString as B
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short.Internal as SBSI
import qualified Data.ByteString.Short as SBS
import qualified Data.ByteString.Internal as BI
import           Data.Word (Word64, Word32)
import           NoThunks.Class (NoThunks)
import           GHC.Generics (Generic)
import qualified Data.Primitive.ByteArray as BA
import qualified Control.Monad.ST as ST

data Blake2b_224
data Blake2b_256

data PackedBytes32 =
  PackedBytes32
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
  deriving (Eq, Ord, Generic)

instance NoThunks PackedBytes32
instance NFData PackedBytes32

baToSBS :: BA.ByteArray -> ShortByteString
baToSBS (BA.ByteArray bytes#) = SBSI.SBS bytes#

baFromSBS :: ShortByteString -> BA.ByteArray
baFromSBS (SBSI.SBS bytes#) = BA.ByteArray bytes#

-- | Converts a ShortByteString into a Blake2b_224 hash rep.
--   This will error if the bytestring length is not 28.
unsafePackBlake2b224 :: ShortByteString -> PackedBytes32
unsafePackBlake2b224 sbs =
  if SBS.length sbs == 28
  then packed
  else error $
        "Attempted to cast bytestring of length "
     <> show (SBS.length sbs)
     <> " into Blake2b256 hash rep, but the required length is 32."
  where
{- [Note: Primitive Indices]
We interpret the bytestring as 3 Word64s follows by a Word32
The offset of read by indexByteArray# is the argument multiplied by the size of the
primitive being read.
For the Word64, we read indices 0,1,2.
We read the Word32 at the index whose calculated offset for Word32 is the same
as the offset we'd get by reading a Word64 at index 3.
Since Word64 is twice as large, this is index 6.

┏━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━┓
┃ 0       ┃ 1       ┃ 2       ┃ 3  ┃
┗━━━━━━━━━┻━━━━━━━━━┻━━━━━━━━━┻━━━━┛

┏━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━┓
┃ 0  | 1  ┃ 2  | 3  ┃ 4  | 5  ┃ 6  ┃
┗━━━━━━━━━┻━━━━━━━━━┻━━━━━━━━━┻━━━━┛
-}
  packed = (PackedBytes32 x0 x1 x2 x3)
  ba = baFromSBS sbs
  x0 = BA.indexByteArray ba 0
  x1 = BA.indexByteArray ba 1
  x2 = BA.indexByteArray ba 2
  x3' :: Word32
  x3' = BA.indexByteArray ba 6
  -- this fromIntegral is safe since this Word64 is wider than Word32
  x3 = fromIntegral x3'

unpackBlake2b224 :: PackedBytes32 -> ShortByteString
unpackBlake2b224 (PackedBytes32 x0 x1 x2 x3) = baToSBS $ ST.runST $ do
  -- this fromIntegral is safe since this Word64 is a widened Word32.
  let x3' = fromIntegral x3 :: Word32
  destination <- BA.newByteArray 28
  -- See [Note: Primitive Indices]
  BA.writeByteArray destination 0 x0
  BA.writeByteArray destination 1 x1
  BA.writeByteArray destination 2 x2
  BA.writeByteArray destination 6 x3'
  BA.unsafeFreezeByteArray destination

-- | Converts a ShortByteString into a Blake2b_256 hash rep.
--   This will error if the bytestring length is not 32.
unsafePackBlake2b256 :: ShortByteString -> PackedBytes32
unsafePackBlake2b256 sbs =
   if SBS.length sbs == 32
   then packed
   else error $
         "Attempted to cast bytestring of length "
      <> show (SBS.length sbs)
      <> " into Blake2b256 hash rep, but the required length is 32."
  where
  packed = PackedBytes32 x0 x1 x2 x3
  ba = baFromSBS sbs
  x0 = BA.indexByteArray ba 0
  x1 = BA.indexByteArray ba 1
  x2 = BA.indexByteArray ba 2
  x3 = BA.indexByteArray ba 3

unpackBlake2b256 :: PackedBytes32 -> ShortByteString
unpackBlake2b256 (PackedBytes32 x0 x1 x2 x3) = baToSBS $ ST.runST $ do
  destination <- BA.newByteArray 32
  BA.writeByteArray destination 0 x0
  BA.writeByteArray destination 1 x1
  BA.writeByteArray destination 2 x2
  BA.writeByteArray destination 3 x3
  BA.unsafeFreezeByteArray destination

instance HashAlgorithm Blake2b_224 where
  type SizeHash Blake2b_224 = 28
  type HashRep Blake2b_224 = PackedBytes32
  unsafeToHashRep _ = unsafePackBlake2b224
  fromHashRep _ = unpackBlake2b224
  hashAlgorithmName _ = "blake2b_224"
  digest _ = blake2b_libsodium 28

instance HashAlgorithm Blake2b_256 where
  type SizeHash Blake2b_256 = 32
  type HashRep Blake2b_256 = PackedBytes32
  unsafeToHashRep _ = unsafePackBlake2b256
  fromHashRep _ = unpackBlake2b256
  hashAlgorithmName _ = "blake2b_256"
  digest _ = blake2b_libsodium 32

blake2b_libsodium :: Int -> B.ByteString -> B.ByteString
blake2b_libsodium size input =
  BI.unsafeCreate size $ \outptr ->
    B.useAsCStringLen input $ \(inptr, inputlen) -> do
      res <- c_crypto_generichash_blake2b (castPtr outptr) (fromIntegral size) (castPtr inptr) (fromIntegral inputlen) nullPtr 0 -- we used unkeyed hash
      unless (res == 0) $ do
        errno <- getErrno
        ioException $ errnoToIOError "digest @Blake2b: crypto_generichash_blake2b" errno Nothing Nothing
