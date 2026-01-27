{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the Blake2b hashing algorithm, with various sizes.
module Cardano.Crypto.Hash.Blake2b (
  Blake2b_224,
  Blake2b_256,
  blake2b_libsodium, -- Used for Hash.Short
)
where

import Cardano.Crypto.Libsodium.C (c_crypto_generichash_blake2b)
import Control.Monad (unless)

import Cardano.Crypto.Hash.Class (HashAlgorithm (..), SizeHash, digest, hashAlgorithmName)
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.Ptr (castPtr, nullPtr)
import GHC.IO.Exception (ioException)

import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import Foreign.C.Types (CSize, CULLong)

data Blake2b_224
data Blake2b_256

instance HashAlgorithm Blake2b_224 where
  type SizeHash Blake2b_224 = 28
  hashAlgorithmName _ = "blake2b_224"
  digest _ = blake2b_libsodium 28

instance HashAlgorithm Blake2b_256 where
  type SizeHash Blake2b_256 = 32
  hashAlgorithmName _ = "blake2b_256"
  digest _ = blake2b_libsodium 32

blake2b_libsodium :: Int -> B.ByteString -> B.ByteString
blake2b_libsodium size input =
  BI.unsafeCreate size $ \outptr ->
    B.useAsCStringLen input $ \(inptr, inputlen) -> do
      res <-
        c_crypto_generichash_blake2b
          (castPtr outptr)
          (fromIntegral @Int @CSize size)
          (castPtr inptr)
          (fromIntegral @Int @CULLong inputlen)
          nullPtr
          0 -- we used unkeyed hash
      unless (res == 0) $ do
        errno <- getErrno
        ioException $ errnoToIOError "digest @Blake2b: crypto_generichash_blake2b" errno Nothing Nothing
