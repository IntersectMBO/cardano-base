{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the Blake2b hashing algorithm, with various sizes.
module Cardano.Crypto.Hash.Blake2b
  ( Blake2b_224
  , Blake2b_256
  )
where

import Control.Monad (unless)
import Cardano.Crypto.Libsodium.C

import Cardano.Crypto.Hash.Class
import Foreign.ForeignPtr (withForeignPtr, mallocForeignPtrBytes)
import Foreign.Ptr (castPtr, nullPtr)
import Foreign.C.Error (errnoToIOError, getErrno)
import Data.Proxy
import GHC.TypeLits (natVal)
import GHC.IO.Exception (ioException)
import System.IO.Unsafe (unsafePerformIO)

import qualified Data.ByteString as B

data Blake2b_224
data Blake2b_256

instance HashAlgorithm Blake2b_224 where
  type SizeHash Blake2b_224 = 28
  hashAlgorithmName _ = "blake2b_224"
  digest _ = blake2b_libsodium (fromIntegral (natVal (Proxy::Proxy (SizeHash Blake2b_224))))

instance HashAlgorithm Blake2b_256 where
  type SizeHash Blake2b_256 = 32
  hashAlgorithmName _ = "blake2b_256"
  digest _ = blake2b_libsodium (fromIntegral (natVal (Proxy::Proxy (SizeHash Blake2b_256))))

blake2b_libsodium :: Int -> ByteString -> ByteString
blake2b_libsodium size = \input -> unsafePerformIO $ do
  output <- mallocForeignPtrBytes size
  withForeignPtr output $ \output' -> do
    B.useAsCStringLen input $ \(ptr, inputlen) -> do
      res <- c_crypto_generichash_blake2b output' (fromIntegral size) (castPtr ptr) (fromIntegral inputlen) nullPtr 0 -- we used unkeyed hash
      unless (res == 0) $ do
        errno <- getErrno
        ioException $ errnoToIOError "digest @Blake2b: crypto_generichash_blake2b" errno Nothing Nothing

      B.packCStringLen (output', size)
