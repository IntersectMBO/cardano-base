{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the SHA256 hashing algorithm.
module Cardano.Crypto.Hash.SHA256
  ( SHA256
  )
where

import Control.Monad (unless)
import Cardano.Crypto.Libsodium.C
import Cardano.Foreign (SizedPtr(SizedPtr))
import Cardano.Crypto.Hash.Class

-- Make all imports specific (or think about it)
import Foreign.ForeignPtr (withForeignPtr, mallocForeignPtrBytes)
import Foreign.Ptr (castPtr)
import Foreign.C.Error (errnoToIOError, getErrno)
import Data.Proxy
import GHC.TypeLits (natVal)
import GHC.IO.Exception (ioException)
import System.IO.Unsafe (unsafePerformIO)

import qualified Data.ByteString as B


data SHA256

instance HashAlgorithm SHA256 where
  type SizeHash SHA256 = 32
  hashAlgorithmName _ = "sha256"
  digest _ = sha256_libsodium

sha256_libsodium :: ByteString -> ByteString
sha256_libsodium input = unsafePerformIO $ do
  output <- mallocForeignPtrBytes expected_size
  withForeignPtr output $ \output' -> do
    B.useAsCStringLen input $ \(ptr, inputlen) -> do
      res <- c_crypto_hash_sha256 (SizedPtr (castPtr output')) (castPtr ptr) (fromIntegral inputlen)
      unless (res == 0) $ do
          errno <- getErrno
          ioException $ errnoToIOError "digest @SHA256: c_crypto_hash_sha256" errno Nothing Nothing

    B.packCStringLen (output', expected_size)

  where
    expected_size = fromIntegral (natVal (Proxy::Proxy (SizeHash SHA256)))
