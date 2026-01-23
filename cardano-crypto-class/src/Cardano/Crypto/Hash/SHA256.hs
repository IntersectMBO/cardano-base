{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the SHA256 hashing algorithm.
module Cardano.Crypto.Hash.SHA256 (
  SHA256,
)
where

import Cardano.Crypto.Hash.Class (HashAlgorithm, HashSize, digest, hashAlgorithmName)
import Cardano.Crypto.Libsodium.C (c_crypto_hash_sha256)
import Cardano.Foreign (SizedPtr (SizedPtr))
import Control.Monad (unless)

import Data.Proxy (Proxy (..))
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.Ptr (castPtr)
import GHC.IO.Exception (ioException)
import GHC.TypeLits (natVal)

import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import Foreign.C.Types (CULLong)

data SHA256

instance HashAlgorithm SHA256 where
  type HashSize SHA256 = 32
  hashAlgorithmName _ = "sha256"
  digest _ = sha256_libsodium

sha256_libsodium :: B.ByteString -> B.ByteString
sha256_libsodium input =
  BI.unsafeCreate expected_size $ \outptr ->
    B.useAsCStringLen input $ \(inptr, inputlen) -> do
      res <-
        c_crypto_hash_sha256
          (SizedPtr (castPtr outptr))
          (castPtr inptr)
          (fromIntegral @Int @CULLong inputlen)
      unless (res == 0) $ do
        errno <- getErrno
        ioException $ errnoToIOError "digest @SHA256: c_crypto_hash_sha256" errno Nothing Nothing
  where
    expected_size = fromIntegral @Integer @Int (natVal (Proxy :: Proxy (HashSize SHA256)))
