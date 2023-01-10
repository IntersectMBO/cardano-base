{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the SHA3_256 hashing algorithm.
module Cardano.Crypto.Hash.SHA3_256
  ( SHA3_256
  )
where

import Cardano.Crypto.Hash.Class
import Foreign.Ptr (castPtr)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import CshaBindings

data SHA3_256

instance HashAlgorithm SHA3_256 where
  type SizeHash SHA3_256 = 32
  hashAlgorithmName _ = "sha3-256"
  digest _ = sha3_256_rustcrypto

sha3_256_rustcrypto :: B.ByteString -> B.ByteString
sha3_256_rustcrypto input =
  BI.unsafeCreate 32 $ \outptr ->
    B.useAsCStringLen input $ \(inptr, inputlen) -> do
      sha3_256 (castPtr inptr) (fromIntegral inputlen) (castPtr outptr)
