{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the Keccak256 hashing algorithm.
module Cardano.Crypto.Hash.Keccak256
  ( Keccak256
  )
where

import Cardano.Crypto.Hash.Class
import CshaBindings
import Foreign.Ptr (castPtr)

import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI

data Keccak256

instance HashAlgorithm Keccak256 where
  type SizeHash Keccak256 = 32
  hashAlgorithmName _ = "keccak256"
  digest _ = keccak_rustcrypto

keccak_rustcrypto :: B.ByteString -> B.ByteString
keccak_rustcrypto input =
  BI.unsafeCreate 32 $ \outptr ->
    B.useAsCStringLen input $ \(inptr, inputlen) -> do
      keccak_256 (castPtr inptr) (fromIntegral inputlen) (castPtr outptr)
