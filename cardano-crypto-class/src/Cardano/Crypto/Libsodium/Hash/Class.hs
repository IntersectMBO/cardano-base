{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Cardano.Crypto.Libsodium.Hash.Class (
  SodiumHashAlgorithm (..),
  digestMLockedStorable,
  digestMLockedBS,
) where

import Control.Monad (unless)
import Data.Proxy (Proxy (..))
import Data.Type.Equality ((:~:) (..))
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (Storable (sizeOf))
import GHC.IO.Exception (ioException)
import GHC.TypeLits

import qualified Data.ByteString as BS

import Cardano.Crypto.Hash (Blake2b_256, HashAlgorithm (SizeHash), SHA256)
import Cardano.Crypto.Libsodium.C
import Cardano.Crypto.Libsodium.MLockedBytes.Internal

-------------------------------------------------------------------------------
-- Type-Class
-------------------------------------------------------------------------------

class HashAlgorithm h => SodiumHashAlgorithm h where
  -- This function is in IO, it is "morally pure"
  -- and can be 'unsafePerformDupableIO'd.
  naclDigestPtr ::
    proxy h ->
    -- | input
    Ptr a ->
    -- | input length
    Int ->
    IO (MLockedSizedBytes (SizeHash h))

-- TODO: provide interface for multi-part?
-- That will be useful to hashing ('1' <> oldseed).

digestMLockedStorable ::
  forall h a proxy.
  (SodiumHashAlgorithm h, Storable a) =>
  proxy h ->
  Ptr a ->
  IO (MLockedSizedBytes (SizeHash h))
digestMLockedStorable p ptr =
  naclDigestPtr p ptr ((sizeOf (undefined :: a)))

digestMLockedBS ::
  forall h proxy.
  SodiumHashAlgorithm h =>
  proxy h ->
  BS.ByteString ->
  IO (MLockedSizedBytes (SizeHash h))
digestMLockedBS p bs =
  BS.useAsCStringLen bs $ \(ptr, len) ->
    naclDigestPtr p (castPtr ptr) len

-------------------------------------------------------------------------------
-- Instances
-------------------------------------------------------------------------------

instance SodiumHashAlgorithm SHA256 where
  naclDigestPtr ::
    forall proxy a. proxy SHA256 -> Ptr a -> Int -> IO (MLockedSizedBytes (SizeHash SHA256))
  naclDigestPtr _ input inputlen = do
    output <- mlsbNew
    mlsbUseAsSizedPtr output $ \output' -> do
      res <- c_crypto_hash_sha256 output' (castPtr input) (fromIntegral inputlen)
      unless (res == 0) $ do
        errno <- getErrno
        ioException $ errnoToIOError "digestMLocked @SHA256: c_crypto_hash_sha256" errno Nothing Nothing
    return output

-- Test that manually written numbers are the same as in libsodium
_testSHA256 :: SizeHash SHA256 :~: CRYPTO_SHA256_BYTES
_testSHA256 = Refl

instance SodiumHashAlgorithm Blake2b_256 where
  naclDigestPtr ::
    forall proxy a. proxy Blake2b_256 -> Ptr a -> Int -> IO (MLockedSizedBytes (SizeHash Blake2b_256))
  naclDigestPtr _ input inputlen = do
    output <- mlsbNew
    mlsbUseAsCPtr output $ \output' -> do
      res <-
        c_crypto_generichash_blake2b
          output'
          (fromInteger $ natVal (Proxy @CRYPTO_BLAKE2B_256_BYTES)) -- output
          (castPtr input)
          (fromIntegral inputlen) -- input
          nullPtr
          0 -- key, unused
      unless (res == 0) $ do
        errno <- getErrno
        ioException $
          errnoToIOError "digestMLocked @Blake2b_256: c_crypto_hash_sha256" errno Nothing Nothing
    return output

_testBlake2b256 :: SizeHash Blake2b_256 :~: CRYPTO_BLAKE2B_256_BYTES
_testBlake2b256 = Refl
