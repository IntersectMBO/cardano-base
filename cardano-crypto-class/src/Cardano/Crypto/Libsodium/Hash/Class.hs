{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Cardano.Crypto.Libsodium.Hash.Class (
    SodiumHashAlgorithm (..),
    digestMLockedStorable,
    digestMLockedBS,
) where

import Control.Monad (unless)
import Control.Monad.ST.Unsafe (unsafeIOToST)
import Control.Monad.Class.MonadST
import Data.Proxy (Proxy (..))
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (Storable (sizeOf))
import Data.Type.Equality ((:~:)(..))
import GHC.IO.Exception (ioException)
import GHC.TypeLits

import qualified Data.ByteString as BS

import Cardano.Crypto.Hash (HashAlgorithm(SizeHash), SHA256, Blake2b_256)
import Cardano.Crypto.Libsodium.C
import Cardano.Crypto.Libsodium.MLockedBytes.Internal
import Cardano.Crypto.MonadMLock.Class

-------------------------------------------------------------------------------
-- Type-Class
-------------------------------------------------------------------------------

class HashAlgorithm h => SodiumHashAlgorithm m h where
    -- This function is in IO, it is "morally pure"
    -- and can be 'unsafePerformDupableIO'd.
    naclDigestPtr
        :: proxy h
        -> Ptr a  -- ^ input
        -> Int    -- ^ input length
        -> m (MLockedSizedBytes m (SizeHash h))

    -- TODO: provide interface for multi-part?
    -- That will be useful to hashing ('1' <> oldseed).

digestMLockedStorable
    :: forall h m a proxy. (SodiumHashAlgorithm m h, Storable a)
    => proxy h -> Ptr a -> m (MLockedSizedBytes m (SizeHash h))
digestMLockedStorable p ptr =
    naclDigestPtr p ptr ((sizeOf (undefined :: a)))

digestMLockedBS
    :: forall h m proxy. (SodiumHashAlgorithm m h, MonadByteStringMemory m)
    => proxy h -> BS.ByteString -> m (MLockedSizedBytes m (SizeHash h))
digestMLockedBS p bs =
    useByteStringAsCStringLen
    bs $ \(ptr, len) ->
    naclDigestPtr p (castPtr ptr) len

-------------------------------------------------------------------------------
-- Instances
-------------------------------------------------------------------------------

unsafeIOToM :: MonadST m => IO a -> m a
unsafeIOToM action = withLiftST $ \liftST -> liftST . unsafeIOToST $ action

instance (MonadMLock m, MonadST m) => SodiumHashAlgorithm m SHA256 where
    naclDigestPtr _ input inputlen = do
        output <- mlsbNew
        mlsbUseAsSizedPtr output $ \output' -> unsafeIOToM $ do
            res <- c_crypto_hash_sha256 output' (castPtr input) (fromIntegral inputlen)
            unless (res == 0) $ do
                errno <- getErrno
                ioException $ errnoToIOError "digestMLocked @SHA256: c_crypto_hash_sha256" errno Nothing Nothing
        return output

-- Test that manually written numbers are the same as in libsodium
_testSHA256 :: SizeHash SHA256 :~: CRYPTO_SHA256_BYTES
_testSHA256 = Refl

instance (MonadMLock m, MonadST m) => SodiumHashAlgorithm m Blake2b_256 where
    naclDigestPtr _ input inputlen = do
        output <- mlsbNew
        mlsbUseAsCPtr output $ \output' -> unsafeIOToM $ do
            res <- c_crypto_generichash_blake2b
                output' (fromInteger $ natVal (Proxy @CRYPTO_BLAKE2B_256_BYTES))  -- output
                (castPtr input) (fromIntegral inputlen)  -- input
                nullPtr 0                                -- key, unused
            unless (res == 0) $ do
                errno <- getErrno
                ioException $ errnoToIOError "digestMLocked @Blake2b_256: c_crypto_hash_sha256" errno Nothing Nothing
        return output

_testBlake2b256 :: SizeHash Blake2b_256 :~: CRYPTO_BLAKE2B_256_BYTES
_testBlake2b256 = Refl
