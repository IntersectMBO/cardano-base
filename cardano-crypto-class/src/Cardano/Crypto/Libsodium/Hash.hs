{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE TypeApplications #-}
module Cardano.Crypto.Libsodium.Hash (
    SodiumHashAlgorithm (..),
    digestMLockedStorable,
    digestMLockedFB,
    digestMLockedBS,
    expandHash,
) where

import Control.Exception (bracket)
import Control.Monad (unless)
import Data.Proxy (Proxy (..))
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.C.Types (CSize)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.Storable (Storable (sizeOf, poke))
import Data.Word (Word8)
import GHC.IO.Exception (ioException)
import GHC.TypeLits
import System.IO.Unsafe (unsafeDupablePerformIO)
import GHC.IO.Handle.Text (memcpy)

import qualified Data.ByteString as BS

import Cardano.Crypto.Hash (HashAlgorithm, SHA256, Blake2b_256)
import Cardano.Crypto.FiniteBytes (FiniteBytes)
import Cardano.Crypto.Libsodium.C
import Cardano.Crypto.Libsodium.Memory.Internal
import Cardano.Crypto.Libsodium.MLockedBytes.Internal

-------------------------------------------------------------------------------
-- Type-Class
-------------------------------------------------------------------------------

class (HashAlgorithm h, KnownNat (SizeHash h)) => SodiumHashAlgorithm h where
    -- | The size in bytes of the output of 'digest'
    type SizeHash h :: Nat

    digestMLocked
        :: proxy h
        -> Ptr a  -- ^ input
        -> Int    -- ^ input length
        -> IO (MLockedFiniteBytes (SizeHash h))

    -- TODO: provide interface for multi-part?
    -- That will be useful to hashing ('1' <> oldseed).

digestMLockedStorable
    :: forall h a proxy. (SodiumHashAlgorithm h, Storable a)
    => proxy h -> Ptr a -> IO (MLockedFiniteBytes (SizeHash h))
digestMLockedStorable p ptr =
  digestMLocked p ptr ((sizeOf (undefined :: a)))

digestMLockedFB
    :: forall h n proxy. (SodiumHashAlgorithm h, KnownNat n)
    => proxy h -> Ptr (FiniteBytes n) -> IO (MLockedFiniteBytes (SizeHash h))
digestMLockedFB = digestMLockedStorable

digestMLockedBS
    :: forall h proxy. (SodiumHashAlgorithm h)
    => proxy h -> BS.ByteString -> IO (MLockedFiniteBytes (SizeHash h))
digestMLockedBS p bs = BS.useAsCStringLen bs $ \(ptr, len) -> do
    digestMLocked p (castPtr ptr) len

-------------------------------------------------------------------------------
-- Hash expansion
-------------------------------------------------------------------------------

expandHash
    :: forall h proxy. SodiumHashAlgorithm h
    => proxy h
    -> (MLockedFiniteBytes (SizeHash h))
    -> (MLockedFiniteBytes (SizeHash h), MLockedFiniteBytes (SizeHash h))
expandHash h (MLFB sfptr) = unsafeDupablePerformIO $ do
    withMLockedForeignPtr sfptr $ \ptr -> do
        l <- bracket (sodiumMalloc size1) sodiumFree $ \ptr' -> do
            poke ptr' (1 :: Word8)
            _ <- memcpy (castPtr (plusPtr ptr' 1)) ptr size
            digestMLocked h ptr' (fromIntegral size1)

        r <- bracket (sodiumMalloc size1) sodiumFree $ \ptr' -> do
            poke ptr' (2 :: Word8)
            _ <- memcpy (castPtr (plusPtr ptr' 1)) ptr size
            digestMLocked h ptr' (fromIntegral size1)

        return (l, r)
  where
    size1 :: CSize
    size1 = size + 1

    size :: CSize
    size = fromInteger $ natVal (Proxy @(SizeHash h))

-------------------------------------------------------------------------------
-- Instances
-------------------------------------------------------------------------------

instance SodiumHashAlgorithm SHA256 where
    type SizeHash SHA256 = CRYPTO_SHA256_BYTES

    digestMLocked :: forall proxy a. proxy SHA256 -> Ptr a -> Int -> IO (MLockedFiniteBytes (SizeHash SHA256))
    digestMLocked _ input inputlen = do
        output <- allocMLockedForeignPtr
        withMLockedForeignPtr output $ \output' -> do
            res <- c_crypto_hash_sha256 (castPtr output') (castPtr input) (fromIntegral inputlen)
            unless (res == 0) $ do
                errno <- getErrno
                ioException $ errnoToIOError "digestMLocked @SHA256: c_crypto_hash_sha256" errno Nothing Nothing

        return (MLFB output)

instance SodiumHashAlgorithm Blake2b_256 where
    type SizeHash Blake2b_256 = CRYPTO_BLAKE2B_256_BYTES

    digestMLocked :: forall proxy a. proxy Blake2b_256 -> Ptr a -> Int -> IO (MLockedFiniteBytes (SizeHash Blake2b_256))
    digestMLocked _ input inputlen = do
        output <- allocMLockedForeignPtr
        withMLockedForeignPtr output $ \output' -> do
            res <- c_crypto_generichash
                output' (fromInteger $ natVal (Proxy @CRYPTO_BLAKE2B_256_BYTES))  -- output
                (castPtr input) (fromIntegral inputlen)  -- input
                nullPtr 0                                -- key, unused
            unless (res == 0) $ do
                errno <- getErrno
                ioException $ errnoToIOError "digestMLocked @Blake2b_256: c_crypto_hash_sha256" errno Nothing Nothing

        return (MLFB output)
