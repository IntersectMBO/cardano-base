{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE TypeApplications #-}
module Cardano.Crypto.Libsodium.Hash (
    SodiumHashAlgorithm (..),
    digestMLockedStorable,
    digestMLockedBS,
    expandHash,
    expandHashWith,
) where

import Data.Proxy (Proxy (..))
import Foreign.C.Types (CSize)
import Foreign.Ptr (castPtr, plusPtr)
import Foreign.Storable (Storable (poke))
import Data.Word (Word8)
import GHC.TypeLits

import Cardano.Crypto.Hash (HashAlgorithm(SizeHash))
import Cardano.Crypto.Libsodium.Memory
import Cardano.Crypto.Libsodium.Hash.Class
import Cardano.Crypto.Libsodium.MLockedBytes.Internal
import Control.Monad.Class.MonadST (MonadST (..))
import Control.Monad.Class.MonadThrow (MonadThrow)
import Control.Monad.ST.Unsafe (unsafeIOToST)

-------------------------------------------------------------------------------
-- Hash expansion
-------------------------------------------------------------------------------

expandHash
    :: forall h m proxy.
       (SodiumHashAlgorithm h, MonadST m, MonadThrow m)
    => proxy h
    -> MLockedSizedBytes (SizeHash h)
    -> m (MLockedSizedBytes (SizeHash h), MLockedSizedBytes (SizeHash h))
expandHash = expandHashWith mlockedMalloc

expandHashWith
    :: forall h m proxy.
       (SodiumHashAlgorithm h, MonadST m, MonadThrow m)
    => MLockedAllocator m Word8
    -> proxy h
    -> MLockedSizedBytes (SizeHash h)
    -> m (MLockedSizedBytes (SizeHash h), MLockedSizedBytes (SizeHash h))
expandHashWith allocator h (MLSB sfptr) = do
    withMLockedForeignPtr sfptr $ \ptr -> do
        l <- mlockedAllocaWith allocator size1 $ \ptr' -> do
              withLiftST $ \liftST -> liftST . unsafeIOToST $ do
                poke ptr' (1 :: Word8)
                copyMem (castPtr (plusPtr ptr' 1)) ptr size
                naclDigestPtr h ptr' (fromIntegral size1)

        r <- mlockedAllocaWith allocator size1 $ \ptr' -> do
              withLiftST $ \liftST -> liftST . unsafeIOToST $ do
                poke ptr' (2 :: Word8)
                copyMem (castPtr (plusPtr ptr' 1)) ptr size
                naclDigestPtr h ptr' (fromIntegral size1)

        return (l, r)
  where
    size1 :: CSize
    size1 = size + 1

    size :: CSize
    size = fromInteger $ natVal (Proxy @(SizeHash h))

