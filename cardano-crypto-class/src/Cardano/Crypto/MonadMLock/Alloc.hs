{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- We need this so that we can forward the deprecated traceMLockedForeignPtr
{-# OPTIONS_GHC -Wno-deprecations #-}

-- | The Libsodium API generalized to fit arbitrary-ish Monads.
--
-- The purpose of this module is to provide a drop-in replacement for the plain
-- 'Cardano.Crypto.Libsodium' module, but such that the Monad in which some
-- essential actions run can be mocked, rather than forcing it to be 'IO'.
--
-- It may also be used to provide Libsodium functionality in monad stacks that
-- have IO at the bottom, but decorate certain Libsodium operations with
-- additional effects, e.g. logging mlocked memory access.
module Cardano.Crypto.MonadMLock.Alloc
(
  -- * MLocked allocations
  mlockedAlloca,
  mlockedAllocaSized,
  mlockedAllocForeignPtr,
  mlockedAllocForeignPtrBytes,

  -- * Allocations using an explicit allocator
  mlockedAllocaWith,
  mlockedAllocaSizedWith,
  mlockedAllocForeignPtrWith,
  mlockedAllocForeignPtrBytesWith,

  -- * Convenient type alias
  MLockedAllocator,

  -- * Re-exports from plain Libsodium module
  NaCl.MLockedForeignPtr,
  mlockedMalloc
)
where

import Cardano.Crypto.MonadMLock.Class
import Control.Monad.Class.MonadThrow (MonadThrow, bracket)
import Control.Monad.Class.MonadST (MonadST)

import qualified Cardano.Crypto.Libsodium.Memory as NaCl

import Cardano.Foreign (SizedPtr (..))

import GHC.TypeLits (KnownNat, natVal)
import Foreign.Storable (Storable (..))
import Foreign.C.Types (CSize)
import Foreign.Ptr (Ptr)
import Data.Proxy (Proxy (..))
import Data.Void (Void)

type MLockedAllocator m a = CSize -> m (MLockedForeignPtr a)

mlockedAllocaSized :: forall m n b. (MonadST m, MonadThrow m, KnownNat n) => (SizedPtr n -> m b) -> m b
mlockedAllocaSized = mlockedAllocaSizedWith mlockedMalloc 

mlockedAllocaSizedWith :: forall m n b. (MonadST m, MonadThrow m, KnownNat n) => MLockedAllocator m Void -> (SizedPtr n -> m b) -> m b
mlockedAllocaSizedWith allocator k = mlockedAllocaWith allocator size (k . SizedPtr) where
    size :: CSize
    size = fromInteger (natVal (Proxy @n))

mlockedAllocForeignPtrBytes :: (MonadST m) => CSize -> CSize -> m (MLockedForeignPtr a)
mlockedAllocForeignPtrBytes = mlockedAllocForeignPtrBytesWith mlockedMalloc

mlockedAllocForeignPtrBytesWith :: MLockedAllocator m a -> CSize -> CSize -> m (MLockedForeignPtr a)
mlockedAllocForeignPtrBytesWith allocator size align = do
  allocator size'
  where
    size' :: CSize
    size'
        | m == 0    = size
        | otherwise = (q + 1) * align
      where
        (q,m) = size `quotRem` align

mlockedAllocForeignPtr :: forall a m . (MonadST m, Storable a) => m (MLockedForeignPtr a)
mlockedAllocForeignPtr = mlockedAllocForeignPtrWith mlockedMalloc

mlockedAllocForeignPtrWith :: forall a m . (Storable a) => MLockedAllocator m a -> m (MLockedForeignPtr a)
mlockedAllocForeignPtrWith allocator =
  mlockedAllocForeignPtrBytesWith allocator size align
  where
    dummy :: a
    dummy = undefined

    size :: CSize
    size = fromIntegral $ sizeOf dummy

    align :: CSize
    align = fromIntegral $ alignment dummy

mlockedAlloca :: forall a b m. (MonadST m, MonadThrow m) => CSize -> (Ptr a -> m b) -> m b
mlockedAlloca = mlockedAllocaWith mlockedMalloc

mlockedAllocaWith :: forall a b m. (MonadST m, MonadThrow m) => MLockedAllocator m a -> CSize -> (Ptr a -> m b) -> m b
mlockedAllocaWith allocator size =
  bracket alloc free . flip withMLockedForeignPtr
  where
    alloc = allocator size
    free = finalizeMLockedForeignPtr
