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
  MonadMLock (..),
  mlockedAlloca,
  mlockedAllocaSized,
  mlockedAllocForeignPtr,
  mlockedAllocForeignPtrBytes,
)
where

import Cardano.Crypto.MonadMLock.Class
import Control.Monad.Class.MonadThrow (MonadThrow, bracket)

import Cardano.Foreign (SizedPtr (..))

import GHC.TypeLits (KnownNat, natVal)
import Foreign.Storable (Storable (..))
import Foreign.C.Types (CSize)
import Foreign.Ptr (Ptr)
import Data.Proxy (Proxy (..))

mlockedAllocaSized :: forall m n b. (MonadMLock m, MonadThrow m, KnownNat n) => (SizedPtr n -> m b) -> m b
mlockedAllocaSized k = mlockedAlloca size (k . SizedPtr) where
    size :: CSize
    size = fromInteger (natVal (Proxy @n))

mlockedAllocForeignPtrBytes :: (MonadMLock m) => CSize -> CSize -> m (MLockedForeignPtr m a)
mlockedAllocForeignPtrBytes size align = do
  mlockedMalloc size'
  where
    size' :: CSize
    size'
        | m == 0    = size
        | otherwise = (q + 1) * align
      where
        (q,m) = size `quotRem` align

mlockedAllocForeignPtr :: forall a m . (MonadMLock m, Storable a) => m (MLockedForeignPtr m a)
mlockedAllocForeignPtr =
  mlockedAllocForeignPtrBytes size align
  where
    dummy :: a
    dummy = undefined

    size :: CSize
    size = fromIntegral $ sizeOf dummy

    align :: CSize
    align = fromIntegral $ alignment dummy

mlockedAlloca :: forall a b m. (MonadMLock m, MonadThrow m) => CSize -> (Ptr a -> m b) -> m b
mlockedAlloca size =
  bracket alloc free . flip withMLockedForeignPtr
  where
    alloc = mlockedMalloc size
    free = finalizeMLockedForeignPtr
