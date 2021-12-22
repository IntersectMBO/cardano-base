{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}

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
module Cardano.Crypto.MonadSodium.Class
(
  MonadSodium (..),

  -- * Re-exports from plain Libsodium module
  NaCl.MLockedForeignPtr,
)
where

import Cardano.Crypto.Libsodium.Memory.Internal (MLockedForeignPtr (..))

import qualified Cardano.Crypto.Libsodium.Memory as NaCl
import Control.Monad (void)

import Cardano.Foreign (c_memset, c_memcpy)

import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (Storable)
import Foreign.C.Types (CSize)

{-# DEPRECATED traceMLockedForeignPtr "Do not use traceMLockedForeignPtr in production" #-}

-- | Primitive operations on unmanaged mlocked memory.
-- These are all implemented in 'IO' underneath, but should morally be in 'ST'.
-- There are two use cases for this:
-- - Running mlocked-memory operations in a mocking context (e.g. 'IOSim') for
--   testing purposes.
-- - Running mlocked-memory operations directly on some monad stack with 'IO'
--   at the bottom.
class Monad m => MonadSodium m where
  withMLockedForeignPtr :: forall a b. MLockedForeignPtr a -> (Ptr a -> m b) -> m b
  finalizeMLockedForeignPtr :: forall a. MLockedForeignPtr a -> m ()
  traceMLockedForeignPtr :: (Storable a, Show a) => MLockedForeignPtr a -> m ()
  mlockedMalloc :: CSize -> m (MLockedForeignPtr a)
  zeroMem :: Ptr a -> CSize -> m ()
  copyMem :: Ptr a -> Ptr a -> CSize -> m ()

instance MonadSodium IO where
  withMLockedForeignPtr = NaCl.withMLockedForeignPtr
  finalizeMLockedForeignPtr = NaCl.finalizeMLockedForeignPtr
  traceMLockedForeignPtr = NaCl.traceMLockedForeignPtr
  mlockedMalloc = NaCl.mlockedMalloc
  zeroMem ptr size = void $ c_memset (castPtr ptr) 0 size
  copyMem dst src size = void $ c_memcpy (castPtr dst) (castPtr src) size
