module Cardano.Crypto.Libsodium.Memory (
  -- * High-level memory management
  MLockedForeignPtr,
  withMLockedForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,

  -- * MLocked allocations
  mlockedMalloc,
  MLockedAllocator (..),

  mlockedAlloca,
  mlockedAllocaSized,
  mlockedAllocForeignPtr,
  mlockedAllocForeignPtrBytes,

  -- * Allocations using an explicit allocator
  mlockedAllocaWith,
  mlockedAllocaSizedWith,
  mlockedAllocForeignPtrWith,
  mlockedAllocForeignPtrBytesWith,

  -- * Unmanaged memory, generalized to 'MonadST'
  zeroMem,
  copyMem,
  allocaBytes,

  -- * ByteString memory access, generalized to 'MonadST'
  packByteStringCStringLen,
) where

import Cardano.Crypto.Libsodium.Memory.Internal
