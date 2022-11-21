module Cardano.Crypto.Libsodium.Memory (
  -- * High-level memory management
  MLockedForeignPtr,
  withMLockedForeignPtr,
  allocMLockedForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,
  -- * Debugging / testing instrumentation
  AllocEvent (..),
  pushAllocLogEvent,
  popAllocLogEvent,
  withAllocLog,
) where

import Cardano.Crypto.Libsodium.Memory.Internal
