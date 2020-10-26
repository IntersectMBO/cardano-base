module Cardano.Crypto.Libsodium.Memory (
  -- * High-level memory management
  MLockedForeignPtr,
  withMLockedForeignPtr,
  allocMLockedForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,
  -- * Debugging / testing instrumentation
  AllocEvent (..),
  popAllocLogEvent,
) where

import Cardano.Crypto.Libsodium.Memory.Internal
