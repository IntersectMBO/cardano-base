module Cardano.Crypto.Libsodium.Memory (
  -- * High-level memory management
  MLockedForeignPtr,
  withMLockedForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,
  mlockedMalloc,
) where

import Cardano.Crypto.Libsodium.Memory.Internal
