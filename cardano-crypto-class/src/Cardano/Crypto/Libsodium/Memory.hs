module Cardano.Crypto.Libsodium.Memory (
  -- * High-level memory management
  MLockedForeignPtr, -- TODO: hide
  withMLockedForeignPtr,
  allocMLockedForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,
) where

import Cardano.Crypto.Libsodium.Memory.Internal
