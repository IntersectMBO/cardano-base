module Cardano.Crypto.Libsodium (
  -- * Initialization
  sodiumInit,
  -- * MLocked memory management
  MLockedForeignPtr,
  withMLockedForeignPtr,
  mlockedAllocForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,
  -- * MLocked bytes
  MLockedSizedBytes,
  mlsbFromByteString,
  mlsbFromByteStringCheck,
  mlsbAsByteString,
  mlsbToByteString,
  mlsbFinalize,
  mlsbCopy,
  -- * Hashing
  SodiumHashAlgorithm (..),
  digestMLockedStorable,
  digestMLockedBS,
  expandHash,
) where

import Cardano.Crypto.Libsodium.Init
import Cardano.Crypto.MonadMLock
