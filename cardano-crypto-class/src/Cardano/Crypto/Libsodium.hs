module Cardano.Crypto.Libsodium (
  -- * Initialization
  sodiumInit,

  -- * MLocked memory management
  MLockedForeignPtr,
  MLockedAllocator,

  finalizeMLockedForeignPtr,
  mlockedAllocForeignPtr,
  mlockedMalloc,
  traceMLockedForeignPtr,
  withMLockedForeignPtr,

  -- * MLocked bytes ('MLockedSizedBytes')
  MLockedSizedBytes,

  mlsbAsByteString,
  mlsbCompare,
  mlsbCopy,
  mlsbCopyWith,
  mlsbEq,
  mlsbFinalize,
  mlsbFromByteString,
  mlsbFromByteStringCheck,
  mlsbFromByteStringCheckWith,
  mlsbFromByteStringWith,
  mlsbNew,
  mlsbNewWith,
  mlsbNewZero,
  mlsbNewZeroWith,
  mlsbToByteString,
  mlsbUseAsCPtr,
  mlsbUseAsSizedPtr,
  mlsbZero,

  -- * Hashing
  digestMLockedBS,
  digestMLockedStorable,
  expandHash,
  expandHashWith,
  SodiumHashAlgorithm (..),
) where

import Cardano.Crypto.Libsodium.Init
import Cardano.Crypto.Libsodium.Memory
import Cardano.Crypto.Libsodium.Hash
import Cardano.Crypto.Libsodium.MLockedBytes
