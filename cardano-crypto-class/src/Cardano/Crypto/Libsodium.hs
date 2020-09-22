module Cardano.Crypto.Libsodium (
  -- * Initialization
  sodiumInit,
  -- * MLocked memory management
  MLockedForeignPtr,
  withMLockedForeignPtr,
  allocMLockedForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,
  -- * MLocked bytes
  MLockedSizedBytes,
  mlsbZero,
  mlsbFromByteString,
  mlsbFromByteStringCheck,
  mlsbToByteString,
  mlsbFinalize,
  mlsbCopy,
  -- * Hashing
  SodiumHashAlgorithm (..),
  digestMLockedStorable,
  digestMLockedBS,
  expandHash,
  -- * Signing
  SodiumDSIGNAlgorithm (..),
  naclSignDSIGN,
  naclVerifyDSIGN,
  naclForgetSignKeyDSIGN,
  SodiumSignKeyDSIGN,
  SodiumVerKeyDSIGN,
  SodiumSigDSIGN,
) where

import Cardano.Crypto.Libsodium.DSIGN
import Cardano.Crypto.Libsodium.Hash
import Cardano.Crypto.Libsodium.Init
import Cardano.Crypto.Libsodium.Memory
import Cardano.Crypto.Libsodium.MLockedBytes
