module Cardano.Crypto.Libsodium (
  -- * Initialization
  sodiumInit,
  -- * Secure memory management
  SecureForeignPtr,
  withSecureForeignPtr,
  allocSecureForeignPtr,
  finalizeSecureForeignPtr,
  traceSecureForeignPtr,
  -- * Secure bytes
  SecureFiniteBytes,
  sfbFromByteString,
  sfbToByteString,
  -- * Hashing
  SodiumHashAlgorithm (..),
  digestSecureStorable,
  digestSecureFB,
  digestSecureBS,
  expandHash,
) where

import Cardano.Crypto.Libsodium.Hash
import Cardano.Crypto.Libsodium.Init
import Cardano.Crypto.Libsodium.Memory
import Cardano.Crypto.Libsodium.SecureBytes
