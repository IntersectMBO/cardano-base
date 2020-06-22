module Cardano.Crypto.Libsodium.Memory (
  -- * High-level memory management
  SecureForeignPtr, -- TODO: hide
  withSecureForeignPtr,
  allocSecureForeignPtr,
  finalizeSecureForeignPtr,
  traceSecureForeignPtr,
) where

import Cardano.Crypto.Libsodium.Memory.Internal
