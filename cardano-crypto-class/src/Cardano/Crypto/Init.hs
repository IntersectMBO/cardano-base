{-# LANGUAGE CPP #-}

-- | Initialization for the library's functionality
module Cardano.Crypto.Init (
  cryptoInit
  ) where

import Cardano.Crypto.Libsodium.Init (sodiumInit)
#if defined(SECP256K1_ENABLED)
import Control.Monad (void)
import Cardano.Crypto.SECP256K1.C (secpCtxPtr)
import Control.Exception (evaluate)
#endif

-- | Initialize all the functionality provided by this library. This should be
-- called at least once /before/ you use anything this library provides, in
-- @main@.
--
-- It is safe to call this multiple times, but isn't necessary.
--
-- = Note
--
-- This includes a call to 'sodiumInit'.
cryptoInit :: IO ()
cryptoInit = do
  sodiumInit
#if defined(SECP256K1_ENABLED)
  void . evaluate $ secpCtxPtr
#endif
