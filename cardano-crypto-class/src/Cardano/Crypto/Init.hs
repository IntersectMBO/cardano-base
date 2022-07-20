-- | Initialization for the library's functionality
module Cardano.Crypto.Init (
  cryptoInit
  ) where

import Control.Monad (void)
import Control.Exception (evaluate)
import Cardano.Crypto.Libsodium.Init (sodiumInit)
import Cardano.Crypto.SECP256K1.C (secpCtxPtr)

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
cryptoInit = void (sodiumInit >> evaluate secpCtxPtr)
