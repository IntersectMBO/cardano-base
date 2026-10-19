{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Loading KES signing keys from locked memory.
--
-- The functions here bridge raw mlocked buffers (for instance the output of
-- "Cardano.Crypto.Libsodium.Hex") and the 'DirectDeserialise' machinery, so
-- that a signing key can be built from file contents without a 'ByteString'
-- copy of the key ever existing on the GHC heap.
module Cardano.Crypto.KES.Locked (
  deserialiseSignKeyKESFromLockedBuf,
) where

import Control.Monad (when)
import Control.Monad.Class.MonadST (MonadST)
import Control.Monad.Class.MonadThrow (MonadThrow, throwIO)
import Data.Proxy (Proxy (..))
import Foreign.C.Types (CChar)
import Foreign.Ptr (Ptr)

import Cardano.Crypto.DirectSerialise (
  DirectDeserialise,
  SizeCheckException (..),
  directDeserialiseBufChecked,
 )
import Cardano.Crypto.KES.Class (KESAlgorithm, SignKeyKES, signKeySizeKES)

-- | Deserialise a 'SignKeyKES' from a buffer of exactly 'signKeySizeKES' bytes
-- in the raw serialisation layout (the same layout 'DirectSerialise' produces
-- and @rawSerialiseSignKeyKES@ returns).
--
-- The buffer should be mlocked; the key's own components are allocated in
-- mlocked memory and the bytes are copied in from the buffer. The buffer is
-- left untouched: the caller still owns it and should erase it once the key
-- has been built.
--
-- Throws 'SizeCheckException' when the length is not 'signKeySizeKES'. The
-- length is checked before anything is deserialised, so a wrong-sized buffer
-- never leaves half-built key components behind in locked memory.
deserialiseSignKeyKESFromLockedBuf ::
  forall v m.
  (KESAlgorithm v, DirectDeserialise (SignKeyKES v), MonadST m, MonadThrow m) =>
  Ptr CChar ->
  Int ->
  m (SignKeyKES v)
deserialiseSignKeyKESFromLockedBuf buf len = do
  let expected = fromIntegral @Word @Int (signKeySizeKES (Proxy @v))
  when (len /= expected) $
    throwIO (SizeCheckException expected len)
  directDeserialiseBufChecked buf len
