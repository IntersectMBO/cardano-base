{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Loading and storing KES signing keys through locked memory.
--
-- The functions here bridge raw mlocked buffers (for instance the output of
-- "Cardano.Crypto.Libsodium.Hex") and the 'DirectDeserialise' /
-- 'DirectSerialise' machinery, so that a signing key can be built from file
-- contents, or serialised for writing back to a file, without a 'ByteString'
-- copy of the key ever existing on the GHC heap.
module Cardano.Crypto.KES.Locked (
  deserialiseSignKeyKESFromLockedBuf,
  serialiseSignKeyKESToLockedBuf,
) where

import Control.Monad (unless, when)
import Control.Monad.Class.MonadST (MonadST, stToIO)
import Control.Monad.Class.MonadThrow (MonadThrow, finally, throwIO)
import Data.Proxy (Proxy (..))
import Data.STRef (newSTRef, readSTRef, writeSTRef)
import Foreign.C.Types (CChar, CSize)
import Foreign.Ptr (Ptr)

import Cardano.Crypto.DirectSerialise (
  DirectDeserialise,
  DirectSerialise,
  SizeCheckException (..),
  directDeserialiseBufChecked,
  directSerialiseBufChecked,
 )
import Cardano.Crypto.KES.Class (KESAlgorithm, SignKeyKES, signKeySizeKES)
import Cardano.Crypto.Libsodium.Memory (
  MLockedAllocator (..),
  MLockedForeignPtr,
  finalizeMLockedForeignPtr,
  mlockedMalloc,
  withMLockedForeignPtr,
 )

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

-- | Serialise a 'SignKeyKES' into a fresh mlocked buffer of exactly
-- 'signKeySizeKES' bytes, in the raw serialisation layout (the inverse of
-- 'deserialiseSignKeyKESFromLockedBuf'; the bytes are what
-- @rawSerialiseSignKeyKES@ would return, but they never touch the heap).
--
-- The returned buffer is a copy: it does not alias the key, so the key may be
-- evolved or forgotten while the buffer is still in use. The caller owns the
-- buffer and must release it with 'finalizeMLockedForeignPtr', which erases
-- it.
--
-- Should serialisation throw (a 'SizeCheckException' from a key whose
-- 'DirectSerialise' instance disagrees with its 'signKeySizeKES'), the buffer
-- is erased and released before the exception propagates.
serialiseSignKeyKESToLockedBuf ::
  forall v m.
  (KESAlgorithm v, DirectSerialise (SignKeyKES v), MonadST m, MonadThrow m) =>
  SignKeyKES v ->
  m (MLockedForeignPtr CChar, Int)
serialiseSignKeyKESToLockedBuf sk = do
  let size = fromIntegral @Word @Int (signKeySizeKES (Proxy @v))
  fptr <- mlAllocate mlockedMalloc (fromIntegral @Int @CSize size)
  -- Only 'MonadThrow' is available here (no 'onException'), so track
  -- completion explicitly and release the buffer in 'finally' when
  -- serialisation did not run to the end.
  done <- stToIO (newSTRef False)
  ( do
      withMLockedForeignPtr fptr $ \buf ->
        directSerialiseBufChecked buf size sk
      stToIO (writeSTRef done True)
    )
    `finally` do
      ok <- stToIO (readSTRef done)
      unless ok (finalizeMLockedForeignPtr fptr)
  return (fptr, size)
