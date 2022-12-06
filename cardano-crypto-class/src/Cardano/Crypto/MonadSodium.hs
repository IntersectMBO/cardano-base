{-# LANGUAGE CPP #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- We need this so that we can forward the deprecated traceMLockedForeignPtr
{-# OPTIONS_GHC -Wno-deprecations #-}

-- | The Libsodium API generalized to fit arbitrary-ish Monads.
--
-- The purpose of this module is to provide a drop-in replacement for the plain
-- 'Cardano.Crypto.Libsodium' module, but such that the Monad in which some
-- essential actions run can be mocked, rather than forcing it to be 'IO'.
--
-- It may also be used to provide Libsodium functionality in monad stacks that
-- have IO at the bottom, but decorate certain Libsodium operations with
-- additional effects, e.g. logging mlocked memory access.
module Cardano.Crypto.MonadSodium
(
  MonadSodium (..),

  -- * Re-exports from plain Libsodium module
  NaCl.sodiumInit,
  NaCl.MLockedForeignPtr,
  NaCl.MLockedSizedBytes,
  NaCl.mlsbAsByteString,
  NaCl.SodiumHashAlgorithm (..),
  NaCl.digestMLockedStorable,
  NaCl.digestMLockedBS,
)
where

import Cardano.Crypto.Libsodium
  ( MLockedForeignPtr
  )
import qualified Cardano.Crypto.Libsodium as NaCl
import Cardano.Crypto.Libsodium.MLockedBytes (MLockedSizedBytes)
import qualified Cardano.Crypto.Libsodium.MLockedBytes as NaCl
import Cardano.Crypto.Libsodium.Hash as NaCl
import Cardano.Crypto.Hash (HashAlgorithm(SizeHash))
import Cardano.Foreign (SizedPtr)

import GHC.TypeLits (KnownNat)
import Foreign.Ptr (Ptr)
import Foreign.Storable (Storable)
import Data.Word (Word8)
import qualified Data.ByteString as BS

{-#DEPRECATED traceMLockedForeignPtr "Do not use traceMLockedForeignPtr in production" #-}

#ifndef ALLOW_MLOCK_VIOLATIONS
{-#WARNING mlsbToByteString "This function is disabled in production builds" #-}
#endif

class Monad m => MonadSodium m where
  -- * MLocked memory management
  withMLockedForeignPtr :: forall a b. MLockedForeignPtr a -> (Ptr a -> m b) -> m b
  finalizeMLockedForeignPtr :: forall a. MLockedForeignPtr a -> m ()
  allocMLockedForeignPtr :: Storable a => m (MLockedForeignPtr a)
  traceMLockedForeignPtr :: (Storable a, Show a) => MLockedForeignPtr a -> m ()

  -- * MLocked bytes
  mlsbNew :: forall n. KnownNat n => m (MLockedSizedBytes n)
  mlsbFinalize :: MLockedSizedBytes n -> m ()
  mlsbCopy :: forall n. KnownNat n => MLockedSizedBytes n -> m (MLockedSizedBytes n)
  mlsbUseAsSizedPtr :: forall n r. KnownNat n => MLockedSizedBytes n -> (SizedPtr n -> m r) -> m r
  mlsbUseAsCPtr :: forall n r. KnownNat n => MLockedSizedBytes n -> (Ptr Word8 -> m r) -> m r
  mlsbFromByteString :: forall n. KnownNat n => BS.ByteString -> m (MLockedSizedBytes n)
  mlsbFromByteStringCheck :: forall n. KnownNat n => BS.ByteString -> m (Maybe (MLockedSizedBytes n))

  -- | Note that this function will leak mlocked memory to the Haskell heap
  -- and should not be used in production code.
  mlsbToByteString :: forall n. KnownNat n => MLockedSizedBytes n -> m BS.ByteString

  -- * Hashing
  expandHash
      :: forall h proxy. NaCl.SodiumHashAlgorithm h
      => proxy h
      -> (MLockedSizedBytes (SizeHash h))
      -> m (MLockedSizedBytes (SizeHash h), MLockedSizedBytes (SizeHash h))


instance MonadSodium IO where
  withMLockedForeignPtr = NaCl.withMLockedForeignPtr
  finalizeMLockedForeignPtr = NaCl.finalizeMLockedForeignPtr
  allocMLockedForeignPtr = NaCl.allocMLockedForeignPtr
  traceMLockedForeignPtr = NaCl.traceMLockedForeignPtr
  mlsbNew = NaCl.mlsbNew
  mlsbFinalize = NaCl.mlsbFinalize
  mlsbCopy = NaCl.mlsbCopy
  mlsbUseAsSizedPtr = NaCl.mlsbUseAsSizedPtr
  mlsbUseAsCPtr = NaCl.mlsbUseAsCPtr
  mlsbFromByteString = NaCl.mlsbFromByteString
  mlsbFromByteStringCheck = NaCl.mlsbFromByteStringCheck
  mlsbToByteString = NaCl.mlsbToByteString
  expandHash = NaCl.expandHash
