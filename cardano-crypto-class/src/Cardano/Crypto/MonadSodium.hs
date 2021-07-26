{-# LANGUAGE RankNTypes #-}

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
  NaCl.mlsbZero,
  NaCl.mlsbFromByteString,
  NaCl.mlsbFromByteStringCheck,
  NaCl.mlsbToByteString,
  NaCl.SodiumHashAlgorithm (..),
  NaCl.digestMLockedStorable,
  NaCl.digestMLockedBS,
  NaCl.expandHash,

  -- * SafePinned
  SP.SafePinned,
  mapSafePinned
)
where

import Cardano.Crypto.Libsodium
  ( MLockedForeignPtr
  , MLockedSizedBytes
  )
import qualified Cardano.Crypto.Libsodium as NaCl
import qualified Cardano.Crypto.SafePinned as SP
import Cardano.Crypto.Libsodium.MLockedBytes as NaCl
import Cardano.Foreign (SizedPtr)

import Data.Proxy (Proxy (..))
import GHC.TypeLits (KnownNat)
import Foreign.Ptr (Ptr)
import Foreign.Storable (Storable)

{-#DEPRECATED traceMLockedForeignPtr "Do not use traceMLockedForeignPtr in production" #-}

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

  -- * SafePinned
  makeSafePinned :: a -> m (SP.SafePinned a)
  releaseSafePinned :: forall a. SP.Release a => SP.SafePinned a -> m ()
  interactSafePinned :: SP.SafePinned a -> (a -> m b) -> m b

instance MonadSodium IO where
  withMLockedForeignPtr = NaCl.withMLockedForeignPtr
  finalizeMLockedForeignPtr = NaCl.finalizeMLockedForeignPtr
  allocMLockedForeignPtr = NaCl.allocMLockedForeignPtr
  traceMLockedForeignPtr = NaCl.traceMLockedForeignPtr
  mlsbNew = NaCl.mlsbNew
  mlsbFinalize = NaCl.mlsbFinalize
  mlsbCopy = NaCl.mlsbCopy
  mlsbUseAsSizedPtr = NaCl.mlsbUseAsSizedPtr
  makeSafePinned = SP.makeSafePinned
  releaseSafePinned = SP.releaseSafePinned
  interactSafePinned = SP.interactSafePinned

mapSafePinned :: MonadSodium m => (a -> m b) -> SP.SafePinned a -> m (SP.SafePinned b)
mapSafePinned f p =
  interactSafePinned p f >>= makeSafePinned
