{-# LANGUAGE RankNTypes #-}

-- We need this so that we can forward the deprecated traceMLockedForeignPtr
{-# OPTIONS_GHC -Wno-deprecations #-}

-- | The Libsodium API generalized to fit arbitrary-ish Monads.
--
-- The purpose of this module is to provide a drop-in replacement for the plain
-- 'Cardano.Crypto.Libsodium' module, but such that the Monad in which some
-- essential actions run can be mocked, rather than forcing it to be 'IO'.
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
  -- * Signing
  NaCl.SodiumDSIGNAlgorithm (..),
  NaCl.naclSignDSIGN,
  NaCl.naclVerifyDSIGN,
  NaCl.SodiumSignKeyDSIGN,
  NaCl.SodiumVerKeyDSIGN,
  NaCl.SodiumSigDSIGN,
)
where

import Cardano.Crypto.Libsodium
  ( MLockedForeignPtr
  , MLockedSizedBytes
  , SodiumSignKeyDSIGN
  )
import qualified Cardano.Crypto.Libsodium as NaCl

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
  mlsbFinalize :: MLockedSizedBytes n -> m ()
  mlsbCopy :: forall n. KnownNat n => MLockedSizedBytes n -> m (MLockedSizedBytes n)
  -- * Signing
  naclForgetSignKeyDSIGN :: Proxy v -> SodiumSignKeyDSIGN v -> m ()

instance MonadSodium IO where
  withMLockedForeignPtr = NaCl.withMLockedForeignPtr
  finalizeMLockedForeignPtr = NaCl.finalizeMLockedForeignPtr
  allocMLockedForeignPtr = NaCl.allocMLockedForeignPtr
  traceMLockedForeignPtr = NaCl.traceMLockedForeignPtr
  mlsbFinalize = NaCl.mlsbFinalize
  mlsbCopy = NaCl.mlsbCopy
  naclForgetSignKeyDSIGN = NaCl.naclForgetSignKeyDSIGN
