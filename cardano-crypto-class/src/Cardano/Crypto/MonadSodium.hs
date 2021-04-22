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
  NaCl.SodiumDSIGNAlgorithm,
  NaCl.naclSignDSIGN,
  NaCl.naclVerifyDSIGN,
  NaCl.SodiumSignKeyDSIGN,
  NaCl.SodiumVerKeyDSIGN,
  NaCl.SodiumSigDSIGN,

  -- * SafePinned
  SP.SafePinned,
  mapSafePinned
)
where

import Cardano.Crypto.Libsodium
  ( MLockedForeignPtr
  , MLockedSizedBytes
  , SodiumSignKeyDSIGN
  )
import qualified Cardano.Crypto.Libsodium as NaCl
import qualified Cardano.Crypto.DSIGN.Class as NaCl
import qualified Cardano.Crypto.SafePinned as SP

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

  -- * SafePinned
  makeSafePinned :: a -> m (SP.SafePinned a)
  releaseSafePinned :: forall a. SP.Release a => SP.SafePinned a -> m ()
  interactSafePinned :: SP.SafePinned a -> (a -> m b) -> m b

  -- * DSIGN
  naclSignDSIGNPtr
      :: forall a v. NaCl.SodiumDSIGNAlgorithm v
      => Proxy v
      -> Ptr a -> Int
      -> NaCl.SodiumSignKeyDSIGN v
      -> m (NaCl.SodiumSigDSIGN v)

  naclVerifyDSIGNPtr
      :: forall a v. NaCl.SodiumDSIGNAlgorithm v
      => Proxy v
      -> NaCl.SodiumVerKeyDSIGN v
      -> Ptr a -> Int
      -> NaCl.SodiumSigDSIGN v
      -> m (Either String ())

  naclGenKeyDSIGN
      :: forall v. NaCl.SodiumDSIGNAlgorithm v
      => Proxy v
      -> MLockedSizedBytes (NaCl.SeedSizeDSIGN v)
      -> m (NaCl.SodiumSignKeyDSIGN v)

  naclDeriveVerKeyDSIGN
      :: forall v. NaCl.SodiumDSIGNAlgorithm v
      => Proxy v
      -> NaCl.SodiumSignKeyDSIGN v
      -> m (NaCl.SodiumVerKeyDSIGN v)

instance MonadSodium IO where
  withMLockedForeignPtr = NaCl.withMLockedForeignPtr
  finalizeMLockedForeignPtr = NaCl.finalizeMLockedForeignPtr
  allocMLockedForeignPtr = NaCl.allocMLockedForeignPtr
  traceMLockedForeignPtr = NaCl.traceMLockedForeignPtr
  mlsbFinalize = NaCl.mlsbFinalize
  mlsbCopy = NaCl.mlsbCopy
  naclForgetSignKeyDSIGN = NaCl.naclForgetSignKeyDSIGN
  makeSafePinned = SP.makeSafePinned
  releaseSafePinned = SP.releaseSafePinned
  interactSafePinned = SP.interactSafePinned
  naclSignDSIGNPtr = NaCl.naclSignDSIGNPtr
  naclVerifyDSIGNPtr = NaCl.naclVerifyDSIGNPtr
  naclGenKeyDSIGN = NaCl.naclGenKeyDSIGN
  naclDeriveVerKeyDSIGN = NaCl.naclDeriveVerKeyDSIGN

mapSafePinned :: MonadSodium m => (a -> m b) -> SP.SafePinned a -> m (SP.SafePinned b)
mapSafePinned f p =
  interactSafePinned p f >>= makeSafePinned
