{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

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
module Cardano.Crypto.MonadMLock
(
  -- * MonadMLock class
  MonadMLock (..),
  MonadUnmanagedMemory (..),
  MonadByteStringMemory (..),
  MonadPSB (..),

  -- * Re-exported types
  MLockedForeignPtr,
  MLockedSizedBytes,

  -- * Monadic Eq and Ord
  MEq (..),
  nequalsM,
  (==!), (!=!),
  PureMEq (..),

  -- * Memory management
  mlockedAllocaSized,
  mlockedAllocForeignPtr,
  mlockedAllocForeignPtrBytes,

  -- * Generalized foreign memory access
  packByteStringCStringLen,

  -- * PinnedSizedBytes operations
  PinnedSizedBytes,

  psbUseAsCPtr,
  psbUseAsSizedPtr,

  psbCreate,
  psbCreateLen,
  psbCreateSizedResult,

  psbToByteString,
  psbFromByteStringCheck,

  -- * MLockedSizedBytes operations
  mlsbNew,
  mlsbZero,
  mlsbNewZero,
  mlsbCopy,
  mlsbFinalize,
  mlsbToByteString,
  mlsbAsByteString,
  mlsbFromByteString,
  mlsbFromByteStringCheck,
  mlsbUseAsSizedPtr,
  mlsbUseAsCPtr,
  mlsbCompare,
  mlsbEq,

  -- * Hashing
  SodiumHashAlgorithm (..),
  expandHash,
  digestMLockedStorable,
  digestMLockedBS,
)
where

import Cardano.Crypto.MonadMLock.Class
import Cardano.Crypto.MonadMLock.Alloc
import Cardano.Crypto.Libsodium.Hash
import Cardano.Crypto.Libsodium.MLockedBytes
import Cardano.Crypto.MEqOrd
