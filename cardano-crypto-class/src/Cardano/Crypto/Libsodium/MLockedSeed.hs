{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE StandaloneDeriving #-}

module Cardano.Crypto.Libsodium.MLockedSeed
where

import Cardano.Crypto.Libsodium.MLockedBytes (
  MLockedSizedBytes,
  mlsbCopyWith,
  mlsbFinalize,
  mlsbNewWith,
  mlsbNewZeroWith,
  mlsbUseAsCPtr,
  mlsbUseAsSizedPtr,
 )
import Cardano.Crypto.Libsodium.Memory (
  MLockedAllocator,
  mlockedMalloc,
 )
import Cardano.Crypto.MEqOrd (
  MEq (..),
 )
import Cardano.Foreign (SizedPtr)
import Control.DeepSeq (NFData)
import Control.Monad.Class.MonadST (MonadST)
import Control.Monad.Class.MonadThrow (MonadThrow)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import GHC.TypeNats (KnownNat)
import NoThunks.Class (NoThunks)

-- | A seed of size @n@, stored in mlocked memory. This is required to prevent
-- the seed from leaking to disk via swapping and reclaiming or scanning memory
-- after its content has been moved.
newtype MLockedSeed n = MLockedSeed {mlockedSeedMLSB :: MLockedSizedBytes n}
  deriving (NFData, NoThunks)

deriving via
  MLockedSizedBytes n
  instance
    KnownNat n => MEq (MLockedSeed n)

withMLockedSeedAsMLSB
  :: Functor m
  => (MLockedSizedBytes n -> m (MLockedSizedBytes n))
  -> MLockedSeed n
  -> m (MLockedSeed n)
withMLockedSeedAsMLSB action =
  fmap MLockedSeed . action . mlockedSeedMLSB

mlockedSeedCopy :: (KnownNat n, MonadST m, MonadThrow m) => MLockedSeed n -> m (MLockedSeed n)
mlockedSeedCopy = mlockedSeedCopyWith mlockedMalloc

mlockedSeedCopyWith
  :: (KnownNat n, MonadST m)
  => MLockedAllocator m
  -> MLockedSeed n
  -> m (MLockedSeed n)
mlockedSeedCopyWith allocator = withMLockedSeedAsMLSB (mlsbCopyWith allocator)

mlockedSeedNew :: (KnownNat n, MonadST m, MonadThrow m) => m (MLockedSeed n)
mlockedSeedNew = mlockedSeedNewWith mlockedMalloc

mlockedSeedNewWith :: (KnownNat n, MonadST m) => MLockedAllocator m -> m (MLockedSeed n)
mlockedSeedNewWith allocator =
  MLockedSeed <$> mlsbNewWith allocator

mlockedSeedNewZero :: (KnownNat n, MonadST m, MonadThrow m) => m (MLockedSeed n)
mlockedSeedNewZero = mlockedSeedNewZeroWith mlockedMalloc

mlockedSeedNewZeroWith :: (KnownNat n, MonadST m) => MLockedAllocator m -> m (MLockedSeed n)
mlockedSeedNewZeroWith allocator =
  MLockedSeed <$> mlsbNewZeroWith allocator

mlockedSeedFinalize :: (MonadST m) => MLockedSeed n -> m ()
mlockedSeedFinalize = mlsbFinalize . mlockedSeedMLSB

mlockedSeedUseAsCPtr :: (MonadST m) => MLockedSeed n -> (Ptr Word8 -> m b) -> m b
mlockedSeedUseAsCPtr seed = mlsbUseAsCPtr (mlockedSeedMLSB seed)

mlockedSeedUseAsSizedPtr :: (MonadST m) => MLockedSeed n -> (SizedPtr n -> m b) -> m b
mlockedSeedUseAsSizedPtr seed = mlsbUseAsSizedPtr (mlockedSeedMLSB seed)
