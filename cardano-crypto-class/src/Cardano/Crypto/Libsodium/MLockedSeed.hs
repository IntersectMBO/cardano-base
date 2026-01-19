{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Cardano.Crypto.Libsodium.MLockedSeed
where

import Cardano.Crypto.DirectSerialise
import Cardano.Crypto.Libsodium.C (
  c_sodium_randombytes_buf,
 )
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
import Cardano.Foreign (SizedPtr)
import Control.DeepSeq (NFData)
import Control.Monad.Class.MonadST (MonadST)
import Data.Proxy (Proxy (..))
import Data.Word (Word8)
import Foreign.C.Types (CSize)
import Foreign.Ptr (Ptr, castPtr)
import GHC.TypeLits (Natural)
import GHC.TypeNats (KnownNat, natVal)
import NoThunks.Class (NoThunks)

-- | A seed of size @n@, stored in mlocked memory. This is required to prevent
-- the seed from leaking to disk via swapping and reclaiming or scanning memory
-- after its content has been moved.
newtype MLockedSeed n = MLockedSeed {mlockedSeedMLSB :: MLockedSizedBytes n}
  deriving (NFData, NoThunks)

instance KnownNat n => DirectSerialise (MLockedSeed n) where
  directSerialise push seed =
    mlockedSeedUseAsCPtr seed $ \ptr ->
      push (castPtr ptr) (fromIntegral @Natural @CSize $ natVal seed)

instance KnownNat n => DirectDeserialise (MLockedSeed n) where
  directDeserialise pull = do
    seed <- mlockedSeedNew
    mlockedSeedUseAsCPtr seed $ \ptr ->
      pull (castPtr ptr) (fromIntegral @Natural @CSize $ natVal seed)
    return seed

withMLockedSeedAsMLSB ::
  Functor m =>
  (MLockedSizedBytes n -> m (MLockedSizedBytes n)) ->
  MLockedSeed n ->
  m (MLockedSeed n)
withMLockedSeedAsMLSB action =
  fmap MLockedSeed . action . mlockedSeedMLSB

mlockedSeedCopy :: (KnownNat n, MonadST m) => MLockedSeed n -> m (MLockedSeed n)
mlockedSeedCopy = mlockedSeedCopyWith mlockedMalloc

mlockedSeedCopyWith ::
  (KnownNat n, MonadST m) =>
  MLockedAllocator m ->
  MLockedSeed n ->
  m (MLockedSeed n)
mlockedSeedCopyWith allocator = withMLockedSeedAsMLSB (mlsbCopyWith allocator)

mlockedSeedNew :: (KnownNat n, MonadST m) => m (MLockedSeed n)
mlockedSeedNew = mlockedSeedNewWith mlockedMalloc

mlockedSeedNewWith :: (KnownNat n, MonadST m) => MLockedAllocator m -> m (MLockedSeed n)
mlockedSeedNewWith allocator =
  MLockedSeed <$> mlsbNewWith allocator

mlockedSeedNewZero :: (KnownNat n, MonadST m) => m (MLockedSeed n)
mlockedSeedNewZero = mlockedSeedNewZeroWith mlockedMalloc

mlockedSeedNewZeroWith :: (KnownNat n, MonadST m) => MLockedAllocator m -> m (MLockedSeed n)
mlockedSeedNewZeroWith allocator =
  MLockedSeed <$> mlsbNewZeroWith allocator

mlockedSeedNewRandom :: forall n. KnownNat n => IO (MLockedSeed n)
mlockedSeedNewRandom = mlockedSeedNewRandomWith mlockedMalloc

mlockedSeedNewRandomWith :: forall n. KnownNat n => MLockedAllocator IO -> IO (MLockedSeed n)
mlockedSeedNewRandomWith allocator = do
  mls <- MLockedSeed <$> mlsbNewZeroWith allocator
  mlockedSeedUseAsCPtr mls $ \dst -> do
    c_sodium_randombytes_buf dst size
  return mls
  where
    size = fromIntegral @Natural @CSize $ natVal (Proxy @n)

mlockedSeedFinalize :: MonadST m => MLockedSeed n -> m ()
mlockedSeedFinalize = mlsbFinalize . mlockedSeedMLSB

mlockedSeedUseAsCPtr :: MonadST m => MLockedSeed n -> (Ptr Word8 -> m b) -> m b
mlockedSeedUseAsCPtr seed = mlsbUseAsCPtr (mlockedSeedMLSB seed)

mlockedSeedUseAsSizedPtr :: MonadST m => MLockedSeed n -> (SizedPtr n -> m b) -> m b
mlockedSeedUseAsSizedPtr seed = mlsbUseAsSizedPtr (mlockedSeedMLSB seed)
