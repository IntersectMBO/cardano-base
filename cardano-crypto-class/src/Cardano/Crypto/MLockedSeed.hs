{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Cardano.Crypto.MLockedSeed
where

import Cardano.Crypto.MonadMLock
  ( MLockedSizedBytes
  , MonadMLock (..)
  , mlsbCopy
  , mlsbNew
  , mlsbNewZero
  , mlsbFinalize
  , mlsbUseAsCPtr
  , mlsbUseAsSizedPtr
  , MEq (..)
  )
import Cardano.Foreign (SizedPtr)
import GHC.TypeNats (KnownNat)
import Control.DeepSeq (NFData)
import Foreign.Ptr (Ptr)
import Data.Word (Word8)
import Control.Monad.Class.MonadST (MonadST)

-- | A seed of size @n@, stored in mlocked memory. This is required to prevent
-- the seed from leaking to disk via swapping and reclaiming or scanning memory
-- after its content has been moved.
newtype MLockedSeed m n =
  MLockedSeed { mlockedSeedMLSB :: MLockedSizedBytes m n }

deriving via (MLockedSizedBytes m n)
  instance (MonadMLock m, MonadST m, KnownNat n) => MEq m (MLockedSeed m n)

deriving via (MLockedSizedBytes m n) instance NFData (MLockedSeed m n)

withMLockedSeedAsMLSB :: Functor m
                  => (MLockedSizedBytes m n -> m (MLockedSizedBytes m n))
                  -> MLockedSeed m n
                  -> m (MLockedSeed m n)
withMLockedSeedAsMLSB action =
  fmap MLockedSeed . action . mlockedSeedMLSB

mlockedSeedCopy :: (KnownNat n, MonadMLock m) => MLockedSeed m n -> m (MLockedSeed m n)
mlockedSeedCopy =
  withMLockedSeedAsMLSB mlsbCopy

mlockedSeedNew :: (KnownNat n, MonadMLock m) => m (MLockedSeed m n)
mlockedSeedNew =
  MLockedSeed <$> mlsbNew

mlockedSeedNewZero :: (KnownNat n, MonadMLock m) => m (MLockedSeed m n)
mlockedSeedNewZero =
  MLockedSeed <$> mlsbNewZero

mlockedSeedFinalize :: (MonadMLock m) => MLockedSeed m n -> m ()
mlockedSeedFinalize = mlsbFinalize . mlockedSeedMLSB

mlockedSeedUseAsCPtr :: (MonadMLock m) => MLockedSeed m n -> (Ptr Word8 -> m b) -> m b
mlockedSeedUseAsCPtr seed = mlsbUseAsCPtr (mlockedSeedMLSB seed)

mlockedSeedUseAsSizedPtr :: (MonadMLock m) => MLockedSeed m n -> (SizedPtr n -> m b) -> m b
mlockedSeedUseAsSizedPtr seed = mlsbUseAsSizedPtr (mlockedSeedMLSB seed)
