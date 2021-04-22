{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Cardano.Crypto.KES.NeverUsed
  ( NeverKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  )
where

import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

import Cardano.Crypto.KES.Class


-- | KES never used
--
-- The type of keys and signatures is isomorphic to unit, but when actually
-- trying to sign or verify something a runtime exception will be thrown.
data NeverKES

instance KESAlgorithm NeverKES where
  type SeedSizeKES NeverKES = 0

  data VerKeyKES  NeverKES = NeverUsedVerKeyKES
      deriving (Show, Eq, Generic, NoThunks)

  data SignKeyKES NeverKES = NeverUsedSignKeyKES
      deriving (Show, Eq, Generic, NoThunks)

  data SigKES     NeverKES = NeverUsedSigKES
      deriving (Show, Eq, Generic, NoThunks)

  algorithmNameKES _ = "never"

  verifyKES = error "KES not available"

  totalPeriodsKES _ = 0

  sizeVerKeyKES  _ = 0
  sizeSignKeyKES _ = 0
  sizeSigKES     _ = 0

  rawSerialiseVerKeyKES  _ = mempty
  rawSerialiseSigKES     _ = mempty

  rawDeserialiseVerKeyKES  _ = Just NeverUsedVerKeyKES
  rawDeserialiseSigKES     _ = Just NeverUsedSigKES

instance Monad m => KESSignAlgorithm m NeverKES where
  deriveVerKeyKES _ = return NeverUsedVerKeyKES

  signKES   = error "KES not available"
  updateKES = error "KES not available"

  genKeyKES       _ = return NeverUsedSignKeyKES

  rawSerialiseSignKeyKES _ = return mempty
  rawDeserialiseSignKeyKES _ = return $ Just NeverUsedSignKeyKES
