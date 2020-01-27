{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
module Cardano.Crypto.KES.NeverUsed
  ( NeverKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  )
where

import GHC.Generics (Generic)

import Cardano.Binary (toCBOR)
import Cardano.Crypto.KES.Class
import Cardano.Prelude (NoUnexpectedThunks)

-- | KES never used
--
-- The type of keys and signatures is isomorphic to unit, but when actually
-- trying to sign or verify something a runtime exception will be thrown.
data NeverKES

instance KESAlgorithm NeverKES where
  data VerKeyKES  NeverKES = NeverUsedVerKeyKES  deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)
  data SignKeyKES NeverKES = NeverUsedSignKeyKES deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)
  data SigKES     NeverKES = NeverUsedSigKES     deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  encodeVerKeyKES  _ = toCBOR ()
  encodeSignKeyKES _ = toCBOR ()
  encodeSigKES     _ = toCBOR ()

  decodeVerKeyKES  = return NeverUsedVerKeyKES
  decodeSignKeyKES = return NeverUsedSignKeyKES
  decodeSigKES     = return NeverUsedSigKES

  genKeyKES       _ = return NeverUsedSignKeyKES
  deriveVerKeyKES _ = NeverUsedVerKeyKES

  signKES   = error "KES not available"
  verifyKES = error "KES not available"
  updateKES = error "KES not available"
  iterationCountKES = error "KES not available"
