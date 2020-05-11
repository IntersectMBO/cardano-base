{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
module Cardano.Crypto.DSIGN.NeverUsed
  ( NeverDSIGN
  , VerKeyDSIGN (..)
  , SignKeyDSIGN (..)
  , SigDSIGN (..)
  )
where

import GHC.Generics (Generic)

import Cardano.Prelude (CanonicalExamples, NoUnexpectedThunks)

import Cardano.Crypto.DSIGN.Class


-- | DSIGN never used
--
-- The type of keys and signatures is isomorphic to unit, but when actually
-- trying to sign or verify something a runtime exception will be thrown.
data NeverDSIGN

instance DSIGNAlgorithm NeverDSIGN where

  data VerKeyDSIGN  NeverDSIGN = NeverUsedVerKeyDSIGN
     deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, CanonicalExamples)

  data SignKeyDSIGN NeverDSIGN = NeverUsedSignKeyDSIGN
     deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, CanonicalExamples)

  data SigDSIGN     NeverDSIGN = NeverUsedSigDSIGN
     deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, CanonicalExamples)

  algorithmNameDSIGN _ = "never"

  deriveVerKeyDSIGN _ = NeverUsedVerKeyDSIGN

  sizeVerKeyDSIGN  _ = 0
  sizeSignKeyDSIGN _ = 0
  sizeSigDSIGN     _ = 0

  signDSIGN   = error "DSIGN not available"
  verifyDSIGN = error "DSIGN not available"

  seedSizeDSIGN     _ = 0
  genKeyDSIGN       _ = NeverUsedSignKeyDSIGN

  rawSerialiseVerKeyDSIGN  _ = mempty
  rawSerialiseSignKeyDSIGN _ = mempty
  rawSerialiseSigDSIGN     _ = mempty

  rawDeserialiseVerKeyDSIGN  _ = Just NeverUsedVerKeyDSIGN
  rawDeserialiseSignKeyDSIGN _ = Just NeverUsedSignKeyDSIGN
  rawDeserialiseSigDSIGN     _ = Just NeverUsedSigDSIGN

