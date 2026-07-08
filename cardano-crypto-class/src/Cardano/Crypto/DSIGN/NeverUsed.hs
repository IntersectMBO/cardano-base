{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Cardano.Crypto.DSIGN.NeverUsed (
  NeverDSIGN,
  VerKeyDSIGN (..),
  SignKeyDSIGN (..),
  SigDSIGN (..),
)
where

import GHC.Generics (Generic)

import NoThunks.Class (NoThunks)

import Cardano.Binary.FixedSizeCodec (FixedSizeCodec (..), guardFixedSized)
import Cardano.Crypto.DSIGN.Class

-- | DSIGN never used
--
-- The type of keys and signatures is isomorphic to unit, but when actually
-- trying to sign or verify something a runtime exception will be thrown.
data NeverDSIGN

instance DSIGNAlgorithm NeverDSIGN where
  type SeedSizeDSIGN NeverDSIGN = 0

  data VerKeyDSIGN NeverDSIGN = NeverUsedVerKeyDSIGN
    deriving (Show, Eq, Generic, NoThunks)

  data SignKeyDSIGN NeverDSIGN = NeverUsedSignKeyDSIGN
    deriving (Show, Eq, Generic, NoThunks)

  data SigDSIGN NeverDSIGN = NeverUsedSigDSIGN
    deriving (Show, Eq, Generic, NoThunks)

  algorithmNameDSIGN _ = "never"

  deriveVerKeyDSIGN _ = NeverUsedVerKeyDSIGN

  signDSIGN = error "DSIGN not available"
  verifyDSIGN = error "DSIGN not available"

  genKeyDSIGN _ = NeverUsedSignKeyDSIGN

instance FixedSizeCodec (VerKeyDSIGN NeverDSIGN) where
  type FixedSize (VerKeyDSIGN NeverDSIGN) = 0
  rawEncodeFixedSized _ = mempty
  rawDecodeFixedSized bs = guardFixedSized bs $ pure NeverUsedVerKeyDSIGN

instance FixedSizeCodec (SignKeyDSIGN NeverDSIGN) where
  type FixedSize (SignKeyDSIGN NeverDSIGN) = 0
  rawEncodeFixedSized _ = mempty
  rawDecodeFixedSized bs = guardFixedSized bs $ pure NeverUsedSignKeyDSIGN

instance FixedSizeCodec (SigDSIGN NeverDSIGN) where
  type FixedSize (SigDSIGN NeverDSIGN) = 0
  rawEncodeFixedSized _ = mempty
  rawDecodeFixedSized bs = guardFixedSized bs $ pure NeverUsedSigDSIGN
