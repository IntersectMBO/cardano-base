{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
module Cardano.Crypto.VRF.NeverUsed
  ( NeverVRF
  , VerKeyVRF (..)
  , SignKeyVRF (..)
  , CertVRF (..)
  )
where

import GHC.Generics (Generic)

import Cardano.Prelude (NoUnexpectedThunks)

import Cardano.Crypto.VRF.Class


-- | VRF not available
--
-- The type of keys and certificates is isomorphic to unit, but when actually
-- trying to sign or verify something a runtime exception will be thrown.
data NeverVRF

instance VRFAlgorithm NeverVRF where

  data VerKeyVRF NeverVRF = NeverUsedVerKeyVRF
    deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  data SignKeyVRF NeverVRF = NeverUsedSignKeyVRF
    deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  data CertVRF NeverVRF = NeverUsedCertVRF
    deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  algorithmNameVRF _ = "never"

  deriveVerKeyVRF _ = NeverUsedVerKeyVRF

  evalVRF = error "VRF unavailable"

  verifyVRF = error "VRF unavailable"

  maxVRF _ = 0

  genKeyVRF _ = NeverUsedSignKeyVRF
  seedSizeVRF _ = 0

  sizeVerKeyVRF  _ = 0
  sizeSignKeyVRF _ = 0
  sizeCertVRF    _ = 0

  rawSerialiseVerKeyVRF  _ = mempty
  rawSerialiseSignKeyVRF _ = mempty
  rawSerialiseCertVRF    _ = mempty

  rawDeserialiseVerKeyVRF  _ = Just NeverUsedVerKeyVRF
  rawDeserialiseSignKeyVRF _ = Just NeverUsedSignKeyVRF
  rawDeserialiseCertVRF    _ = Just NeverUsedCertVRF
