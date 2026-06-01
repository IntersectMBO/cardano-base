{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}

module Cardano.Crypto.VRF.NeverUsed (
  NeverVRF,
  VerKeyVRF (..),
  SignKeyVRF (..),
  CertVRF (..),
)
where

import Control.DeepSeq (NFData (..))
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

import Cardano.Crypto.VRF.Class

-- | VRF not available
--
-- The type of keys and certificates is isomorphic to unit, but when actually
-- trying to sign or verify something a runtime exception will be thrown.
data NeverVRF

instance NFData (VerKeyVRF NeverVRF) where
  rnf x = x `seq` ()

instance NFData (SignKeyVRF NeverVRF) where
  rnf x = x `seq` ()

instance NFData (CertVRF NeverVRF) where
  rnf x = x `seq` ()

instance VRFAlgorithm NeverVRF where
  data VerKeyVRF NeverVRF = NeverUsedVerKeyVRF
    deriving (Show, Eq, Generic, NoThunks)

  data SignKeyVRF NeverVRF = NeverUsedSignKeyVRF
    deriving (Show, Eq, Generic, NoThunks)

  data CertVRF NeverVRF = NeverUsedCertVRF
    deriving (Show, Eq, Ord, Generic, NoThunks)

  type VerKeySizeVRF NeverVRF = 0
  type SignKeySizeVRF NeverVRF = 0
  type CertSizeVRF NeverVRF = 0

  algorithmNameVRF _ = "never"

  deriveVerKeyVRF _ = NeverUsedVerKeyVRF

  evalVRF = error "VRF unavailable"

  verifyVRF = error "VRF unavailable"

  sizeOutputVRF _ = 0

  genKeyVRF _ = NeverUsedSignKeyVRF
  seedSizeVRF _ = 0

  rawSerialiseVerKeyVRF _ = mempty
  rawSerialiseSignKeyVRF _ = mempty
  rawSerialiseCertVRF _ = mempty

  rawDeserialiseVerKeyVRF _ = Just NeverUsedVerKeyVRF
  rawDeserialiseSignKeyVRF _ = Just NeverUsedSignKeyVRF
  rawDeserialiseCertVRF _ = Just NeverUsedCertVRF
