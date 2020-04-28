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

import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Cardano.Crypto.VRF.Class
import Cardano.Prelude (NoUnexpectedThunks)

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

  deriveVerKeyVRF _ = NeverUsedVerKeyVRF

  evalVRF = error "VRF unavailable"

  verifyVRF = error "VRF unavailable"

  maxVRF _ = 0

  genKeyVRF _ = NeverUsedSignKeyVRF
  seedSizeVRF _ = 0

  encodeVerKeyVRF  _ = error "VRF unavailable"
  decodeVerKeyVRF    = error "VRF unavailable"
  encodeSignKeyVRF _ = error "VRF unavailable"
  decodeSignKeyVRF   = error "VRF unavailable"
  encodeCertVRF    _ = error "VRF unavailable"
  decodeCertVRF      = error "VRF unavailable"

instance ToCBOR (CertVRF NeverVRF) where
  toCBOR _ = toCBOR ()

instance FromCBOR (CertVRF NeverVRF) where
  fromCBOR = (\() -> NeverUsedCertVRF) <$> fromCBOR
