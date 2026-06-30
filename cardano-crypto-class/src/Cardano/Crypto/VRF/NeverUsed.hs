{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Cardano.Crypto.VRF.NeverUsed (
  NeverVRF,
  VerKeyVRF (..),
  SignKeyVRF (..),
  CertVRF (..),
)
where

import Cardano.Binary.FixedSizeCodec (FixedSizeCodec (..), guardFixedSized)
import Control.DeepSeq (NFData (..))
import qualified Data.ByteString as BS
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

  algorithmNameVRF _ = "never"

  deriveVerKeyVRF _ = NeverUsedVerKeyVRF

  evalVRF = error "VRF unavailable"

  verifyVRF = error "VRF unavailable"

  sizeOutputVRF _ = 0

  genKeyVRF _ = NeverUsedSignKeyVRF
  seedSizeVRF _ = 0

instance FixedSizeCodec (VerKeyVRF NeverVRF) where
  type FixedSize (VerKeyVRF NeverVRF) = 0
  rawEncodeFixedSized _ = BS.empty
  rawDecodeFixedSized bs = guardFixedSized bs $ do
    pure NeverUsedVerKeyVRF
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyVRF NeverVRF) where
  type FixedSize (SignKeyVRF NeverVRF) = 0
  rawEncodeFixedSized _ = BS.empty
  rawDecodeFixedSized bs = guardFixedSized bs $ do
    pure NeverUsedSignKeyVRF
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (CertVRF NeverVRF) where
  type FixedSize (CertVRF NeverVRF) = 0
  rawEncodeFixedSized _ = BS.empty
  rawDecodeFixedSized bs = guardFixedSized bs $ do
    pure NeverUsedCertVRF
  {-# INLINE rawDecodeFixedSized #-}
