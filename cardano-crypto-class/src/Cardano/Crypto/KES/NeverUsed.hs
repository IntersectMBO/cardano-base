{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Cardano.Crypto.KES.NeverUsed (
  NeverKES,
  VerKeyKES (..),
  SignKeyKES (..),
  SigKES (..),
)
where

import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

import Cardano.Binary.FixedSizeCodec (FixedSizeCodec (..), guardFixedSized)
import Cardano.Crypto.KES.Class

-- | KES never used
--
-- The type of keys and signatures is isomorphic to unit, but when actually
-- trying to sign or verify something a runtime exception will be thrown.
data NeverKES

instance KESAlgorithm NeverKES where
  type SeedSizeKES NeverKES = 0

  data VerKeyKES NeverKES = NeverUsedVerKeyKES
    deriving (Show, Eq, Generic, NoThunks)

  data SigKES NeverKES = NeverUsedSigKES
    deriving (Show, Eq, Generic, NoThunks)

  data SignKeyKES NeverKES = NeverUsedSignKeyKES
    deriving (Show, Eq, Generic, NoThunks)

  algorithmNameKES _ = "never"

  verifyKES = error "KES not available"

  type TotalPeriodsKES NeverKES = 0

  type SignKeySizeKES NeverKES = 0

  deriveVerKeyKES _ = return NeverUsedVerKeyKES

  signKES = error "KES not available"
  updateKESWith _ = error "KES not available"

  genKeyKESWith _ _ = return NeverUsedSignKeyKES

  forgetSignKeyKESWith _ = const $ return ()

instance FixedSizeCodec (VerKeyKES NeverKES) where
  type FixedSize (VerKeyKES NeverKES) = 0
  rawEncodeFixedSized _ = mempty
  rawDecodeFixedSized bs = guardFixedSized bs $ do
    return NeverUsedVerKeyKES
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SigKES NeverKES) where
  type FixedSize (SigKES NeverKES) = 0
  rawEncodeFixedSized _ = mempty
  rawDecodeFixedSized bs = guardFixedSized bs $ do
    return NeverUsedSigKES
  {-# INLINE rawDecodeFixedSized #-}

instance UnsoundKESAlgorithm NeverKES where
  rawSerialiseSignKeyKES _ = return mempty
  rawDeserialiseSignKeyKESWith _ _ = return $ Just NeverUsedSignKeyKES

instance FixedSizeCodec (UnsoundPureSignKeyKES NeverKES) where
  type FixedSize (UnsoundPureSignKeyKES NeverKES) = SignKeySizeKES NeverKES
  rawEncodeFixedSized _ = mempty
  rawDecodeFixedSized bs = guardFixedSized bs $ do
    return NeverUsedUnsoundPureSignKeyKES
  {-# INLINE rawDecodeFixedSized #-}

instance UnsoundPureKESAlgorithm NeverKES where
  data UnsoundPureSignKeyKES NeverKES = NeverUsedUnsoundPureSignKeyKES
    deriving (Show, Eq, Generic, NoThunks)

  unsoundPureSignKES = error "KES not available"
  unsoundPureGenKeyKES _ = NeverUsedUnsoundPureSignKeyKES
  unsoundPureDeriveVerKeyKES _ = NeverUsedVerKeyKES
  unsoundPureUpdateKES _ = error "KES not available"
  unsoundPureSignKeyKESToSoundSignKeyKES _ = return NeverUsedSignKeyKES
