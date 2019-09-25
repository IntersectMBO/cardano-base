{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Abstract Verifiable Random Functions.
module Cardano.Crypto.VRF.Class
  ( VRFAlgorithm (..)
  , CertifiedVRF (..)
  , evalCertified
  , verifyCertified
  )
where

import Cardano.Binary
  ( Encoding
  , FromCBOR (..)
  , ToCBOR (..)
  , encodeListLen
  , enforceSize
  )
import Cardano.Crypto.Util (Empty)
import Cardano.Prelude (NoUnexpectedThunks)
import Crypto.Random (MonadRandom)
import Data.Kind (Type)
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack
import Numeric.Natural

class ( Typeable v
      , Show (VerKeyVRF v)
      , Eq (VerKeyVRF v)
      , Show (SignKeyVRF v)
      , Show (CertVRF v)
      , Eq (CertVRF v)
      , FromCBOR (CertVRF v)
      , ToCBOR (CertVRF v)
      , NoUnexpectedThunks (CertVRF v)
      )
      => VRFAlgorithm v where

  type Signable v :: Type -> Constraint

  type Signable c = Empty

  data VerKeyVRF v :: Type

  data SignKeyVRF v :: Type

  data CertVRF v :: Type

  maxVRF :: proxy v -> Natural

  genKeyVRF :: MonadRandom m => m (SignKeyVRF v)

  deriveVerKeyVRF :: SignKeyVRF v -> VerKeyVRF v

  encodeVerKeyVRF :: VerKeyVRF v -> Encoding

  evalVRF
    :: (MonadRandom m, HasCallStack, Signable v a)
    => a
    -> SignKeyVRF v
    -> m (Natural, CertVRF v)

  verifyVRF
    :: (HasCallStack, Signable v a)
    =>  VerKeyVRF v
    -> a
    -> (Natural, CertVRF v)
    -> Bool

data CertifiedVRF v a
  = CertifiedVRF
      { certifiedNatural :: Natural
      , certifiedProof :: CertVRF v
      }
  deriving Generic

deriving instance VRFAlgorithm v => Show (CertifiedVRF v a)
deriving instance VRFAlgorithm v => Eq   (CertifiedVRF v a)

instance (VRFAlgorithm v, Typeable a) => NoUnexpectedThunks (CertifiedVRF v a)
  -- use generic instance

instance (VRFAlgorithm v, Typeable a) => ToCBOR (CertifiedVRF v a) where
  toCBOR cvrf =
    encodeListLen 2 <>
      toCBOR (certifiedNatural cvrf) <>
      toCBOR (certifiedProof cvrf)

instance (VRFAlgorithm v, Typeable a) => FromCBOR (CertifiedVRF v a) where
  fromCBOR =
    CertifiedVRF <$
      enforceSize "CertifiedVRF" 2 <*>
      fromCBOR <*>
      fromCBOR

evalCertified
  :: (VRFAlgorithm v, MonadRandom m, Signable v a)
  => a
  -> SignKeyVRF v
  -> m (CertifiedVRF v a)
evalCertified a key = uncurry CertifiedVRF <$> evalVRF a key

verifyCertified
  :: (VRFAlgorithm v, Signable v a)
  => VerKeyVRF v
  -> a
  -> CertifiedVRF v a
  -> Bool
verifyCertified vk a CertifiedVRF {..} = verifyVRF vk a (certifiedNatural, certifiedProof)
