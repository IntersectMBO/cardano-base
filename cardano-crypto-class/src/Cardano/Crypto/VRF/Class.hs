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
import Crypto.Random (MonadRandom)
import Data.Kind (Type)
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import GHC.Stack
import Numeric.Natural

class ( Typeable v
      , Show (VerKeyVRF v)
      , Ord (VerKeyVRF v)
      , Show (SignKeyVRF v)
      , Ord (SignKeyVRF v)
      , Show (CertVRF v)
      , Ord (CertVRF v)
      , FromCBOR (CertVRF v)
      , ToCBOR (CertVRF v)
      )
      => VRFAlgorithm v where

  data VerKeyVRF v :: Type

  data SignKeyVRF v :: Type

  data CertVRF v :: Type

  maxVRF :: proxy v -> Natural

  genKeyVRF :: MonadRandom m => m (SignKeyVRF v)

  deriveVerKeyVRF :: SignKeyVRF v -> VerKeyVRF v

  evalVRF
    :: (MonadRandom m, HasCallStack)
    => (a -> Encoding)
    -> a
    -> SignKeyVRF v
    -> m (Natural, CertVRF v)

  verifyVRF
    :: HasCallStack
    => (a -> Encoding)
    -> VerKeyVRF v
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

deriving instance VRFAlgorithm v => Eq (CertifiedVRF v a)

deriving instance VRFAlgorithm v => Ord (CertifiedVRF v a)

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
  :: (VRFAlgorithm v, MonadRandom m)
  => (a -> Encoding)
  -> a
  -> SignKeyVRF v
  -> m (CertifiedVRF v a)
evalCertified toEnc a key = uncurry CertifiedVRF <$> evalVRF toEnc a key

verifyCertified
  :: (VRFAlgorithm v)
  => (a -> Encoding)
  -> VerKeyVRF v
  -> a
  -> CertifiedVRF v a
  -> Bool
verifyCertified toEnc vk a CertifiedVRF {..} = verifyVRF toEnc vk a (certifiedNatural, certifiedProof)
