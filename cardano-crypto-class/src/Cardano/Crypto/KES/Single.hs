{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | A standard signature scheme is a forward-secure signature scheme with a
-- single time period.
--
-- This is the base case in the naive recursive implementation of the sum
-- composition from section 3 of the \"MMM\" paper:
--
-- /Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures/
-- By Tal Malkin, Daniele Micciancio and Sara Miner
-- <https://eprint.iacr.org/2001/034>
--
-- Specfically it states:
--
-- > In order to unify the presentation, we regard standard signature schemes
-- > as forward-seure signature schemes with one time period, namely T = 1.
--
-- So this module simply provides a wrapper 'SingleKES' that turns any
-- 'DSIGNMAlgorithm' into an instance of 'KESAlgorithm' with a single period.
--
-- See "Cardano.Crypto.KES.Sum" for the composition case.
--
module Cardano.Crypto.KES.Single (
    SingleKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  ) where

import Data.Proxy (Proxy(..))
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

import Control.Exception (assert)
import Control.DeepSeq (NFData)
import Control.Monad ((<$!>))

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash.Class
import Cardano.Crypto.DSIGNM.Class as DSIGNM
import Cardano.Crypto.KES.Class


-- | A standard signature scheme is a forward-secure signature scheme with a
-- single time period.
--
data SingleKES d

deriving instance NFData (VerKeyDSIGNM d) => NFData (VerKeyKES (SingleKES d))
deriving instance NFData (SigDSIGNM d) => NFData (SigKES (SingleKES d))

deriving via (SignKeyDSIGNM d) instance NFData (SignKeyDSIGNM d) => NFData (SignKeyKES (SingleKES d))

instance (DSIGNMAlgorithmBase d) => KESAlgorithm (SingleKES d) where
    type SeedSizeKES (SingleKES d) = SeedSizeDSIGNM d

    --
    -- Key and signature types
    --

    newtype VerKeyKES (SingleKES d) = VerKeySingleKES (VerKeyDSIGNM d)
        deriving Generic

    newtype SigKES (SingleKES d) = SigSingleKES (SigDSIGNM d)
        deriving Generic

    type ContextKES (SingleKES d) = ContextDSIGNM d
    type Signable   (SingleKES d) = DSIGNM.SignableM     d


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES _ = algorithmNameDSIGNM (Proxy :: Proxy d) ++ "_kes_2^0"

    totalPeriodsKES  _ = 1

    verifyKES ctxt (VerKeySingleKES vk) t a (SigSingleKES sig) =
        assert (t == 0) $
        verifyDSIGNM ctxt vk a sig

    --
    -- raw serialise/deserialise
    --

    type SizeVerKeyKES (SingleKES d) = SizeVerKeyDSIGNM d
    type SizeSignKeyKES (SingleKES d) = SizeSignKeyDSIGNM d
    type SizeSigKES (SingleKES d) = SizeSigDSIGNM d

    hashVerKeyKES (VerKeySingleKES vk) =
        castHash (hashVerKeyDSIGNM vk)

    rawSerialiseVerKeyKES  (VerKeySingleKES  vk) = rawSerialiseVerKeyDSIGNM vk
    rawSerialiseSigKES     (SigSingleKES    sig) = rawSerialiseSigDSIGNM sig

    rawDeserialiseVerKeyKES  = fmap VerKeySingleKES  . rawDeserialiseVerKeyDSIGNM
    rawDeserialiseSigKES     = fmap SigSingleKES     . rawDeserialiseSigDSIGNM


instance ( DSIGNMAlgorithm m d -- needed for secure forgetting
         , Monad m
         ) => KESSignAlgorithm m (SingleKES d) where
    newtype SignKeyKES (SingleKES d) = SignKeySingleKES (SignKeyDSIGNM d)

    deriveVerKeyKES (SignKeySingleKES v) =
      VerKeySingleKES <$!> deriveVerKeyDSIGNM v

    --
    -- Core algorithm operations
    --

    signKES ctxt t a (SignKeySingleKES sk) =
        assert (t == 0) $!
        SigSingleKES <$!> signDSIGNM ctxt a sk

    updateKES _ctx (SignKeySingleKES _sk) _to = return $! Nothing

    --
    -- Key generation
    --

    genKeyKES seed = SignKeySingleKES <$!> genKeyDSIGNM seed

    --
    -- forgetting
    --
    forgetSignKeyKES (SignKeySingleKES v) =
      forgetSignKeyDSIGNM v

instance (KESSignAlgorithm m (SingleKES d), UnsoundDSIGNMAlgorithm m d)
         => UnsoundKESSignAlgorithm m (SingleKES d) where
    rawSerialiseSignKeyKES (SignKeySingleKES sk) =
      rawSerialiseSignKeyDSIGNM sk

    rawDeserialiseSignKeyKES bs =
      fmap SignKeySingleKES <$> rawDeserialiseSignKeyDSIGNM bs

--
-- VerKey instances
--

deriving instance DSIGNMAlgorithmBase d => Show (VerKeyKES (SingleKES d))
deriving instance DSIGNMAlgorithmBase d => Eq   (VerKeyKES (SingleKES d))

instance DSIGNMAlgorithmBase d => ToCBOR (VerKeyKES (SingleKES d)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance DSIGNMAlgorithmBase d => FromCBOR (VerKeyKES (SingleKES d)) where
  fromCBOR = decodeVerKeyKES

instance DSIGNMAlgorithmBase d => NoThunks (VerKeyKES  (SingleKES d))


--
-- SignKey instances
--

deriving via (SignKeyDSIGNM d) instance DSIGNMAlgorithmBase d => NoThunks (SignKeyKES (SingleKES d))

--
-- Sig instances
--

deriving instance DSIGNMAlgorithmBase d => Show (SigKES (SingleKES d))
deriving instance DSIGNMAlgorithmBase d => Eq   (SigKES (SingleKES d))

instance DSIGNMAlgorithmBase d => NoThunks (SigKES (SingleKES d))

instance DSIGNMAlgorithmBase d => ToCBOR (SigKES (SingleKES d)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance DSIGNMAlgorithmBase d => FromCBOR (SigKES (SingleKES d)) where
  fromCBOR = decodeSigKES
