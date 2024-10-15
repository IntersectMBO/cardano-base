{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
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
import Cardano.Crypto.DSIGN.Class as DSIGN
import Cardano.Crypto.KES.Class
import Cardano.Crypto.DirectSerialise

-- | A standard signature scheme is a forward-secure signature scheme with a
-- single time period.
--
data SingleKES d

deriving instance NFData (VerKeyDSIGN d) => NFData (VerKeyKES (SingleKES d))
deriving instance NFData (SigDSIGN d) => NFData (SigKES (SingleKES d))

deriving via (SignKeyDSIGNM d) instance NFData (SignKeyDSIGNM d) => NFData (SignKeyKES (SingleKES d))

instance (DSIGNMAlgorithm d) => KESAlgorithm (SingleKES d) where
    type SeedSizeKES (SingleKES d) = SeedSizeDSIGN d

    --
    -- Key and signature types
    --

    newtype VerKeyKES (SingleKES d) = VerKeySingleKES (VerKeyDSIGN d)
        deriving Generic

    newtype SigKES (SingleKES d) = SigSingleKES (SigDSIGN d)
        deriving Generic

    newtype SignKeyKES (SingleKES d) = SignKeySingleKES (SignKeyDSIGNM d)


    type ContextKES (SingleKES d) = ContextDSIGN d
    type Signable   (SingleKES d) = DSIGN.Signable     d


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES _ = algorithmNameDSIGN (Proxy :: Proxy d) ++ "_kes_2^0"

    totalPeriodsKES  _ = 1

    verifyKES ctxt (VerKeySingleKES vk) t a (SigSingleKES sig) =
        assert (t == 0) $
        verifyDSIGN ctxt vk a sig

    --
    -- raw serialise/deserialise
    --

    type SizeVerKeyKES (SingleKES d) = SizeVerKeyDSIGN d
    type SizeSignKeyKES (SingleKES d) = SizeSignKeyDSIGN d
    type SizeSigKES (SingleKES d) = SizeSigDSIGN d

    hashVerKeyKES (VerKeySingleKES vk) =
        castHash (hashVerKeyDSIGN vk)

    rawSerialiseVerKeyKES  (VerKeySingleKES  vk) = rawSerialiseVerKeyDSIGN vk
    rawSerialiseSigKES     (SigSingleKES    sig) = rawSerialiseSigDSIGN sig

    rawDeserialiseVerKeyKES  = fmap VerKeySingleKES  . rawDeserialiseVerKeyDSIGN
    {-# INLINE rawDeserialiseVerKeyKES #-}
    rawDeserialiseSigKES     = fmap SigSingleKES     . rawDeserialiseSigDSIGN
    {-# INLINE rawDeserialiseSigKES #-}


    deriveVerKeyKES (SignKeySingleKES v) =
      VerKeySingleKES <$!> deriveVerKeyDSIGNM v

    --
    -- Core algorithm operations
    --

    signKES ctxt t a (SignKeySingleKES sk) =
        assert (t == 0) $!
        SigSingleKES <$!> signDSIGNM ctxt a sk

    updateKESWith _allocator _ctx (SignKeySingleKES _sk) _to = return Nothing

    --
    -- Key generation
    --

    genKeyKESWith allocator seed =
      SignKeySingleKES <$!> genKeyDSIGNMWith allocator seed

    --
    -- forgetting
    --
    forgetSignKeyKESWith allocator (SignKeySingleKES v) =
      forgetSignKeyDSIGNMWith allocator v

instance (KESAlgorithm (SingleKES d), UnsoundDSIGNMAlgorithm d)
         => UnsoundKESAlgorithm (SingleKES d) where
    rawSerialiseSignKeyKES (SignKeySingleKES sk) =
      rawSerialiseSignKeyDSIGNM sk

    rawDeserialiseSignKeyKESWith allocator bs =
      fmap SignKeySingleKES <$> rawDeserialiseSignKeyDSIGNMWith allocator bs

--
-- VerKey instances
--

deriving instance DSIGNAlgorithm d => Show (VerKeyKES (SingleKES d))
deriving instance DSIGNAlgorithm d => Eq   (VerKeyKES (SingleKES d))

instance DSIGNMAlgorithm d => ToCBOR (VerKeyKES (SingleKES d)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance DSIGNMAlgorithm d => FromCBOR (VerKeyKES (SingleKES d)) where
  fromCBOR = decodeVerKeyKES
  {-# INLINE fromCBOR #-}

instance DSIGNMAlgorithm d => NoThunks (VerKeyKES  (SingleKES d))


--
-- SignKey instances
--

deriving via (SignKeyDSIGNM d) instance DSIGNMAlgorithm d => NoThunks (SignKeyKES (SingleKES d))

--
-- Sig instances
--

deriving instance DSIGNAlgorithm d => Show (SigKES (SingleKES d))
deriving instance DSIGNAlgorithm d => Eq   (SigKES (SingleKES d))

instance DSIGNAlgorithm d => NoThunks (SigKES (SingleKES d))

instance DSIGNMAlgorithm d => ToCBOR (SigKES (SingleKES d)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance DSIGNMAlgorithm d => FromCBOR (SigKES (SingleKES d)) where
  fromCBOR = decodeSigKES

--
-- Direct ser/deser
--

instance (DirectSerialise (SignKeyDSIGNM d)) => DirectSerialise (SignKeyKES (SingleKES d)) where
  directSerialise push (SignKeySingleKES sk) = directSerialise push sk

instance (DirectDeserialise (SignKeyDSIGNM d)) => DirectDeserialise (SignKeyKES (SingleKES d)) where
  directDeserialise pull = SignKeySingleKES <$!> directDeserialise pull

instance (DirectSerialise (VerKeyDSIGN d)) => DirectSerialise (VerKeyKES (SingleKES d)) where
  directSerialise push (VerKeySingleKES sk) = directSerialise push sk

instance (DirectDeserialise (VerKeyDSIGN d)) => DirectDeserialise (VerKeyKES (SingleKES d)) where
  directDeserialise pull = VerKeySingleKES <$!> directDeserialise pull
