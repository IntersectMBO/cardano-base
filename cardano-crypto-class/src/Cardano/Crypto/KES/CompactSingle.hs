{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NoStarIsType #-}

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
-- So this module simply provides a wrapper 'CompactSingleKES' that turns any
-- 'DSIGNMAlgorithm' into an instance of 'KESAlgorithm' with a single period.
--
-- See "Cardano.Crypto.KES.CompactSum" for the composition case.
--
-- Compared to the implementation in 'Cardano.Crypto.KES.Single', this flavor
-- stores the VerKey used for signing along with the signature. The purpose of
-- this is so that we can avoid storing a pair of VerKeys at every branch node,
-- like 'Cardano.Crypto.KES.Sum' does. See 'Cardano.Crypto.KES.CompactSum' for
-- more details.
module Cardano.Crypto.KES.CompactSingle (
  CompactSingleKES,
  VerKeyKES (..),
  SignKeyKES (..),
  SigKES (..),
) where

import Control.Monad (guard, (<$!>))
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)
import GHC.TypeLits (KnownNat, type (+))
import NoThunks.Class (NoThunks)

import Control.DeepSeq (NFData)
import Control.Exception (assert)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.DSIGN.Class as DSIGN
import Cardano.Crypto.DirectSerialise
import Cardano.Crypto.Hash.Class
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Util (slice)

-- | A standard signature scheme is a forward-secure signature scheme with a
-- single time period.
data CompactSingleKES d

deriving newtype instance NFData (VerKeyDSIGN d) => NFData (VerKeyKES (CompactSingleKES d))
deriving newtype instance NFData (SignKeyDSIGNM d) => NFData (SignKeyKES (CompactSingleKES d))

deriving instance
  (NFData (SigDSIGN d), NFData (VerKeyDSIGN d)) => NFData (SigKES (CompactSingleKES d))

instance
  ( DSIGNMAlgorithm d
  , KnownNat (SigSizeDSIGN d + VerKeySizeDSIGN d)
  ) =>
  KESAlgorithm (CompactSingleKES d)
  where
  type SeedSizeKES (CompactSingleKES d) = SeedSizeDSIGN d

  --
  -- Key and signature types
  --

  newtype VerKeyKES (CompactSingleKES d) = VerKeyCompactSingleKES (VerKeyDSIGN d)
    deriving (Generic)

  data SigKES (CompactSingleKES d) = SigCompactSingleKES !(SigDSIGN d) !(VerKeyDSIGN d)
    deriving (Generic)

  newtype SignKeyKES (CompactSingleKES d) = SignKeyCompactSingleKES (SignKeyDSIGNM d)

  type ContextKES (CompactSingleKES d) = ContextDSIGN d
  type Signable (CompactSingleKES d) = DSIGN.Signable d

  --
  -- Metadata and basic key operations
  --

  algorithmNameKES _ = algorithmNameDSIGN (Proxy :: Proxy d) ++ "_kes_2^0"

  totalPeriodsKES _ = 1

  --
  -- Core algorithm operations
  --

  verifyKES = verifyOptimizedKES

  --
  -- raw serialise/deserialise
  --

  type SizeVerKeyKES (CompactSingleKES d) = VerKeySizeDSIGN d
  type SizeSignKeyKES (CompactSingleKES d) = SignKeySizeDSIGN d
  type SizeSigKES (CompactSingleKES d) = SigSizeDSIGN d + VerKeySizeDSIGN d

  hashVerKeyKES (VerKeyCompactSingleKES vk) =
    castHash (hashVerKeyDSIGN vk)

  rawSerialiseVerKeyKES (VerKeyCompactSingleKES vk) = rawSerialiseVerKeyDSIGN vk
  rawSerialiseSigKES (SigCompactSingleKES sig vk) =
    rawSerialiseSigDSIGN sig <> rawSerialiseVerKeyDSIGN vk

  rawDeserialiseVerKeyKES = fmap VerKeyCompactSingleKES . rawDeserialiseVerKeyDSIGN
  rawDeserialiseSigKES b = do
    guard (BS.length b == fromIntegral @Word @Int size_total)
    sigma <- rawDeserialiseSigDSIGN b_sig
    vk <- rawDeserialiseVerKeyDSIGN b_vk
    return (SigCompactSingleKES sigma vk)
    where
      b_sig = slice off_sig size_sig b
      b_vk = slice off_vk size_vk b

      size_sig = sigSizeDSIGN (Proxy :: Proxy d)
      size_vk = verKeySizeDSIGN (Proxy :: Proxy d)
      size_total = sizeSigKES (Proxy :: Proxy (CompactSingleKES d))

      off_sig = 0 :: Word
      off_vk = size_sig

  deriveVerKeyKES (SignKeyCompactSingleKES v) =
    VerKeyCompactSingleKES <$!> deriveVerKeyDSIGNM v

  --
  -- Core algorithm operations
  --
  signKES ctxt t a (SignKeyCompactSingleKES sk) =
    assert (t == 0) $
      SigCompactSingleKES <$!> signDSIGNM ctxt a sk <*> deriveVerKeyDSIGNM sk

  updateKESWith _allocator _ctx (SignKeyCompactSingleKES _sk) _to = return Nothing

  --
  -- Key generation
  --

  genKeyKESWith allocator seed = SignKeyCompactSingleKES <$!> genKeyDSIGNMWith allocator seed

  --
  -- forgetting
  --
  forgetSignKeyKESWith allocator (SignKeyCompactSingleKES v) =
    forgetSignKeyDSIGNMWith allocator v

instance
  ( KESAlgorithm (CompactSingleKES d)
  , UnsoundDSIGNMAlgorithm d
  ) =>
  UnsoundPureKESAlgorithm (CompactSingleKES d)
  where
  data UnsoundPureSignKeyKES (CompactSingleKES d)
    = UnsoundPureSignKeyCompactSingleKES (SignKeyDSIGN d)
    deriving (Generic)

  unsoundPureSignKES ctxt t a (UnsoundPureSignKeyCompactSingleKES sk) =
    assert (t == 0) $!
      SigCompactSingleKES (signDSIGN ctxt a sk) (deriveVerKeyDSIGN sk)

  unsoundPureUpdateKES _ctx _sk _to = Nothing

  --
  -- Key generation
  --

  unsoundPureGenKeyKES seed =
    UnsoundPureSignKeyCompactSingleKES $! genKeyDSIGN seed

  unsoundPureDeriveVerKeyKES (UnsoundPureSignKeyCompactSingleKES v) =
    VerKeyCompactSingleKES $! deriveVerKeyDSIGN v

  unsoundPureSignKeyKESToSoundSignKeyKES =
    unsoundPureSignKeyKESToSoundSignKeyKESViaSer

  rawSerialiseUnsoundPureSignKeyKES (UnsoundPureSignKeyCompactSingleKES sk) =
    rawSerialiseSignKeyDSIGN sk
  rawDeserialiseUnsoundPureSignKeyKES b =
    UnsoundPureSignKeyCompactSingleKES <$> rawDeserialiseSignKeyDSIGN b

instance
  ( KESAlgorithm (CompactSingleKES d)
  , DSIGNMAlgorithm d
  ) =>
  OptimizedKESAlgorithm (CompactSingleKES d)
  where
  verifySigKES ctxt t a (SigCompactSingleKES sig vk) =
    assert (t == 0) $
      verifyDSIGN ctxt vk a sig

  verKeyFromSigKES _ctxt t (SigCompactSingleKES _ vk) =
    assert (t == 0) $
      VerKeyCompactSingleKES vk

instance
  (KESAlgorithm (CompactSingleKES d), UnsoundDSIGNMAlgorithm d) =>
  UnsoundKESAlgorithm (CompactSingleKES d)
  where
  rawSerialiseSignKeyKES (SignKeyCompactSingleKES sk) = rawSerialiseSignKeyDSIGNM sk
  rawDeserialiseSignKeyKESWith allocator bs = fmap SignKeyCompactSingleKES <$> rawDeserialiseSignKeyDSIGNMWith allocator bs

--
-- VerKey instances
--

deriving instance DSIGNMAlgorithm d => Show (VerKeyKES (CompactSingleKES d))
deriving instance DSIGNMAlgorithm d => Eq (VerKeyKES (CompactSingleKES d))

instance
  (DSIGNMAlgorithm d, KnownNat (SigSizeDSIGN d + VerKeySizeDSIGN d)) =>
  ToCBOR (VerKeyKES (CompactSingleKES d))
  where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance
  (DSIGNMAlgorithm d, KnownNat (SigSizeDSIGN d + VerKeySizeDSIGN d)) =>
  FromCBOR (VerKeyKES (CompactSingleKES d))
  where
  fromCBOR = decodeVerKeyKES

instance DSIGNMAlgorithm d => NoThunks (VerKeyKES (CompactSingleKES d))

--
-- SignKey instances
--

deriving via
  (SignKeyDSIGNM d)
  instance
    DSIGNMAlgorithm d => NoThunks (SignKeyKES (CompactSingleKES d))

--
-- Sig instances
--

deriving instance DSIGNMAlgorithm d => Show (SigKES (CompactSingleKES d))
deriving instance DSIGNMAlgorithm d => Eq (SigKES (CompactSingleKES d))

instance DSIGNMAlgorithm d => NoThunks (SigKES (CompactSingleKES d))

instance
  (DSIGNMAlgorithm d, KnownNat (SizeSigKES (CompactSingleKES d))) =>
  ToCBOR (SigKES (CompactSingleKES d))
  where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance
  (DSIGNMAlgorithm d, KnownNat (SizeSigKES (CompactSingleKES d))) =>
  FromCBOR (SigKES (CompactSingleKES d))
  where
  fromCBOR = decodeSigKES

--
-- UnsoundPureSignKey instances
--

deriving instance DSIGNAlgorithm d => Show (UnsoundPureSignKeyKES (CompactSingleKES d))
deriving instance
  (DSIGNAlgorithm d, Eq (SignKeyDSIGN d)) => Eq (UnsoundPureSignKeyKES (CompactSingleKES d))

instance
  (UnsoundDSIGNMAlgorithm d, KnownNat (SigSizeDSIGN d + VerKeySizeDSIGN d)) =>
  ToCBOR (UnsoundPureSignKeyKES (CompactSingleKES d))
  where
  toCBOR = encodeUnsoundPureSignKeyKES
  encodedSizeExpr _size _skProxy = encodedSignKeyKESSizeExpr (Proxy :: Proxy (SignKeyKES (CompactSingleKES d)))

instance
  (UnsoundDSIGNMAlgorithm d, KnownNat (SigSizeDSIGN d + VerKeySizeDSIGN d)) =>
  FromCBOR (UnsoundPureSignKeyKES (CompactSingleKES d))
  where
  fromCBOR = decodeUnsoundPureSignKeyKES

instance DSIGNAlgorithm d => NoThunks (UnsoundPureSignKeyKES (CompactSingleKES d))

--
-- Direct ser/deser
--

instance DirectSerialise (SignKeyDSIGNM d) => DirectSerialise (SignKeyKES (CompactSingleKES d)) where
  directSerialise push (SignKeyCompactSingleKES sk) = directSerialise push sk

instance DirectDeserialise (SignKeyDSIGNM d) => DirectDeserialise (SignKeyKES (CompactSingleKES d)) where
  directDeserialise pull = SignKeyCompactSingleKES <$!> directDeserialise pull

instance DirectSerialise (VerKeyDSIGN d) => DirectSerialise (VerKeyKES (CompactSingleKES d)) where
  directSerialise push (VerKeyCompactSingleKES sk) = directSerialise push sk

instance DirectDeserialise (VerKeyDSIGN d) => DirectDeserialise (VerKeyKES (CompactSingleKES d)) where
  directDeserialise pull = VerKeyCompactSingleKES <$!> directDeserialise pull
