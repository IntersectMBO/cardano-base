{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
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
    CompactSingleKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  ) where

import Data.Proxy (Proxy(..))
import GHC.Generics (Generic)
import GHC.TypeLits (KnownNat, type (+))
import NoThunks.Class (NoThunks)
import qualified Data.ByteString as BS
import           Control.Monad (guard, (<$!>))

import Control.Exception (assert)
import Control.DeepSeq (NFData)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash.Class
import Cardano.Crypto.DSIGN.Class as DSIGN
import Cardano.Crypto.KES.Class


-- | A standard signature scheme is a forward-secure signature scheme with a
-- single time period.
--
data CompactSingleKES d

deriving newtype instance NFData (VerKeyDSIGN d) => NFData (VerKeyKES (CompactSingleKES d))
deriving newtype instance NFData (SignKeyDSIGNM d) => NFData (SignKeyKES (CompactSingleKES d))

deriving instance (NFData (SigDSIGN d), NFData (VerKeyDSIGN d)) => NFData (SigKES (CompactSingleKES d))



instance ( DSIGNMAlgorithm d
         , KnownNat (SizeSigDSIGN d + SizeVerKeyDSIGN d)
         )
         => KESAlgorithm (CompactSingleKES d) where
    type SeedSizeKES (CompactSingleKES d) = SeedSizeDSIGN d


    --
    -- Key and signature types
    --

    newtype VerKeyKES (CompactSingleKES d) = VerKeyCompactSingleKES (VerKeyDSIGN d)
        deriving Generic

    data SigKES (CompactSingleKES d) = SigCompactSingleKES !(SigDSIGN d) !(VerKeyDSIGN d)
        deriving Generic

    newtype SignKeyKES (CompactSingleKES d) = SignKeyCompactSingleKES (SignKeyDSIGNM d)

    type ContextKES (CompactSingleKES d) = ContextDSIGN d
    type Signable   (CompactSingleKES d) = DSIGN.Signable     d


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES _ = algorithmNameDSIGN (Proxy :: Proxy d) ++ "_kes_2^0"

    totalPeriodsKES  _ = 1

    --
    -- Core algorithm operations
    --

    verifyKES = verifyOptimizedKES

    --
    -- raw serialise/deserialise
    --

    type SizeVerKeyKES (CompactSingleKES d) = SizeVerKeyDSIGN d
    type SizeSignKeyKES (CompactSingleKES d) = SizeSignKeyDSIGN d
    type SizeSigKES (CompactSingleKES d) = SizeSigDSIGN d + SizeVerKeyDSIGN d

    hashVerKeyKES (VerKeyCompactSingleKES vk) =
        castHash (hashVerKeyDSIGN vk)


    rawSerialiseVerKeyKES  (VerKeyCompactSingleKES  vk) = rawSerialiseVerKeyDSIGN vk
    rawSerialiseSigKES     (SigCompactSingleKES sig vk) =
      rawSerialiseSigDSIGN sig <> rawSerialiseVerKeyDSIGN vk

    rawDeserialiseVerKeyKES  = fmap VerKeyCompactSingleKES  . rawDeserialiseVerKeyDSIGN
    rawDeserialiseSigKES b   = do
        guard (BS.length b == fromIntegral size_total)
        sigma <- rawDeserialiseSigDSIGN  b_sig
        vk  <- rawDeserialiseVerKeyDSIGN b_vk
        return (SigCompactSingleKES sigma vk)
      where
        b_sig = slice off_sig size_sig b
        b_vk = slice off_vk size_vk  b

        size_sig   = sizeSigDSIGN    (Proxy :: Proxy d)
        size_vk    = sizeVerKeyDSIGN (Proxy :: Proxy d)
        size_total = sizeSigKES    (Proxy :: Proxy (CompactSingleKES d))

        off_sig    = 0 :: Word
        off_vk     = size_sig

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

instance ( KESAlgorithm (CompactSingleKES d)
         , DSIGNMAlgorithm d
         ) => OptimizedKESAlgorithm (CompactSingleKES d) where
    verifySigKES ctxt t a (SigCompactSingleKES sig vk) =
      assert (t == 0) $
      verifyDSIGN ctxt vk a sig

    verKeyFromSigKES _ctxt t (SigCompactSingleKES _ vk) =
      assert (t == 0) $
      VerKeyCompactSingleKES vk

instance (KESAlgorithm (CompactSingleKES d), UnsoundDSIGNMAlgorithm d)
         => UnsoundKESAlgorithm (CompactSingleKES d) where
    rawSerialiseSignKeyKES (SignKeyCompactSingleKES sk) = rawSerialiseSignKeyDSIGNM sk
    rawDeserialiseSignKeyKESWith allocator bs = fmap SignKeyCompactSingleKES <$> rawDeserialiseSignKeyDSIGNMWith allocator bs


--
-- VerKey instances
--

deriving instance DSIGNMAlgorithm d => Show (VerKeyKES (CompactSingleKES d))
deriving instance DSIGNMAlgorithm d => Eq   (VerKeyKES (CompactSingleKES d))

instance (DSIGNMAlgorithm d, KnownNat (SizeSigDSIGN d + SizeVerKeyDSIGN d)) => ToCBOR (VerKeyKES (CompactSingleKES d)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance (DSIGNMAlgorithm d, KnownNat (SizeSigDSIGN d + SizeVerKeyDSIGN d)) => FromCBOR (VerKeyKES (CompactSingleKES d)) where
  fromCBOR = decodeVerKeyKES

instance DSIGNMAlgorithm d => NoThunks (VerKeyKES  (CompactSingleKES d))


--
-- SignKey instances
--

deriving via (SignKeyDSIGNM d) instance DSIGNMAlgorithm d => NoThunks (SignKeyKES (CompactSingleKES d))

--
-- Sig instances
--

deriving instance DSIGNMAlgorithm d => Show (SigKES (CompactSingleKES d))
deriving instance DSIGNMAlgorithm d => Eq   (SigKES (CompactSingleKES d))

instance DSIGNMAlgorithm d => NoThunks (SigKES (CompactSingleKES d))

instance (DSIGNMAlgorithm d, KnownNat (SizeSigKES (CompactSingleKES d))) => ToCBOR (SigKES (CompactSingleKES d)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance (DSIGNMAlgorithm d, KnownNat (SizeSigKES (CompactSingleKES d))) => FromCBOR (SigKES (CompactSingleKES d)) where
  fromCBOR = decodeSigKES

slice :: Word -> Word -> ByteString -> ByteString
slice offset size = BS.take (fromIntegral size)
                  . BS.drop (fromIntegral offset)
