{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
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
-- So this module simply provides a wrapper 'CompactSingleKES' that turns any
-- 'DSIGNAlgorithm' into an instance of 'KESAlgorithm' with a single period.
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
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import qualified Data.ByteString as BS
import           Control.Monad (guard)

import Control.Exception (assert)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash.Class
import Cardano.Crypto.DSIGN.Class
import qualified Cardano.Crypto.DSIGN as DSIGN
import Cardano.Crypto.KES.Class
import Control.DeepSeq (NFData)


-- | A standard signature scheme is a forward-secure signature scheme with a
-- single time period.
--
data CompactSingleKES d

deriving newtype instance NFData (VerKeyDSIGN d) => NFData (VerKeyKES (CompactSingleKES d))
deriving newtype instance NFData (SignKeyDSIGN d) => NFData (SignKeyKES (CompactSingleKES d))

deriving anyclass instance (NFData (SigDSIGN d), NFData (VerKeyDSIGN d)) => NFData (SigKES (CompactSingleKES d))

instance (DSIGNAlgorithm d, Typeable d) => KESAlgorithm (CompactSingleKES d) where
    type SeedSizeKES (CompactSingleKES d) = SeedSizeDSIGN d

    --
    -- Key and signature types
    --

    newtype VerKeyKES (CompactSingleKES d) = VerKeyCompactSingleKES (VerKeyDSIGN d)
        deriving Generic

    newtype SignKeyKES (CompactSingleKES d) = SignKeyCompactSingleKES (SignKeyDSIGN d)
        deriving Generic

    data SigKES (CompactSingleKES d) = SigCompactSingleKES !(SigDSIGN d) !(VerKeyDSIGN d)
        deriving Generic


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES _ = algorithmNameDSIGN (Proxy :: Proxy d) ++ "_kes_2^0"

    deriveVerKeyKES (SignKeyCompactSingleKES sk) =
        VerKeyCompactSingleKES (deriveVerKeyDSIGN sk)

    hashVerKeyKES (VerKeyCompactSingleKES vk) =
        castHash (hashVerKeyDSIGN vk)


    --
    -- Core algorithm operations
    --

    type ContextKES (CompactSingleKES d) = DSIGN.ContextDSIGN d
    type Signable   (CompactSingleKES d) = DSIGN.Signable     d

    signKES ctxt t a (SignKeyCompactSingleKES sk) =
        assert (t == 0) $
        SigCompactSingleKES (signDSIGN ctxt a sk) (deriveVerKeyDSIGN sk)

    verifyKES = verifyOptimizedKES

    updateKES _ctx (SignKeyCompactSingleKES _sk) _to = Nothing

    totalPeriodsKES  _ = 1

    --
    -- Key generation
    --

    seedSizeKES _ = seedSizeDSIGN (Proxy :: Proxy d)
    genKeyKES seed = SignKeyCompactSingleKES (genKeyDSIGN seed)


    --
    -- raw serialise/deserialise
    --

    sizeVerKeyKES  _ = sizeVerKeyDSIGN  (Proxy :: Proxy d)
    sizeSignKeyKES _ = sizeSignKeyDSIGN (Proxy :: Proxy d)
    sizeSigKES     _ = sizeSigDSIGN     (Proxy :: Proxy d) +
                       sizeVerKeyDSIGN  (Proxy :: Proxy d)

    rawSerialiseVerKeyKES  (VerKeyCompactSingleKES  vk) = rawSerialiseVerKeyDSIGN vk
    rawSerialiseSignKeyKES (SignKeyCompactSingleKES sk) = rawSerialiseSignKeyDSIGN sk
    rawSerialiseSigKES     (SigCompactSingleKES sig vk) =
      rawSerialiseSigDSIGN sig <> rawSerialiseVerKeyDSIGN vk

    rawDeserialiseVerKeyKES  = fmap VerKeyCompactSingleKES  . rawDeserialiseVerKeyDSIGN
    rawDeserialiseSignKeyKES = fmap SignKeyCompactSingleKES . rawDeserialiseSignKeyDSIGN
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

instance (KESAlgorithm (CompactSingleKES d), DSIGNAlgorithm d) => OptimizedKESAlgorithm (CompactSingleKES d) where
    verifySigKES ctxt t a (SigCompactSingleKES sig vk) =
      assert (t == 0) $
      verifyDSIGN ctxt vk a sig

    verKeyFromSigKES _ctxt t (SigCompactSingleKES _ vk) =
      assert (t == 0) $
      VerKeyCompactSingleKES vk


--
-- VerKey instances
--

deriving instance DSIGNAlgorithm d => Show (VerKeyKES (CompactSingleKES d))
deriving instance DSIGNAlgorithm d => Eq   (VerKeyKES (CompactSingleKES d))

instance DSIGNAlgorithm d => NoThunks (SignKeyKES (CompactSingleKES d))

instance DSIGNAlgorithm d => ToCBOR (VerKeyKES (CompactSingleKES d)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance DSIGNAlgorithm d => FromCBOR (VerKeyKES (CompactSingleKES d)) where
  fromCBOR = decodeVerKeyKES


--
-- SignKey instances
--

deriving instance DSIGNAlgorithm d => Show (SignKeyKES (CompactSingleKES d))

instance DSIGNAlgorithm d => NoThunks (VerKeyKES  (CompactSingleKES d))

instance DSIGNAlgorithm d => ToCBOR (SignKeyKES (CompactSingleKES d)) where
  toCBOR = encodeSignKeyKES
  encodedSizeExpr _size = encodedSignKeyKESSizeExpr

instance DSIGNAlgorithm d => FromCBOR (SignKeyKES (CompactSingleKES d)) where
  fromCBOR = decodeSignKeyKES


--
-- Sig instances
--

deriving instance DSIGNAlgorithm d => Show (SigKES (CompactSingleKES d))
deriving instance DSIGNAlgorithm d => Eq   (SigKES (CompactSingleKES d))

instance DSIGNAlgorithm d => NoThunks (SigKES (CompactSingleKES d))

instance DSIGNAlgorithm d => ToCBOR (SigKES (CompactSingleKES d)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance DSIGNAlgorithm d => FromCBOR (SigKES (CompactSingleKES d)) where
  fromCBOR = decodeSigKES

slice :: Word -> Word -> ByteString -> ByteString
slice offset size = BS.take (fromIntegral size)
                  . BS.drop (fromIntegral offset)
