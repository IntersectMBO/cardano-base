{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
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
import           Control.Monad (guard)

import Control.Exception (assert)
import Control.DeepSeq (NFData)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash.Class
import Cardano.Crypto.DSIGNM.Class as DSIGNM
import Cardano.Crypto.KES.Class


-- | A standard signature scheme is a forward-secure signature scheme with a
-- single time period.
--
data CompactSingleKES d

deriving newtype instance NFData (VerKeyDSIGNM d) => NFData (VerKeyKES (CompactSingleKES d))
deriving newtype instance NFData (SignKeyDSIGNM d) => NFData (SignKeyKES (CompactSingleKES d))

deriving instance (NFData (SigDSIGNM d), NFData (VerKeyDSIGNM d)) => NFData (SigKES (CompactSingleKES d))



instance ( DSIGNMAlgorithmBase d
         , KnownNat (SizeSigDSIGNM d + SizeVerKeyDSIGNM d)
         )
         => KESAlgorithm (CompactSingleKES d) where
    type SeedSizeKES (CompactSingleKES d) = SeedSizeDSIGNM d

    --
    -- Key and signature types
    --

    newtype VerKeyKES (CompactSingleKES d) = VerKeyCompactSingleKES (VerKeyDSIGNM d)
        deriving Generic

    newtype SignKeyKES (CompactSingleKES d) = SignKeyCompactSingleKES (SignKeyDSIGNM d)
        deriving Generic

    data SigKES (CompactSingleKES d) = SigCompactSingleKES !(SigDSIGNM d) !(VerKeyDSIGNM d)
        deriving Generic

    type ContextKES (CompactSingleKES d) = ContextDSIGNM d
    type Signable   (CompactSingleKES d) = DSIGNM.SignableM     d


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES _ = algorithmNameDSIGNM (Proxy :: Proxy d) ++ "_kes_2^0"

    totalPeriodsKES  _ = 1

    --
    -- Core algorithm operations
    --

    verifyKES = verifyOptimizedKES

    --
    -- Key generation
    --

    seedSizeKES _ = seedSizeDSIGNM (Proxy :: Proxy d)


    --
    -- raw serialise/deserialise
    --

    type SizeVerKeyKES (CompactSingleKES d) = SizeVerKeyDSIGNM d
    type SizeSignKeyKES (CompactSingleKES d) = SizeSignKeyDSIGNM d
    type SizeSigKES (CompactSingleKES d) = SizeSigDSIGNM d + SizeVerKeyDSIGNM d

    hashVerKeyKES (VerKeyCompactSingleKES vk) =
        castHash (hashVerKeyDSIGNM vk)


    rawSerialiseVerKeyKES  (VerKeyCompactSingleKES  vk) = rawSerialiseVerKeyDSIGNM vk
    rawSerialiseSigKES     (SigCompactSingleKES sig vk) =
      rawSerialiseSigDSIGNM sig <> rawSerialiseVerKeyDSIGNM vk

    rawDeserialiseVerKeyKES  = fmap VerKeyCompactSingleKES  . rawDeserialiseVerKeyDSIGNM
    rawDeserialiseSigKES b   = do
        guard (BS.length b == fromIntegral size_total)
        sigma <- rawDeserialiseSigDSIGNM  b_sig
        vk  <- rawDeserialiseVerKeyDSIGNM b_vk
        return (SigCompactSingleKES sigma vk)
      where
        b_sig = slice off_sig size_sig b
        b_vk = slice off_vk size_vk  b

        size_sig   = sizeSigDSIGNM    (Proxy :: Proxy d)
        size_vk    = sizeVerKeyDSIGNM (Proxy :: Proxy d)
        size_total = sizeSigKES    (Proxy :: Proxy (CompactSingleKES d))

        off_sig    = 0 :: Word
        off_vk     = size_sig

instance ( DSIGNMAlgorithm m d -- needed for secure forgetting
         , Monad m
         , KnownNat (SizeSigDSIGNM d + SizeVerKeyDSIGNM d)
         )
         => KESSignAlgorithm m (CompactSingleKES d) where
    deriveVerKeyKES (SignKeyCompactSingleKES v) =
        VerKeyCompactSingleKES <$> deriveVerKeyDSIGNM v

    --
    -- Core algorithm operations
    --
    signKES ctxt t a (SignKeyCompactSingleKES sk) =
        assert (t == 0) $
        SigCompactSingleKES <$> signDSIGNM ctxt a sk <*> deriveVerKeyDSIGNM sk

    updateKES _ctx (SignKeyCompactSingleKES _sk) _to = return Nothing

    --
    -- Key generation
    --

    genKeyKES seed = SignKeyCompactSingleKES <$> genKeyDSIGNM seed

    rawSerialiseSignKeyKES (SignKeyCompactSingleKES sk) = rawSerialiseSignKeyDSIGNM sk
    rawDeserialiseSignKeyKES bs = fmap SignKeyCompactSingleKES <$> rawDeserialiseSignKeyDSIGNM bs

    --
    -- forgetting
    --
    forgetSignKeyKES (SignKeyCompactSingleKES v) =
      forgetSignKeyDSIGNM v

instance ( KESAlgorithm (CompactSingleKES d)
         , DSIGNMAlgorithmBase d
         ) => OptimizedKESAlgorithm (CompactSingleKES d) where
    verifySigKES ctxt t a (SigCompactSingleKES sig vk) =
      assert (t == 0) $
      verifyDSIGNM ctxt vk a sig

    verKeyFromSigKES _ctxt t (SigCompactSingleKES _ vk) =
      assert (t == 0) $
      VerKeyCompactSingleKES vk


--
-- VerKey instances
--

deriving instance DSIGNMAlgorithmBase d => Show (VerKeyKES (CompactSingleKES d))
deriving instance DSIGNMAlgorithmBase d => Eq   (VerKeyKES (CompactSingleKES d))

instance (DSIGNMAlgorithmBase d, KnownNat (SizeSigDSIGNM d + SizeVerKeyDSIGNM d)) => ToCBOR (VerKeyKES (CompactSingleKES d)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance (DSIGNMAlgorithmBase d, KnownNat (SizeSigDSIGNM d + SizeVerKeyDSIGNM d)) => FromCBOR (VerKeyKES (CompactSingleKES d)) where
  fromCBOR = decodeVerKeyKES

instance DSIGNMAlgorithmBase d => NoThunks (VerKeyKES  (CompactSingleKES d))


--
-- SignKey instances
--

instance DSIGNMAlgorithmBase d => NoThunks (SignKeyKES (CompactSingleKES d))

-- deriving instance DSIGNMAlgorithmBase d => Show (SignKeyKES (CompactSingleKES d))

--
-- Sig instances
--

deriving instance DSIGNMAlgorithmBase d => Show (SigKES (CompactSingleKES d))
deriving instance DSIGNMAlgorithmBase d => Eq   (SigKES (CompactSingleKES d))

instance DSIGNMAlgorithmBase d => NoThunks (SigKES (CompactSingleKES d))

instance (DSIGNMAlgorithmBase d, KnownNat (SizeSigKES (CompactSingleKES d))) => ToCBOR (SigKES (CompactSingleKES d)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance (DSIGNMAlgorithmBase d, KnownNat (SizeSigKES (CompactSingleKES d))) => FromCBOR (SigKES (CompactSingleKES d)) where
  fromCBOR = decodeSigKES

slice :: Word -> Word -> ByteString -> ByteString
slice offset size = BS.take (fromIntegral size)
                  . BS.drop (fromIntegral offset)
