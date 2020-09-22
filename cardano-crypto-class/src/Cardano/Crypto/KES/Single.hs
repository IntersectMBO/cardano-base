{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TypeApplications #-}

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
-- 'DSIGNAlgorithm' into an instance of 'KESAlgorithm' with a single period.
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
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

import Control.Exception (assert)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash.Class
import Cardano.Crypto.DSIGN.Class
import qualified Cardano.Crypto.DSIGN as DSIGN
import Cardano.Crypto.KES.Class

import Cardano.Crypto.PinnedSizedBytes
import qualified Cardano.Crypto.Libsodium as NaCl

-- | A standard signature scheme is a forward-secure signature scheme with a
-- single time period.
--
data SingleKES d

instance ( NaCl.SodiumDSIGNAlgorithm d -- needed for secure forgetting
         , Typeable d) => KESAlgorithm (SingleKES d) where
    type SeedSizeKES (SingleKES d) = SeedSizeDSIGN d

    --
    -- Key and signature types
    --

    newtype VerKeyKES (SingleKES d) = VerKeySingleKES (NaCl.SodiumVerKeyDSIGN d)
        deriving Generic

    newtype SignKeyKES (SingleKES d) = SignKeySingleKES (NaCl.SodiumSignKeyDSIGN d)
        deriving Generic

    newtype SigKES (SingleKES d) = SigSingleKES (NaCl.SodiumSigDSIGN d)
        deriving Generic


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES _ = algorithmNameDSIGN (Proxy :: Proxy d) ++ "_kes_2^0"

    deriveVerKeyKES (SignKeySingleKES sk) =
        VerKeySingleKES $ NaCl.naclDeriveVerKeyDSIGN (Proxy :: Proxy d) sk

    hashVerKeyKES (VerKeySingleKES vk) =
        castHash (hashWith psbToByteString vk)


    --
    -- Core algorithm operations
    --

    type ContextKES (SingleKES d) = DSIGN.ContextDSIGN d
    type Signable   (SingleKES d) = DSIGN.Signable     d

    signKES _ctxt t a (SignKeySingleKES sk) =
        assert (t == 0) $
        SigSingleKES (NaCl.naclSignDSIGN (Proxy @d) a sk)

    verifyKES _ctxt (VerKeySingleKES vk) t a (SigSingleKES sig) =
        assert (t == 0) $
        NaCl.naclVerifyDSIGN (Proxy @d) vk a sig

    updateKES _ctx (SignKeySingleKES _sk) _to = return Nothing

    totalPeriodsKES  _ = 1

    --
    -- Key generation
    --

    genKeyKES seed =
      return $ SignKeySingleKES (NaCl.naclGenKeyDSIGN (Proxy @d) seed)

    --
    -- forgetting
    --

    -- TODO: to implement this, we
    -- should know how to forget DSIGN keys.
    forgetSignKeyKES = const $ return ()

    --
    -- raw serialise/deserialise
    --

    sizeVerKeyKES  _ = sizeVerKeyDSIGN  (Proxy :: Proxy d)
    sizeSignKeyKES _ = sizeSignKeyDSIGN (Proxy :: Proxy d)
    sizeSigKES     _ = sizeSigDSIGN     (Proxy :: Proxy d)

    rawSerialiseVerKeyKES  (VerKeySingleKES  vk) = psbToByteString vk
    rawSerialiseSignKeyKES (SignKeySingleKES sk) = NaCl.mlsbToByteString sk
    rawSerialiseSigKES     (SigSingleKES    sig) = psbToByteString sig

    rawDeserialiseVerKeyKES  = fmap VerKeySingleKES  . psbFromByteStringCheck
    rawDeserialiseSignKeyKES = fmap SignKeySingleKES . NaCl.mlsbFromByteStringCheck
    rawDeserialiseSigKES     = fmap SigSingleKES     . psbFromByteStringCheck

--
-- VerKey instances
--

deriving instance DSIGNAlgorithm d => Show (VerKeyKES (SingleKES d))
deriving instance DSIGNAlgorithm d => Eq   (VerKeyKES (SingleKES d))

instance DSIGNAlgorithm d => NoThunks (SignKeyKES (SingleKES d))

instance NaCl.SodiumDSIGNAlgorithm d => ToCBOR (VerKeyKES (SingleKES d)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance NaCl.SodiumDSIGNAlgorithm d => FromCBOR (VerKeyKES (SingleKES d)) where
  fromCBOR = decodeVerKeyKES


--
-- SignKey instances
--

deriving instance DSIGNAlgorithm d => Show (SignKeyKES (SingleKES d))

instance DSIGNAlgorithm d => NoThunks (VerKeyKES  (SingleKES d))

instance NaCl.SodiumDSIGNAlgorithm d => ToCBOR (SignKeyKES (SingleKES d)) where
  toCBOR = encodeSignKeyKES
  encodedSizeExpr _size = encodedSignKeyKESSizeExpr

instance NaCl.SodiumDSIGNAlgorithm d => FromCBOR (SignKeyKES (SingleKES d)) where
  fromCBOR = decodeSignKeyKES


--
-- Sig instances
--

deriving instance DSIGNAlgorithm d => Show (SigKES (SingleKES d))
deriving instance DSIGNAlgorithm d => Eq   (SigKES (SingleKES d))

instance DSIGNAlgorithm d => NoThunks (SigKES (SingleKES d))

instance NaCl.SodiumDSIGNAlgorithm d => ToCBOR (SigKES (SingleKES d)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance NaCl.SodiumDSIGNAlgorithm d => FromCBOR (SigKES (SingleKES d)) where
  fromCBOR = decodeSigKES

