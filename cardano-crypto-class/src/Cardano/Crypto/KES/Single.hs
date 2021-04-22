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
{-# LANGUAGE MultiParamTypeClasses #-}

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
import Control.DeepSeq (NFData)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash.Class
import Cardano.Crypto.DSIGN.Class
import qualified Cardano.Crypto.DSIGN as DSIGN
import Cardano.Crypto.KES.Class
import Cardano.Crypto.PinnedSizedBytes

import Cardano.Crypto.MonadSodium (MonadSodium (..), makeSafePinned, releaseSafePinned, interactSafePinned)
import qualified Cardano.Crypto.MonadSodium as NaCl


-- | A standard signature scheme is a forward-secure signature scheme with a
-- single time period.
--
data SingleKES d

deriving instance NFData (VerKeyKES (SingleKES d))
deriving instance NFData (SignKeyKES (SingleKES d))
deriving instance NFData (SigKES (SingleKES d))

instance (NaCl.SodiumDSIGNAlgorithm d, Typeable d) => KESAlgorithm (SingleKES d) where
    type SeedSizeKES (SingleKES d) = SeedSizeDSIGN d

    --
    -- Key and signature types
    --

    newtype VerKeyKES (SingleKES d) = VerKeySingleKES (NaCl.SodiumVerKeyDSIGN d)
        deriving Generic

    newtype SignKeyKES (SingleKES d) = SignKeySingleKES (NaCl.SafePinned (NaCl.SodiumSignKeyDSIGN d))
        deriving Generic

    newtype SigKES (SingleKES d) = SigSingleKES (NaCl.SodiumSigDSIGN d)
        deriving Generic

    type ContextKES (SingleKES d) = DSIGN.ContextDSIGN d
    type Signable   (SingleKES d) = DSIGN.Signable     d


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES _ = algorithmNameDSIGN (Proxy :: Proxy d) ++ "_kes_2^0"

    totalPeriodsKES  _ = 1

    verifyKES _ctxt (VerKeySingleKES vk) t a (SigSingleKES sig) =
        assert (t == 0) $
        NaCl.naclVerifyDSIGN (Proxy @d) vk a sig

    --
    -- raw serialise/deserialise
    --

    sizeVerKeyKES  _ = sizeVerKeyDSIGN  (Proxy :: Proxy d)
    sizeSignKeyKES _ = sizeSignKeyDSIGN (Proxy :: Proxy d)
    sizeSigKES     _ = sizeSigDSIGN     (Proxy :: Proxy d)

    hashVerKeyKES (VerKeySingleKES vk) =
        castHash (hashWith psbToByteString vk)

    rawSerialiseVerKeyKES  (VerKeySingleKES  vk) = psbToByteString vk
    rawSerialiseSigKES     (SigSingleKES    sig) = psbToByteString sig

    rawDeserialiseVerKeyKES  = fmap VerKeySingleKES  . psbFromByteStringCheck
    rawDeserialiseSigKES     = fmap SigSingleKES     . psbFromByteStringCheck


instance ( NaCl.SodiumDSIGNAlgorithm d -- needed for secure forgetting
         , Monad m
         , MonadSodium m
         , Typeable d) => KESSignAlgorithm m (SingleKES d) where
    deriveVerKeyKES (SignKeySingleKES v) =
      interactSafePinned v $ \sk -> do
        vk <- NaCl.naclDeriveVerKeyDSIGN (Proxy :: Proxy d) sk
        vk `seq` return (VerKeySingleKES vk)

    --
    -- Core algorithm operations
    --

    signKES _ctxt t a (SignKeySingleKES v) =
        assert (t == 0) $
        interactSafePinned v $ \sk ->
        return (SigSingleKES (NaCl.naclSignDSIGN (Proxy @d) a sk))

    updateKES _ctx (SignKeySingleKES _sk) _to = return Nothing

    --
    -- Key generation
    --

    genKeyKES seed = do
      rawKey <- NaCl.naclGenKeyDSIGN (Proxy @d) seed
      SignKeySingleKES <$> makeSafePinned rawKey

    --
    -- forgetting
    --
    forgetSignKeyKES (SignKeySingleKES v) =
      releaseSafePinned v
      -- NaCl.naclForgetSignKeyDSIGN (Proxy @d) sk

    rawSerialiseSignKeyKES (SignKeySingleKES sk) = interactSafePinned sk $ return . NaCl.mlsbToByteString
    rawDeserialiseSignKeyKES bs = do
      case NaCl.mlsbFromByteStringCheck bs of
        Nothing -> return Nothing
        Just x -> Just . SignKeySingleKES <$> makeSafePinned x

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

-- deriving instance DSIGNAlgorithm d => Show (SignKeyKES (SingleKES d))

instance DSIGNAlgorithm d => NoThunks (VerKeyKES  (SingleKES d))

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

