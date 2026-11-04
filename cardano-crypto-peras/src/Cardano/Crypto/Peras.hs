{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeApplications #-}

module Cardano.Crypto.Peras (
  -- * Peras round numbers
  PerasRoundNo (..),
  onPerasRoundNo,
  PerasSeatIndex (..),
  maxPerasSeatIndex,
  PerasBlockRef (..),
  perasBlockHashSize,
  mkPerasBlockRef,
  PerasBoostedBlock (..),
  PerasDSIGN,
  PerasSigningKey,
  PerasVerificationKey,
  PerasSignature (..),
  PerasVRFOutput (..),
  perasSignatureSize,
  perasSignatureToBytes,
  perasVRFOutputToBytes,
) where

import Cardano.Binary.FixedSizeCodec (fixedSize, rawEncodeFixedSized)
import Cardano.Crypto.DSIGN (SigDSIGN, SignKeyDSIGN, VerKeyDSIGN)
import Cardano.Crypto.DSIGN.BLS12381 (BLS12381MinSigDSIGN)
import Cardano.Slotting.Slot (SlotNo, WithOrigin)
import Codec.Serialise (Serialise)
import Control.DeepSeq (NFData)
import Data.ByteString (ByteString)
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SBS
import Data.Coerce (coerce)
import Data.Ord (comparing)
import Data.Proxy (Proxy (..))
import Data.Word (Word16, Word32)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import Quiet (Quiet (..))

{-------------------------------------------------------------------------------
   Peras round numbers
-------------------------------------------------------------------------------}

-- | Round number in a Peras election.
newtype PerasRoundNo = PerasRoundNo {unPerasRoundNo :: Word32}
  deriving (Show) via Quiet PerasRoundNo
  deriving stock (Generic)
  deriving newtype (Enum, Eq, Ord, Num, Bounded, NoThunks, NFData, Serialise)

-- | Lift a binary operation on 'Word32' to 'PerasRoundNo'
onPerasRoundNo ::
  (Word32 -> Word32 -> Word32) ->
  (PerasRoundNo -> PerasRoundNo -> PerasRoundNo)
onPerasRoundNo = coerce

{-------------------------------------------------------------------------------
   Seat indices
-------------------------------------------------------------------------------}

-- | Seat index in the voting committee used for Peras
newtype PerasSeatIndex = PerasSeatIndex {unPerasSeatIndex :: Word16}
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (Enum, Bounded, NoThunks, NFData)

maxPerasSeatIndex :: PerasSeatIndex
maxPerasSeatIndex = maxBound

{-------------------------------------------------------------------------------
   Block references
-------------------------------------------------------------------------------}

-- | A reference to a block: its slot number and 32-byte hash.
--
-- NOTE: this is intended to be equivalent to a @Point blk@ when
-- @HeaderHash blk ~ ShortByteString@.
data PerasBlockRef = PerasBlockRef
  { pbrSlot :: !SlotNo
  , pbrHash :: !ShortByteString
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass (NoThunks, NFData)

perasBlockHashSize :: Int
perasBlockHashSize = 32

mkPerasBlockRef :: SlotNo -> ShortByteString -> Maybe PerasBlockRef
mkPerasBlockRef slot hash
  | SBS.length hash == perasBlockHashSize = Just (PerasBlockRef slot hash)
  | otherwise = Nothing

-- | The slot number and 32-byte hash of the block being voted for.
newtype PerasBoostedBlock = PerasBoostedBlock {unPerasBoostedBlock :: WithOrigin PerasBlockRef}
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NoThunks, NFData)

{-------------------------------------------------------------------------------
   BLS cryptography
-------------------------------------------------------------------------------}

type PerasDSIGN = BLS12381MinSigDSIGN

type PerasSigningKey = SignKeyDSIGN PerasDSIGN

type PerasVerificationKey = VerKeyDSIGN PerasDSIGN

newtype PerasSignature = PerasSignature {unPerasSignature :: SigDSIGN PerasDSIGN}
  deriving stock (Show, Eq, Generic)
  deriving newtype (NoThunks, NFData)

-- | 'SigDSIGN PerasDSIGN' (an elliptic curve point) has no natural total
-- order to derive an 'Ord' instance from (unlike 'Eq', which
-- @cardano-crypto-class@ provides via curve-point equality), so we compare on
-- the fixed-size wire encoding instead.
instance Ord PerasSignature where
  compare = comparing perasSignatureToBytes

newtype PerasVRFOutput = PerasVRFOutput {unPerasVRFOutput :: SigDSIGN PerasDSIGN}
  deriving stock (Show, Eq, Generic)
  deriving newtype (NoThunks, NFData)

-- | See the 'Ord PerasSignature' instance: no derivable 'Ord' exists either.
instance Ord PerasVRFOutput where
  compare = comparing perasVRFOutputToBytes

perasSignatureSize :: Word
perasSignatureSize = fixedSize (Proxy @(SigDSIGN PerasDSIGN))

perasSignatureToBytes :: PerasSignature -> ByteString
perasSignatureToBytes = rawEncodeFixedSized . unPerasSignature

perasVRFOutputToBytes :: PerasVRFOutput -> ByteString
perasVRFOutputToBytes = rawEncodeFixedSized . unPerasVRFOutput
