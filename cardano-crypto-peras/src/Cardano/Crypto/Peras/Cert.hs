{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}

module Cardano.Crypto.Peras.Cert (
  PerasVotersBitmap (UnsafePerasVotersBitmap, perasVotersMaxIndex, perasVotersBits),
  mkPerasVotersBitmap,
  perasVotersBitmapFromSeats,
  perasVotersBitmapSeats,
  perasVotersBitmapSize,
  PerasCertVoters (UnsafePerasCertVoters, perasCertVotersBitmap, perasCertNonPersistentVRFOutputs),
  mkPerasCertVoters,
  perasCertVotersFromSeats,
  perasCertVoterSeats,
  perasCertNumberOfVoters,
  perasCertNumberOfNonPersistentVoters,
  PerasCert (..),
  PerasRoundNo (..),
  PerasBoostedBlock (..),
  PerasSignature (..),
  PerasVRFOutput (..),
  PerasCertSize (..),
  perasCertSizeUpperBound,
) where

import Cardano.Crypto.Peras (
  PerasBoostedBlock (..),
  PerasRoundNo (..),
  PerasSeatIndex (..),
  PerasSignature (..),
  PerasVRFOutput (..),
 )
import Control.DeepSeq (NFData)
import Control.Monad (unless, when)
import Data.Bitmap (Bitmap)
import qualified Data.Bitmap as Bitmap
import Data.List (sortOn)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (catMaybes, isJust, isNothing)
import Data.Word (Word16, Word32)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

{-------------------------------------------------------------------------------
   Voters bitmap
-------------------------------------------------------------------------------}

data PerasVotersBitmap = UnsafePerasVotersBitmap
  { perasVotersMaxIndex :: !Word16
  , perasVotersBits :: !Bitmap
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass (NoThunks, NFData)

mkPerasVotersBitmap :: Word16 -> Bitmap -> Maybe PerasVotersBitmap
mkPerasVotersBitmap maxIx bs
  | Bitmap.wellFormed (fromIntegral maxIx + 1) bs = Just (UnsafePerasVotersBitmap maxIx bs)
  | otherwise = Nothing

perasVotersBitmapFromSeats :: Word16 -> [PerasSeatIndex] -> PerasVotersBitmap
perasVotersBitmapFromSeats maxIx seats =
  UnsafePerasVotersBitmap maxIx $
    Bitmap.fromIndices (fromIntegral maxIx + 1) (fromIntegral . unPerasSeatIndex <$> seats)

perasVotersBitmapSeats :: PerasVotersBitmap -> [PerasSeatIndex]
perasVotersBitmapSeats (UnsafePerasVotersBitmap maxIx bs) =
  PerasSeatIndex . fromIntegral <$> Bitmap.toIndices (fromIntegral maxIx + 1) bs

perasVotersBitmapSize :: PerasVotersBitmap -> Int
perasVotersBitmapSize = Bitmap.numSetBits . perasVotersBits

{-------------------------------------------------------------------------------
   Voters
-------------------------------------------------------------------------------}

-- | Compact representation of the voters in a Peras certificate.
--
-- This compact representation consists of a bitmap of voter seat indices and a
-- list of non-persistent eligibility proofs (VRF outputs). In this setup, the
-- last @np@ indices in the bitmap that are flipped to 1 correspond to
-- non-persistent voters, where @np@ is the length of the list of non-persistent
-- eligibility proofs. The remaining flipped indices in the bitmap correspond
-- to persistent voters.
data PerasCertVoters = UnsafePerasCertVoters
  { perasCertVotersBitmap :: !PerasVotersBitmap
  , perasCertNonPersistentVRFOutputs :: ![PerasVRFOutput]
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass (NoThunks, NFData)

mkPerasCertVoters :: PerasVotersBitmap -> [PerasVRFOutput] -> Either String PerasCertVoters
mkPerasCertVoters bitmap vrfOutputs = do
  let numVoters = perasVotersBitmapSize bitmap
      numProofs = length vrfOutputs
  when (numVoters == 0) $
    Left "Invalid Peras certificate: empty voters bitmap"
  when (numProofs > numVoters) $
    Left $
      unlines
        [ "Invalid Peras certificate:"
            <> " more non-persistent voter eligibility proofs were provided"
            <> " than the number of voters in the certificate"
        , " * number of voters: "
            <> show numVoters
        , " * number of proofs: "
            <> show numProofs
        ]
  pure (UnsafePerasCertVoters bitmap vrfOutputs)

perasCertVoterSeats :: PerasCertVoters -> NonEmpty (PerasSeatIndex, Maybe PerasVRFOutput)
perasCertVoterSeats UnsafePerasCertVoters {perasCertVotersBitmap, perasCertNonPersistentVRFOutputs} =
  case zip seats proofs of
    [] -> error "perasCertVoterSeats: empty voters bitmap (invariant violated via UnsafePerasCertVoters)"
    x : xs -> x :| xs
  where
    seats = perasVotersBitmapSeats perasCertVotersBitmap
    numPersistent = length seats - length perasCertNonPersistentVRFOutputs
    proofs = replicate numPersistent Nothing <> fmap Just perasCertNonPersistentVRFOutputs

perasCertVotersFromSeats ::
  NonEmpty (PerasSeatIndex, Maybe PerasVRFOutput) ->
  Either String PerasCertVoters
perasCertVotersFromSeats seats = do
  let sorted = sortOn fst (NonEmpty.toList seats)
      indices = unPerasSeatIndex . fst <$> sorted
      proofs = snd <$> sorted
  when (any (uncurry (==)) (zip indices (drop 1 indices))) $
    Left "Invalid Peras certificate voters: duplicate seat index"
  unless (all isJust (dropWhile isNothing proofs)) $
    Left "Invalid Peras certificate voters: persistent voter after a non-persistent one"
  let bitmap = perasVotersBitmapFromSeats (last indices) (fst <$> sorted)
  mkPerasCertVoters bitmap (catMaybes proofs)

perasCertNumberOfVoters :: PerasCertVoters -> Int
perasCertNumberOfVoters = perasVotersBitmapSize . perasCertVotersBitmap

perasCertNumberOfNonPersistentVoters :: PerasCertVoters -> Int
perasCertNumberOfNonPersistentVoters = length . perasCertNonPersistentVRFOutputs

{-------------------------------------------------------------------------------
   Certificates
-------------------------------------------------------------------------------}

-- | Concrete Peras certificates using BLS signatures
data PerasCert = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !PerasSignature
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass (NoThunks, NFData)

-- | Size of a serialised 'PerasCert', in bytes.
newtype PerasCertSize = PerasCertSize {unPerasCertSize :: Word32}
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NoThunks, NFData)

-- | An upper bound (not necessarily tight) on the size, in bytes, of a
-- serialised 'PerasCert'.
--
-- The three constants below are themselves upper bounds (in bits, not
-- bytes) on the CBOR encoding of the certificate's fixed overhead, of each
-- voter's contribution to the voters bitmap, and of each non-persistent
-- voter's additional VRF output, respectively. For their derivation, see
-- <https://github.com/IntersectMBO/ouroboros-consensus/pull/2187#discussion_r3955585768>.
perasCertSizeUpperBound :: PerasCert -> PerasCertSize
perasCertSizeUpperBound cert =
  PerasCertSize . fromIntegral $
    (`divCeiling` 8) $
      constSize
        + numVoters * sizePerVoter
        + numNonPersistentVoters * extraSizePerNonPersistentVoter
  where
    numNonPersistentVoters = perasCertNumberOfNonPersistentVoters (pcVoters cert)
    numVoters = perasCertNumberOfVoters (pcVoters cert)

    constSize = 135 * 8
    sizePerVoter = 1
    extraSizePerNonPersistentVoter = 50 * 8

    divCeiling n d = q + min 1 r
      where
        (q, r) = n `quotRem` d
