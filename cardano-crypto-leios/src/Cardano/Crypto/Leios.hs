{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- | Leios cryptographic types and operations per CIP-164 (BLS12-381 MinSig).
-- Defines the on-chain 'LeiosCert'; the off-chain 'LeiosVote' lives elsewhere.
module Cardano.Crypto.Leios (
  -- * Cryptographic primitives
  LeiosDSIGN,
  LeiosSigningKey,
  LeiosVerificationKey,
  LeiosSignature,
  leiosSignContext,
  leiosSignatureSize,
  leiosSignatureToBytes,

  -- * Voting committee
  Weight,
  LeiosSeatId (..),
  LeiosSeat (..),
  LeiosCommittee (..),
  mkLeiosCommittee,
  leiosCommitteeSize,
  resolveLeiosSeat,
  getLeiosSeatId,

  -- * Leios certificates
  LeiosCert (..),

  -- ** Construction
  AggregationError (..),
  aggregateLeiosCert,

  -- ** Verification
  VerificationError (..),
  verifyLeiosCert,

  -- * Bitfield wire-format helpers
  BitField (..),
) where

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  fixedSize,
 )
import Cardano.Crypto.DSIGN (
  DSIGNAggregatable (aggregateSigsDSIGN, uncheckedAggregateVerKeysDSIGN),
  PossessionProofDSIGN,
  SigDSIGN,
  SignKeyDSIGN,
  VerKeyDSIGN,
  verifyDSIGN,
  verifyPossessionProofDSIGN,
 )
import Cardano.Crypto.DSIGN.BLS12381 (BLS12381MinSigDSIGN, BLS12381SignContext, minSigPoPDST)
import Cardano.Crypto.Util (SignableRepresentation)
import Control.DeepSeq (NFData)
import Control.Monad (forM_, when)
import Data.Array.Byte (ByteArray)
import Data.Bifunctor (first)
import Data.Bits (setBit, shiftR, testBit, (.&.))
import Data.ByteString (ByteString)
import Data.Data (Proxy (..))
import Data.Function ((&))
import Data.Functor ((<&>))
import Data.List.NonEmpty (NonEmpty, nonEmpty)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
import Data.Maybe.Strict (StrictMaybe (..))
import Data.Primitive.ByteArray (
  fillByteArray,
  indexByteArray,
  newByteArray,
  readByteArray,
  runByteArray,
  sizeofByteArray,
  writeByteArray,
 )
import Data.Text (Text)
import qualified Data.Text as T
import Data.Vector.Strict (Vector)
import qualified Data.Vector.Strict as V
import Data.Word (Word16, Word8)
import GHC.Generics (Generic)
import GHC.Stack (HasCallStack)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

type LeiosDSIGN = BLS12381MinSigDSIGN

type LeiosSigningKey = SignKeyDSIGN LeiosDSIGN

type LeiosVerificationKey = VerKeyDSIGN LeiosDSIGN

type LeiosProofOfPossession = PossessionProofDSIGN LeiosDSIGN

type LeiosSignature = SigDSIGN LeiosDSIGN

-- | The BLS12-381 MinSig proof-of-possession ciphersuite DST used by Leios,
-- per CIP-164. Pass this as the 'ContextDSIGN' to 'signDSIGN' / 'verifyDSIGN'.
leiosSignContext :: BLS12381SignContext
leiosSignContext = minSigPoPDST

-- | Size of a Leios signature in the chosen signature scheme.
leiosSignatureSize :: Word
leiosSignatureSize = fixedSize (Proxy @(SigDSIGN LeiosDSIGN))

-- | Get the bytes of a Leios signature.
leiosSignatureToBytes :: LeiosSignature -> ByteString
leiosSignatureToBytes = rawEncodeFixedSized

-- | Weight of a committee seat, its vote or target threshold weight; typically
-- a fraction in [0,1] (see 'mkLeiosCommittee').
type Weight = Rational

-- | A seat's index: its position in 'leiosCommitteeSeats' and its bit in the
-- 'LeiosCert' bitfield.
-- MSB-first: seat @i@ ↔ bit @7-(i mod 8)@ of byte @i \`div\` 8@.
newtype LeiosSeatId = LeiosSeatId {leiosSeatIndex :: Word16}
  deriving stock (Eq, Ord, Show, Generic)
  deriving newtype (NFData, NoThunks)

-- | A committee seat: a weight and an optional BLS key (e.g. when not yet
-- registered).
data LeiosSeat = LeiosSeat
  { seatWeight :: !Weight
  , seatVKey :: !(StrictMaybe LeiosVerificationKey)
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

-- | A Leios epoch's voting committee: an ordered vector of seats (build via
-- 'mkLeiosCommittee'). Order is significant and is used by votes.
newtype LeiosCommittee = UnsafeLeiosCommittee {leiosCommitteeSeats :: Vector LeiosSeat}
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)
  -- WHNF check suffices: a strict 'Vector' of strict-field 'LeiosSeat's has no thunks in WHNF.
  deriving (NoThunks) via OnlyCheckWhnfNamed "LeiosCommittee" LeiosCommittee

-- | Build a 'LeiosCommittee' from an ordered vector of seats. A seat with no
-- key, or one whose proof of possession fails to verify, is admitted keyless.
-- Seat order is the voter indexing, so derive it deterministically.
--
-- NOTE: Seat weights are assumed to be in range [0,1] with sum ≤ 1.
--
-- XXX: the positional @(key, pop)@ input is awkward; a @Map k (Weight, StrictMaybe (key, pop))@
-- carrying identity would be correct-by-construction. Left to the call site for now.
mkLeiosCommittee ::
  Vector (StrictMaybe (LeiosVerificationKey, LeiosProofOfPossession), Weight) ->
  LeiosCommittee
mkLeiosCommittee seats =
  UnsafeLeiosCommittee $
    seats <&> \(mKeyPoP, w) ->
      LeiosSeat
        { seatWeight = w
        , seatVKey = do
            (vk, pop) <- mKeyPoP
            case verifyPossessionProofDSIGN leiosSignContext vk pop of
              -- XXX: The error string is a constant and just says it could not verify.
              Left _err -> SNothing
              Right () -> SJust vk
        }

-- | Number of seats in the committee.
leiosCommitteeSize :: LeiosCommittee -> Int
leiosCommitteeSize = length . leiosCommitteeSeats

-- | Resolve a 'LeiosSeatId' to its 'LeiosSeat' on the 'LeiosCommittee', or 'Nothing'
-- if the index is past the committee bound.
resolveLeiosSeat :: LeiosCommittee -> LeiosSeatId -> Maybe LeiosSeat
resolveLeiosSeat committee voterId =
  committee.leiosCommitteeSeats V.!? idx
  where
    idx = fromIntegral @Word16 @Int voterId.leiosSeatIndex

-- | The 'LeiosSeatId' for a verification key (smallest matching index if the
-- committee has duplicates), or 'Nothing' if absent. Errors on a committee with
-- more than @2^16@ seats — already malformed for the 16-bit bitfield.
getLeiosSeatId :: HasCallStack => LeiosVerificationKey -> LeiosCommittee -> Maybe LeiosSeatId
getLeiosSeatId vk committee =
  toVoterId <$> V.findIndex ((== SJust vk) . seatVKey) committee.leiosCommitteeSeats
  where
    toVoterId i
      | i > fromIntegral @Word16 @Int maxBound =
          error $
            "Cardano.Crypto.Leios.getLeiosSeatId: committee index "
              <> show i
              <> " does not fit in Word16"
      | otherwise = LeiosSeatId (fromIntegral @Int @Word16 i)

-- | A Leios certificate over an endorser block (CIP-164): a bitfield of which
-- committee seats signed, plus their aggregate signature. Build via
-- 'aggregateLeiosCert', verify via 'verifyLeiosCert'.
data LeiosCert = LeiosCert
  { leiosCertSigners :: !BitField
  , leiosCertSignature :: !LeiosSignature
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

data AggregationError
  = -- | One or more voter indices in the sigs are past the committee bound.
    VoterIdsOutOfBounds (NonEmpty LeiosSeatId)
  | -- | BLS signature aggregation failed (e.g. malformed input signature).
    BLSAggregationFailed Text
  deriving stock (Eq, Show, Generic)
  deriving anyclass (NFData)

-- | Aggregate committee members' signatures into a 'LeiosCert', range-checking
-- each 'LeiosSeatId'. All signatures must be over the same message — this is
-- not checked here, so a wrong-message contribution only surfaces later as a
-- 'verifyLeiosCert' failure. The only way to build a 'LeiosCert'.
aggregateLeiosCert ::
  LeiosCommittee ->
  Map LeiosSeatId LeiosSignature ->
  Either AggregationError LeiosCert
aggregateLeiosCert committee sigs = do
  case nonEmpty outOfBoundsVoterIds of
    Just vs -> Left (VoterIdsOutOfBounds vs)
    Nothing -> pure ()
  leiosCertSignature <-
    first (BLSAggregationFailed . T.pack) $
      aggregateSigsDSIGN (Map.elems sigs)
  pure LeiosCert {leiosCertSigners, leiosCertSignature}
  where
    outOfBoundsVoterIds =
      [vid | vid <- Map.keys sigs, isNothing $ resolveLeiosSeat committee vid]

    -- Builds directly into a mutable 'ByteArray' via a single allocation and
    -- writes one bit per member of the input set.
    leiosCertSigners = BitField $ runByteArray $ do
      mba <- newByteArray len
      fillByteArray mba 0 len 0
      forM_ (Map.keys sigs) $ \(LeiosSeatId i) -> do
        let idx = fromIntegral @Word16 @Int i
        when (idx < n) $ do
          let byteIx = idx `shiftR` 3
              bitIx = 7 - (idx .&. 7)
          b <- readByteArray @Word8 mba byteIx
          writeByteArray mba byteIx (b `setBit` bitIx)
      pure mba

    n = leiosCommitteeSize committee

    len = (n + 7) `div` 8

data VerificationError
  = -- | 'leiosCertSigners' bitfield is longer than @⌈leiosCommitteeSize/8⌉@ bytes.
    MalformedSigners
  | -- | The aggregate-BLS verification failed (wrong message, tampered
    -- signature, or a bitfield/aggregate mismatch).
    InvalidSignature
  | -- | Sum of signers' weights is below the required threshold.
    InsufficientWeight Weight
  | -- | Set bits select keyless seats; rejected before their weight counts, so
    -- keyless seats cannot pad the total towards the threshold.
    SignerWithoutKey (NonEmpty LeiosSeatId)
  deriving stock (Eq, Show, Generic)
  deriving anyclass (NFData)

-- | Verify a 'LeiosCert' against a committee, a weight threshold, and the
-- signed message, returning the signers' total weight. Rejects a malformed
-- bitfield, any bit on a keyless seat, a summed weight below the threshold , or
-- a bad aggregate signature with a 'VerificationError'. Keys are trusted as
-- PoP-checked by 'mkLeiosCommittee'.
verifyLeiosCert ::
  SignableRepresentation msg =>
  LeiosCommittee ->
  -- | Minimum signer weight required to accept the cert.
  Weight ->
  -- | The message the signers signed.
  msg ->
  LeiosCert ->
  -- | Total weight of the contributing signers on success.
  Either VerificationError Weight
verifyLeiosCert committee weightRequired msg cert = do
  -- Bitfield length is fixed at ⌈committee/8⌉ bytes; anything else is malformed.
  when (sizeofByteArray (bitFieldBytes cert.leiosCertSigners) /= (n + 7) `div` 8) $
    Left MalformedSigners
  -- Set bits are in-bounds by construction, so each resolves to a keyed or keyless seat.
  let seats = [(vid, resolveLeiosSeat committee vid) | vid <- bitFieldMembers cert.leiosCertSigners]
  -- Reject all keyless-seat bits up front, before any weight is counted.
  case nonEmpty [vid | (vid, Just (LeiosSeat _ SNothing)) <- seats] of
    Just keyless -> Left (SignerWithoutKey keyless)
    Nothing -> Right ()
  let (weightReceived, vks) = foldr accumSigner (0, []) [seat | (_, Just seat) <- seats]
  when (weightReceived < weightRequired) $
    Left (InsufficientWeight weightReceived)
  aggVk <-
    uncheckedAggregateVerKeysDSIGN vks
      & first (const InvalidSignature)
  verifyDSIGN leiosSignContext aggVk msg cert.leiosCertSignature
    & first (const InvalidSignature)
  pure weightReceived
  where
    n = leiosCommitteeSize committee

    -- Keyless seats already rejected above; 'SNothing' just keeps the total honest.
    accumSigner (LeiosSeat w' vk) (!w, !ks) =
      case vk of
        SJust k -> (w + w', k : ks)
        SNothing -> (w, ks)

    bitFieldMembers (BitField ba) =
      [ LeiosSeatId (fromIntegral @Int @Word16 globalIx)
      | byteIx <- [0 .. sizeofByteArray ba - 1]
      , let byte = indexByteArray ba byteIx :: Word8
      , bitIx <- [0 .. 7]
      , let globalIx = byteIx * 8 + bitIx
      , globalIx < n
      , testBit byte (7 - bitIx)
      ]

-- | A 'LeiosCert' signers bitfield: @⌈leiosCommitteeSize\/8⌉@ bytes, MSB-first,
-- bit @i@ set iff seat @i@ signed. Newtype so it isn't confused with raw bytes.
newtype BitField = BitField {bitFieldBytes :: ByteArray}
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)
  deriving (NoThunks) via OnlyCheckWhnfNamed "BitField" BitField
