{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- | Cryptographic data types and operations used in Leios per CIP-164. Leios
-- uses BLS12-381 MinSig as its signature scheme and defines a 'LeiosCert' that
-- can be included into blocks. This module deliberately not includes a
-- 'LeiosVote' because the vote itself is not an artifact that is on-chain.
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
  LeiosVoterId (..),
  encodeLeiosVoterId,
  decodeLeiosVoterId,
  LeiosVoter (..),
  LeiosCommittee (..),
  leiosCommitteeSize,
  resolveLeiosVoter,
  getLeiosVoterId,

  -- * Leios certificates
  LeiosCert (..),
  encodeLeiosCert,
  decodeLeiosCert,

  -- ** Construction
  AggregationError (..),
  aggregateLeiosCert,

  -- ** Verification
  VerificationError (..),
  verifyLeiosCert,

  -- * Bitfield wire-format helpers
  BitField,
  encodeBitField,
  decodeBitField,
) where

import Cardano.Base.Bytes (byteArrayFromByteString)
import Cardano.Binary (matchSize, toCBOR)
import Cardano.Crypto.DSIGN (
  DSIGNAggregatable (aggregateSigsDSIGN, uncheckedAggregateVerKeysDSIGN),
  DSIGNAlgorithm (rawSerialiseSigDSIGN),
  SigDSIGN,
  SignKeyDSIGN,
  VerKeyDSIGN,
  decodeSigDSIGN,
  encodeSigDSIGN,
  verifyDSIGN,
 )
import Cardano.Crypto.DSIGN.BLS12381 (BLS12381MinSigDSIGN, BLS12381SignContext, minSigPoPDST)
import Cardano.Crypto.DSIGN.Class (sigSizeDSIGN)
import Cardano.Crypto.Util (SignableRepresentation)
import Codec.CBOR.Decoding (Decoder, decodeBreakOr, decodeBytes, decodeListLenOrIndef, decodeWord16)
import Codec.CBOR.Encoding (Encoding, encodeListLen, encodeWord16)
import Control.DeepSeq (NFData)
import Control.Monad (forM_, unless, when)
import Data.Array.Byte (ByteArray)
import Data.Bifunctor (first)
import Data.Bits (setBit, shiftR, testBit, (.&.))
import Data.ByteString (ByteString)
import Data.Data (Proxy (..))
import Data.Foldable (foldrM)
import Data.Function ((&))
import Data.List.NonEmpty (NonEmpty, nonEmpty)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
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

type LeiosSignature = SigDSIGN LeiosDSIGN

-- | The BLS12-381 MinSig proof-of-possession ciphersuite DST used by Leios,
-- per CIP-164. Pass this as the 'ContextDSIGN' to 'signDSIGN' / 'verifyDSIGN'.
leiosSignContext :: BLS12381SignContext
leiosSignContext = minSigPoPDST

-- | Size of a Leios signature in the chosen signature scheme.
leiosSignatureSize :: Word
leiosSignatureSize = sigSizeDSIGN (Proxy @LeiosDSIGN)

-- | Get the bytes of a Leios signature.
leiosSignatureToBytes :: LeiosSignature -> ByteString
leiosSignatureToBytes = rawSerialiseSigDSIGN

-- | A weight assigned to a committee voter, normalised so the total over a
-- committee sums to @1@. Threshold checks in 'verifyLeiosCert' are against
-- this same scale.
type Weight = Rational

-- | A committee member's seat index. The index is the voter's position in
-- 'leiosCommitteeVoters' and determines its bit in the 'LeiosCert' @leiosCertSigners@
-- bitfield (MSB-first within each byte, so voter @i@ ↔ bit @7-(i mod 8)@ of
-- byte @i \`div\` 8@).
newtype LeiosVoterId = LeiosVoterId {leiosVoterIndex :: Word16}
  deriving stock (Eq, Ord, Show, Generic)
  deriving newtype (NFData, NoThunks)

-- | Plain CBOR encoder for 'LeiosVoterId'.
encodeLeiosVoterId :: LeiosVoterId -> Encoding
encodeLeiosVoterId (LeiosVoterId idx) = encodeWord16 idx

-- | Plain CBOR decoder for 'LeiosVoterId'.
decodeLeiosVoterId :: Decoder s LeiosVoterId
decodeLeiosVoterId = LeiosVoterId <$> decodeWord16

-- | A single seat in a 'LeiosCommittee': a voter's normalised weight paired with
-- its BLS verification key.
data LeiosVoter = LeiosVoter
  { voterWeight :: !Weight
  , voterVKey :: !LeiosVerificationKey
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

-- | The voting committee for a Leios epoch: an ordered vector of
-- 'LeiosVoter' seats.
--
-- Ixition determines the voter's 'LeiosVoterId' and its bit in the certificate's
-- bitfield, so callers must keep the order stable between construction and
-- verification of any cert.
--
-- This package intentionally does not provide committee selection — sampling
-- voters from the active stake distribution lives in consensus/ledger.
-- However, callers are responsible for ensuring that every voter's BLS
-- proof-of-possession has been verified before a 'LeiosCommittee' value is built;
-- 'verifyLeiosCert' and 'aggregateLeiosCert' both rely on this invariant to
-- skip per-key PoP checks (they use 'uncheckedAggregateVerKeysDSIGN' /
-- 'aggregateSigsDSIGN' under the hood). Passing in unchecked keys defeats
-- the security of the aggregate signature.
newtype LeiosCommittee = LeiosCommittee {leiosCommitteeVoters :: Vector LeiosVoter}
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)
  -- 'nothunks' ships no instance for 'Data.Vector.Strict.Vector' and we don't
  -- want to add an orphan. A WHNF-only check on the wrapper is sufficient here:
  -- the strict 'Vector' forces every cell to WHNF, and a WHNF 'LeiosVoter'
  -- forces both of its strict fields, so "LeiosCommittee in WHNF" structurally
  -- implies no thunks anywhere inside.
  deriving (NoThunks) via OnlyCheckWhnfNamed "LeiosCommittee" LeiosCommittee

-- | Number of seats in the committee.
leiosCommitteeSize :: LeiosCommittee -> Int
leiosCommitteeSize LeiosCommittee {leiosCommitteeVoters} = length leiosCommitteeVoters

-- | Resolve a 'LeiosVoterId' to its 'LeiosVoter' on the 'LeiosCommittee', or 'Nothing'
-- if the index is past the committee bound.
resolveLeiosVoter :: LeiosCommittee -> LeiosVoterId -> Maybe LeiosVoter
resolveLeiosVoter committee voterId =
  committee.leiosCommitteeVoters V.!? idx
  where
    idx = fromIntegral @Word16 @Int voterId.leiosVoterIndex

-- | Find a voter's 'LeiosVoterId' on the 'LeiosCommittee' by its
-- 'LeiosVerificationKey', or 'Nothing' if the key is not on the committee.
--
-- If the committee carries duplicate verification keys, returns the smallest
-- index matching @vk@ (committee selection is expected to deduplicate, but
-- this module does not enforce it).
--
-- Errors if the matching index does not fit in 'Word16'. The wire format of
-- 'LeiosCert' indexes voters by a 16-bit field, so a committee with more than
-- @2^16@ seats is already malformed. NOTE: this partiality could later be
-- avoided by introducing a smart constructor for 'LeiosCommittee' (or for the
-- committee-selection step in consensus) that rejects oversized committees
-- up front.
getLeiosVoterId :: HasCallStack => LeiosVerificationKey -> LeiosCommittee -> Maybe LeiosVoterId
getLeiosVoterId vk committee =
  toVoterId <$> V.findIndex ((== vk) . voterVKey) committee.leiosCommitteeVoters
  where
    toVoterId i
      | i > fromIntegral @Word16 @Int maxBound =
          error $
            "Cardano.Crypto.Leios.getLeiosVoterId: committee index "
              <> show i
              <> " does not fit in Word16"
      | otherwise = LeiosVoterId (fromIntegral @Int @Word16 i)

-- | A Leios certificate over an endorser block, as specified in CIP-164

-- The committee is derived deterministically from the active stake
-- distribution for the epoch of the announcing RB, so individual voter
-- identities and eligibility proofs are not carried in the certificate;
-- 'leiosCertSigners' is a @⌈N\/8⌉@-byte bitfield over the committee where bit @i@ is
-- set iff voter index @i@ signed.
--
-- Producers should build 'LeiosCert' values via 'aggregateLeiosCert' and
-- consumers verify them via 'verifyLeiosCert'; the bitfield layout is an
-- implementation detail of the wire format.
--
-- XXX: This says it's over an EB, but this modules does not specify the
-- "message" that is signed anymore and only it's usage within a block will add
-- these semantics.
data LeiosCert = LeiosCert
  { leiosCertSigners :: !BitField
  , leiosCertSignature :: !LeiosSignature
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

-- | Plain CBOR encoder for 'LeiosCert', matching the CDDL in 'LeiosCert'.
encodeLeiosCert :: LeiosCert -> Encoding
encodeLeiosCert cert =
  encodeListLen 2
    <> encodeBitField cert.leiosCertSigners
    <> encodeSigDSIGN cert.leiosCertSignature

-- | Plain CBOR decoder for 'LeiosCert', matching the CDDL in 'LeiosCert'.
-- Accepts both definite-length and indefinite-length encodings of the
-- outer 2-element array.
decodeLeiosCert :: Decoder s LeiosCert
decodeLeiosCert = do
  isIndef <-
    decodeListLenOrIndef >>= \case
      Just n -> False <$ matchSize "LeiosCert" 2 n
      Nothing -> pure True
  cert <-
    LeiosCert
      <$> decodeBitField
      <*> decodeSigDSIGN
  when isIndef $ do
    isBreak <- decodeBreakOr
    unless isBreak $
      fail "LeiosCert: expected break after 2 elements of indefinite-length list"
  pure cert

data AggregationError
  = -- | One or more voter indices in the sigs are past the committee bound.
    VoterIdsOutOfBounds (NonEmpty LeiosVoterId)
  | -- | BLS signature aggregation failed (e.g. malformed input signature).
    BLSAggregationFailed Text
  deriving stock (Eq, Show, Generic)
  deriving anyclass (NFData)

-- | Build a 'LeiosCert' from the sigs of committee members.
--
-- == Caller obligations
--
-- All signatures must be over the same message. Individual 'LeiosSignature'
-- values are not verified here, and once aggregated they cannot be told apart.
-- Feeding signatures cast over different messages produces a 'LeiosCert' that
-- will silently fail 'verifyLeiosCert' with no indication of which contribution
-- was wrong.
--
-- == What this function does
--
--   * Range-checks each 'LeiosVoterId' against the committee.
--   * Encodes the bitfield over the committee and aggregates the input
--     signatures.
--
-- This is the only way to construct a 'LeiosCert' from outside the package;
-- the bitfield layout is an internal wire-format detail.
aggregateLeiosCert ::
  LeiosCommittee ->
  Map LeiosVoterId LeiosSignature ->
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
      [vid | vid <- Map.keys sigs, isNothing $ resolveLeiosVoter committee vid]

    -- Builds directly into a mutable 'ByteArray' via a single allocation and
    -- writes one bit per member of the input set.
    leiosCertSigners = BitField $ runByteArray $ do
      mba <- newByteArray len
      fillByteArray mba 0 len 0
      forM_ (Map.keys sigs) $ \(LeiosVoterId i) -> do
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
  deriving stock (Eq, Show, Generic)
  deriving anyclass (NFData)

-- | Verify a 'LeiosCert' against a 'LeiosCommittee', a weight threshold, and the
-- message the signers were supposed to have signed.
--
-- == Caller obligations
--
-- Every voter in the 'LeiosCommittee' must have had its BLS proof-of-possession
-- verified beforehand (when the committee was selected). 'verifyLeiosCert'
-- uses 'uncheckedAggregateVerKeysDSIGN' and does not re-check PoPs; passing
-- in an unchecked committee breaks the security of the aggregate signature.
--
-- == What this function does
--
--   1. Decodes the 'leiosCertSigners' bitfield to the list of contributing voter
--      indices, rejecting too small or big bitfield with 'MalformedSigners'.
--
--   2. Sums those voters' weights from the committee; short-circuits with
--      'InsufficientWeight' if the sum is below the threshold.
--
--   3. Aggregates the contributing verification keys and verifies the
--      certificate's 'leiosCertSignature' against the aggregate key over
--      @msg@.
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
  -- The bitfield must be exactly the canonical 'committee-many bits, padded
  -- to a whole byte' length. Trailing bytes (zero-padded or otherwise) are
  -- not accepted; the wire form is fixed for a given committee size.
  when (sizeofByteArray (bitFieldBytes cert.leiosCertSigners) /= (n + 7) `div` 8) $
    Left MalformedSigners
  (weightReceived, vks) <- foldrM accumSigner (0, []) $ bitFieldMembers cert.leiosCertSigners
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

    accumSigner vid (!w, !ks) =
      case resolveLeiosVoter committee vid of
        Nothing -> Left MalformedSigners
        Just (LeiosVoter w' vk) -> Right (w + w', vk : ks)

    bitFieldMembers (BitField ba) =
      [ LeiosVoterId (fromIntegral @Int @Word16 globalIx)
      | byteIx <- [0 .. sizeofByteArray ba - 1]
      , let byte = indexByteArray ba byteIx :: Word8
      , bitIx <- [0 .. 7]
      , let globalIx = byteIx * 8 + bitIx
      , globalIx < n
      , testBit byte (7 - bitIx)
      ]

-- | The @leiosCertSigners@ bitfield of a 'LeiosCert': a @⌈leiosCommitteeSize\/8⌉@-byte
-- MSB-first packed-bits representation of which committee voters contributed
-- to the aggregate signature.
--
-- A 'newtype' wrapper around 'ByteArray' so type signatures throughout the
-- aggregate / verify path say what they're working on, and so the on-wire
-- form cannot be accidentally confused with arbitrary @bytes@.
newtype BitField = BitField {bitFieldBytes :: ByteArray}
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)
  deriving (NoThunks) via OnlyCheckWhnfNamed "BitField" BitField

-- | Encode a 'BitField' to CBOR bytes.
encodeBitField :: BitField -> Encoding
encodeBitField = toCBOR . bitFieldBytes

-- | Decode a 'BitField' from CBOR bytes.
decodeBitField :: Decoder s BitField
decodeBitField = BitField . byteArrayFromByteString <$> decodeBytes
