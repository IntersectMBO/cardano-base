{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
-- Named fields on the 'InsufficientWeight' variant of 'VerificationError'
-- are wanted at the call site; the project-wide @-Wpartial-fields@ would
-- otherwise reject record syntax on a single sum-type alternative.
{-# OPTIONS_GHC -Wno-partial-fields #-}

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

  -- * Voting committee
  Committee (..),
  Weight,
  committeeSize,
  VoterId (..),

  -- * Certificates
  LeiosCert (..),
  encodeLeiosCert,
  decodeLeiosCert,

  -- ** Construction
  aggregateLeiosCert,
  AggregationError (..),

  -- ** Verification
  verifyLeiosCert,
  VerificationError (..),

  -- * Internal
  --
  -- $internal
  BitField (..),
  bitFieldFromBytes,
  bitFieldToBytes,
) where

import Cardano.Binary (enforceSize)
import Cardano.Crypto.DSIGN (
  DSIGNAggregatable (aggregateSigsDSIGN, uncheckedAggregateVerKeysDSIGN),
  SigDSIGN,
  SignKeyDSIGN,
  VerKeyDSIGN,
  decodeSigDSIGN,
  encodeSigDSIGN,
  verifyDSIGN,
 )
import Cardano.Crypto.DSIGN.BLS12381 (BLS12381MinSigDSIGN, BLS12381SignContext, minSigPoPDST)
import Cardano.Crypto.Util (SignableRepresentation)
import Codec.CBOR.Decoding (Decoder, decodeBytes)
import Codec.CBOR.Encoding (Encoding, encodeBytes, encodeListLen)
import Control.DeepSeq (NFData)
import Control.Monad (when)
import Data.Array.Byte (ByteArray (ByteArray))
import Data.Bits (setBit, testBit)
import qualified Data.ByteString as BS
import Data.ByteString.Short (ShortByteString (SBS))
import qualified Data.ByteString.Short as SBS
import Data.Foldable (foldlM)
import Data.List (foldl')
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Vector (Vector)
import qualified Data.Vector as V
import Data.Word (Word16, Word8)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

-- * Cryptographic primitives

type LeiosDSIGN = BLS12381MinSigDSIGN

type LeiosSigningKey = SignKeyDSIGN LeiosDSIGN

type LeiosVerificationKey = VerKeyDSIGN LeiosDSIGN

type LeiosSignature = SigDSIGN LeiosDSIGN

-- | The BLS12-381 MinSig proof-of-possession ciphersuite DST used by Leios,
-- per CIP-164. Pass this as the 'ContextDSIGN' to 'signDSIGN' / 'verifyDSIGN'.
leiosSignContext :: BLS12381SignContext
leiosSignContext = minSigPoPDST

-- * Voting committee

-- | A weight assigned to a committee voter, normalised so the total over a
-- committee sums to @1@. Threshold checks in 'verifyLeiosCert' are against
-- this same scale.
type Weight = Rational

-- | A committee member's seat index. The index is the voter's position in
-- 'committeeVoters' and determines its bit in the 'LeiosCert' @signers@
-- bitfield (MSB-first within each byte, so voter @i@ ↔ bit @7-(i mod 8)@ of
-- byte @i \`div\` 8@).
newtype VoterId = VoterId {voterIndex :: Word16}
  deriving stock (Eq, Ord, Show, Generic)
  deriving anyclass (NFData, NoThunks)

-- | The voting committee for a Leios epoch: an ordered vector of
-- @(weight, verification-key)@ pairs.
--
-- Position determines the voter's 'VoterId' and its bit in the certificate's
-- bitfield, so callers must keep the order stable between construction and
-- verification of any cert.
--
-- This package intentionally does not provide committee selection — sampling
-- voters from the active stake distribution lives in consensus/ledger.
-- However, callers are responsible for ensuring that every voter's BLS
-- proof-of-possession has been verified before a 'Committee' value is built;
-- 'verifyLeiosCert' and 'aggregateLeiosCert' both rely on this invariant to
-- skip per-key PoP checks (they use 'uncheckedAggregateVerKeysDSIGN' /
-- 'aggregateSigsDSIGN' under the hood). Passing in unchecked keys defeats
-- the security of the aggregate signature.
newtype Committee = Committee {committeeVoters :: Vector (Weight, LeiosVerificationKey)}
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

-- | Number of seats in the committee.
committeeSize :: Committee -> Int
committeeSize = V.length . committeeVoters

-- * Leios certificates

-- | A Leios certificate over an endorser block, as specified in CIP-164:
--
-- @
-- leios_certificate =
--   [ signers               : bytes ; bitfield over the epoch's committee, MSB-first
--   , aggregated_signature  : leios_bls_signature
--   ]
-- @
--
-- The committee is derived deterministically from the active stake
-- distribution for the epoch of the announcing RB, so individual voter
-- identities and eligibility proofs are not carried in the certificate;
-- 'signers' is a @⌈N\/8⌉@-byte bitfield over the committee where bit @i@ is
-- set iff voter index @i@ signed.
--
-- Producers should build 'LeiosCert' values via 'aggregateLeiosCert' and
-- consumers verify them via 'verifyLeiosCert'; the bitfield layout is an
-- implementation detail of the wire format.
data LeiosCert = LeiosCert
  { signers :: !BitField
  , aggregatedSignature :: !LeiosSignature
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

-- | Plain CBOR encoder for 'LeiosCert', matching the CDDL in 'LeiosCert'.
encodeLeiosCert :: LeiosCert -> Encoding
encodeLeiosCert cert =
  encodeListLen 2
    <> encodeBytes (bitFieldToBytes cert.signers)
    <> encodeSigDSIGN cert.aggregatedSignature

-- | Plain CBOR decoder for 'LeiosCert', matching the CDDL in 'LeiosCert'.
decodeLeiosCert :: Decoder s LeiosCert
decodeLeiosCert = do
  enforceSize "LeiosCert" 2
  LeiosCert
    <$> (bitFieldFromBytes <$> decodeBytes)
    <*> decodeSigDSIGN

-- ** Construction

data AggregationError
  = -- | A voter index in the contributions is past the committee bound.
    VoterIdOutOfBounds !VoterId
  | -- | BLS signature aggregation failed (e.g. malformed input signature).
    BLSAggregationFailed !String
  deriving stock (Eq, Show, Generic)
  deriving anyclass (NFData)

-- | Build a 'LeiosCert' from the contributions of committee members.
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
--   * Range-checks each 'VoterId' against the committee.
--   * Encodes the bitfield over the committee and aggregates the input
--     signatures.
--
-- This is the only way to construct a 'LeiosCert' from outside the package;
-- the bitfield layout is an internal wire-format detail.
aggregateLeiosCert ::
  Committee ->
  Map VoterId LeiosSignature ->
  Either AggregationError LeiosCert
aggregateLeiosCert committee contributions = do
  let n = committeeSize committee
      entries = Map.toAscList contributions
  case [v | (v, _) <- entries, fromIntegral (voterIndex v) >= n] of
    v : _ -> Left (VoterIdOutOfBounds v)
    [] -> pure ()
  aggSig <-
    case aggregateSigsDSIGN (map snd entries) of
      Left e -> Left (BLSAggregationFailed e)
      Right s -> Right s
  pure
    LeiosCert
      { signers = mkBitField n (Map.keysSet contributions)
      , aggregatedSignature = aggSig
      }

-- ** Verification

data VerificationError
  = -- | 'signers' bitfield is longer than @⌈committeeSize/8⌉@ bytes.
    MalformedSigners
  | -- | The aggregate-BLS verification failed (wrong message, tampered
    -- signature, or a bitfield/aggregate mismatch).
    InvalidSignature
  | -- | Sum of signers' weights is below the required threshold.
    InsufficientWeight {got :: !Weight, required :: !Weight}
  deriving stock (Eq, Show, Generic)
  deriving anyclass (NFData)

-- | Verify a 'LeiosCert' against a 'Committee', a weight threshold, and the
-- message the signers were supposed to have signed.
--
-- == Caller obligations
--
-- Every voter in the 'Committee' must have had its BLS proof-of-possession
-- verified beforehand (when the committee was selected). 'verifyLeiosCert'
-- uses 'uncheckedAggregateVerKeysDSIGN' and does not re-check PoPs; passing
-- in an unchecked committee breaks the security of the aggregate signature.
--
-- == What this function does
--
--   1. Decodes the 'signers' bitfield to the list of contributing voter
--      indices, rejecting an oversized bitfield with
--      'MalformedSigners'.
--   2. Sums those voters' weights from the committee; short-circuits with
--      'InsufficientWeight' if the sum is below the threshold,
--      which avoids the BLS pairing when the bitfield can't reach quorum on
--      its own.
--   3. Aggregates the contributing verification keys and verifies the
--      certificate's 'aggregatedSignature' against that aggregate key over
--      @msg@.
verifyLeiosCert ::
  SignableRepresentation msg =>
  Committee ->
  -- | Minimum signer weight required to accept the cert.
  Weight ->
  -- | The message the signers signed.
  msg ->
  LeiosCert ->
  -- | Total weight of the contributing signers on success.
  Either VerificationError Weight
verifyLeiosCert committee required msg cert = do
  let voters = committeeVoters committee
      n = V.length voters
  signers <-
    maybe (Left MalformedSigners) Right $
      bitFieldMembers n cert.signers
  let idxs = [fromIntegral (voterIndex v) | v <- Set.toAscList signers]
  (got, vks) <- foldlM (accumSigner voters) (0, []) idxs
  when (got < required) $
    Left InsufficientWeight {got, required}
  aggVk <-
    case uncheckedAggregateVerKeysDSIGN (reverse vks) of
      Left _ -> Left InvalidSignature
      Right k -> Right k
  case verifyDSIGN leiosSignContext aggVk msg cert.aggregatedSignature of
    Left _ -> Left InvalidSignature
    Right () -> Right got
  where
    -- The bitfield decoder already enforced @i < n@; if the committee is
    -- shorter than the decoder's idea of @n@ we treat it as a malformed cert.
    accumSigner voters (w, ks) i = case voters V.!? i of
      Nothing -> Left MalformedSigners
      Just (w', vk) -> Right (w + w', vk : ks)

-- * Internal

-- $internal
--
-- These definitions back the wire-format @signers@ field of 'LeiosCert' and
-- are exported only as an escape hatch for debugging, tooling, and
-- adversarial testing. Production code should not need to touch them
-- directly: producers go through 'aggregateLeiosCert' and consumers through
-- 'verifyLeiosCert', and the CBOR codecs handle on-wire transport.

-- | The @signers@ bitfield of a 'LeiosCert': a @⌈committeeSize\/8⌉@-byte
-- MSB-first packed-bits representation of which committee voters contributed
-- to the aggregate signature.
--
-- A 'newtype' wrapper around 'ByteArray' so type signatures throughout the
-- aggregate / verify path say what they're working on, and so the on-wire
-- form cannot be accidentally confused with arbitrary @bytes@.
newtype BitField = BitField {bitFieldBytes :: ByteArray}
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData)
  deriving (NoThunks) via OnlyCheckWhnfNamed "BitField" BitField

-- | Project the raw byte payload of a 'BitField' as a strict 'BS.ByteString'.
-- O(1) — the underlying 'ByteArray' is reinterpreted via 'ShortByteString'.
bitFieldToBytes :: BitField -> BS.ByteString
bitFieldToBytes (BitField (ByteArray ba#)) = SBS.fromShort (SBS ba#)

-- | Wrap a strict 'BS.ByteString' as a 'BitField'. O(1) on the wire-level
-- byte payload (no copy beyond 'ShortByteString' construction).
bitFieldFromBytes :: BS.ByteString -> BitField
bitFieldFromBytes bs = case SBS.toShort bs of
  SBS ba# -> BitField (ByteArray ba#)

-- | Build the @⌈n\/8⌉@-byte MSB-first 'BitField' for a committee of size @n@.
-- Members at or past the committee bound are silently dropped (the producer
-- should never pass any; 'aggregateLeiosCert' range-checks separately and
-- raises 'VoterIdOutOfBounds').
mkBitField :: Int -> Set VoterId -> BitField
mkBitField n members =
  bitFieldFromBytes $ BS.pack [byteFor b | b <- [0 .. expectedBytes - 1]]
  where
    expectedBytes = (n + 7) `div` 8
    isSet b bitIx =
      Set.member (VoterId (fromIntegral (b * 8 + bitIx))) members
        && b * 8 + bitIx < n
    byteFor b =
      foldl'
        (\acc bitIx -> if isSet b bitIx then setBit acc (7 - bitIx) else acc)
        (0 :: Word8)
        [0 .. 7]

-- | The voter ids whose bit is set in the 'BitField', interpreting it against
-- a committee of size @n@. Returns 'Nothing' if the underlying byte payload
-- is strictly longer than @⌈n\/8⌉@ bytes (malformed certificate); a shorter
-- payload is accepted as if right-padded with zero bytes.
bitFieldMembers :: Int -> BitField -> Maybe (Set VoterId)
bitFieldMembers n bf
  | BS.length bs > expectedBytes = Nothing
  | otherwise = Just $ Set.fromList members
  where
    bs = bitFieldToBytes bf
    expectedBytes = (n + 7) `div` 8
    members =
      [ VoterId (fromIntegral globalIx)
      | (byteIx, byte) <- zip [0 ..] (BS.unpack bs)
      , bitIx <- [0 .. 7]
      , let globalIx = byteIx * 8 + bitIx
      , globalIx < n
      , testBit byte (7 - bitIx)
      ]
