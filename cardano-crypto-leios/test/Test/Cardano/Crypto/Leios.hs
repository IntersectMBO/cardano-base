{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Crypto.Leios (spec, exampleCert) where

import qualified Cardano.Binary as CBOR
import Cardano.Crypto.DSIGN (
  DSIGNAlgorithm (deriveVerKeyDSIGN),
  encodeSigDSIGN,
  genKeyDSIGN,
  seedSizeDSIGN,
  signDSIGN,
 )
import Cardano.Crypto.Leios (
  AggregationError (..),
  Committee (..),
  LeiosCert (..),
  LeiosDSIGN,
  LeiosSignature,
  LeiosSigningKey,
  LeiosVoter (..),
  VerificationError (..),
  VoterId (..),
  Weight,
  aggregateLeiosCert,
  decodeLeiosCert,
  decodeVoterId,
  encodeBitField,
  encodeLeiosCert,
  encodeVoterId,
  getVoterId,
  leiosSignContext,
  resolveVoter,
  verifyLeiosCert,
 )
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Codec.CBOR.Encoding (Encoding, encodeBreak, encodeListLenIndef)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import Data.Foldable (toList)
import Data.List.NonEmpty (NonEmpty (..), fromList)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Proxy (Proxy (Proxy))
import qualified Data.Vector.Strict as V
import Data.Word (Word16, Word8)
import Test.Cardano.Base.Bytes (genByteString)
import Test.Cardano.Crypto.Leios.Gen (genLeiosCert)
import Test.Hspec (Spec, context, describe, it)
import Test.Hspec.Golden (Golden (..))
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (
  Property,
  chooseInt,
  counterexample,
  forAll,
  (===),
 )
import qualified Test.QuickCheck as QC

spec :: Spec
spec = do
  describe "LeiosCert" $ do
    prop "round-trips through CBOR" prop_roundtrip_LeiosCert
    prop "decodes indefinite-length encoding" prop_decode_indefinite_LeiosCert
    it "matches golden encoding" $
      goldenEncoding "test/golden/LeiosCert" encodeLeiosCert exampleCert

    describe "aggregateLeiosCert" $ do
      prop "rejects an out-of-range VoterId" prop_aggregateLeiosCert_rejects_out_of_range
      prop "rejects empty contributions" prop_aggregateLeiosCert_rejects_empty

    describe "verifyLeiosCert" $ do
      context "with a valid certificate" $ do
        prop "accepts a full-committee aggregation" prop_verifyLeiosCert_accepts_aggregated
        prop "accepts a subset of signers above threshold" prop_verifyLeiosCert_accepts_subset
      context "with an invalid certificate" $ do
        prop "rejects a wrong message" prop_verifyLeiosCert_rejects_wrong_message
        prop "rejects when total weight is below threshold" prop_verifyLeiosCert_rejects_below_threshold
        prop "rejects a bitfield wider than the committee" prop_verifyLeiosCert_rejects_oversized_signers
        prop "rejects a tampered bitfield" prop_verifyLeiosCert_rejects_tampered_bitfield

  describe "VoterId" $ do
    prop "round-trips through CBOR" prop_roundtrip_VoterId
    it "matches golden encoding" $
      goldenEncoding "test/golden/VoterId" encodeVoterId exampleVoterId

  describe "Committee" $ do
    prop "getVoterId and resolveVoter agree on verification keys" prop_resolveVoter_getVoterId_inverse
    prop "getVoterId returns the first matching index" prop_getVoterId_returns_first_index

-- * CBOR roundtrip / golden

prop_roundtrip_LeiosCert :: Property
prop_roundtrip_LeiosCert = forAll genLeiosCert $ \cert ->
  let bs = CBOR.serialize (encodeLeiosCert cert)
   in CBOR.decodeFullDecoder "LeiosCert" decodeLeiosCert bs === Right cert

-- | The decoder must accept indefinite-length encodings of the outer
-- 2-element array, not just the canonical definite-length form.
prop_decode_indefinite_LeiosCert :: Property
prop_decode_indefinite_LeiosCert = forAll genLeiosCert $ \cert ->
  let indef =
        encodeListLenIndef
          <> encodeBitField (signers cert)
          <> encodeSigDSIGN (aggregatedSignature cert)
          <> encodeBreak
   in CBOR.decodeFullDecoder "LeiosCert" decodeLeiosCert (CBOR.serialize indef)
        === Right cert

-- | Pin the byte-for-byte CBOR encoding of a value to a golden file using
-- 'hspec-golden'. Failure diffs are rendered as base16 hex. Decode
-- round-trip of arbitrary values is covered by the matching @roundtrip_@
-- property; this only locks the encoding shape.
goldenEncoding :: FilePath -> (a -> Encoding) -> a -> Golden BSL.ByteString
goldenEncoding path enc value =
  Golden
    { output = CBOR.serialize (enc value)
    , encodePretty = BS8.unpack . BS16.encode . BSL.toStrict
    , writeToFile = BSL.writeFile
    , readFromFile = BSL.readFile
    , goldenFile = path
    , actualFile = Nothing
    , failFirstTime = False
    }

exampleCert :: LeiosCert
exampleCert = case aggregateLeiosCert committee contributions of
  Right c -> c
  Left e -> error ("exampleCert: aggregation failed: " <> show e)
  where
    (sks, committee) = fixedCommittee 1000
    msg = "leios-golden-message" :: BS.ByteString
    contributions = signContribs msg (zip [0 ..] (toList sks))

-- * VoterId CBOR / committee lookup

prop_roundtrip_VoterId :: Property
prop_roundtrip_VoterId = forAll (VoterId <$> QC.arbitrary) $ \vid ->
  let bs = CBOR.serialize (encodeVoterId vid)
   in CBOR.decodeFullDecoder "VoterId" decodeVoterId bs === Right vid

exampleVoterId :: VoterId
exampleVoterId = VoterId 0xABCD

-- | 'getVoterId' and 'resolveVoter' are mutual inverses on the verification
-- key projection: for any voter in the committee, looking up its 'VoterId'
-- via its key and resolving back to a 'LeiosVoter' yields the same key.
prop_resolveVoter_getVoterId_inverse :: Property
prop_resolveVoter_getVoterId_inverse =
  forAll genN $ \n ->
    let (_, committee) = fixedCommittee n
        voters = V.toList committee.committeeVoters
     in QC.conjoin
          [ counterexample ("voter index " <> show i) $
              case getVoterId (voterVKey voter) committee of
                Nothing -> QC.property False
                Just vid ->
                  case resolveVoter committee vid of
                    Nothing -> QC.property False
                    Just voter' -> voterVKey voter' === voterVKey voter
          | (i :: Int, voter) <- zip [0 ..] voters
          ]

-- | When the committee carries duplicate verification keys, 'getVoterId'
-- returns the smallest matching index. We don't deduplicate committees
-- internally; downstream selection is expected to.
prop_getVoterId_returns_first_index :: Property
prop_getVoterId_returns_first_index =
  forAll genN $ \n ->
    let (_, committee) = fixedCommittee n
        voters = V.toList committee.committeeVoters
     in QC.conjoin
          [ counterexample ("first occurrence at " <> show i) $
              getVoterId (voterVKey voter) duped
                === Just (VoterId (fromIntegral i))
          | let duped =
                  Committee
                    (committee.committeeVoters <> committee.committeeVoters)
          , (i :: Int, voter) <- zip [0 ..] voters
          ]

-- * aggregate / verify

-- | Equal-weighted committee of @n@ voters derived from a fixed seed pattern.
-- Returns the signing keys alongside the committee so tests can produce
-- contributions. The 'NonEmpty' return reflects the @n ≥ 1@ precondition and
-- gives tests a total 'head' for "any-one-signer" cases.
fixedCommittee :: Int -> (NonEmpty LeiosSigningKey, Committee)
fixedCommittee n =
  ( sks
  , Committee
      ( V.fromList
          [LeiosVoter (1 / fromIntegral @Int @Weight n) (deriveVerKeyDSIGN sk) | sk <- toList sks]
      )
  )
  where
    seedLen = fromIntegral @Word @Int (seedSizeDSIGN (Proxy @LeiosDSIGN))
    sks =
      fromList
        [ genKeyDSIGN @LeiosDSIGN (mkSeedFromBytes (BS.replicate seedLen (fromIntegral @Int @Word8 i)))
        | i <- [1 .. max 1 n]
        ]

-- | Default committee size range exercised by the verify/aggregate properties.
-- 1 ≤ n ≤ 16 covers single-voter (n=1), single-byte bitfield (n ≤ 8) and the
-- two-byte boundary (n=9..16).
genN :: QC.Gen Int
genN = chooseInt (1, 16)

genMsg :: QC.Gen BS.ByteString
genMsg = chooseInt (0, 64) >>= genByteString

-- | Sign @msg@ with each of the given keys and pack them into a 'Map' keyed
-- by 'VoterId', matching the input shape of 'aggregateLeiosCert'.
signContribs :: BS.ByteString -> [(Int, LeiosSigningKey)] -> Map VoterId LeiosSignature
signContribs msg pairs =
  Map.fromList
    [(VoterId (fromIntegral @Int @Word16 i), signDSIGN leiosSignContext msg sk) | (i, sk) <- pairs]

-- | Aggregate or fail the property with the error.
aggregateOrFail ::
  Committee ->
  Map VoterId LeiosSignature ->
  (LeiosCert -> Property) ->
  Property
aggregateOrFail committee contributions k = case aggregateLeiosCert committee contributions of
  Right c -> k c
  Left e -> counterexample (show e) (QC.property False)

-- | All committee members sign the same message; the resulting cert verifies
-- against that committee, threshold and message, and reports full weight.
prop_verifyLeiosCert_accepts_aggregated :: Property
prop_verifyLeiosCert_accepts_aggregated = forAll genN $ \n -> forAll genMsg $ \msg ->
  let (sks, committee) = fixedCommittee n
      contributions = signContribs msg (zip [0 :: Int ..] (toList sks))
   in aggregateOrFail committee contributions $ \cert ->
        verifyLeiosCert committee 1 msg cert === Right 1

-- | An arbitrary subset of @k@ committee members signs the same message.
-- The cert must verify against any threshold @≤ k/n@ and report weight
-- @k/n@. Catches bugs where the verifier doesn't actually sum the correct
-- subset of weights.
prop_verifyLeiosCert_accepts_subset :: Property
prop_verifyLeiosCert_accepts_subset = forAll genN $ \n ->
  forAll (chooseInt (1, n)) $ \k ->
    forAll genMsg $ \msg ->
      let (sks, committee) = fixedCommittee n
          contributions = signContribs msg (take k (zip [0 :: Int ..] (toList sks)))
          expectedWeight = fromIntegral @Int @Weight k / fromIntegral @Int @Weight n
       in aggregateOrFail committee contributions $ \cert ->
            verifyLeiosCert committee expectedWeight msg cert === Right expectedWeight

-- | A cert built over message @m1@ must not verify against message @m2@.
prop_verifyLeiosCert_rejects_wrong_message :: Property
prop_verifyLeiosCert_rejects_wrong_message = forAll genN $ \n ->
  let (sks, committee) = fixedCommittee n
      m1 = "leios-message-one" :: BS.ByteString
      m2 = "leios-message-two" :: BS.ByteString
      contributions = signContribs m1 (zip [0 :: Int ..] (toList sks))
   in aggregateOrFail committee contributions $ \cert ->
        verifyLeiosCert committee 1 m2 cert === Left InvalidSignature

-- | A cert whose signers' summed weight is below the threshold must be
-- rejected with 'InsufficientWeight', without ever performing the BLS
-- pairing. Uses n ≥ 2 so a single signer's weight @1/n@ is strictly less
-- than the full-weight threshold.
prop_verifyLeiosCert_rejects_below_threshold :: Property
prop_verifyLeiosCert_rejects_below_threshold = forAll (chooseInt (2, 16)) $ \n ->
  let (sk0 :| _, committee) = fixedCommittee n
      msg = "leios-quorum-test" :: BS.ByteString
      contributions = signContribs msg [(0, sk0)]
   in aggregateOrFail committee contributions $ \cert ->
        verifyLeiosCert committee 1 msg cert
          === Left (InsufficientWeight (1 / fromIntegral @Int @Weight n))

-- | A 'signers' bitfield whose byte length differs from @⌈n/8⌉@ must be
-- rejected as 'MalformedSigners' before any signature work is done. We
-- build a cert against committee A and verify against committee B whose
-- size sits in the next byte bucket (A's bitfield is one byte short of
-- what B expects).
prop_verifyLeiosCert_rejects_oversized_signers :: Property
prop_verifyLeiosCert_rejects_oversized_signers = forAll genN $ \n ->
  let (sks, committeeA) = fixedCommittee n
      (_, committeeB) = fixedCommittee (n + 8)
      msg = "leios-malformed-test" :: BS.ByteString
      contributions = signContribs msg (zip [0 :: Int ..] (toList sks))
   in aggregateOrFail committeeA contributions $ \cert ->
        verifyLeiosCert committeeB 1 msg cert === Left MalformedSigners

-- | A cert whose 'signers' bitfield disagrees with its 'aggregatedSignature'
-- must be rejected with 'InvalidSignature'. We construct two real certs
-- against the same committee (voter 0 alone, then voters 0+1), then splice
-- certA's signature with certB's bitfield. The bitfield claims voter 1 also
-- signed but the aggregate doesn't include voter 1's signature, so the BLS
-- pairing fails. Uses n ≥ 2 so there are at least two voters to splice.
prop_verifyLeiosCert_rejects_tampered_bitfield :: Property
prop_verifyLeiosCert_rejects_tampered_bitfield = forAll (chooseInt (2, 16)) $ \n ->
  let (sks, committee) = fixedCommittee n
      (sks0, sks1) = case sks of
        s0 :| (s1 : _) -> (s0, s1)
        _ -> error "prop_verifyLeiosCert_rejects_tampered_bitfield: n >= 2 invariant violated"
      msg = "leios-tamper-test" :: BS.ByteString
      contribsAlone = signContribs msg [(0, sks0)]
      contribsPair = signContribs msg [(0, sks0), (1, sks1)]
   in aggregateOrFail committee contribsAlone $ \certA ->
        aggregateOrFail committee contribsPair $ \certB ->
          let tampered = certA {signers = certB.signers}
           in -- Threshold is below the tampered weight 2/n so we exercise the BLS
              -- pairing failure, not the short-circuit.
              verifyLeiosCert committee (1 / fromIntegral @Int @Weight n) msg tampered
                === Left InvalidSignature

-- | A 'VoterId' past the committee bound is rejected at aggregation time.
prop_aggregateLeiosCert_rejects_out_of_range :: Property
prop_aggregateLeiosCert_rejects_out_of_range = forAll genN $ \n ->
  forAll (chooseInt (n, n + 100)) $ \badIdx ->
    let (sk0 :| _, committee) = fixedCommittee n
        msg = "x" :: BS.ByteString
        bad = VoterId (fromIntegral @Int @Word16 badIdx)
        contributions = Map.singleton bad (signDSIGN leiosSignContext msg sk0)
     in aggregateLeiosCert committee contributions === Left (VoterIdsOutOfBounds (bad :| []))

-- | Aggregating an empty contribution set must fail: the underlying BLS
-- 'aggregateSigsDSIGN' rejects the empty input, which surfaces as
-- 'BLSAggregationFailed'. We don't pin the exact message string.
prop_aggregateLeiosCert_rejects_empty :: Property
prop_aggregateLeiosCert_rejects_empty = forAll genN $ \n ->
  let (_, committee) = fixedCommittee n
   in case aggregateLeiosCert committee Map.empty of
        Left BLSAggregationFailed {} -> QC.property True
        other -> counterexample (show other) (QC.property False)
