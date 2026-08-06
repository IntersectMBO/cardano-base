{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Crypto.Leios (spec, exampleCert) where

import Cardano.Crypto.DSIGN (
  DSIGNAlgorithm (deriveVerKeyDSIGN),
  createPossessionProofDSIGN,
  genKeyDSIGN,
  seedSizeDSIGN,
  signDSIGN,
 )
import Cardano.Crypto.Leios (
  AggregationError (..),
  LeiosCert (..),
  LeiosCommittee (..),
  LeiosDSIGN,
  LeiosSignature,
  LeiosSigningKey,
  LeiosSeat (..),
  LeiosSeatId (..),
  VerificationError (..),
  Weight,
  aggregateLeiosCert,
  getLeiosSeatId,
  leiosSignContext,
  mkLeiosCommittee,
  resolveLeiosSeat,
  verifyLeiosCert,
 )
import Cardano.Crypto.Seed (mkSeedFromBytes)
import qualified Data.ByteString as BS
import Data.Foldable (toList)
import Data.List.NonEmpty (NonEmpty (..), fromList)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe.Strict (StrictMaybe (..), isSJust)
import Data.Proxy (Proxy (Proxy))
import qualified Data.Set as Set
import qualified Data.Vector.Strict as V
import Data.Word (Word16, Word8)
import Test.Cardano.Base.Bytes (genByteString)
import Test.Hspec (Spec, context, describe)
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (
  Property,
  chooseInt,
  counterexample,
  forAll,
  once,
  sublistOf,
  (.&&.),
  (===),
 )
import qualified Test.QuickCheck as QC

spec :: Spec
spec = do
  describe "LeiosCert" $ do
    describe "aggregateLeiosCert" $ do
      prop "rejects an out-of-range LeiosSeatId" prop_aggregateLeiosCert_rejects_out_of_range
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
        prop "rejects a bit set for a seat without a key" prop_verifyLeiosCert_rejects_keyless_signer

  describe "LeiosCommittee" $ do
    prop
      "getLeiosSeatId and resolveLeiosSeat agree on verification keys"
      prop_resolveVoter_getVoterId_inverse
    prop "getLeiosSeatId returns the first matching index" prop_getVoterId_returns_first_index

    describe "mkLeiosCommittee" $ do
      prop
        "keeps every seat; only pools with a registered key carry one"
        prop_committee_reflects_registered_keys
      prop
        "an invalid proof of possession yields a keyless seat"
        prop_invalid_pop_yields_keyless_seat

exampleCert :: LeiosCert
exampleCert = case aggregateLeiosCert committee contributions of
  Right c -> c
  Left e -> error ("exampleCert: aggregation failed: " <> show e)
  where
    (sks, committee) = fixedCommittee 1000
    msg = "leios-golden-message" :: BS.ByteString
    contributions = signContribs msg (zip [0 ..] (toList sks))

-- * LeiosSeatId committee lookup

-- | 'getLeiosSeatId' and 'resolveLeiosSeat' are mutual inverses on the verification
-- key projection: for any voter in the committee, looking up its 'LeiosSeatId'
-- via its key and resolving back to a 'LeiosSeat' yields the same key.
prop_resolveVoter_getVoterId_inverse :: Property
prop_resolveVoter_getVoterId_inverse =
  forAll genN $ \n ->
    let (_, committee) = fixedCommittee n
        voters = V.toList committee.leiosCommitteeSeats
     in QC.conjoin
          [ counterexample ("voter index " <> show i) $
              case seatVKey voter of
                SNothing -> counterexample "fixedCommittee seat unexpectedly keyless" (QC.property False)
                SJust vk ->
                  case getLeiosSeatId vk committee of
                    Nothing -> QC.property False
                    Just vid ->
                      case resolveLeiosSeat committee vid of
                        Nothing -> QC.property False
                        Just voter' -> seatVKey voter' === seatVKey voter
          | (i :: Int, voter) <- zip [0 ..] voters
          ]

-- | When the committee carries duplicate verification keys, 'getLeiosSeatId'
-- returns the smallest matching index. We don't deduplicate committees
-- internally; downstream selection is expected to.
prop_getVoterId_returns_first_index :: Property
prop_getVoterId_returns_first_index =
  forAll genN $ \n ->
    let (_, committee) = fixedCommittee n
        voters = V.toList committee.leiosCommitteeSeats
     in QC.conjoin
          [ counterexample ("first occurrence at " <> show i) $
              case seatVKey voter of
                SNothing -> counterexample "fixedCommittee seat unexpectedly keyless" (QC.property False)
                SJust vk -> getLeiosSeatId vk duped === Just (LeiosSeatId (fromIntegral i))
          | let duped =
                  UnsafeLeiosCommittee
                    (committee.leiosCommitteeSeats <> committee.leiosCommitteeSeats)
          , (i :: Int, voter) <- zip [0 ..] voters
          ]

-- * aggregate / verify

-- | Equal-weighted committee of @n@ voters derived from a fixed seed pattern.
-- Returns the signing keys alongside the committee so tests can produce
-- contributions. The 'NonEmpty' return reflects the @n ≥ 1@ precondition and
-- gives tests a total 'head' for "any-one-signer" cases.
fixedCommittee :: Int -> (NonEmpty LeiosSigningKey, LeiosCommittee)
fixedCommittee n =
  ( sks
  , UnsafeLeiosCommittee
      ( V.fromList
          [LeiosSeat (1 / fromIntegral @Int @Weight n) (SJust (deriveVerKeyDSIGN sk)) | sk <- toList sks]
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
-- by 'LeiosSeatId', matching the input shape of 'aggregateLeiosCert'.
signContribs :: BS.ByteString -> [(Int, LeiosSigningKey)] -> Map LeiosSeatId LeiosSignature
signContribs msg pairs =
  Map.fromList
    [(LeiosSeatId (fromIntegral @Int @Word16 i), signDSIGN leiosSignContext msg sk) | (i, sk) <- pairs]

-- | Aggregate or fail the property with the error.
aggregateOrFail ::
  LeiosCommittee ->
  Map LeiosSeatId LeiosSignature ->
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

-- | A cert whose 'leiosCertSigners' bitfield disagrees with its 'leiosCertSignature'
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
          let tampered = certA {leiosCertSigners = certB.leiosCertSigners}
           in -- Threshold is below the tampered weight 2/n so we exercise the BLS
              -- pairing failure, not the short-circuit.
              verifyLeiosCert committee (1 / fromIntegral @Int @Weight n) msg tampered
                === Left InvalidSignature

-- | A 'LeiosSeatId' past the committee bound is rejected at aggregation time.
prop_aggregateLeiosCert_rejects_out_of_range :: Property
prop_aggregateLeiosCert_rejects_out_of_range = forAll genN $ \n ->
  forAll (chooseInt (n, n + 100)) $ \badIdx ->
    let (sk0 :| _, committee) = fixedCommittee n
        msg = "x" :: BS.ByteString
        bad = LeiosSeatId (fromIntegral @Int @Word16 badIdx)
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

-- * Committee derived from the stake distribution

-- | A deterministic signing key from a single seed byte.
skFromByte :: Word8 -> LeiosSigningKey
skFromByte b = genKeyDSIGN @LeiosDSIGN (mkSeedFromBytes (BS.replicate seedLen b))
  where
    seedLen = fromIntegral @Word @Int (seedSizeDSIGN (Proxy @LeiosDSIGN))

-- | Build a committee from a list of seats, each with equal weight @1/n@. A
-- 'Just' seat carries a real key and a valid proof of possession; a 'Nothing'
-- seat is a pool that has not (yet) registered a Leios key. This mirrors the
-- consensus path: the committee is the whole stake distribution, keyed or not.
mkMixedCommittee :: [Maybe LeiosSigningKey] -> LeiosCommittee
mkMixedCommittee seats =
  mkLeiosCommittee . V.fromList $
    [(maybe SNothing (SJust . keyPop) mSk, weight) | mSk <- seats]
  where
    weight = 1 / fromIntegral @Int @Weight (length seats)
    keyPop sk = (deriveVerKeyDSIGN sk, createPossessionProofDSIGN leiosSignContext sk)

-- | Every pool in the stake distribution gets a seat with its stake weight,
-- whether or not it registered a key. Seats for pools with a registered key
-- carry it ('Just'); the rest are keyless ('Nothing'). Crucially the seat
-- count and the weights are independent of which pools have keys, so voter
-- indices are stable as keys come and go.
prop_committee_reflects_registered_keys :: Property
prop_committee_reflects_registered_keys = forAll genN $ \n ->
  forAll (sublistOf [0 .. n - 1]) $ \keyedList ->
    let keyed = Set.fromList keyedList
        seats =
          [ if i `Set.member` keyed
              then Just (skFromByte (fromIntegral @Int @Word8 (i + 1)))
              else Nothing
          | i <- [0 .. n - 1]
          ]
        committee = mkMixedCommittee seats
        voters = V.toList committee.leiosCommitteeSeats
     in counterexample ("keyed = " <> show keyedList) $
          (length voters === n)
            .&&. QC.conjoin
              [ counterexample ("seat " <> show i) $
                  isSJust (seatVKey v) === (i `Set.member` keyed)
              | (i :: Int, v) <- zip [0 ..] voters
              ]
            .&&. QC.conjoin
              [ counterexample ("weight " <> show i) $
                  seatWeight v === 1 / fromIntegral @Int @Weight n
              | (i :: Int, v) <- zip [0 ..] voters
              ]

-- | A seat whose registered key comes with a proof of possession that does
-- not verify is admitted to the committee but stripped of its key, exactly as
-- if the pool had never registered one. Committee construction never fails on
-- a bad proof: one misbehaving pool must not take down the whole committee
-- (and the ledger POOL rule rejects such registrations upstream anyway).
prop_invalid_pop_yields_keyless_seat :: Property
prop_invalid_pop_yields_keyless_seat = once $
  let sk0 = skFromByte 1
      sk1 = skFromByte 2
      vk0 = deriveVerKeyDSIGN sk0
      vk1 = deriveVerKeyDSIGN sk1
      half = 1 / 2 :: Weight
      -- vk1 paired with a proof of possession for sk0's secret: does not verify.
      forgedPoP = createPossessionProofDSIGN leiosSignContext sk0
      committee =
        mkLeiosCommittee $
          V.fromList
            [ (SJust (vk0, createPossessionProofDSIGN leiosSignContext sk0), half)
            , (SJust (vk1, forgedPoP), half)
            ]
   in case V.toList committee.leiosCommitteeSeats of
        [v0, v1] ->
          counterexample (show committee) $
            seatVKey v0 === SJust vk0 .&&. seatVKey v1 === SNothing
        _ -> counterexample "expected exactly two seats" (QC.property False)

-- | The forgery this whole design turns on: a certificate must not be able to
-- borrow weight from keyless seats. Seat 0 (keyed) signs alone — below the
-- full-weight threshold. We splice in a bitfield that additionally sets the
-- keyless seat 1, which would push the summed weight to the threshold. The
-- verifier must reject on the keyless seat *before* counting its weight or
-- touching the BLS pairing, so the padded weight never helps.
prop_verifyLeiosCert_rejects_keyless_signer :: Property
prop_verifyLeiosCert_rejects_keyless_signer = forAll genMsg $ \msg ->
  let sk0 = skFromByte 1
      sk1 = skFromByte 2
      mixed = mkMixedCommittee [Just sk0, Nothing]
      allKeyed = mkMixedCommittee [Just sk0, Just sk1]
      sig0 = signDSIGN leiosSignContext msg sk0
      sig1 = signDSIGN leiosSignContext msg sk1
      certAlone =
        either (error . show) id $
          aggregateLeiosCert mixed (Map.singleton (LeiosSeatId 0) sig0)
      -- A well-formed cert on the all-keyed committee whose bitfield sets {0,1}.
      certPair =
        either (error . show) id $
          aggregateLeiosCert
            allKeyed
            (Map.fromList [(LeiosSeatId 0, sig0), (LeiosSeatId 1, sig1)])
      tampered = certAlone {leiosCertSigners = certPair.leiosCertSigners}
   in verifyLeiosCert mixed 1 msg tampered === Left (SignerWithoutKey (LeiosSeatId 1 :| []))
