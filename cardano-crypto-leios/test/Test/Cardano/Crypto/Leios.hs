{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Crypto.Leios (spec, exampleCert) where

import Cardano.Crypto.DSIGN (
  signDSIGN,
 )
import Cardano.Crypto.Leios (
  AggregationError (..),
  BitField (..),
  LeiosCert (..),
  LeiosCommittee (..),
  LeiosSeat (..),
  LeiosSeatId (..),
  LeiosSignature,
  LeiosSigningKey,
  VerificationError (..),
  Weight,
  aggregateLeiosCert,
  getLeiosSeatId,
  maxLeiosCommitteeSize,
  resolveLeiosSeat,
  verifyLeiosCert,
 )
import qualified Data.ByteString as BS
import Data.Foldable (toList)
import Data.List (uncons)
import Data.List.NonEmpty (NonEmpty (..))
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe.Strict (StrictMaybe (..), isSJust)
import Data.Primitive.ByteArray (byteArrayFromList, sizeofByteArray)
import qualified Data.Vector.Strict as V
import Data.Word (Word16, Word8)
import Test.Cardano.Base.Bytes (genByteString)
import Test.Cardano.Crypto.Leios.Gen (
  TestCommittee (..),
  TestSeatType (..),
  genCommittee,
  genLeiosSigningKey,
  genTestSeats,
  generateWith,
  mkCommitteeFromTestSeats,
 )
import Test.Hspec (Spec, context, describe)
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (
  Gen,
  Property,
  chooseInt,
  conjoin,
  counterexample,
  discard,
  forAll,
  forAllShrink,
  genericShrink,
  property,
  (.&&.),
  (===),
 )

spec :: Spec
spec = do
  describe "LeiosCommittee" $ do
    prop "mkLeiosCommittee checks proof of possession" prop_seats_without_valid_key_are_keyless
    prop "getLeiosSeatId and resolveLeiosSeat are inverse" prop_resolveVoter_getVoterId_inverse
    prop "getLeiosSeatId returns the first matching index" prop_getVoterId_returns_first_index

  describe "LeiosCert" $ do
    describe "aggregateLeiosCert" $ do
      prop "rejects an out-of-range LeiosSeatId" prop_aggregateLeiosCert_rejects_out_of_range
      prop "rejects empty contributions" prop_aggregateLeiosCert_rejects_empty
      prop
        "never builds a bitfield past what maxLeiosCommitteeSize needs"
        prop_aggregateLeiosCert_bitfield_fits_max_committee

    describe "verifyLeiosCert" $ do
      context "with a valid certificate" $ do
        prop "accepts a full-committee aggregation" prop_verifyLeiosCert_accepts_aggregated
        prop "accepts a subset of signers above threshold" prop_verifyLeiosCert_accepts_subset
      context "with an invalid certificate" $ do
        prop "rejects a wrong message" prop_verifyLeiosCert_rejects_wrong_message
        prop "rejects when total weight is below threshold" prop_verifyLeiosCert_rejects_below_threshold
        prop "rejects a bitfield wider than the committee" prop_verifyLeiosCert_rejects_oversized_signers
        prop
          "rejects a committee past maxLeiosCommitteeSize"
          prop_verifyLeiosCert_rejects_oversized_committee
        prop "rejects a tampered bitfield" prop_verifyLeiosCert_rejects_tampered_bitfield
        prop "rejects a bit set for a seat without a key" prop_verifyLeiosCert_rejects_keyless_signer

exampleCert :: LeiosCert
exampleCert = case aggregateLeiosCert committee contributions of
  Right c -> c
  Left e -> error ("exampleCert: aggregation failed: " <> show e)
  where
    (sks, committee) = mkCommitteeFromTestSeats (replicate 1000 (WithKey, 1 / 1000))
    msg = "leios-golden-message" :: BS.ByteString
    contributions = signContribs msg (zip [0 ..] (toList sks))

-- | 'getLeiosSeatId' and 'resolveLeiosSeat' are mutual inverses on the verification
-- key projection: for any voter in the committee, looking up its 'LeiosSeatId'
-- via its key and resolving back to a 'LeiosSeat' yields the same key.
prop_resolveVoter_getVoterId_inverse :: Property
prop_resolveVoter_getVoterId_inverse = property $ do
  TestCommittee {committee} <- genCommittee
  let voters = V.toList committee.leiosCommitteeSeats
  pure $
    conjoin
      [ counterexample ("voter index " <> show i) $
          case seatVKey voter of
            SNothing -> counterexample "genCommittee seat unexpectedly keyless" (property False)
            SJust vk ->
              case getLeiosSeatId vk committee of
                Nothing -> property False
                Just vid ->
                  case resolveLeiosSeat committee vid of
                    Nothing -> property False
                    Just voter' -> seatVKey voter' === seatVKey voter
      | (i :: Int, voter) <- zip [0 ..] voters
      ]

-- | When the committee carries duplicate verification keys, 'getLeiosSeatId'
-- returns the smallest matching index. We don't deduplicate committees
-- internally; downstream selection is expected to.
prop_getVoterId_returns_first_index :: Property
prop_getVoterId_returns_first_index = property $ do
  TestCommittee {committee} <- genCommittee
  let voters = V.toList committee.leiosCommitteeSeats
      duped = UnsafeLeiosCommittee (committee.leiosCommitteeSeats <> committee.leiosCommitteeSeats)
  pure $
    conjoin
      [ counterexample ("first occurrence at " <> show i) $
          case seatVKey voter of
            SNothing -> counterexample "genCommittee seat unexpectedly keyless" (property False)
            SJust vk -> getLeiosSeatId vk duped === Just (LeiosSeatId (fromIntegral i))
      | (i :: Int, voter) <- zip [0 ..] voters
      ]

-- | All committee members sign the same message; the resulting cert verifies
-- against that committee, threshold and message, and reports full weight.
prop_verifyLeiosCert_accepts_aggregated :: Property
prop_verifyLeiosCert_accepts_aggregated = property $ do
  TestCommittee {committee, allKeys} <- genCommittee
  msg <- genMsg
  let contributions = signContribs msg (zip [0 :: Int ..] allKeys)
  pure $
    aggregateOrFail committee contributions $ \cert ->
      verifyLeiosCert committee 1 msg cert === Right 1

-- | An arbitrary subset of @k@ committee members signs the same message.
-- The cert must verify against any threshold @≤ k/n@ and report weight
-- @k/n@. Catches bugs where the verifier doesn't actually sum the correct
-- subset of weights.
prop_verifyLeiosCert_accepts_subset :: Property
prop_verifyLeiosCert_accepts_subset = property $ do
  TestCommittee {committee, allKeys} <- genCommittee
  let n = length allKeys
  k <- chooseInt (1, n)
  msg <- genMsg
  let contributions = signContribs msg (take k (zip [0 :: Int ..] allKeys))
      expectedWeight = fromIntegral @Int @Weight k / fromIntegral @Int @Weight n
  pure $
    aggregateOrFail committee contributions $ \cert ->
      verifyLeiosCert committee expectedWeight msg cert === Right expectedWeight

-- | A cert built over message @m1@ must not verify against message @m2@.
prop_verifyLeiosCert_rejects_wrong_message :: Property
prop_verifyLeiosCert_rejects_wrong_message = property $ do
  TestCommittee {committee, allKeys} <- genCommittee
  let m1 = "leios-message-one" :: BS.ByteString
      m2 = "leios-message-two" :: BS.ByteString
      contributions = signContribs m1 (zip [0 :: Int ..] allKeys)
  pure $
    aggregateOrFail committee contributions $ \cert ->
      verifyLeiosCert committee 1 m2 cert === Left InvalidSignature

-- | A cert whose signers' summed weight is below the threshold must be
-- rejected with 'InsufficientWeight', without ever performing the BLS
-- pairing. Uses n ≥ 2 so a single signer's weight @1/n@ is strictly less
-- than the full-weight threshold.
prop_verifyLeiosCert_rejects_below_threshold :: Property
prop_verifyLeiosCert_rejects_below_threshold = property $ do
  n <- chooseInt (2, 16)
  let (sks, committee) = mkCommitteeFromTestSeats (replicate n (WithKey, 1 / fromIntegral n))
      sk0 = case sks of
        (s0 : _) -> s0
        _ -> error "prop_verifyLeiosCert_rejects_below_threshold: n >= 2 invariant violated"
      msg = "leios-quorum-test" :: BS.ByteString
      contributions = signContribs msg [(0, sk0)]
  pure $
    aggregateOrFail committee contributions $ \cert ->
      verifyLeiosCert committee 1 msg cert
        === Left (InsufficientWeight (1 / fromIntegral @Int @Weight n))

-- | A 'signers' bitfield whose byte length differs from @⌈n/8⌉@ must be
-- rejected as 'MalformedSigners' before any signature work is done. We
-- build a cert against committee A and verify against committee B whose
-- size sits in the next byte bucket (A's bitfield is one byte short of
-- what B expects).
prop_verifyLeiosCert_rejects_oversized_signers :: Property
prop_verifyLeiosCert_rejects_oversized_signers = property $ do
  TestCommittee {committee, allKeys} <- genCommittee
  let n = length allKeys
      (_, committeeB) = mkCommitteeFromTestSeats (replicate (n + 8) (WithKey, 1 / fromIntegral (n + 8)))
      msg = "leios-malformed-test" :: BS.ByteString
      contributions = signContribs msg (zip [0 :: Int ..] allKeys)
  pure $
    aggregateOrFail committee contributions $ \cert ->
      verifyLeiosCert committeeB 1 msg cert === Left MalformedSigners

-- | A committee past 'maxLeiosCommitteeSize' has seats whose index no longer
-- fits a 'LeiosSeatId', so a bit set for one of them would wrap onto a low seat
-- and borrow its key and weight. Verification must refuse the committee outright
-- rather than resolve any bit against it, and must say so as 'MalformedCommittee'
-- — 'MalformedSigners' would pin the blame on a bitfield that is above reproach.
prop_verifyLeiosCert_rejects_oversized_committee :: Property
prop_verifyLeiosCert_rejects_oversized_committee = property $ do
  n <- chooseInt (maxLeiosCommitteeSize + 1, maxLeiosCommitteeSize + 8)
  msg <- genMsg
  let committee = UnsafeLeiosCommittee $ V.replicate n (LeiosSeat 1 SNothing)
      -- Exactly the length this committee demands, so the bitfield is not what fails.
      signers = BitField $ byteArrayFromList (replicate ((n + 7) `div` 8) (0xff :: Word8))
      sig = signDSIGN () msg (genLeiosSigningKey `generateWith` n)
      cert = LeiosCert {leiosCertSigners = signers, leiosCertSignature = sig}
  pure . counterexample ("committee of " <> show n <> " seats") $
    verifyLeiosCert committee 1 msg cert === Left (MalformedCommittee n)

-- | A cert whose 'leiosCertSigners' bitfield disagrees with its 'leiosCertSignature'
-- must be rejected with 'InvalidSignature'. We construct two real certs
-- against the same committee (voter 0 alone, then voters 0+1), then splice
-- certA's signature with certB's bitfield. The bitfield claims voter 1 also
-- signed but the aggregate doesn't include voter 1's signature, so the BLS
-- pairing fails. Uses n ≥ 2 so there are at least two voters to splice.
prop_verifyLeiosCert_rejects_tampered_bitfield :: Property
prop_verifyLeiosCert_rejects_tampered_bitfield = property $ do
  n <- chooseInt (2, 16)
  let (sks, committee) = mkCommitteeFromTestSeats (replicate n (WithKey, 1 / fromIntegral n))
      (sks0, sks1) = case sks of
        (s0 : s1 : _) -> (s0, s1)
        _ -> error "prop_verifyLeiosCert_rejects_tampered_bitfield: n >= 2 invariant violated"
      msg = "leios-tamper-test" :: BS.ByteString
      contribsAlone = signContribs msg [(0, sks0)]
      contribsPair = signContribs msg [(0, sks0), (1, sks1)]
  pure $
    aggregateOrFail committee contribsAlone $ \certA ->
      aggregateOrFail committee contribsPair $ \certB ->
        let tampered = certA {leiosCertSigners = certB.leiosCertSigners}
         in -- Threshold is below the tampered weight 2/n so we exercise the BLS
            -- pairing failure, not the short-circuit.
            verifyLeiosCert committee (1 / fromIntegral @Int @Weight n) msg tampered
              === Left InvalidSignature

-- | A 'LeiosSeatId' past the committee bound is rejected at aggregation time.
prop_aggregateLeiosCert_rejects_out_of_range :: Property
prop_aggregateLeiosCert_rejects_out_of_range = property $ do
  TestCommittee {committee, allKeys} <- genCommittee
  (sk0, _) <- maybe discard pure $ uncons allKeys
  let n = length allKeys
  badIdx <- chooseInt (n, n + 100)
  let msg = "x" :: BS.ByteString
      bad = LeiosSeatId (fromIntegral @Int @Word16 badIdx)
      contributions = Map.singleton bad (signDSIGN () msg sk0)
  pure $ aggregateLeiosCert committee contributions === Left (VoterIdsOutOfBounds (bad :| []))

-- | A decoder has no committee to size 'leiosCertSigners' against, so it can
-- only bound it by what the largest addressable committee would need. That bound
-- is worth nothing unless aggregation respects it, so no committee may push the
-- bitfield past it — we straddle the boundary. Seats are keyless (and so cheap
-- to build in bulk) because only their count matters here.
prop_aggregateLeiosCert_bitfield_fits_max_committee :: Property
prop_aggregateLeiosCert_bitfield_fits_max_committee = property $ do
  n <- chooseInt (maxLeiosCommitteeSize - 8, maxLeiosCommitteeSize + 8)
  msg <- genMsg
  let committee = UnsafeLeiosCommittee $ V.replicate n (LeiosSeat 0 SNothing)
      sig = signDSIGN () msg (genLeiosSigningKey `generateWith` n)
      contributions = Map.singleton (LeiosSeatId 0) sig
  pure . counterexample ("committee of " <> show n <> " seats") $
    case aggregateLeiosCert committee contributions of
      -- Refusing an unaddressable committee outright is just as sound.
      Left _ -> property True
      Right cert ->
        let numBytes = sizeofByteArray (bitFieldBytes cert.leiosCertSigners)
         in counterexample ("bitfield of " <> show numBytes <> " bytes") $
              numBytes <= (maxLeiosCommitteeSize + 7) `div` 8

-- | Aggregating an empty contribution set must fail: the underlying BLS
-- 'aggregateSigsDSIGN' rejects the empty input, which surfaces as
-- 'BLSAggregationFailed'. We don't pin the exact message string.
prop_aggregateLeiosCert_rejects_empty :: Property
prop_aggregateLeiosCert_rejects_empty = property $ do
  TestCommittee {committee} <- genCommittee
  pure $ case aggregateLeiosCert committee Map.empty of
    Left BLSAggregationFailed {} -> property True
    other -> counterexample (show other) (property False)

-- | Every committee member gets a seat with its weight regardless of its key,
-- and a seat keeps its key exactly when a valid key was registered with a
-- verifying proof of possession. A seat with no key ('NoKey') or with a
-- proof of possession that does not verify ('BadPoP') is admitted to the
-- committee but keyless.
prop_seats_without_valid_key_are_keyless :: Property
prop_seats_without_valid_key_are_keyless =
  forAllShrink genTestSeats genericShrink $ \testSeats ->
    let (_, committee) = mkCommitteeFromTestSeats testSeats
        seats = V.toList committee.leiosCommitteeSeats
     in counterexample (show seats) $
          (length seats === length testSeats)
            .&&. conjoin
              [ counterexample ("unexpected seat " <> show i) $
                  (isSJust seat.seatVKey === (kind == WithKey))
                    .&&. (seat.seatWeight === w)
              | (i :: Int, seat, (kind, w)) <- zip3 [0 ..] seats testSeats
              ]

-- | A certificate must not be able to borrow weight from keyless seats. For
-- each keyless seat we build a cert whose bitfield sets that seat (the
-- signature value is irrelevant — 'verifyLeiosCert' rejects on the keyless seat
-- before counting weight or touching the BLS pairing). Verification must fail
-- with 'SignerWithoutKey' naming that seat, never accept or fall through to a
-- weight/signature check.
prop_verifyLeiosCert_rejects_keyless_signer :: Property
prop_verifyLeiosCert_rejects_keyless_signer =
  forAllShrink genTestSeats genericShrink $ \testSeats ->
    forAll genMsg $ \msg ->
      let (sks, committee) = mkCommitteeFromTestSeats testSeats
          keylessIxs = [i | (i, (kind, _)) <- zip [0 :: Int ..] testSeats, kind /= WithKey]
       in conjoin
            [ counterexample ("keyless seat " <> show j) $
                let vid = LeiosSeatId (fromIntegral j)
                    sig = signDSIGN () msg (sks !! j)
                    cert = either (error . show) id (aggregateLeiosCert committee (Map.singleton vid sig))
                 in verifyLeiosCert committee 1 msg cert === Left (SignerWithoutKey (vid :| []))
            | j <- keylessIxs
            ]

-- * Generators and helpers

genMsg :: Gen BS.ByteString
genMsg = chooseInt (0, 64) >>= genByteString

-- | Sign @msg@ with each of the given keys and pack them into a 'Map' keyed
-- by 'LeiosSeatId', matching the input shape of 'aggregateLeiosCert'.
signContribs :: BS.ByteString -> [(Int, LeiosSigningKey)] -> Map LeiosSeatId LeiosSignature
signContribs msg pairs =
  Map.fromList
    [(LeiosSeatId (fromIntegral @Int @Word16 i), signDSIGN () msg sk) | (i, sk) <- pairs]

-- | Aggregate or fail the property with the error.
aggregateOrFail ::
  LeiosCommittee ->
  Map LeiosSeatId LeiosSignature ->
  (LeiosCert -> Property) ->
  Property
aggregateOrFail committee contributions k = case aggregateLeiosCert committee contributions of
  Right c -> k c
  Left e -> counterexample (show e) (property False)
