{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Crypto.Leios (tests, exampleCert) where

import qualified Cardano.Binary as CBOR
import Cardano.Crypto.DSIGN (
  DSIGNAlgorithm (deriveVerKeyDSIGN),
  genKeyDSIGN,
  seedSizeDSIGN,
  signDSIGN,
 )
import Cardano.Crypto.Leios (
  AggregationError (..),
  Committee (..),
  LeiosCert (..),
  LeiosDSIGN,
  LeiosSigningKey,
  VerificationError (..),
  VoterId (..),
  aggregateLeiosCert,
  decodeLeiosCert,
  encodeLeiosCert,
  leiosSignContext,
  verifyLeiosCert,
 )
import Cardano.Crypto.Seed (mkSeedFromBytes)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Proxy (Proxy (Proxy))
import qualified Data.Vector as V
import Hedgehog (
  Gen,
  Group (..),
  Property,
  annotateShow,
  checkParallel,
  forAll,
  property,
  tripping,
  withTests,
  (===),
 )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Test.Cardano.Binary.Helpers.GoldenRoundTrip (goldenTestCBORExplicit)

tests :: IO Bool
tests =
  checkParallel $
    Group
      "Test.Cardano.Crypto.Leios"
      [ ("prop_roundtrip_LeiosCert", prop_roundtrip_LeiosCert)
      , ("prop_golden_LeiosCert", prop_golden_LeiosCert)
      , ("prop_verifyLeiosCert_accepts_aggregated", prop_verifyLeiosCert_accepts_aggregated)
      , ("prop_verifyLeiosCert_rejects_wrong_message", prop_verifyLeiosCert_rejects_wrong_message)
      , ("prop_verifyLeiosCert_rejects_below_threshold", prop_verifyLeiosCert_rejects_below_threshold)
      , ("prop_aggregateLeiosCert_rejects_out_of_range", prop_aggregateLeiosCert_rejects_out_of_range)
      ]

-- * CBOR roundtrip / golden

-- | A 'LeiosCert' with a real (deterministically-derived) BLS aggregated
-- signature and a 'signers' bitfield whose length walks the CBOR uint
-- width boundaries (1 / 2 / 3-byte length headers).
genLeiosCert :: Gen LeiosCert
genLeiosCert = do
  let seedLen = fromIntegral (seedSizeDSIGN (Proxy @LeiosDSIGN))
  seedBytes <- Gen.bytes (Range.singleton seedLen)
  msg <- Gen.bytes (Range.linear 0 256)
  signersLen <- Gen.element [0, 1, 23, 24, 255, 256]
  signersBytes <- Gen.bytes (Range.singleton signersLen)
  let sk = genKeyDSIGN @LeiosDSIGN (mkSeedFromBytes seedBytes)
  pure
    LeiosCert
      { signers = signersBytes
      , aggregatedSignature = signDSIGN leiosSignContext msg sk
      }

prop_roundtrip_LeiosCert :: Property
prop_roundtrip_LeiosCert = property $ do
  cert <- forAll genLeiosCert
  tripping
    cert
    (CBOR.serialize . encodeLeiosCert)
    (CBOR.decodeFullDecoder "LeiosCert" decodeLeiosCert)

-- | Locks the on-wire encoding of 'LeiosCert' against accidental drift.
-- Inputs are fixed (constant seed, fixed message, fixed bitfield) so the
-- byte-for-byte golden is reproducible.
prop_golden_LeiosCert :: Property
prop_golden_LeiosCert =
  goldenTestCBORExplicit "LeiosCert" encodeLeiosCert decodeLeiosCert exampleCert path
  where
    path = "test/golden/LeiosCert"

exampleCert :: LeiosCert
exampleCert =
  LeiosCert
    { signers = BS.pack [0xF0]
    , aggregatedSignature = signDSIGN leiosSignContext exampleMessage exampleSigningKey
    }
  where
    seedLen = fromIntegral (seedSizeDSIGN (Proxy @LeiosDSIGN))
    exampleSigningKey = genKeyDSIGN @LeiosDSIGN (mkSeedFromBytes (BS.replicate seedLen 0x01))
    exampleMessage = "leios-golden-message" :: BS.ByteString

-- * aggregate / verify

-- | Equal-weighted committee of @n@ voters derived from a fixed seed pattern.
-- Returns the signing keys alongside the committee so tests can produce
-- contributions.
fixedCommittee :: Int -> ([LeiosSigningKey], Committee)
fixedCommittee n =
  ( sks
  , Committee (V.fromList [(1 / fromIntegral n, deriveVerKeyDSIGN sk) | sk <- sks])
  )
  where
    seedLen = fromIntegral (seedSizeDSIGN (Proxy @LeiosDSIGN))
    sks =
      [ genKeyDSIGN @LeiosDSIGN (mkSeedFromBytes (BS.replicate seedLen (fromIntegral i)))
      | i <- [1 .. n]
      ]

-- | All committee members sign the same message; the resulting cert verifies
-- against that committee, threshold and message, and reports full weight.
prop_verifyLeiosCert_accepts_aggregated :: Property
prop_verifyLeiosCert_accepts_aggregated = withTests 20 $ property $ do
  n <- forAll (Gen.int (Range.linear 1 16))
  msg <- forAll (Gen.bytes (Range.linear 0 64))
  let (sks, committee) = fixedCommittee n
      contributions =
        Map.fromList
          [ (VoterId (fromIntegral i), signDSIGN leiosSignContext msg sk)
          | (i, sk) <- zip [0 :: Int ..] sks
          ]
  cert <- case aggregateLeiosCert committee contributions of
    Right c -> pure c
    Left e -> do annotateShow e; fail "aggregateLeiosCert failed"
  verifyLeiosCert committee 1 msg cert === Right 1

-- | A cert built over message @m1@ must not verify against message @m2@.
prop_verifyLeiosCert_rejects_wrong_message :: Property
prop_verifyLeiosCert_rejects_wrong_message = withTests 20 $ property $ do
  let n = 4
      (sks, committee) = fixedCommittee n
      m1 = "leios-message-one" :: BS.ByteString
      m2 = "leios-message-two" :: BS.ByteString
      contributions =
        Map.fromList
          [ (VoterId (fromIntegral i), signDSIGN leiosSignContext m1 sk)
          | (i, sk) <- zip [0 :: Int ..] sks
          ]
  cert <- case aggregateLeiosCert committee contributions of
    Right c -> pure c
    Left e -> do annotateShow e; fail "aggregateLeiosCert failed"
  verifyLeiosCert committee 1 m2 cert === Left InvalidSignature

-- | A cert whose signers' summed weight is below the threshold must be
-- rejected with 'InsufficientWeight', without ever performing the BLS
-- pairing.
prop_verifyLeiosCert_rejects_below_threshold :: Property
prop_verifyLeiosCert_rejects_below_threshold = withTests 1 $ property $ do
  let n = 4 -- four equal-weight voters; one signer ⇒ weight = 1/4
      (sks, committee) = fixedCommittee n
      msg = "leios-quorum-test" :: BS.ByteString
      contributions = Map.singleton (VoterId 0) (signDSIGN leiosSignContext msg (head sks))
  cert <- case aggregateLeiosCert committee contributions of
    Right c -> pure c
    Left e -> do annotateShow e; fail "aggregateLeiosCert failed"
  verifyLeiosCert committee (3 / 4) msg cert
    === Left InsufficientWeight {got = 1 / 4, required = 3 / 4}

prop_aggregateLeiosCert_rejects_out_of_range :: Property
prop_aggregateLeiosCert_rejects_out_of_range = withTests 1 $ property $ do
  let (sks, committee) = fixedCommittee 4
      msg = "x" :: BS.ByteString
      contributions = Map.singleton (VoterId 7) (signDSIGN leiosSignContext msg (head sks))
  aggregateLeiosCert committee contributions === Left (VoterIdOutOfBounds (VoterId 7))
