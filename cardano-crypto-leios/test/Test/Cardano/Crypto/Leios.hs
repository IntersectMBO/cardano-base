{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Crypto.Leios (tests, exampleCert) where

import qualified Cardano.Binary as CBOR
import Cardano.Crypto.DSIGN (genKeyDSIGN, seedSizeDSIGN, signDSIGN)
import Cardano.Crypto.DSIGN.BLS12381 (minSigPoPDST)
import Cardano.Crypto.Leios (
  LeiosCert (..),
  LeiosDSIGN,
  decodeLeiosCert,
  encodeLeiosCert,
 )
import Cardano.Crypto.Seed (mkSeedFromBytes)
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (Proxy))
import Hedgehog (Gen, Group (..), Property, checkParallel, forAll, property, tripping)
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
      ]

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
      , aggregatedSignature = signDSIGN minSigPoPDST msg sk
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
    , aggregatedSignature = signDSIGN minSigPoPDST exampleMessage exampleSigningKey
    }
  where
    seedLen = fromIntegral (seedSizeDSIGN (Proxy @LeiosDSIGN))
    exampleSigningKey = genKeyDSIGN @LeiosDSIGN (mkSeedFromBytes (BS.replicate seedLen 0x01))
    exampleMessage = "leios-golden-message" :: BS.ByteString
