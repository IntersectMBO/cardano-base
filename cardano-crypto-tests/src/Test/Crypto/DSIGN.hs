{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.DSIGN
  ( tests
  )
where

import Data.Proxy (Proxy (..))

import Cardano.Binary (FromCBOR, ToCBOR (..))

import Cardano.Crypto.DSIGN
import Cardano.Crypto.Util (SignableRepresentation(..))

import Test.Crypto.Util
import Test.QuickCheck ((=/=), (===), (==>), Arbitrary(..), Gen, Property)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)
import Test.Tasty.HUnit (testCase, assertEqual, assertFailure, Assertion)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteArray.Encoding (convertFromBase, Base (Base16))
import Data.Char (ord)
import Data.Word (Word8)
import Control.Monad (forM_)

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.DSIGN"
    [ testDSIGNAlgorithm (Proxy :: Proxy MockDSIGN) "MockDSIGN"
    , testDSIGNAlgorithm (Proxy :: Proxy Ed25519DSIGN) "Ed25519DSIGN"
    , testDSIGNAlgorithm (Proxy :: Proxy Ed448DSIGN) "Ed448DSIGN"
    , testDSIGNRegressions (Proxy :: Proxy Ed25519DSIGN) "fixtures/ed25519.input"
    ]

testDSIGNAlgorithm
  :: forall proxy v. ( DSIGNAlgorithm v
                     , ToCBOR (VerKeyDSIGN v)
                     , FromCBOR (VerKeyDSIGN v)
                     , ToCBOR (SignKeyDSIGN v)
                     , FromCBOR (SignKeyDSIGN v)
                     , Eq (SignKeyDSIGN v)   -- no Eq for signing keys normally
                     , ToCBOR (SigDSIGN v)
                     , FromCBOR (SigDSIGN v)
                     , Signable v ~ SignableRepresentation
                     , ContextDSIGN v ~ ()
                     )
  => proxy v
  -> String
  -> TestTree
testDSIGNAlgorithm _ n =
  testGroup n
    [ testGroup "serialisation"
      [ testGroup "raw"
        [ testProperty "VerKey"  $ prop_raw_serialise @(VerKeyDSIGN v)
                                                      rawSerialiseVerKeyDSIGN
                                                      rawDeserialiseVerKeyDSIGN
        , testProperty "SignKey" $ prop_raw_serialise @(SignKeyDSIGN v)
                                                      rawSerialiseSignKeyDSIGN
                                                      rawDeserialiseSignKeyDSIGN
        , testProperty "Sig"     $ prop_raw_serialise @(SigDSIGN v)
                                                      rawSerialiseSigDSIGN
                                                      rawDeserialiseSigDSIGN
        ]

      , testGroup "size"
        [ testProperty "VerKey"  $ prop_size_serialise @(VerKeyDSIGN v)
                                                       rawSerialiseVerKeyDSIGN
                                                       (sizeVerKeyDSIGN (Proxy @ v))
        , testProperty "SignKey" $ prop_size_serialise @(SignKeyDSIGN v)
                                                       rawSerialiseSignKeyDSIGN
                                                       (sizeSignKeyDSIGN (Proxy @ v))
        , testProperty "Sig"     $ prop_size_serialise @(SigDSIGN v)
                                                       rawSerialiseSigDSIGN
                                                       (sizeSigDSIGN (Proxy @ v))
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey"  $ prop_cbor_with @(VerKeyDSIGN v)
                                                  encodeVerKeyDSIGN
                                                  decodeVerKeyDSIGN
        , testProperty "SignKey" $ prop_cbor_with @(SignKeyDSIGN v)
                                                  encodeSignKeyDSIGN
                                                  decodeSignKeyDSIGN
        , testProperty "Sig"     $ prop_cbor_with @(SigDSIGN v)
                                                  encodeSigDSIGN
                                                  decodeSigDSIGN
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $ prop_cbor @(VerKeyDSIGN v)
        , testProperty "SignKey" $ prop_cbor @(SignKeyDSIGN v)
        , testProperty "Sig"     $ prop_cbor @(SigDSIGN v)
        ]

      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $ prop_cbor_size @(VerKeyDSIGN v)
        , testProperty "SignKey" $ prop_cbor_size @(SignKeyDSIGN v)
        , testProperty "Sig"     $ prop_cbor_size @(SigDSIGN v)
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey"  $ prop_cbor_direct_vs_class @(VerKeyDSIGN v)
                                                             encodeVerKeyDSIGN
        , testProperty "SignKey" $ prop_cbor_direct_vs_class @(SignKeyDSIGN v)
                                                             encodeSignKeyDSIGN
        , testProperty "Sig"     $ prop_cbor_direct_vs_class @(SigDSIGN v)
                                                             encodeSigDSIGN
        ]
      ]

    , testGroup "verify"
      [ testProperty "verify positive" $ prop_dsign_verify_pos @v
      , testProperty "verify newgative (wrong key)" $ prop_dsign_verify_neg_key @v
      , testProperty "verify newgative (wrong message)" $ prop_dsign_verify_neg_msg @v
      ]

    , testGroup "NoUnexpectedThunks"
      [ testProperty "VerKey"  $ prop_no_unexpected_thunks @(VerKeyDSIGN v)
      , testProperty "SignKey" $ prop_no_unexpected_thunks @(SignKeyDSIGN v)
      , testProperty "Sig"     $ prop_no_unexpected_thunks @(SigDSIGN v)
      ]
    ]

-- | If we sign a message @a@ with the signing key, then we can verify the
-- signature using the corresponding verification key.
--
prop_dsign_verify_pos
  :: forall v. (DSIGNAlgorithm v, ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> SignKeyDSIGN v
  -> Property
prop_dsign_verify_pos a sk =
  let sig = signDSIGN () a sk
      vk = deriveVerKeyDSIGN sk
  in verifyDSIGN () vk a sig === Right ()


-- | If we sign a message @a@ with one signing key, if we try to verify the
-- signature (and message @a@) using a verification key corresponding to a
-- different signing key, then the verification fails.
--
prop_dsign_verify_neg_key
  :: forall v. (DSIGNAlgorithm v, Eq (SignKeyDSIGN v),
                ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> SignKeyDSIGN v
  -> SignKeyDSIGN v
  -> Property
prop_dsign_verify_neg_key a sk sk' =
  sk /= sk' ==>
    let sig = signDSIGN () a sk
        vk' = deriveVerKeyDSIGN sk'
    in verifyDSIGN () vk' a sig =/= Right ()


-- | If we sign a message @a@ with one signing key, if we try to verify the
-- signature with a message other than @a@, then the verification fails.
--
prop_dsign_verify_neg_msg
  :: forall v. (DSIGNAlgorithm v,
                ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> Message
  -> SignKeyDSIGN v
  -> Property
prop_dsign_verify_neg_msg a a' sk =
  a /= a' ==>
    let sig = signDSIGN () a sk
        vk = deriveVerKeyDSIGN sk
    in verifyDSIGN () vk a' sig =/= Right ()

testDSIGNRegressions
  :: forall v. (DSIGNAlgorithm v, ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
  => Proxy v
  -> FilePath
  -> TestTree
testDSIGNRegressions p fp =
  testCase ("DSIGN regressions " <> fp) (test_dsign_regressions p fp)

test_dsign_regressions
  :: forall v. (DSIGNAlgorithm v, ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
  => Proxy v
  -> FilePath
  -> Assertion
test_dsign_regressions _ fixtureFilePath = do
  fixture <- parseFixture <$> BS.readFile fixtureFilePath
  forM_ (zip [1..] fixture) $ \(lineNum :: Int, (sk, pk, m, sm)) -> do
    let s = signDSIGN () m sk
    assertEqual ("signature " ++ fixtureFilePath ++ ":" ++ show lineNum) sm s
    let v = deriveVerKeyDSIGN sk
    assertEqual ("ver key " ++ fixtureFilePath ++ ":" ++ show lineNum) pk v
    case verifyDSIGN () pk m sm of
      Left err -> assertFailure ("verify " ++ fixtureFilePath ++ ":" ++ show lineNum ++ ":" ++ err)
      Right () -> return ()
    let forged = BS.pack . forge . BS.unpack $ m
    case verifyDSIGN () pk forged sm of
      Left _ -> return ()
      Right () -> assertFailure ("verify forged " ++ fixtureFilePath ++ ":" ++ show lineNum)
  where
    -- ported from https://ed25519.cr.yp.to/python/sign.py
    forge :: [Word8] -> [Word8]
    forge [] = [fromIntegral $ ord 'x']
    forge xs = init xs ++ [last xs + 1]

    parseFixture input =
      [ ( maybe (error "Failed to parse key") id . rawDeserialiseSignKeyDSIGN $ either error id (convertFromBase Base16 sk) :: SignKeyDSIGN v
        , maybe (error "Failed to parse key") id . rawDeserialiseVerKeyDSIGN $ either error id (convertFromBase Base16 pk) :: VerKeyDSIGN v
        , either error id (convertFromBase Base16 m) :: ByteString
        , maybe (error "Failed to parse key") id . rawDeserialiseSigDSIGN $ either error id (convertFromBase Base16 sm) :: SigDSIGN v
        )
      | [sk, pk, m, sm] <-
        map (BS.split (fromIntegral $ ord ':')) (BS.split (fromIntegral $ ord '\n') input)
      ]

--
-- Arbitrary instances
--

instance DSIGNAlgorithm v => Arbitrary (VerKeyDSIGN v) where
  arbitrary = deriveVerKeyDSIGN <$> arbitrary
  shrink = const []

instance DSIGNAlgorithm v => Arbitrary (SignKeyDSIGN v) where
  arbitrary = genKeyDSIGN <$> arbitrarySeedOfSize seedSize
    where
      seedSize = seedSizeDSIGN (Proxy :: Proxy v)
  shrink = const []

instance (DSIGNAlgorithm v,
          ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
      => Arbitrary (SigDSIGN v) where
  arbitrary = do
    a <- arbitrary :: Gen Message
    sk <- arbitrary
    return $ signDSIGN () a sk
  shrink = const []

