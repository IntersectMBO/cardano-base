{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NumericUnderscores #-}

module Test.Crypto.DSIGN
  ( tests
  )
where

#ifdef SECP256K1_ENABLED
import Control.Monad (replicateM)
import qualified GHC.Exts as GHC
#endif

import Text.Show.Pretty (ppShow)
import qualified Test.QuickCheck.Gen as Gen
import Data.Kind (Type)
import Data.Proxy (Proxy (..))
import Cardano.Crypto.DSIGN (
  MockDSIGN, 
  Ed25519DSIGN, 
  Ed448DSIGN,
#ifdef SECP256K1_ENABLED
  EcdsaSecp256k1DSIGN,
  SchnorrSecp256k1DSIGN,
  MessageHash,
  toMessageHash,
#endif
  DSIGNAlgorithm (
    VerKeyDSIGN,
    SignKeyDSIGN,
    SigDSIGN,
    ContextDSIGN,
    Signable,
    rawSerialiseVerKeyDSIGN,
    rawDeserialiseVerKeyDSIGN,
    rawSerialiseSignKeyDSIGN,
    rawDeserialiseSignKeyDSIGN,
    rawSerialiseSigDSIGN,
    rawDeserialiseSigDSIGN
    ),
  sizeVerKeyDSIGN,
  sizeSignKeyDSIGN,
  sizeSigDSIGN,
  encodeVerKeyDSIGN,
  decodeVerKeyDSIGN,
  encodeSignKeyDSIGN,
  decodeSignKeyDSIGN,
  encodeSigDSIGN,
  decodeSigDSIGN,
  signDSIGN,
  deriveVerKeyDSIGN,
  verifyDSIGN,
  genKeyDSIGN,
  seedSizeDSIGN,
  )
import Cardano.Binary (FromCBOR, ToCBOR)
import Test.Crypto.Util (
  Message,
  prop_raw_serialise,
  prop_raw_deserialise,
  prop_size_serialise,
  prop_cbor_with,
  prop_cbor,
  prop_cbor_size,
  prop_cbor_direct_vs_class,
  prop_no_thunks,
  arbitrarySeedOfSize,
  genBadInputFor,
  shrinkBadInputFor,
  showBadInputFor,
  )
import Test.Crypto.Instances ()
import Test.QuickCheck (
  (=/=), 
  (===), 
  Arbitrary(..), 
  Gen, 
  Property,
  forAllShow,
  forAllShrinkShow,
  )
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckTests)

mockSigGen :: Gen (SigDSIGN MockDSIGN)
mockSigGen = defaultSigGen

ed25519SigGen :: Gen (SigDSIGN Ed25519DSIGN)
ed25519SigGen = defaultSigGen

ed448SigGen :: Gen (SigDSIGN Ed448DSIGN)
ed448SigGen = defaultSigGen

#ifdef SECP256K1_ENABLED
secp256k1SigGen :: Gen (SigDSIGN EcdsaSecp256k1DSIGN)
secp256k1SigGen = do 
  msg <- genSECPMsg
  signDSIGN () msg <$> defaultSignKeyGen

schnorrSigGen :: Gen (SigDSIGN SchnorrSecp256k1DSIGN)
schnorrSigGen = defaultSigGen

genSECPMsg :: Gen MessageHash
genSECPMsg = 
  Gen.suchThatMap (GHC.fromListN 32 <$> replicateM 32 arbitrary) 
                  toMessageHash
#endif

defaultVerKeyGen :: forall (a :: Type) . 
  (DSIGNAlgorithm a) => Gen (VerKeyDSIGN a)
defaultVerKeyGen = deriveVerKeyDSIGN <$> defaultSignKeyGen @a

defaultSignKeyGen :: forall (a :: Type).
  (DSIGNAlgorithm a) => Gen (SignKeyDSIGN a)
defaultSignKeyGen = 
  genKeyDSIGN <$> arbitrarySeedOfSize (seedSizeDSIGN (Proxy :: Proxy a))

defaultSigGen :: forall (a :: Type) . 
  (DSIGNAlgorithm a, ContextDSIGN a ~ (), Signable a Message) => 
  Gen (SigDSIGN a)
defaultSigGen = do
  msg :: Message <- arbitrary
  signDSIGN () msg <$> defaultSignKeyGen

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.DSIGN"
    [ testDSIGNAlgorithm mockSigGen (arbitrary @Message) "MockDSIGN"
    , testDSIGNAlgorithm ed25519SigGen (arbitrary @Message) "Ed25519DSIGN"
    , testDSIGNAlgorithm ed448SigGen (arbitrary @Message) "Ed448DSIGN"
#ifdef SECP256K1_ENABLED
    , testDSIGNAlgorithm secp256k1SigGen genSECPMsg "EcdsaSecp256k1DSIGN"
    , testDSIGNAlgorithm schnorrSigGen (arbitrary @Message) "SchnorrSecp256k1DSIGN"
#endif
    ]

testDSIGNAlgorithm :: forall (v :: Type) (a :: Type).
  (DSIGNAlgorithm v,
   Signable v a,
   ContextDSIGN v ~ (),
   Show a,
   Eq (SignKeyDSIGN v),
   Eq a,
   ToCBOR (VerKeyDSIGN v),
   FromCBOR (VerKeyDSIGN v),
   ToCBOR (SignKeyDSIGN v),
   FromCBOR (SignKeyDSIGN v),
   ToCBOR (SigDSIGN v),
   FromCBOR (SigDSIGN v)) =>
  Gen (SigDSIGN v) -> 
  Gen a ->
  String -> 
  TestTree
testDSIGNAlgorithm genSig genMsg name = adjustOption testEnough . testGroup name $ [
  testGroup "serialization" [
    testGroup "raw" [
      testProperty "VerKey serialization" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $ 
                   prop_raw_serialise rawSerialiseVerKeyDSIGN rawDeserialiseVerKeyDSIGN,
      testProperty "VerKey deserialization (wrong length)" . 
        forAllShrinkShow (genBadInputFor . expectedVKLen $ expected)
                         (shrinkBadInputFor @(VerKeyDSIGN v))
                         showBadInputFor $ 
                         prop_raw_deserialise rawDeserialiseVerKeyDSIGN,
      testProperty "SignKey serialization" . 
        forAllShow (defaultSignKeyGen @v)
                   ppShow $ 
                   prop_raw_serialise rawSerialiseSignKeyDSIGN rawDeserialiseSignKeyDSIGN,
      testProperty "SignKey deserialization (wrong length)" . 
        forAllShrinkShow (genBadInputFor . expectedSKLen $ expected)
                         (shrinkBadInputFor @(SignKeyDSIGN v))
                         showBadInputFor $
                         prop_raw_deserialise rawDeserialiseSignKeyDSIGN,
      testProperty "Sig serialization" . 
        forAllShow genSig 
                   ppShow $ 
                   prop_raw_serialise rawSerialiseSigDSIGN rawDeserialiseSigDSIGN,
      testProperty "Sig deserialization (wrong length)" . 
        forAllShrinkShow (genBadInputFor . expectedSigLen $ expected)
                         (shrinkBadInputFor @(SigDSIGN v))
                         showBadInputFor $ 
                         prop_raw_deserialise rawDeserialiseSigDSIGN
      ],
    testGroup "size" [ 
      testProperty "VerKey" . 
        forAllShow (defaultVerKeyGen @v)
                   ppShow $ 
                   prop_size_serialise rawSerialiseVerKeyDSIGN (sizeVerKeyDSIGN (Proxy @v)),
      testProperty "SignKey" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $ 
                   prop_size_serialise rawSerialiseSignKeyDSIGN (sizeSignKeyDSIGN (Proxy @v)),
      testProperty "Sig" . 
        forAllShow genSig 
                   ppShow $ 
                   prop_size_serialise rawSerialiseSigDSIGN (sizeSigDSIGN (Proxy @v))
      ],
    testGroup "direct CBOR" [
      testProperty "VerKey" . 
        forAllShow (defaultVerKeyGen @v)
                   ppShow $ 
                   prop_cbor_with encodeVerKeyDSIGN decodeVerKeyDSIGN,
      testProperty "SignKey" . 
        forAllShow (defaultSignKeyGen @v)
                   ppShow $ 
                   prop_cbor_with encodeSignKeyDSIGN decodeSignKeyDSIGN,
      testProperty "Sig" . 
        forAllShow genSig 
                   ppShow $ 
                   prop_cbor_with encodeSigDSIGN decodeSigDSIGN
      ],
    testGroup "To/FromCBOR class" [
      testProperty "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_cbor,
      testProperty "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_cbor,
      testProperty "Sig" . forAllShow genSig ppShow $ prop_cbor
      ],
    testGroup "ToCBOR size" [
      testProperty "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_cbor_size,
      testProperty "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_cbor_size,
      testProperty "Sig" . forAllShow genSig ppShow $ prop_cbor_size
      ],
    testGroup "direct matches class" [
      testProperty "VerKey" . 
        forAllShow (defaultVerKeyGen @v) ppShow $ 
        prop_cbor_direct_vs_class encodeVerKeyDSIGN,
      testProperty "SignKey" . 
        forAllShow (defaultSignKeyGen @v) ppShow $ 
        prop_cbor_direct_vs_class encodeSignKeyDSIGN,
      testProperty "Sig" . 
        forAllShow genSig ppShow $ 
        prop_cbor_direct_vs_class encodeSigDSIGN
      ]
    ],
    testGroup "verify" [
      testProperty "signing and verifying with matching keys" . 
        forAllShow ((,) <$> genMsg <*> defaultSignKeyGen @v) ppShow $
        prop_dsign_verify,
      testProperty "verifying with wrong key" . 
        forAllShow genWrongKey ppShow $
        prop_dsign_verify_wrong_key,
      testProperty "verifying wrong message" . 
        forAllShow genWrongMsg ppShow $ 
        prop_dsign_verify_wrong_msg
    ],
    testGroup "NoThunks" [
      testProperty "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_no_thunks,
      testProperty "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_no_thunks,
      testProperty "Sig" . forAllShow genSig ppShow $ prop_no_thunks
    ]
  ]
  where
    expected :: ExpectedLengths v
    expected = defaultExpected
    genWrongKey :: Gen (a, SignKeyDSIGN v, SignKeyDSIGN v)
    genWrongKey = do
      sk1 <- defaultSignKeyGen
      sk2 <- Gen.suchThat defaultSignKeyGen (/= sk1)
      msg <- genMsg
      pure (msg, sk1, sk2)
    genWrongMsg :: Gen (a, a, SignKeyDSIGN v)
    genWrongMsg = do
      msg1 <- genMsg
      msg2 <- Gen.suchThat genMsg (/= msg1)
      sk <- defaultSignKeyGen
      pure (msg1, msg2, sk)
    testEnough :: QuickCheckTests -> QuickCheckTests
    testEnough = max 10_000

-- If we sign a message with the key, we can verify the signature with the
-- corresponding verification key.
prop_dsign_verify  
  :: forall (v :: Type) (a :: Type) . 
  (DSIGNAlgorithm v, ContextDSIGN v ~ (), Signable v a) 
  => (a, SignKeyDSIGN v)
  -> Property
prop_dsign_verify (msg, sk) = 
  let signed = signDSIGN () msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN () vk msg signed === Right ()

-- If we sign a message with one key, and try to verify with another, then
-- verification fails.
prop_dsign_verify_wrong_key
  :: forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a, ContextDSIGN v ~ ()) 
  => (a, SignKeyDSIGN v, SignKeyDSIGN v) 
  -> Property
prop_dsign_verify_wrong_key (msg, sk, sk') = 
  let signed = signDSIGN () msg sk
      vk' = deriveVerKeyDSIGN sk'
    in verifyDSIGN () vk' msg signed =/= Right ()

-- If we sign a a message with a key, but then try to verify with a different
-- message, then verification fails.
prop_dsign_verify_wrong_msg 
  :: forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a, ContextDSIGN v ~ ())
  => (a, a, SignKeyDSIGN v)
  -> Property
prop_dsign_verify_wrong_msg (msg, msg', sk) = 
  let signed = signDSIGN () msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN () vk msg' signed =/= Right ()

data ExpectedLengths (v :: Type) = 
  ExpectedLengths {
    expectedVKLen :: Int,
    expectedSKLen :: Int,
    expectedSigLen :: Int
    }

defaultExpected :: 
  forall (v :: Type) .
  (DSIGNAlgorithm v) =>
  ExpectedLengths v
defaultExpected = ExpectedLengths {
  expectedVKLen = fromIntegral . sizeVerKeyDSIGN $ Proxy @v,
  expectedSKLen = fromIntegral . sizeSignKeyDSIGN $ Proxy @v,
  expectedSigLen = fromIntegral . sizeSigDSIGN $ Proxy @v
  }
