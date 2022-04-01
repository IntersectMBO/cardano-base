{-# LANGUAGE CPP #-}
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

#ifdef SECP256K1
import Data.ByteString (ByteString)
import Control.Monad (replicateM)
import qualified Crypto.Secp256k1 as SECP
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
#ifdef SECP256K1
  EcdsaSecp256k1DSIGN,
  SchnorrSecp256k1DSIGN,
#endif
  DSIGNAlgorithm (VerKeyDSIGN,
                  SignKeyDSIGN,
                  SigDSIGN,
                  ContextDSIGN,
                  Signable,
                  rawSerialiseVerKeyDSIGN,
                  rawDeserialiseVerKeyDSIGN,
                  rawSerialiseSignKeyDSIGN,
                  rawDeserialiseSignKeyDSIGN,
                  rawSerialiseSigDSIGN,
                  rawDeserialiseSigDSIGN),
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
  prop_size_serialise,
  prop_cbor_with,
  prop_cbor,
  prop_cbor_size,
  prop_cbor_direct_vs_class,
  prop_no_thunks,
  arbitrarySeedOfSize
  )
import Test.Crypto.Instances ()
import Test.QuickCheck (
  (=/=), 
  (===), 
  Arbitrary(..), 
  Gen, 
  Property,
  forAllShow
  )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

mockSigGen :: Gen (SigDSIGN MockDSIGN)
mockSigGen = defaultSigGen

ed25519SigGen :: Gen (SigDSIGN Ed25519DSIGN)
ed25519SigGen = defaultSigGen

ed448SigGen :: Gen (SigDSIGN Ed448DSIGN)
ed448SigGen = defaultSigGen

#ifdef SECP256K1
secp256k1SigGen :: Gen (SigDSIGN EcdsaSecp256k1DSIGN)
secp256k1SigGen = do 
  msg <- genSECPMsg
  signDSIGN () msg <$> defaultSignKeyGen

schnorrSigGen :: Gen (SigDSIGN SchnorrSecp256k1DSIGN)
schnorrSigGen = defaultSigGen

genSECPMsg :: Gen SECP.Msg
genSECPMsg = Gen.suchThatMap go SECP.msg
  where
    go :: Gen ByteString
    go = GHC.fromListN 32 <$> replicateM 32 arbitrary
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
#ifdef SECP256K1
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
testDSIGNAlgorithm genSig genMsg name = testGroup name [
  testGroup "serialization" [
    testGroup "raw" [
      testProperty "VerKey" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $ 
                   prop_raw_serialise rawSerialiseVerKeyDSIGN rawDeserialiseVerKeyDSIGN,
      testProperty "SignKey" . 
        forAllShow (defaultSignKeyGen @v)
                   ppShow $ 
                   prop_raw_serialise rawSerialiseSignKeyDSIGN rawDeserialiseSignKeyDSIGN,
      testProperty "Sig" . 
        forAllShow genSig 
                   ppShow $ 
                   prop_raw_serialise rawSerialiseSigDSIGN rawDeserialiseSigDSIGN
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

-- If we signa a message with a key, but then try to verify with a different
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
