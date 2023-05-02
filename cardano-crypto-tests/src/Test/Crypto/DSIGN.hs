{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NumericUnderscores #-}

module Test.Crypto.DSIGN
  ( tests
  )
where

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}

import Test.QuickCheck (
  (=/=),
  (===),
  (==>),
  Arbitrary(..),
  Gen,
  Property,
  Testable,
  forAllShow,
  forAllShrinkShow,
  ioProperty,
  )
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckTests)

import qualified Data.ByteString as BS
import Cardano.Crypto.Libsodium
import Cardano.Crypto.MEqOrd (MEq (..), (==!))

import Text.Show.Pretty (ppShow)

#ifdef SECP256K1_ENABLED
import Control.Monad (replicateM)
import qualified GHC.Exts as GHC
#endif

import qualified Test.QuickCheck.Gen as Gen
import Data.Kind (Type)
import Data.Proxy (Proxy (..))
import Data.Maybe (fromJust)

import Control.Exception (evaluate, bracket)

import Cardano.Crypto.DSIGN (
  MockDSIGN,
  Ed25519DSIGN,
  Ed25519DSIGNM,
  Ed448DSIGN,
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

  DSIGNMAlgorithmBase (VerKeyDSIGNM,
                      SignKeyDSIGNM,
                      SigDSIGNM,
                      ContextDSIGNM,
                      SignableM,
                      SeedSizeDSIGNM,
                      rawSerialiseVerKeyDSIGNM,
                      rawDeserialiseVerKeyDSIGNM,
                      rawSerialiseSigDSIGNM,
                      rawDeserialiseSigDSIGNM),
  DSIGNMAlgorithm (),
  UnsoundDSIGNMAlgorithm (
                  rawSerialiseSignKeyDSIGNM,
                  rawDeserialiseSignKeyDSIGNM),
  sizeVerKeyDSIGNM,
  sizeSignKeyDSIGNM,
  sizeSigDSIGNM,
  encodeVerKeyDSIGNM,
  decodeVerKeyDSIGNM,
  -- encodeSignKeyDSIGNM,
  -- decodeSignKeyDSIGNM,
  encodeSigDSIGNM,
  decodeSigDSIGNM,
  signDSIGNM,
  deriveVerKeyDSIGNM,
  verifyDSIGNM,
  genKeyDSIGNM,

  getSeedDSIGNM,
  forgetSignKeyDSIGNM
  )
import Cardano.Binary (FromCBOR, ToCBOR)
import Cardano.Crypto.PinnedSizedBytes (PinnedSizedBytes)
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
  prop_no_thunks_IO,
  arbitrarySeedOfSize,
  genBadInputFor,
  shrinkBadInputFor,
  showBadInputFor,
  Lock,
  withLock,
  )
import Test.Crypto.Instances (withMLockedSeedFromPSB)
import Cardano.Crypto.Libsodium.MLockedSeed

#ifdef SECP256K1_ENABLED
import Cardano.Crypto.DSIGN (
  EcdsaSecp256k1DSIGN,
  SchnorrSecp256k1DSIGN,
  MessageHash,
  toMessageHash,
  hashAndPack,
  )
import Test.Crypto.Util (
  Message (messageBytes),
  )
import Cardano.Crypto.SECP256K1.Constants (SECP256K1_ECDSA_MESSAGE_BYTES)
import GHC.TypeLits (natVal)
import Cardano.Crypto.Hash (SHA3_256, HashAlgorithm (SizeHash), Blake2b_256, SHA256, Keccak256)
#endif

mockSigGen :: Gen (SigDSIGN MockDSIGN)
mockSigGen = defaultSigGen

ed25519SigGen :: Gen (SigDSIGN Ed25519DSIGN)
ed25519SigGen = defaultSigGen

ed448SigGen :: Gen (SigDSIGN Ed448DSIGN)
ed448SigGen = defaultSigGen

#ifdef SECP256K1_ENABLED
ecdsaSigGen :: Gen (SigDSIGN EcdsaSecp256k1DSIGN)
ecdsaSigGen = do
  msg <- genEcdsaMsg
  signDSIGN () msg <$> defaultSignKeyGen

schnorrSigGen :: Gen (SigDSIGN SchnorrSecp256k1DSIGN)
schnorrSigGen = defaultSigGen

genEcdsaMsg :: Gen MessageHash
genEcdsaMsg =
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

#ifdef SECP256K1_ENABLED
-- Used for adjusting no of quick check tests
-- By default up to 100 tests are performed which may not be enough to catch hidden bugs
defaultTestEnough :: QuickCheckTests -> QuickCheckTests
defaultTestEnough = max 10_000
#endif

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}

--
-- The list of all tests
--
tests :: Lock -> TestTree
tests lock =
  testGroup "Crypto.DSIGN"
    [ testDSIGNAlgorithm mockSigGen (arbitrary @Message) "MockDSIGN"
    , testDSIGNAlgorithm ed25519SigGen (arbitrary @Message) "Ed25519DSIGN"
    , testDSIGNAlgorithm ed448SigGen (arbitrary @Message) "Ed448DSIGN"
#ifdef SECP256K1_ENABLED
    , testDSIGNAlgorithm ecdsaSigGen genEcdsaMsg "EcdsaSecp256k1DSIGN"
    , testDSIGNAlgorithm schnorrSigGen (arbitrary @Message) "SchnorrSecp256k1DSIGN"
    -- Specific tests related only to ecdsa
    , testEcdsaInvalidMessageHash "EcdsaSecp256k1InvalidMessageHash"
    , testEcdsaWithHashAlgorithm (Proxy @SHA3_256) "EcdsaSecp256k1WithSHA3_256"
    , testEcdsaWithHashAlgorithm (Proxy @Blake2b_256) "EcdsaSecp256k1WithBlake2b_256"
    , testEcdsaWithHashAlgorithm (Proxy @SHA256) "EcdsaSecp256k1WithSHA256"
    , testEcdsaWithHashAlgorithm (Proxy @Keccak256) "EcdsaSecp256k1WithKeccak256"
#endif
    , testDSIGNMAlgorithm lock (Proxy @Ed25519DSIGNM) "Ed25519DSIGNM"
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
      testProperty "Sig" . forAllShow genSig ppShow $ prop_no_thunks,
      testProperty "VerKey rawSerialise" . forAllShow (defaultVerKeyGen @v) ppShow $ \vk ->
        prop_no_thunks (rawSerialiseVerKeyDSIGN vk),
      testProperty "VerKey rawDeserialise" . forAllShow (defaultVerKeyGen @v) ppShow $ \vk ->
        prop_no_thunks (fromJust $! rawDeserialiseVerKeyDSIGN @v . rawSerialiseVerKeyDSIGN $ vk)
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

testDSIGNMAlgorithm
  :: forall v. ( -- change back to DSIGNMAlgorithm when unsound API is phased out
                 UnsoundDSIGNMAlgorithm IO v
               , ToCBOR (VerKeyDSIGNM v)
               , FromCBOR (VerKeyDSIGNM v)
               -- DSIGNM cannot satisfy To/FromCBOR (not even with
               -- UnsoundDSIGNMAlgorithm), because those typeclasses assume
               -- that a non-monadic encoding/decoding exists. Hence, we only
               -- test direct encoding/decoding for 'SignKeyDSIGNM'.
               -- , ToCBOR (SignKeyDSIGNM v)
               -- , FromCBOR (SignKeyDSIGNM v)
               , MEq IO (SignKeyDSIGNM v)   -- only monadic MEq for signing keys
               , ToCBOR (SigDSIGNM v)
               , FromCBOR (SigDSIGNM v)
               , ContextDSIGNM v ~ ()
               , SignableM v Message
               )
  => Lock
  -> Proxy v
  -> String
  -> TestTree
testDSIGNMAlgorithm lock _ n =
  testGroup n
    [ testGroup "serialisation"
      [ testGroup "raw"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk <- deriveVerKeyDSIGNM sk
              return $ (rawDeserialiseVerKeyDSIGNM . rawSerialiseVerKeyDSIGNM $ vk) === Just vk
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- rawSerialiseSignKeyDSIGNM sk
              bracket
                (rawDeserialiseSignKeyDSIGNM serialized)
                (maybe (return ()) forgetSignKeyDSIGNM)
                (\msk' -> Just sk ==! msk')
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig <- signDSIGNM () msg sk
              return $ (rawDeserialiseSigDSIGNM . rawSerialiseSigDSIGNM $ sig) === Just sig
        ]
      , testGroup "size"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk <- deriveVerKeyDSIGNM sk
              return $ (fromIntegral . BS.length . rawSerialiseVerKeyDSIGNM $ vk) === (sizeVerKeyDSIGNM (Proxy @v))
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- rawSerialiseSignKeyDSIGNM sk
              evaluate ((fromIntegral . BS.length $ serialized) == (sizeSignKeyDSIGNM (Proxy @v)))
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGNM v <- signDSIGNM () msg sk
              return $ (fromIntegral . BS.length . rawSerialiseSigDSIGNM $ sig) === (sizeSigDSIGNM (Proxy @v))
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGNM v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_with encodeVerKeyDSIGNM decodeVerKeyDSIGNM vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \(msg :: Message) -> do
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGNM v <- signDSIGNM () msg sk
              return $ prop_cbor_with encodeSigDSIGNM decodeSigDSIGNM sig
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGNM v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGNM v <- signDSIGNM () msg sk
              return $ prop_cbor sig
        ]

      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGNM v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_size vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGNM v <- signDSIGNM () msg sk
              return $ prop_cbor_size sig
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGNM v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_direct_vs_class encodeVerKeyDSIGNM vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGNM v <- signDSIGNM () msg sk
              return $ prop_cbor_direct_vs_class encodeSigDSIGNM sig
        ]
      ]

    , testGroup "verify"
      [ testProperty "verify positive" $
          prop_dsignm_verify_pos lock (Proxy @v)
      , testProperty "verify negative (wrong key)" $
          prop_dsignm_verify_neg_key lock (Proxy @v)
      , testProperty "verify negative (wrong message)" $
          prop_dsignm_verify_neg_msg lock (Proxy @v)
      ]

    , testGroup "seed extraction"
      [ testProperty "extracted seed equals original seed" $ prop_dsignm_seed_roundtrip (Proxy @v)
      ]

    , testGroup "forgetting"
      [ testProperty "key overwritten after forget" $ prop_key_overwritten_after_forget (Proxy @v)
      ]

    , testGroup "NoThunks"
      [ testProperty "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> prop_no_thunks_IO (deriveVerKeyDSIGNM sk)
      , testProperty "SignKey" $
          ioPropertyWithSK @v lock $ prop_no_thunks_IO . return
      , testProperty "Sig"     $ \(msg :: Message) ->
          ioPropertyWithSK @v lock $ prop_no_thunks_IO . signDSIGNM () msg
      ]
    ]

-- | Wrap an IO action that requires a 'SignKeyDSIGNM' into one that takes an
-- mlocked seed to generate the key from. The key is bracketed off to ensure
-- timely forgetting. Special care must be taken to not leak the key outside of
-- the wrapped action (be particularly mindful of thunks and unsafe key access
-- here).
withSK :: (DSIGNMAlgorithm IO v) => PinnedSizedBytes (SeedSizeDSIGNM v) -> (SignKeyDSIGNM v -> IO b) -> IO b
withSK seedPSB action =
  withMLockedSeedFromPSB seedPSB $ \seed ->
    bracket
      (genKeyDSIGNM seed)
      forgetSignKeyDSIGNM
      action

-- | Wrap an IO action that requires a 'SignKeyDSIGNM' into a 'Property' that
-- takes a non-mlocked seed (provided as a 'PinnedSizedBytes' of the
-- appropriate size). The key, and the mlocked seed necessary to generate it,
-- are bracketed off, to ensure timely forgetting and avoid leaking mlocked
-- memory. Special care must be taken to not leak the key outside of the
-- wrapped action (be particularly mindful of thunks and unsafe key access
-- here).
ioPropertyWithSK :: forall v a. (Testable a, DSIGNMAlgorithm IO v)
                 => Lock
                 -> (SignKeyDSIGNM v -> IO a)
                 -> PinnedSizedBytes (SeedSizeDSIGNM v)
                 -> Property
ioPropertyWithSK lock action seedPSB =
  ioProperty . withLock lock $ withSK seedPSB action

prop_key_overwritten_after_forget
  :: forall v.
     (DSIGNMAlgorithm IO v
     )
  => Proxy v
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_key_overwritten_after_forget p seedPSB =
  ioProperty . withMLockedSeedFromPSB seedPSB $ \seed -> do
    sk <- genKeyDSIGNM seed
    mlockedSeedFinalize seed

    seedBefore <- getSeedDSIGNM p sk
    bsBefore <- mlsbToByteString . mlockedSeedMLSB $ seedBefore
    mlockedSeedFinalize seedBefore

    forgetSignKeyDSIGNM sk

    seedAfter <- getSeedDSIGNM p sk
    bsAfter <- mlsbToByteString . mlockedSeedMLSB $ seedAfter
    mlockedSeedFinalize seedAfter

    return (bsBefore =/= bsAfter)

prop_dsignm_seed_roundtrip
  :: forall v.
     ( DSIGNMAlgorithm IO v
     )
  => Proxy v
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_dsignm_seed_roundtrip p seedPSB = ioProperty . withMLockedSeedFromPSB seedPSB $ \seed -> do
  sk <- genKeyDSIGNM seed
  seed' <- getSeedDSIGNM p sk
  bs <- mlsbToByteString . mlockedSeedMLSB $ seed
  bs' <- mlsbToByteString . mlockedSeedMLSB $ seed'
  forgetSignKeyDSIGNM sk
  mlockedSeedFinalize seed'
  return (bs === bs')

-- If we sign a message with the key, we can verify the signature with the
-- corresponding verification key.
prop_dsign_verify
  :: forall (v :: Type) (a :: Type) .
     ( DSIGNAlgorithm v
     , ContextDSIGN v ~ ()
     , Signable v a
     )
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
     ( DSIGNAlgorithm v
     , ContextDSIGN v ~ ()
     , Signable v a
     )
  => (a, SignKeyDSIGN v, SignKeyDSIGN v)
  -> Property
prop_dsign_verify_wrong_key (msg, sk, sk') =
  let signed = signDSIGN () msg sk
      vk' = deriveVerKeyDSIGN sk'
    in verifyDSIGN () vk' msg signed =/= Right ()

prop_dsignm_verify_pos
  :: forall v. (DSIGNMAlgorithm IO v, ContextDSIGNM v ~ (), SignableM v Message)
  => Lock
  -> Proxy v
  -> Message
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_dsignm_verify_pos lock _ msg =
  ioPropertyWithSK @v lock $ \sk -> do
    sig <- signDSIGNM () msg sk
    vk <- deriveVerKeyDSIGNM sk
    return $ verifyDSIGNM () vk msg sig === Right ()

-- | If we sign a message @a@ with one signing key, if we try to verify the
-- signature (and message @a@) using a verification key corresponding to a
-- different signing key, then the verification fails.
--
prop_dsignm_verify_neg_key
  :: forall v. (DSIGNMAlgorithm IO v, ContextDSIGNM v ~ (), SignableM v Message)
  => Lock
  -> Proxy v
  -> Message
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_dsignm_verify_neg_key lock _ msg seedPSB seedPSB' =
  ioProperty . withLock lock $ do
    sig <- withSK @v seedPSB $ signDSIGNM () msg
    vk' <- withSK @v seedPSB' deriveVerKeyDSIGNM
    return $
      seedPSB /= seedPSB' ==> verifyDSIGNM () vk' msg sig =/= Right ()

-- If we sign a message with a key, but then try to verify with a different
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

#ifdef SECP256K1_ENABLED
testEcdsaInvalidMessageHash :: String -> TestTree
testEcdsaInvalidMessageHash name = adjustOption defaultTestEnough . testGroup name $ [
    testProperty "MessageHash deserialization (wrong length)" .
      forAllShrinkShow (genBadInputFor expectedMHLen)
                       (shrinkBadInputFor @MessageHash)
                       showBadInputFor $ prop_raw_deserialise toMessageHash
  ]
  where
    expectedMHLen :: Int
    expectedMHLen = fromIntegral $ natVal $ Proxy @SECP256K1_ECDSA_MESSAGE_BYTES

testEcdsaWithHashAlgorithm ::
  forall (h :: Type).
  (HashAlgorithm h, SizeHash h ~ SECP256K1_ECDSA_MESSAGE_BYTES) =>
  Proxy h -> String -> TestTree
testEcdsaWithHashAlgorithm _ name = adjustOption defaultTestEnough . testGroup name $ [
    testProperty "Ecdsa sign and verify" .
    forAllShow ((,) <$> genMsg <*> defaultSignKeyGen @EcdsaSecp256k1DSIGN) ppShow $
      prop_dsign_verify
  ]
  where
    genMsg :: Gen MessageHash
    genMsg = hashAndPack (Proxy @h) . messageBytes <$> arbitrary
#endif

prop_dsignm_verify_neg_msg
  :: forall v. (DSIGNMAlgorithm IO v, ContextDSIGNM v ~ (), SignableM v Message)
  => Lock
  -> Proxy v
  -> Message
  -> Message
  -> PinnedSizedBytes (SeedSizeDSIGNM v)
  -> Property
prop_dsignm_verify_neg_msg lock _ a a' =
  ioPropertyWithSK @v lock $ \sk -> do
    sig <- signDSIGNM () a sk
    vk <- deriveVerKeyDSIGNM sk
    return $
      a /= a' ==> verifyDSIGNM () vk a' sig =/= Right ()

-- TODO: verify that DSIGN and DSIGNM implementations match (see #363)
