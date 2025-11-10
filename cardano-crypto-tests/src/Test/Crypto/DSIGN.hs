{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

{- FOURMOLU_DISABLE -}
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
  property,
  suchThat,
  forAllShow,
  forAllShrinkShow,
  ioProperty,
  counterexample,
  conjoin,
  )
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckTests)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Bits (xor)
import Cardano.Crypto.Libsodium

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
  Ed448DSIGN,
  DSIGNAlgorithm (
    SeedSizeDSIGN,
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

  DSIGNMAlgorithm (SignKeyDSIGNM, deriveVerKeyDSIGNM),
  UnsoundDSIGNMAlgorithm,
  rawSerialiseSignKeyDSIGNM,
  rawDeserialiseSignKeyDSIGNM,
  signDSIGNM,
  genKeyDSIGNM,

  getSeedDSIGNM,
  forgetSignKeyDSIGNM,

  PoPDSIGN (
    PoPDSIGNData,
    provePoPDSIGN,
    verifyPoPDSIGN,
    rawSerialisePoPDSIGN,
    rawDeserialisePoPDSIGN
    )
  )
import Cardano.Crypto.DSIGN.BLS12381MinPk (BLS12381MinPkDSIGN, pattern PoPBLSMinPk)
import Cardano.Crypto.DSIGN.BLS12381MinSig (BLS12381MinSigDSIGN, pattern PoPBLSMinSig)
import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS
import Cardano.Binary (FromCBOR, ToCBOR)
import Cardano.Crypto.PinnedSizedBytes (PinnedSizedBytes)
import Cardano.Crypto.DirectSerialise
import NoThunks.Class (NoThunks)
import Test.Crypto.Util (
  Lock,
  Message (..),
  arbitrarySeedOfSize,
  directDeserialiseFromBS,
  directSerialiseToBS,
  genBadInputFor,
  hexBS,
  prop_cbor,
  prop_cbor_direct_vs_class,
  prop_cbor_size,
  prop_cbor_with,
  prop_no_thunks,
  prop_no_thunks_IO,
  prop_raw_deserialise,
  prop_raw_serialise,
  prop_size_serialise,
  shrinkBadInputFor,
  showBadInputFor,
  withLock,
  )
import Cardano.Crypto.Libsodium.MLockedSeed

import Test.Crypto.Instances (withMLockedSeedFromPSB)
import Test.Crypto.EqST (EqST (..), (==!))

#ifdef SECP256K1_ENABLED
import Cardano.Crypto.DSIGN (
  EcdsaSecp256k1DSIGN,
  SchnorrSecp256k1DSIGN,
  MessageHash,
  toMessageHash,
  hashAndPack,
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

blsMinPkSigGen :: Gen (SigDSIGN BLS12381MinPkDSIGN)
blsMinPkSigGen = defaultSigGenWithCtx (Nothing, Nothing)

blsMinSigSigGen :: Gen (SigDSIGN BLS12381MinSigDSIGN)
blsMinSigSigGen = defaultSigGenWithCtx (Nothing, Nothing)

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

defaultSigGenWithCtx ::
  forall (a :: Type) .
  (DSIGNAlgorithm a, Signable a Message) =>
  ContextDSIGN a ->
  Gen (SigDSIGN a)
defaultSigGenWithCtx ctx = do
  msg :: Message <- arbitrary
  signDSIGN ctx msg <$> defaultSignKeyGen

defaultSigGen ::
  forall (a :: Type) .
  (DSIGNAlgorithm a, ContextDSIGN a ~ (), Signable a Message) =>
  Gen (SigDSIGN a)
defaultSigGen = defaultSigGenWithCtx @a ()

defaultBlsDst :: ByteString
defaultBlsDst = BS8.pack "BLS_DST_CARDANO_BASE_V1"

badBlsDst :: ByteString
badBlsDst = BS8.pack "BLS_DST_CARDANO_BASE_V1_X"

blsAugVote :: ByteString
blsAugVote = BS8.pack "role=vote"

blsAugCert :: ByteString
blsAugCert = BS8.pack "role=cert"

blsTestMessage :: Message
blsTestMessage = Message (BS8.pack "dst-aug-test-message")

blsDstAugTests :: TestTree
blsDstAugTests =
  testGroup
    "DST/AUG behaviour"
    [ blsDstAugGroup "BLS12381MinPkDSIGN" (Proxy @BLS12381MinPkDSIGN)
    , blsDstAugGroup "BLS12381MinSigDSIGN" (Proxy @BLS12381MinSigDSIGN)
    ]

blsDstAugGroup ::
  forall v.
  ( DSIGNAlgorithm v
  , Signable v Message
  , ContextDSIGN v ~ (Maybe ByteString, Maybe ByteString)
  ) =>
  String ->
  Proxy v ->
  TestTree
blsDstAugGroup label _ =
  testGroup
    label
    [ testProperty "dst default equivalence" $
        forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
          let msg = blsTestMessage
              sigDefault = signDSIGN ctxDefault msg sk
              sigExplicit = signDSIGN ctxExplicitDst msg sk
              vk = deriveVerKeyDSIGN sk
           in conjoin
                [ counterexample "default context should verify"
                    (verifyDSIGN ctxDefault vk msg sigDefault === Right ())
                , counterexample "explicit default DST should verify"
                    (verifyDSIGN ctxExplicitDst vk msg sigExplicit === Right ())
                , counterexample "signatures should match when DST defaults"
                    (sigDefault === sigExplicit)
                ]
    , testProperty "aug empty equivalence" $
        forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
          let msg = blsTestMessage
              sigNothing = signDSIGN ctxExplicitDst msg sk
              sigEmpty = signDSIGN ctxExplicitEmptyAug msg sk
              vk = deriveVerKeyDSIGN sk
           in conjoin
                [ counterexample "aug Nothing should verify"
                    (verifyDSIGN ctxExplicitDst vk msg sigNothing === Right ())
                , counterexample "aug empty string should verify"
                    (verifyDSIGN ctxExplicitEmptyAug vk msg sigEmpty === Right ())
                , counterexample "signatures should match when AUG defaults"
                    (sigNothing === sigEmpty)
                ]
    , testProperty "verify fails on wrong dst" $
        forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
          let msg = blsTestMessage
              sig = signDSIGN ctxExplicitEmptyAug msg sk
              vk = deriveVerKeyDSIGN sk
           in conjoin
                [ counterexample "control context should verify"
                    (verifyDSIGN ctxExplicitEmptyAug vk msg sig === Right ())
                , counterexample "verification should fail with wrong DST"
                    (verifyDSIGN ctxWrongDst vk msg sig =/= Right ())
                ]
    , testProperty "verify fails on wrong aug" $
        forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
          let msg = blsTestMessage
              sig = signDSIGN ctxVote msg sk
              vk = deriveVerKeyDSIGN sk
           in conjoin
                [ counterexample "control context should verify"
                    (verifyDSIGN ctxVote vk msg sig === Right ())
                , counterexample "verification should fail with wrong AUG"
                    (verifyDSIGN ctxCert vk msg sig =/= Right ())
                ]
    ]
  where
    ctxDefault = (Nothing, Nothing)
    ctxExplicitDst = (Just defaultBlsDst, Nothing)
    ctxExplicitEmptyAug = (Just defaultBlsDst, Just BS.empty)
    ctxWrongDst = (Just badBlsDst, Just BS.empty)
    ctxVote = (Just defaultBlsDst, Just blsAugVote)
    ctxCert = (Just defaultBlsDst, Just blsAugCert)

class PoPCompressedBytes v where
  popCompressedBytes :: PoPDSIGNData v -> ByteString

instance PoPCompressedBytes BLS12381MinPkDSIGN where
  popCompressedBytes pop =
    case pop of
      PoPBLSMinPk blsPop -> BLS.toCompressedBytes blsPop

instance PoPCompressedBytes BLS12381MinSigDSIGN where
  popCompressedBytes pop =
    case pop of
      PoPBLSMinSig blsPop -> BLS.toCompressedBytes blsPop

mutateBytes :: ByteString -> ByteString
mutateBytes bs =
  case BS.uncons bs of
    Nothing -> bs
    Just (h, t) -> BS.cons (h `xor` 0x01) t

testPoPDSIGN ::
  forall v.
  ( PoPDSIGN v
  , Eq (SignKeyDSIGN v)
  , Eq (PoPDSIGNData v)
  , Show (PoPDSIGNData v)
  , NoThunks (PoPDSIGNData v)
  , ContextDSIGN v ~ (Maybe ByteString, Maybe ByteString)
  , PoPCompressedBytes v
  ) =>
  String ->
  Proxy v ->
  TestTree
testPoPDSIGN label _ =
  testGroup
    ("PoP " <> label)
    [ testProperty "prove/verify context equivalence" propContextEquivalence
    , testProperty "verification fails on wrong dst" propWrongDst
    , testProperty "verification fails on wrong aug" propWrongAug
    , testProperty "verification fails with mismatched verification key" propWrongKey
    , testProperty "verification fails for tampered PoP bytes" propTampered
    , testProperty "verification fails for random PoP bytes" propRandomPoP
    , testProperty "raw serialisation round-trip" propRawRoundTrip
    , testProperty "raw deserialisation rejects truncated bytes" propRejectShort
    , testProperty "raw deserialisation rejects extended bytes" propRejectLong
    , testProperty "raw bytes match BLS compressed form" propMatchesBls
    , testProperty "PoP is NoThunks" propPoPNoThunks
    ]
  where
    ctxDefault = (Nothing, Nothing)
    ctxExplicitDst = (Just defaultBlsDst, Nothing)
    ctxExplicitEmptyAug = (Just defaultBlsDst, Just BS.empty)
    ctxOnlyAug = (Nothing, Just BS.empty)
    ctxWrongDst = (Just badBlsDst, Just BS.empty)
    ctxVote = (Just defaultBlsDst, Just blsAugVote)
    ctxCert = (Just defaultBlsDst, Just blsAugCert)

    propContextEquivalence =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        let vk = deriveVerKeyDSIGN sk
            pop = provePoPDSIGN ctxDefault sk
            contexts =
              [ ("Nothing/Nothing", ctxDefault)
              , ("explicit dst default", ctxExplicitDst)
              , ("explicit dst with empty aug", ctxExplicitEmptyAug)
              , ("Nothing dst with empty aug", ctxOnlyAug)
              ]
         in conjoin
              [ counterexample ("context: " <> labelCtx)
                  (verifyPoPDSIGN ctx vk pop === Right ())
              | (labelCtx, ctx) <- contexts
              ]

    propWrongDst =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        let vk = deriveVerKeyDSIGN sk
            pop = provePoPDSIGN ctxExplicitEmptyAug sk
         in conjoin
              [ counterexample "control context should verify"
                  (verifyPoPDSIGN ctxExplicitEmptyAug vk pop === Right ())
              , counterexample "wrong dst should fail"
                  (verifyPoPDSIGN ctxWrongDst vk pop =/= Right ())
              ]

    propWrongAug =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        let vk = deriveVerKeyDSIGN sk
            pop = provePoPDSIGN ctxVote sk
         in conjoin
              [ counterexample "control context should verify"
                  (verifyPoPDSIGN ctxVote vk pop === Right ())
              , counterexample "wrong aug should fail"
                  (verifyPoPDSIGN ctxCert vk pop =/= Right ())
              ]

    propWrongKey =
      forAllShow genDistinctSignKeys ppShow $ \(skGood, skOther) ->
        let vkOther = deriveVerKeyDSIGN skOther
            pop = provePoPDSIGN ctxDefault skGood
         in counterexample "verification with different key should fail" $
              verifyPoPDSIGN ctxDefault vkOther pop =/= Right ()

    propTampered =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        let vk = deriveVerKeyDSIGN sk
            pop = provePoPDSIGN ctxDefault sk
            tamperedBs = mutateBytes (rawSerialisePoPDSIGN pop)
         in counterexample "tampered bytes should not verify" $
              case rawDeserialisePoPDSIGN @v tamperedBs of
                Nothing -> property True
                Just tamperedPop ->
                  verifyPoPDSIGN ctxDefault vk tamperedPop =/= Right ()

    propRandomPoP =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        let vk = deriveVerKeyDSIGN sk
            pop = provePoPDSIGN ctxDefault sk
            len = BS.length (rawSerialisePoPDSIGN pop)
         in forAllShow (randomPoPBytesOf len) hexBS $ \randomBs ->
              case rawDeserialisePoPDSIGN @v randomBs of
                Nothing -> property True
                Just randomPop ->
                  verifyPoPDSIGN ctxDefault vk randomPop =/= Right ()

    propRawRoundTrip =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        let pop = provePoPDSIGN ctxDefault sk
            bs = rawSerialisePoPDSIGN pop
         in counterexample "round-trip failed" $
              rawDeserialisePoPDSIGN @v bs === Just pop

    propRejectShort =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        let pop = provePoPDSIGN ctxDefault sk
            bs = rawSerialisePoPDSIGN pop
            shortBs = BS.drop 1 bs
         in counterexample "short bytes should fail" $
              rawDeserialisePoPDSIGN @v shortBs === Nothing

    propRejectLong =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        let pop = provePoPDSIGN ctxDefault sk
            bs = rawSerialisePoPDSIGN pop
            longBs = bs <> BS.singleton 0
         in counterexample "extended bytes should fail" $
              rawDeserialisePoPDSIGN @v longBs === Nothing

    propMatchesBls =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        let pop = provePoPDSIGN ctxDefault sk
         in rawSerialisePoPDSIGN pop === popCompressedBytes pop

    propPoPNoThunks =
      forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
        prop_no_thunks (provePoPDSIGN ctxDefault sk)

    genDistinctSignKeys = do
      skA <- defaultSignKeyGen @v
      skB <- suchThat (defaultSignKeyGen @v) (/= skA)
      pure (skA, skB)

    randomPoPBytesOf n =
      BS.pack <$> Gen.vectorOf n arbitrary

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
    [ testGroup "Pure"
      [ testDSIGNAlgorithm () mockSigGen (arbitrary @Message) "MockDSIGN"
      , testDSIGNAlgorithm () ed25519SigGen (arbitrary @Message) "Ed25519DSIGN"
      , testDSIGNAlgorithm () ed448SigGen (arbitrary @Message) "Ed448DSIGN"
      , testDSIGNAlgorithm (Nothing, Nothing) blsMinPkSigGen (arbitrary @Message) "BLS12381MinPkDSIGN"
      , testDSIGNAlgorithm (Nothing, Nothing) blsMinSigSigGen (arbitrary @Message) "BLS12381MinSigDSIGN"
      -- Specific tests related only to BLS
      , testPoPDSIGN "BLS12381MinPkDSIGN" (Proxy @BLS12381MinPkDSIGN)
      , testPoPDSIGN "BLS12381MinSigDSIGN" (Proxy @BLS12381MinSigDSIGN)
#ifdef SECP256K1_ENABLED
      , testDSIGNAlgorithm () ecdsaSigGen genEcdsaMsg "EcdsaSecp256k1DSIGN"
      , testDSIGNAlgorithm () schnorrSigGen (arbitrary @Message) "SchnorrSecp256k1DSIGN"
      -- Specific tests related only to ecdsa
      , testEcdsaInvalidMessageHash "EcdsaSecp256k1InvalidMessageHash"
      , testEcdsaWithHashAlgorithm (Proxy @SHA3_256) "EcdsaSecp256k1WithSHA3_256"
      , testEcdsaWithHashAlgorithm (Proxy @Blake2b_256) "EcdsaSecp256k1WithBlake2b_256"
      , testEcdsaWithHashAlgorithm (Proxy @SHA256) "EcdsaSecp256k1WithSHA256"
      , testEcdsaWithHashAlgorithm (Proxy @Keccak256) "EcdsaSecp256k1WithKeccak256"
#endif
      ]
    , blsDstAugTests
    , testGroup "MLocked"
      [ testDSIGNMAlgorithm lock (Proxy @Ed25519DSIGN) "Ed25519DSIGN"
      ]
    ]

testDSIGNAlgorithm :: forall (v :: Type) (a :: Type).
  (DSIGNAlgorithm v,
   Signable v a,
   Show a,
   Eq (SignKeyDSIGN v),
   Eq a,
   ToCBOR (VerKeyDSIGN v),
   FromCBOR (VerKeyDSIGN v),
   ToCBOR (SignKeyDSIGN v),
   FromCBOR (SignKeyDSIGN v),
   ToCBOR (SigDSIGN v),
   FromCBOR (SigDSIGN v)) =>
  ContextDSIGN v ->
  Gen (SigDSIGN v) ->
  Gen a ->
  String ->
  TestTree
testDSIGNAlgorithm ctx genSig genMsg name = adjustOption testEnough . testGroup name $ [
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
        prop_dsign_verify ctx,
      testProperty "verifying with wrong key" .
        forAllShow genWrongKey ppShow $
        prop_dsign_verify_wrong_key ctx,
      testProperty "verifying wrong message" .
        forAllShow genWrongMsg ppShow $
        prop_dsign_verify_wrong_msg ctx
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
                 UnsoundDSIGNMAlgorithm v
               , ToCBOR (VerKeyDSIGN v)
               , FromCBOR (VerKeyDSIGN v)
               -- DSIGNM cannot satisfy To/FromCBOR (not even with
               -- UnsoundDSIGNMAlgorithm), because those typeclasses assume
               -- that a non-monadic encoding/decoding exists. Hence, we only
               -- test direct encoding/decoding for 'SignKeyDSIGNM'.
               -- , ToCBOR (SignKeyDSIGNM v)
               -- , FromCBOR (SignKeyDSIGNM v)
               , EqST (SignKeyDSIGNM v)   -- only monadic EqST for signing keys
               , ToCBOR (SigDSIGN v)
               , FromCBOR (SigDSIGN v)
               , ContextDSIGN v ~ ()
               , Signable v Message
               , DirectSerialise (SignKeyDSIGNM v)
               , DirectDeserialise (SignKeyDSIGNM v)
               , DirectSerialise (VerKeyDSIGN v)
               , DirectDeserialise (VerKeyDSIGN v)
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
              return $ (rawDeserialiseVerKeyDSIGN . rawSerialiseVerKeyDSIGN $ vk) === Just vk
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
              return $ (rawDeserialiseSigDSIGN . rawSerialiseSigDSIGN $ sig) === Just sig
        ]
      , testGroup "size"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk <- deriveVerKeyDSIGNM sk
              return $ (fromIntegral . BS.length . rawSerialiseVerKeyDSIGN $ vk) === sizeVerKeyDSIGN (Proxy @v)
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- rawSerialiseSignKeyDSIGNM sk
              evaluate ((fromIntegral . BS.length $ serialized) == sizeSignKeyDSIGN (Proxy @v))
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ (fromIntegral . BS.length . rawSerialiseSigDSIGN $ sig) === sizeSigDSIGN (Proxy @v)
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_with encodeVerKeyDSIGN decodeVerKeyDSIGN vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \(msg :: Message) -> do
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor_with encodeSigDSIGN decodeSigDSIGN sig
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor sig
        ]

      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_size vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor_size sig
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_direct_vs_class encodeVerKeyDSIGN vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor_direct_vs_class encodeSigDSIGN sig
        ]
      , testGroup "DirectSerialise"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              serialized <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
              vk' <- directDeserialiseFromBS serialized
              return $ vk === vk'
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
              sk' <- directDeserialiseFromBS serialized
              equals <- sk ==! sk'
              forgetSignKeyDSIGNM sk'
              return $
                counterexample ("Serialized: " ++ hexBS serialized ++ " (length: " ++ show (BS.length serialized) ++ ")") $
                equals
        ]
      , testGroup "DirectSerialise matches raw"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
              let raw = rawSerialiseVerKeyDSIGN vk
              return $ direct === raw
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
              raw <- rawSerialiseSignKeyDSIGNM sk
              return $ direct === raw
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
      , testProperty "SignKey DirectSerialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
            prop_no_thunks_IO (return $! direct)
      , testProperty "SignKey DirectDeserialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
            prop_no_thunks_IO (directDeserialiseFromBS @IO @(SignKeyDSIGNM v) $! direct)
      , testProperty "VerKey DirectSerialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk <- deriveVerKeyDSIGNM sk
            direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
            prop_no_thunks_IO (return $! direct)
      , testProperty "VerKey DirectDeserialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk <- deriveVerKeyDSIGNM sk
            direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
            prop_no_thunks_IO (directDeserialiseFromBS @IO @(VerKeyDSIGN v) $! direct)
      ]
    ]

-- | Wrap an IO action that requires a 'SignKeyDSIGNM' into one that takes an
-- mlocked seed to generate the key from. The key is bracketed off to ensure
-- timely forgetting. Special care must be taken to not leak the key outside of
-- the wrapped action (be particularly mindful of thunks and unsafe key access
-- here).
withSK :: (DSIGNMAlgorithm v) => PinnedSizedBytes (SeedSizeDSIGN v) -> (SignKeyDSIGNM v -> IO b) -> IO b
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
ioPropertyWithSK :: forall v a. (Testable a, DSIGNMAlgorithm v)
                 => Lock
                 -> (SignKeyDSIGNM v -> IO a)
                 -> PinnedSizedBytes (SeedSizeDSIGN v)
                 -> Property
ioPropertyWithSK lock action seedPSB =
  ioProperty . withLock lock $ withSK seedPSB action

prop_key_overwritten_after_forget
  :: forall v.
     (DSIGNMAlgorithm v
     )
  => Proxy v
  -> PinnedSizedBytes (SeedSizeDSIGN v)
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
     ( DSIGNMAlgorithm v
     )
  => Proxy v
  -> PinnedSizedBytes (SeedSizeDSIGN v)
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
prop_dsign_verify ::
  forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a) =>
  ContextDSIGN v ->
  (a, SignKeyDSIGN v) ->
  Property
prop_dsign_verify ctx (msg, sk) =
  let signed = signDSIGN ctx msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN ctx vk msg signed === Right ()

-- If we sign a message with one key, and try to verify with another, then
-- verification fails.
prop_dsign_verify_wrong_key ::
  forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a) =>
  ContextDSIGN v ->
  (a, SignKeyDSIGN v, SignKeyDSIGN v) ->
  Property
prop_dsign_verify_wrong_key ctx (msg, sk, sk') =
  let signed = signDSIGN ctx msg sk
      vk' = deriveVerKeyDSIGN sk'
    in verifyDSIGN ctx vk' msg signed =/= Right ()

prop_dsignm_verify_pos
  :: forall v. (DSIGNMAlgorithm v, ContextDSIGN v ~ (), Signable v Message)
  => Lock
  -> Proxy v
  -> Message
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> Property
prop_dsignm_verify_pos lock _ msg =
  ioPropertyWithSK @v lock $ \sk -> do
    sig <- signDSIGNM () msg sk
    vk <- deriveVerKeyDSIGNM sk
    return $ verifyDSIGN () vk msg sig === Right ()

-- | If we sign a message @a@ with one signing key, if we try to verify the
-- signature (and message @a@) using a verification key corresponding to a
-- different signing key, then the verification fails.
--
prop_dsignm_verify_neg_key
  :: forall v. (DSIGNMAlgorithm v, ContextDSIGN v ~ (), Signable v Message)
  => Lock
  -> Proxy v
  -> Message
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> Property
prop_dsignm_verify_neg_key lock _ msg seedPSB seedPSB' =
  ioProperty . withLock lock $ do
    sig <- withSK @v seedPSB $ signDSIGNM () msg
    vk' <- withSK @v seedPSB' deriveVerKeyDSIGNM
    return $
      seedPSB /= seedPSB' ==> verifyDSIGN () vk' msg sig =/= Right ()

-- If we sign a message with a key, but then try to verify with a different
-- message, then verification fails.
prop_dsign_verify_wrong_msg ::
  forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a) =>
  ContextDSIGN v ->
  (a, a, SignKeyDSIGN v) ->
  Property
prop_dsign_verify_wrong_msg ctx (msg, msg', sk) =
  let signed = signDSIGN ctx msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN ctx vk msg' signed =/= Right ()

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
      prop_dsign_verify ()
  ]
  where
    genMsg :: Gen MessageHash
    genMsg = hashAndPack (Proxy @h) . messageBytes <$> arbitrary
#endif

prop_dsignm_verify_neg_msg
  :: forall v. (DSIGNMAlgorithm v, ContextDSIGN v ~ (), Signable v Message)
  => Lock
  -> Proxy v
  -> Message
  -> Message
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> Property
prop_dsignm_verify_neg_msg lock _ a a' =
  ioPropertyWithSK @v lock $ \sk -> do
    sig <- signDSIGNM () a sk
    vk <- deriveVerKeyDSIGNM sk
    return $
      a /= a' ==> verifyDSIGN () vk a' sig =/= Right ()

-- TODO: verify that DSIGN and DSIGNM implementations match (see #363)
