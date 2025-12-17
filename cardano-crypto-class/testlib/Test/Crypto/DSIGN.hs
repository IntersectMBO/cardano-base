{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
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
  forAllShow,
  ioProperty,
  counterexample,
  )
import Test.Hspec (Spec, describe)
import Test.Hspec.QuickCheck (prop, modifyMaxSuccess)

import qualified Data.ByteString as BS
import Cardano.Crypto.Libsodium

import Text.Show.Pretty (ppShow)

#ifdef SECP256K1_ENABLED
import qualified GHC.Exts as GHC
#endif

import qualified Test.QuickCheck.Gen as Gen
import Data.Kind (Type)
import Data.Proxy (Proxy (..))
import Data.Maybe (fromJust)

import Control.Exception (evaluate, bracket)
import Control.Monad (replicateM)

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
  deriveVerKeyDSIGN,
  genKeyDSIGNM,

  getSeedDSIGNM,
  forgetSignKeyDSIGNM,
  BLS12381CurveConstraints,
  BLS12381DSIGN,

  DSIGNAggregatable (..),
  sizeProofOfPossessionDSIGN,
  encodeProofOfPossessionDSIGN,
  decodeProofOfPossessionDSIGN
  )
import Cardano.Binary (FromCBOR, ToCBOR)
import Cardano.Crypto.EllipticCurve.BLS12_381 (Curve1, Curve2)
import Cardano.Crypto.PinnedSizedBytes (PinnedSizedBytes)
import Cardano.Crypto.DirectSerialise
import Test.Crypto.Util (
  BadInputFor,
  genBadInputFor,
  shrinkBadInputFor,
  Message,
  prop_raw_serialise,
  prop_raw_deserialise,
  prop_size_serialise,
  prop_bad_cbor_bytes,
  prop_cbor_with,
  prop_cbor,
  prop_cbor_size,
  prop_cbor_direct_vs_class,
  prop_no_thunks,
  prop_no_thunks_IO,
  arbitrarySeedOfSize,
  Lock,
  withLock,
  directSerialiseToBS,
  directDeserialiseFromBS,
  hexBS,
  BLS12381SignContext (..),
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

blsSigGen :: forall curve. BLS12381CurveConstraints curve => Gen (SigDSIGN (BLS12381DSIGN curve))
blsSigGen = do
  msg :: Message <- arbitrary
  BLS12381SignContext dst aug :: BLS12381SignContext <- arbitrary
  signDSIGN (dst,aug) msg <$> defaultSignKeyGen @(BLS12381DSIGN curve)

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

defaultProofOfPossessionGen
  :: forall v.
     ( DSIGNAggregatable v
     )
  => Gen (ContextDSIGN v)
  -> Gen (ProofOfPossessionDSIGN v)
defaultProofOfPossessionGen genContext = do
  ctx <- genContext
  sk  <- defaultSignKeyGen @v
  pure $ proveProofOfPossessionDSIGN ctx sk

blsContextGen :: Gen (ContextDSIGN (BLS12381DSIGN curve))
blsContextGen = do
  BLS12381SignContext dst aug <- arbitrary
  pure (dst, aug)

-- Used for adjusting no of quick check tests
-- By default up to 100 tests are performed which may not be enough to catch hidden bugs
testEnough :: Spec -> Spec
testEnough = modifyMaxSuccess (max 10_000)

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}

--
-- The list of all tests
--
tests :: Lock -> Spec
tests lock =
  describe "Crypto.DSIGN" $ do
     describe "Pure" $ do
       testDSIGNAlgorithm mockSigGen (arbitrary @Message) "MockDSIGN"
       testDSIGNAlgorithm ed25519SigGen (arbitrary @Message) "Ed25519DSIGN"
       testDSIGNAlgorithm ed448SigGen (arbitrary @Message) "Ed448DSIGN"
       testDSIGNAlgorithmWithContext (blsContextGen @Curve1) (blsSigGen @Curve1) (arbitrary @Message) "BLS12381MinVerKeyDSIGN"
       testDSIGNAlgorithmWithContext (blsContextGen @Curve2) (blsSigGen @Curve2) (arbitrary @Message) "BLS12381MinSigDSIGN"
#ifdef SECP256K1_ENABLED
       testDSIGNAlgorithm ecdsaSigGen genEcdsaMsg "EcdsaSecp256k1DSIGN"
       testDSIGNAlgorithm schnorrSigGen (arbitrary @Message) "SchnorrSecp256k1DSIGN"
       -- Specific tests related only to ecdsa
       testEcdsaInvalidMessageHash "EcdsaSecp256k1InvalidMessageHash"
       testEcdsaWithHashAlgorithm (Proxy @SHA3_256) "EcdsaSecp256k1WithSHA3_256"
       testEcdsaWithHashAlgorithm (Proxy @Blake2b_256) "EcdsaSecp256k1WithBlake2b_256"
       testEcdsaWithHashAlgorithm (Proxy @SHA256) "EcdsaSecp256k1WithSHA256"
       testEcdsaWithHashAlgorithm (Proxy @Keccak256) "EcdsaSecp256k1WithKeccak256"
#endif
     describe "MLocked" $ do
      testDSIGNMAlgorithm lock (Proxy @Ed25519DSIGN) "Ed25519DSIGN"
     describe "Aggregatable" $ do
      testDSIGNAggregatableWithContext (Proxy @(BLS12381DSIGN Curve1)) (blsContextGen @Curve1) (arbitrary @Message) "BLS12381MinVerKeyDSIGN"
      testDSIGNAggregatableWithContext (Proxy @(BLS12381DSIGN Curve2)) (blsContextGen @Curve2) (arbitrary @Message) "BLS12381MinSigDSIGN"

testDSIGNAlgorithmWithContext :: forall (v :: Type) (a :: Type).
  (DSIGNAlgorithm v,
   Signable v a,
   Show a,
   Show (ContextDSIGN v),
   Eq (SignKeyDSIGN v),
   Eq a,
   ToCBOR (VerKeyDSIGN v),
   FromCBOR (VerKeyDSIGN v),
   ToCBOR (SignKeyDSIGN v),
   FromCBOR (SignKeyDSIGN v),
   ToCBOR (SigDSIGN v),
   FromCBOR (SigDSIGN v)) =>
  Gen (ContextDSIGN v) ->
  Gen (SigDSIGN v) ->
  Gen a ->
  String ->
  Spec
testDSIGNAlgorithmWithContext genContext genSig genMsg name = testEnough . describe name $ do
  describe "serialization" $ do
    describe "raw" $ do
      prop "VerKey serialization" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $
                   prop_raw_serialise rawSerialiseVerKeyDSIGN rawDeserialiseVerKeyDSIGN
      prop "VerKey deserialization (wrong length)" $ prop_raw_deserialise (rawDeserialiseVerKeyDSIGN @v)
      prop "VerKey fail fromCBOR" $ prop_bad_cbor_bytes @(VerKeyDSIGN v)
      prop "SignKey serialization" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $
                   prop_raw_serialise rawSerialiseSignKeyDSIGN rawDeserialiseSignKeyDSIGN
      prop "SignKey deserialization (wrong length)" $ prop_raw_deserialise (rawDeserialiseSignKeyDSIGN @v)
      prop "SignKey fail fromCBOR" $ prop_bad_cbor_bytes @(SignKeyDSIGN v)
      prop "Sig serialization" .
        forAllShow genSig
                   ppShow $
                   prop_raw_serialise rawSerialiseSigDSIGN rawDeserialiseSigDSIGN
      prop "Sig deserialization (wrong length)" $ prop_raw_deserialise (rawDeserialiseSigDSIGN @v)
      prop "VerKey fail fromCBOR" $ prop_bad_cbor_bytes @(SigDSIGN v)
    describe "size" $ do
      prop "VerKey" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $
                   prop_size_serialise rawSerialiseVerKeyDSIGN (sizeVerKeyDSIGN (Proxy @v))
      prop "SignKey" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $
                   prop_size_serialise rawSerialiseSignKeyDSIGN (sizeSignKeyDSIGN (Proxy @v))
      prop "Sig" .
        forAllShow genSig
                   ppShow $
                   prop_size_serialise rawSerialiseSigDSIGN (sizeSigDSIGN (Proxy @v))
    describe "direct CBOR" $ do
      prop "VerKey" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $
                   prop_cbor_with encodeVerKeyDSIGN decodeVerKeyDSIGN
      prop "SignKey" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $
                   prop_cbor_with encodeSignKeyDSIGN decodeSignKeyDSIGN
      prop "Sig" .
        forAllShow genSig
                   ppShow $
                   prop_cbor_with encodeSigDSIGN decodeSigDSIGN
    describe "To/FromCBOR class" $ do
      prop "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_cbor
      prop "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_cbor
      prop "Sig" . forAllShow genSig ppShow $ prop_cbor
    describe "ToCBOR size" $ do
      prop "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_cbor_size
      prop "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_cbor_size
      prop "Sig" . forAllShow genSig ppShow $ prop_cbor_size
    describe "direct matches class" $ do
      prop "VerKey" .
        forAllShow (defaultVerKeyGen @v) ppShow $
        prop_cbor_direct_vs_class encodeVerKeyDSIGN
      prop "SignKey" .
        forAllShow (defaultSignKeyGen @v) ppShow $
        prop_cbor_direct_vs_class encodeSignKeyDSIGN
      prop "Sig" .
        forAllShow genSig ppShow $
        prop_cbor_direct_vs_class encodeSigDSIGN
    describe "verify" $ do
      prop "signing and verifying with matching keys" .
        forAllShow ((,,) <$> genContext <*> genMsg <*> defaultSignKeyGen @v) ppShow $
        prop_dsign_verify
      prop "verifying with wrong key" .
        forAllShow genWrongKey ppShow $
        prop_dsign_verify_wrong_key
      prop "verifying wrong message" .
        forAllShow genWrongMsg ppShow $
        prop_dsign_verify_wrong_msg
    describe "NoThunks" $ do
      prop "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_no_thunks
      prop "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_no_thunks
      prop "Sig" . forAllShow genSig ppShow $ prop_no_thunks
      prop "VerKey rawSerialise" . forAllShow (defaultVerKeyGen @v) ppShow $ \vk ->
        prop_no_thunks (rawSerialiseVerKeyDSIGN vk)
      prop "VerKey rawDeserialise" . forAllShow (defaultVerKeyGen @v) ppShow $ \vk ->
        prop_no_thunks (fromJust $! rawDeserialiseVerKeyDSIGN @v . rawSerialiseVerKeyDSIGN $ vk)
  where
    genWrongKey :: Gen (ContextDSIGN v, a, SignKeyDSIGN v, SignKeyDSIGN v)
    genWrongKey = do
      ctx <- genContext
      sk1 <- defaultSignKeyGen
      sk2 <- Gen.suchThat defaultSignKeyGen (/= sk1)
      msg <- genMsg
      pure (ctx, msg, sk1, sk2)
    genWrongMsg :: Gen (ContextDSIGN v, a, a, SignKeyDSIGN v)
    genWrongMsg = do
      ctx <- genContext
      msg1 <- genMsg
      msg2 <- Gen.suchThat genMsg (/= msg1)
      sk <- defaultSignKeyGen
      pure (ctx, msg1, msg2, sk)

testDSIGNAlgorithm :: forall v a.
  ( DSIGNAlgorithm v
  , Signable v a
  , ContextDSIGN v ~ ()
  , Show a
  , Eq (SignKeyDSIGN v)
  , Eq a
  , ToCBOR (VerKeyDSIGN v)
  , FromCBOR (VerKeyDSIGN v)
  , ToCBOR (SignKeyDSIGN v)
  , FromCBOR (SignKeyDSIGN v)
  , ToCBOR (SigDSIGN v)
  , FromCBOR (SigDSIGN v)
  ) =>
  Gen (SigDSIGN v) ->
  Gen a ->
  String ->
  Spec
testDSIGNAlgorithm = testDSIGNAlgorithmWithContext (pure ())

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
  -> Spec
testDSIGNMAlgorithm lock _ n =
  describe n $ do
     describe "serialisation" $ do
       describe "raw" $ do
         prop "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk <- deriveVerKeyDSIGNM sk
              return $ (rawDeserialiseVerKeyDSIGN . rawSerialiseVerKeyDSIGN $ vk) === Just vk
         prop "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- rawSerialiseSignKeyDSIGNM sk
              bracket
                (rawDeserialiseSignKeyDSIGNM serialized)
                (maybe (return ()) forgetSignKeyDSIGNM)
                (\msk' -> Just sk ==! msk')
         prop "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig <- signDSIGNM () msg sk
              return $ (rawDeserialiseSigDSIGN . rawSerialiseSigDSIGN $ sig) === Just sig
       describe "size" $ do
         prop "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk <- deriveVerKeyDSIGNM sk
              return $ (fromIntegral . BS.length . rawSerialiseVerKeyDSIGN $ vk) === sizeVerKeyDSIGN (Proxy @v)
         prop "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- rawSerialiseSignKeyDSIGNM sk
              evaluate ((fromIntegral . BS.length $ serialized) == sizeSignKeyDSIGN (Proxy @v))
         prop "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ (fromIntegral . BS.length . rawSerialiseSigDSIGN $ sig) === sizeSigDSIGN (Proxy @v)

       describe "direct CBOR" $ do
         prop "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_with encodeVerKeyDSIGN decodeVerKeyDSIGN vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
         prop "Sig" $ \(msg :: Message) -> do
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor_with encodeSigDSIGN decodeSigDSIGN sig

       describe "To/FromCBOR class" $ do
         prop "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
         prop "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor sig

       describe "ToCBOR size" $ do
         prop "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_size vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
         prop "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor_size sig

       describe "direct matches class" $ do
         prop "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_direct_vs_class encodeVerKeyDSIGN vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
         prop "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor_direct_vs_class encodeSigDSIGN sig
       describe "DirectSerialise" $ do
         prop "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              serialized <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
              vk' <- directDeserialiseFromBS serialized
              return $ vk === vk'
         prop "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
              sk' <- directDeserialiseFromBS serialized
              equals <- sk ==! sk'
              forgetSignKeyDSIGNM sk'
              return $
                counterexample ("Serialized: " ++ hexBS serialized ++ " (length: " ++ show (BS.length serialized) ++ ")") $
                equals
       describe "DirectSerialise matches raw" $ do
         prop "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
              let raw = rawSerialiseVerKeyDSIGN vk
              return $ direct === raw
         prop "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
              raw <- rawSerialiseSignKeyDSIGNM sk
              return $ direct === raw

     describe "verify" $ do
       prop "verify positive" $
          prop_dsignm_verify_pos lock (Proxy @v)
       prop "verify negative (wrong key)" $
          prop_dsignm_verify_neg_key lock (Proxy @v)
       prop "verify negative (wrong message)" $
          prop_dsignm_verify_neg_msg lock (Proxy @v)

     describe "seed extraction" $ do
       prop "extracted seed equals original seed" $ prop_dsignm_seed_roundtrip (Proxy @v)

     describe "forgetting" $ do
       prop "key overwritten after forget" $ prop_key_overwritten_after_forget (Proxy @v)

     describe "NoThunks" $ do
       prop "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> prop_no_thunks_IO (deriveVerKeyDSIGNM sk)
       prop "SignKey" $
          ioPropertyWithSK @v lock $ prop_no_thunks_IO . return
       prop "Sig"     $ \(msg :: Message) ->
          ioPropertyWithSK @v lock $ prop_no_thunks_IO . signDSIGNM () msg
       prop "SignKey DirectSerialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
            prop_no_thunks_IO (return $! direct)
       prop "SignKey DirectDeserialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
            prop_no_thunks_IO (directDeserialiseFromBS @IO @(SignKeyDSIGNM v) $! direct)
       prop "VerKey DirectSerialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk <- deriveVerKeyDSIGNM sk
            direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
            prop_no_thunks_IO (return $! direct)
       prop "VerKey DirectDeserialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk <- deriveVerKeyDSIGNM sk
            direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
            prop_no_thunks_IO (directDeserialiseFromBS @IO @(VerKeyDSIGN v) $! direct)

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
prop_dsign_verify
  :: forall (v :: Type) (a :: Type) .
     ( DSIGNAlgorithm v
     , Signable v a
     )
  => (ContextDSIGN v,a, SignKeyDSIGN v)
  -> Property
prop_dsign_verify (ctx, msg, sk) =
  let signed = signDSIGN ctx msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN ctx vk msg signed === Right ()

-- If we sign a message with one key, and try to verify with another, then
-- verification fails.
prop_dsign_verify_wrong_key
  :: forall (v :: Type) (a :: Type) .
     ( DSIGNAlgorithm v
     , Signable v a
     )
  => (ContextDSIGN v, a, SignKeyDSIGN v, SignKeyDSIGN v)
  -> Property
prop_dsign_verify_wrong_key (ctx, msg, sk, sk') =
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
prop_dsign_verify_wrong_msg
  :: forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a)
  => (ContextDSIGN v ,a, a, SignKeyDSIGN v)
  -> Property
prop_dsign_verify_wrong_msg (ctx, msg, msg', sk) =
  let signed = signDSIGN ctx msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN ctx vk msg' signed =/= Right ()

#ifdef SECP256K1_ENABLED
instance Arbitrary (BadInputFor MessageHash) where
  arbitrary = genBadInputFor (fromIntegral (natVal $ Proxy @SECP256K1_ECDSA_MESSAGE_BYTES))
  shrink = shrinkBadInputFor

testEcdsaInvalidMessageHash :: String -> Spec
testEcdsaInvalidMessageHash name = testEnough . describe name $ do
    prop "MessageHash deserialization (wrong length)" $
      prop_raw_deserialise toMessageHash
    prop "MessageHash fail fromCBOR" $ prop_bad_cbor_bytes @MessageHash

testEcdsaWithHashAlgorithm ::
  forall (h :: Type).
  (HashAlgorithm h, SizeHash h ~ SECP256K1_ECDSA_MESSAGE_BYTES) =>
  Proxy h -> String -> Spec
testEcdsaWithHashAlgorithm _ name = testEnough . describe name $ do
  prop "Ecdsa sign and verify" .
    forAllShow ((,,) <$> genContext <*> genMsg <*> defaultSignKeyGen @EcdsaSecp256k1DSIGN) ppShow $
      prop_dsign_verify
  where
    genMsg :: Gen MessageHash
    genMsg = hashAndPack (Proxy @h) . messageBytes <$> arbitrary
    genContext :: Gen (ContextDSIGN EcdsaSecp256k1DSIGN)
    genContext = pure ()

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

-- Tests and instances for DSIGNAggregatable v

instance DSIGNAggregatable v => Arbitrary (BadInputFor (ProofOfPossessionDSIGN v)) where
  arbitrary =
    genBadInputFor (fromIntegral $ sizeProofOfPossessionDSIGN (Proxy @v))
  shrink = shrinkBadInputFor

testDSIGNAggregatableWithContext
  :: forall (v :: Type).
     ( DSIGNAggregatable v
     , Signable v Message
     , Show (ContextDSIGN v)
     , ToCBOR (ProofOfPossessionDSIGN v)
     , FromCBOR (ProofOfPossessionDSIGN v)
     )
  => Proxy v
  -> Gen (ContextDSIGN v)
  -> Gen Message
  -> String
  -> Spec
testDSIGNAggregatableWithContext _ genContext genMsg name = testEnough . describe name $ do
  describe "serialization" $ do
    describe "raw" $ do
      prop "PoP serialization" .
        forAllShow (defaultProofOfPossessionGen @v genContext)
                   ppShow $
                   prop_raw_serialise rawSerialiseProofOfPossessionDSIGN rawDeserialiseProofOfPossessionDSIGN
      prop "PoP deserialization (wrong length)" $ prop_raw_deserialise (rawDeserialiseProofOfPossessionDSIGN @v)
      prop "PoP fail fromCBOR" $ prop_bad_cbor_bytes @(ProofOfPossessionDSIGN v)
    describe "size" $ do
      prop "PoP" .
        forAllShow (defaultProofOfPossessionGen @v genContext)
                   ppShow $
                   prop_size_serialise rawSerialiseProofOfPossessionDSIGN (sizeProofOfPossessionDSIGN (Proxy @v))
    describe "direct CBOR" $ do
      prop "PoP" .
        forAllShow (defaultProofOfPossessionGen @v genContext)
                   ppShow $
                   prop_cbor_with encodeProofOfPossessionDSIGN decodeProofOfPossessionDSIGN
    describe "To/FromCBOR class" $ do
      prop "PoP" . forAllShow (defaultProofOfPossessionGen @v genContext) ppShow $ prop_cbor
    describe "ToCBOR size" $ do
      prop "PoP" . forAllShow (defaultProofOfPossessionGen @v genContext) ppShow $ prop_cbor_size
    describe "direct matches class" $ do
      prop "PoP" .
        forAllShow (defaultProofOfPossessionGen @v genContext) ppShow $
        prop_cbor_direct_vs_class encodeProofOfPossessionDSIGN
  describe "aggregate" $ do
    prop "aggregate verify positive" $
      forAllShow (genAggregateCase genContext genMsg) ppShow $
          \(ctx, msg, vksPops, sigs) ->
            case aggregateSigDSIGN @v sigs of
              Left _  -> counterexample "aggregateSigDSIGN failed" False
              Right s -> verifyAggregateDSIGN @v ctx vksPops msg s === Right ()
    prop "aggregate verify negative (wrong message)" $
      forAllShow (genAggregateCase2Msgs genContext genMsg) ppShow $
        \(ctx, msg, msg', vksPops, sigs) ->
          msg /= msg' ==> case aggregateSigDSIGN @v sigs of
            Left _  -> counterexample "aggregateSigDSIGN failed" False
            Right s -> verifyAggregateDSIGN @v ctx vksPops msg' s =/= Right ()
    prop "aggregate verify negative (wrong PoP)" $
        forAllShow (genAggregateCaseAtLeast2 genContext genMsg) ppShow $
          \(ctx, msg, vksPops, sigs) ->
            case vksPops of
              (a:b:rest) ->
                let vksPops' = (fst a, snd b) : (fst b, snd a) : rest
                in case aggregateSigDSIGN @v sigs of
                    Left _  -> counterexample "aggregateSigDSIGN failed" False
                    Right s -> verifyAggregateDSIGN @v ctx vksPops' msg s =/= Right ()
              _ ->
                counterexample "genAggregateCaseAtLeast2 produced <2 entries (bug in generator)" False
    describe "NoThunks" $ do
      prop "PoP" . forAllShow (defaultProofOfPossessionGen @v genContext) ppShow $ prop_no_thunks
      prop "PoP rawSerialise" . forAllShow (defaultProofOfPossessionGen @v genContext) ppShow $ \pop ->
        prop_no_thunks (rawSerialiseProofOfPossessionDSIGN pop)
      prop "PoP rawDeserialise" . forAllShow (defaultProofOfPossessionGen @v genContext) ppShow $ \pop ->
        prop_no_thunks (fromJust $! rawDeserialiseProofOfPossessionDSIGN @v . rawSerialiseProofOfPossessionDSIGN $ pop)
  where
    genAggregateCase genCtx genMsg' = do
      ctx <- genCtx
      msg <- genMsg'
      -- These crypto operations can be expensive, so limit the number of
      -- signatures to a reasonable number for testing.
      n   <- Gen.chooseInt (1, 8)
      sks <- replicateM n (defaultSignKeyGen @v)
      let vksPops = [ ( deriveVerKeyDSIGN sk
                     , proveProofOfPossessionDSIGN ctx sk
                     )
                   | sk <- sks
                   ]
          sigs = [ signDSIGN ctx msg sk | sk <- sks ]
      pure (ctx, msg, vksPops, sigs)
    genAggregateCase2Msgs genCtx genMsg' = do
      (ctx, msg, vksPops, sigs) <- genAggregateCase genCtx genMsg'
      msg' <- Gen.suchThat genMsg' (/= msg)
      pure (ctx, msg, msg', vksPops, sigs)
    genAggregateCaseAtLeast2 genCtx genMsg' = do
      ctx <- genCtx
      msg <- genMsg'
      -- These crypto operations can be expensive, so limit the number of
      -- signatures to a reasonable number for testing.
      n   <- Gen.chooseInt (2, 8)
      sks <- replicateM n (defaultSignKeyGen @v)
      let vksPops = [ ( deriveVerKeyDSIGN sk
                     , proveProofOfPossessionDSIGN ctx sk
                     )
                   | sk <- sks
                   ]
          sigs = [ signDSIGN ctx msg sk | sk <- sks ]
      pure (ctx, msg, vksPops, sigs)
