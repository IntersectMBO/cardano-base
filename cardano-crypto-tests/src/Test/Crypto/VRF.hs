{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.VRF (
  tests,
)
where

import Cardano.Crypto.Util
import Cardano.Crypto.VRF
import Cardano.Crypto.VRF.Praos
import Cardano.Crypto.VRF.PraosBatchCompat
import qualified Cardano.Crypto.VRF.PraosBatchCompat as Ver13

import qualified Data.ByteString as BS
import qualified Data.Char as Char
import Data.Maybe (fromJust, isJust)
import Data.Proxy (Proxy (..))
import Data.Word (Word64, Word8)
import System.Directory (getCurrentDirectory)
import qualified Text.ParserCombinators.ReadP as Parse
import qualified Text.Read as Read

import Test.Crypto.Util
import Test.QuickCheck (
  Arbitrary (..),
  Gen,
  NonNegative (..),
  Property,
  counterexample,
  (===),
  (==>),
 )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertBool, testCase, (@?=))
import Test.Tasty.QuickCheck (testProperty, vectorOf)

{- HLINT IGNORE "Use <$>" -}
--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup
    "Crypto.VRF"
    [ testVRFAlgorithm (Proxy :: Proxy MockVRF) "MockVRF"
    , testVRFAlgorithm (Proxy :: Proxy SimpleVRF) "SimpleVRF"
    , testVRFAlgorithm (Proxy :: Proxy PraosVRF) "PraosVRF"
    , testVRFAlgorithm (Proxy :: Proxy PraosBatchCompatVRF) "PraosBatchCompatVRF"
    , testGroup
        "OutputVRF"
        [ testProperty "bytesToNatural" prop_bytesToNatural
        , testProperty "naturalToBytes" prop_naturalToBytes
        ]
    , testGroup
        "ConvertingTypes"
        [ testProperty "pubKeyToBatchCompat" prop_pubKeyToBatchComopat
        , testProperty "signKeyToBatchCompat" prop_signKeyToBatchCompat
        , testProperty "outputToBatchCompat" prop_outputToBatchComat
        , testProperty "compatibleVerKeyConversion" prop_verKeyValidConversion
        , testProperty "compatibleSignKeyConversion" prop_signKeyValidConversion
        ]
    , testGroup
        "test vectors for PraosBatchCompat"
        [ testCase "generated golden test vector: vrf_ver13_generated_1" $ checkTestVector "vrf_ver13_generated_1"
        , testCase "generated golden test vector: vrf_ver13_generated_2" $ checkTestVector "vrf_ver13_generated_2"
        , testCase "generated golden test vector: vrf_ver13_generated_3" $ checkTestVector "vrf_ver13_generated_3"
        , testCase "generated golden test vector: vrf_ver13_generated_4" $ checkTestVector "vrf_ver13_generated_4"
        ]
    ]

checkTestVector :: FilePath -> Assertion
checkTestVector file = do
    dir <- getCurrentDirectory
    str <- readFile $ dir <> "/test_vectors/" <> file
    let testVectorE = Read.readMaybe @VRFTestVector str
    assertBool ("parsing test vector: " <> file <> " not successful") $ isJust testVectorE
    let VRFTestVector{..} = fromJust testVectorE
    let (Ver13.SignKeyPraosBatchCompatVRF signKey) = signingKey
    let (Ver13.VerKeyPraosBatchCompatVRF verKey) = verifyingKey
    let bytesEq left right = case left of
            Just left' ->
                Ver13.outputBytes left' @?= Ver13.outputBytes right
            Nothing ->
                assertBool ("left side in byteEq gave Nothing") False

    name @?= algorithmNameVRF (Proxy :: Proxy PraosBatchCompatVRF)
    version @?= "ietfdraft13"
    ciphersuite @?= "ECVRF-ED25519-SHA512-Elligator2"
    -- prove signKey msg -> proof
    Ver13.prove signKey message @?= Just proof
    -- signKey -> verKey
    Ver13.skToVerKey signKey @?= verKey
    -- proof -> hashed msg
    bytesEq (Ver13.outputFromProof proof) hash
    -- verify verKey proof msg -> hashed msg
    bytesEq (Ver13.verify verKey proof message) hash

data VRFTestVector = VRFTestVector
    { name         :: String
    , version      :: String
    , ciphersuite  :: String
    , signingKey   :: Ver13.SignKeyVRF PraosBatchCompatVRF
    , verifyingKey :: Ver13.VerKeyVRF PraosBatchCompatVRF
    , message      :: BS.ByteString
    , proof        :: Ver13.Proof
    , hash         :: Ver13.Output
    }

data HexStringWithLength = HexStringWithLength
    { payload :: String
    , expectedLength :: Int
    } deriving (Show, Eq)

parserHex :: Maybe Int -> Parse.ReadP BS.ByteString
parserHex lenM = do
    str <- parseString
    case lenM of
        Just len -> handleDecode str len
        Nothing -> handleDecode str ((length str) `div` 2)
  where
    handleDecode str size = case decodeHexString str size of
        Right bs -> pure bs
        Left err -> error err

parseKey :: String -> Parse.ReadP String
parseKey key = do
    key' <- Parse.string key
    Parse.skipSpaces
    _ <- Parse.string ":"
    Parse.skipSpaces
    pure key'

parseEOL :: Parse.ReadP ()
parseEOL = Parse.choice
    [ Parse.char '\n' >> return ()
    , Parse.eof
    ]

parseContent :: String -> Parse.ReadP a -> Parse.ReadP a
parseContent key parser =
    Parse.between (parseKey key) parseEOL parser

parseString :: Parse.ReadP String
parseString = Parse.munch1 (\c -> Char.isAlphaNum c || c == '-')

parserVRFTestVector :: Parse.ReadP VRFTestVector
parserVRFTestVector = do
    name <- parseContent "vrf" parseString
    version <- parseContent "ver" parseString
    ciphersuite <- parseContent "ciphersuite" parseString
    sk <- parseContent "sk" $ parserHex (Just 32)
    vk <- parseContent "vk" $ parserHex (Just 32)
    let signingKey = Ver13.SignKeyPraosBatchCompatVRF . Ver13.skFromBytes $ sk <> vk
    let verifyingKey = Ver13.VerKeyPraosBatchCompatVRF $ Ver13.vkFromBytes vk
    message <- parseContent "alpha" $ parserHex Nothing
    proof <- Ver13.proofFromBytes <$> parseContent "pi" (parserHex (Just 128))
    hash <- Ver13.outputFromBytes <$> parseContent "beta" (parserHex (Just 64))
    pure VRFTestVector{..}

instance Read VRFTestVector where
  readsPrec _ = Parse.readP_to_S parserVRFTestVector

testVRFAlgorithm ::
  forall proxy v.
  ( VRFAlgorithm v
  , ToCBOR (VerKeyVRF v)
  , FromCBOR (VerKeyVRF v)
  , ToCBOR (SignKeyVRF v)
  , FromCBOR (SignKeyVRF v)
  , ToCBOR (CertVRF v)
  , FromCBOR (CertVRF v)
  , Eq (SignKeyVRF v) -- no Eq for signing keys normally
  , ContextVRF v ~ ()
  , Signable v ~ SignableRepresentation
  ) =>
  proxy v ->
  String ->
  TestTree
testVRFAlgorithm _ n =
  testGroup
    n
    [ testGroup
        "serialisation"
        [ testGroup
            "raw"
            [ testProperty "VerKey" $
                prop_raw_serialise @(VerKeyVRF v)
                  rawSerialiseVerKeyVRF
                  rawDeserialiseVerKeyVRF
            , testProperty "SignKey" $
                prop_raw_serialise @(SignKeyVRF v)
                  rawSerialiseSignKeyVRF
                  rawDeserialiseSignKeyVRF
            , testProperty "Cert" $
                prop_raw_serialise @(CertVRF v)
                  rawSerialiseCertVRF
                  rawDeserialiseCertVRF
            ]
        , testGroup
            "size"
            [ testProperty "VerKey" $
                prop_size_serialise @(VerKeyVRF v)
                  rawSerialiseVerKeyVRF
                  (sizeVerKeyVRF (Proxy @v))
            , testProperty "SignKey" $
                prop_size_serialise @(SignKeyVRF v)
                  rawSerialiseSignKeyVRF
                  (sizeSignKeyVRF (Proxy @v))
            , testProperty "Cert" $
                prop_size_serialise @(CertVRF v)
                  rawSerialiseCertVRF
                  (sizeCertVRF (Proxy @v))
            ]
        , testGroup
            "direct CBOR"
            [ testProperty "VerKey" $
                prop_cbor_with @(VerKeyVRF v)
                  encodeVerKeyVRF
                  decodeVerKeyVRF
            , testProperty "SignKey" $
                prop_cbor_with @(SignKeyVRF v)
                  encodeSignKeyVRF
                  decodeSignKeyVRF
            , testProperty "Cert" $
                prop_cbor_with @(CertVRF v)
                  encodeCertVRF
                  decodeCertVRF
            ]
        , testGroup
            "To/FromCBOR class"
            [ testProperty "VerKey" $ prop_cbor @(VerKeyVRF v)
            , testProperty "SignKey" $ prop_cbor @(SignKeyVRF v)
            , testProperty "Cert" $ prop_cbor @(CertVRF v)
            ]
        , testGroup
            "ToCBOR size"
            [ testProperty "VerKey" $ prop_cbor_size @(VerKeyVRF v)
            , testProperty "SignKey" $ prop_cbor_size @(SignKeyVRF v)
            , testProperty "Sig" $ prop_cbor_size @(CertVRF v)
            ]
        , testGroup
            "direct matches class"
            [ testProperty "VerKey" $
                prop_cbor_direct_vs_class @(VerKeyVRF v)
                  encodeVerKeyVRF
            , testProperty "SignKey" $
                prop_cbor_direct_vs_class @(SignKeyVRF v)
                  encodeSignKeyVRF
            , testProperty "Cert" $
                prop_cbor_direct_vs_class @(CertVRF v)
                  encodeCertVRF
            ]
        ]
    , testGroup
        "verify"
        [ -- NOTE: we no longer test against maxVRF, because the maximum numeric
          -- value isn't actually what we're interested in, as long as all
          -- keys/hashes have the correct sizes, which 'prop_size_serialise'
          -- tests already.
          testProperty "verify positive" $ prop_vrf_verify_pos @v
        , testProperty "verify negative" $ prop_vrf_verify_neg @v
        ]
    , testGroup
        "output"
        [ testProperty "sizeOutputVRF" $ prop_vrf_output_size @v
        , testProperty "mkTestOutputVRF" $ prop_vrf_output_natural @v
        ]
    , testGroup
        "NoThunks"
        [ testProperty "VerKey" $ prop_no_thunks @(VerKeyVRF v)
        , testProperty "SignKey" $ prop_no_thunks @(SignKeyVRF v)
        , testProperty "Cert" $ prop_no_thunks @(CertVRF v)
        ]
    ]

prop_vrf_verify_pos ::
  forall v.
  ( VRFAlgorithm v
  , ContextVRF v ~ ()
  , Signable v ~ SignableRepresentation
  ) =>
  Message ->
  SignKeyVRF v ->
  Bool
prop_vrf_verify_pos a sk =
  let (y, c) = evalVRF () a sk
      vk = deriveVerKeyVRF sk
   in verifyVRF () vk a c == Just y

prop_vrf_verify_neg ::
  forall v.
  ( VRFAlgorithm v
  , Eq (SignKeyVRF v)
  , ContextVRF v ~ ()
  , Signable v ~ SignableRepresentation
  ) =>
  Message ->
  SignKeyVRF v ->
  SignKeyVRF v ->
  Property
prop_vrf_verify_neg a sk sk' =
  sk
    /= sk'
    ==> let (_y, c) = evalVRF () a sk'
            vk = deriveVerKeyVRF sk
         in verifyVRF () vk a c == Nothing

prop_vrf_output_size ::
  forall v.
  ( VRFAlgorithm v
  , ContextVRF v ~ ()
  , Signable v ~ SignableRepresentation
  ) =>
  Message ->
  SignKeyVRF v ->
  Property
prop_vrf_output_size a sk =
  let (out, _c) = evalVRF () a sk
   in BS.length (getOutputVRFBytes out)
        === fromIntegral (sizeOutputVRF (Proxy :: Proxy v))

prop_vrf_output_natural ::
  forall v.
  ( VRFAlgorithm v
  , ContextVRF v ~ ()
  , Signable v ~ SignableRepresentation
  ) =>
  Message ->
  SignKeyVRF v ->
  Property
prop_vrf_output_natural a sk =
  let (out, _c) = evalVRF () a sk
      n = getOutputVRFNatural out
   in counterexample (show n) $
        mkTestOutputVRF n === out

--
-- Natural <-> bytes conversion
--

prop_bytesToNatural :: [Word8] -> Bool
prop_bytesToNatural ws =
  naturalToBytes (BS.length bs) (bytesToNatural bs) == bs
  where
    bs = BS.pack ws

prop_naturalToBytes :: NonNegative Int -> Word64 -> Property
prop_naturalToBytes (NonNegative sz) n =
  sz >= 8 ==>
    bytesToNatural (naturalToBytes sz (fromIntegral n)) == fromIntegral n

--
-- Praos <-> BatchCompatPraos VerKey conversion
--
prop_pubKeyToBatchComopat :: VerKeyVRF PraosVRF -> Property
prop_pubKeyToBatchComopat vk =
  rawSerialiseVerKeyVRF (vkToBatchCompat vk) === rawSerialiseVerKeyVRF vk

--
-- Praos <-> BatchCompatPraos SignKey conversion
--
prop_signKeyToBatchCompat :: SignKeyVRF PraosVRF -> Property
prop_signKeyToBatchCompat sk =
  rawSerialiseSignKeyVRF (skToBatchCompat sk) === rawSerialiseSignKeyVRF sk

--
-- Praos <-> BatchCompatPraos Output conversion
--
prop_outputToBatchComat :: OutputVRF PraosVRF -> Property
prop_outputToBatchComat output =
  getOutputVRFBytes (outputToBatchCompat output) === getOutputVRFBytes output

--
-- Praos <-> BatchCompatPraos VerKey compatibility. We check that a proof is validated with a
-- transformed key
--
prop_verKeyValidConversion :: SizedSeed 32 -> Message -> Bool
prop_verKeyValidConversion sharedBytes msg =
  let
    vkPraos = deriveVerKeyVRF . genKeyVRF . unSizedSeed $ sharedBytes
    skBatchCompat = genKeyVRF . unSizedSeed $ sharedBytes
    vkBatchCompat = vkToBatchCompat vkPraos
    (y, c) = evalVRF () msg skBatchCompat
   in
    verifyVRF () vkBatchCompat msg c == Just y

--
-- Praos <-> BatchCompatPraos SignKey compatibility. We check that a proof is validated with a
-- transformed key
--
prop_signKeyValidConversion :: SizedSeed 32 -> Bool
prop_signKeyValidConversion sharedBytes =
  let
    skPraos = genKeyVRF . unSizedSeed $ sharedBytes
    skBatchCompat = genKeyVRF . unSizedSeed $ sharedBytes
   in
    skBatchCompat == skToBatchCompat skPraos

--
-- Arbitrary instances
--

instance VRFAlgorithm v => Arbitrary (VerKeyVRF v) where
  arbitrary = deriveVerKeyVRF <$> arbitrary
  shrink = const []

instance VRFAlgorithm v => Arbitrary (SignKeyVRF v) where
  arbitrary = genKeyVRF <$> arbitrarySeedOfSize seedSize
    where
      seedSize = seedSizeVRF (Proxy :: Proxy v)
  shrink = const []

instance
  ( VRFAlgorithm v
  , ContextVRF v ~ ()
  , Signable v ~ SignableRepresentation
  ) =>
  Arbitrary (CertVRF v)
  where
  arbitrary = do
    a <- arbitrary :: Gen Message
    sk <- arbitrary
    return $ snd $ evalVRF () a sk
  shrink = const []

instance VRFAlgorithm v => Arbitrary (OutputVRF v) where
  arbitrary = do
    bytes <- BS.pack <$> vectorOf (fromIntegral (sizeOutputVRF (Proxy :: Proxy v))) arbitrary
    return $ OutputVRF bytes
