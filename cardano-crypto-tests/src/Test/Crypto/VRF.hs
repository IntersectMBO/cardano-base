{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
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
import Data.Proxy (Proxy (..))
import Data.Word (Word64, Word8)

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
import Test.Tasty.HUnit (testCase, (@?=))
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
        "test vectors"
        [ testCase "producing golden test vectors" $
            Golden
            { name = algorithmNameVRF (Proxy :: Proxy PraosBatchCompatVRF)
            , certSize = Ver13.certSizeVRF
            , signKeySize = Ver13.signKeySizeVRF
            , verKeySize = Ver13.verKeySizeVRF
            , vrfKeySize = Ver13.vrfKeySizeVRF
            , seedLen = seedSizeVRF (Proxy :: Proxy PraosBatchCompatVRF)
            , seed = BS.replicate 32 0
            , signingKey = Ver13.skBytes $ snd $ Ver13.keypairFromSeed $
                Ver13.seedFromBytes $
                BS.replicate 32 0
            , verifyingKey = Ver13.vkBytes $ fst $ Ver13.keypairFromSeed $
                Ver13.seedFromBytes $
                BS.replicate 32 0
            , message = unsafeFromRight $ decodeHexString "00" 1
            , proof = Ver13.proofBytes $
                unsafeFromJust $
                Ver13.prove
                (snd $ Ver13.keypairFromSeed $ Ver13.seedFromBytes $ BS.replicate 32 0)
                (unsafeFromRight $ decodeHexString "00" 1)
            , hash = Ver13.outputBytes $
                unsafeFromJust $
                Ver13.verify
                (fst $ Ver13.keypairFromSeed $ Ver13.seedFromBytes $ BS.replicate 32 0)
                (unsafeFromJust $ Ver13.prove (snd $ Ver13.keypairFromSeed $ Ver13.seedFromBytes $ BS.replicate 32 0) (unsafeFromRight $ decodeHexString "00" 1))
                (unsafeFromRight $ decodeHexString "00" 1)
            }
            @?= Golden
            { name = "PraosBatchCompatVRF"
            , certSize = 128
            , signKeySize = 64
            , verKeySize = 32
            , vrfKeySize = 64
            , seedLen = 32
            , seed = unsafeFromRight $
                decodeHexString "0000000000000000000000000000000000000000000000000000000000000000" 32
            , signingKey = unsafeFromRight $
                decodeHexString "00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29" 64
            , verifyingKey = unsafeFromRight $
                decodeHexString "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29" 32
            , message = unsafeFromRight $ decodeHexString "00" 1
            , proof = unsafeFromRight $
                decodeHexString "93d70c5ed59ccb21ca9991be561756939ff9753bf85764d2a7b937d6fbf9183443cd118bee8a0f61e8bdc5403c03d6c94ead31956e98bfd6a5e02d3be5900d17a540852d586f0891caed3e3b0e0871d6a741fb0edcdb586f7f10252f79c35176474ece4936e0190b5167832c10712884ad12acdfff2e434aacb165e1f789660f" 128
            , hash = unsafeFromRight $
                decodeHexString "9a4d34f87003412e413ca42feba3b6158bdf11db41c2bbde98961c5865400cfdee07149b928b376db365c5d68459378b0981f1cb0510f1e0c194c4a17603d44d" 64
            }
        ]
    ]

unsafeFromJust :: Maybe a -> a
unsafeFromJust (Just r) = r
unsafeFromJust _        = error "expecting properly constructed value"

unsafeFromRight :: Either a b -> b
unsafeFromRight (Right r) = r
unsafeFromRight _         = error "expecting properly constructed value"

data Golden = Golden
    { name         :: String
    , certSize     :: Int
    , signKeySize  :: Int
    , verKeySize   :: Int
    , vrfKeySize   :: Int
    , seedLen      :: Word
    , seed         :: BS.ByteString
    , signingKey   :: BS.ByteString
    , verifyingKey :: BS.ByteString
    , message      :: BS.ByteString
    , proof        :: BS.ByteString
    , hash         :: BS.ByteString
    } deriving (Show, Eq)

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
