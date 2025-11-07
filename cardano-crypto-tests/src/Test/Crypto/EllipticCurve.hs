{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.EllipticCurve
where

import Paths_cardano_crypto_tests

import Test.Crypto.Util (Message (..), eitherShowError)

import qualified Cardano.Crypto.EllipticCurve.BLS12_381 as BLS
import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS
import Cardano.Crypto.Hash (SHA256, digest)
import Cardano.Crypto.Seed
import Data.Bits (shiftL)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import qualified Data.Foldable as F (foldl')
import Data.Proxy (Proxy (..))
import System.IO.Unsafe (unsafePerformIO)
import Test.Crypto.Instances ()
import Test.QuickCheck (
  Arbitrary (..),
  Gen,
  Property,
  choose,
  chooseAny,
  counterexample,
  forAll,
  oneof,
  property,
  suchThat,
  suchThatMap,
  vectorOf,
  (===),
  (==>),
 )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)
import Test.Tasty.QuickCheck (frequency, testProperty)

tests :: TestTree
tests =
  testGroup
    "Crypto.EllipticCurve"
    [ testGroup
        "BLS12_381"
        [ testUtil "Utility"
        , testScalar "Scalar"
        , testBLSCurve "Curve 1" (Proxy @BLS.Curve1)
        , testBLSCurve "Curve 2" (Proxy @BLS.Curve2)
        , testPT "PT"
        , testPairing "Pairing"
        , testVectors "Vectors"
        , testBlsSerDeHelpers "Serialization helpers"
        , testBlsKeyGenIKM "BLS KeyGen / IKM"
        , testBlsSignature "BLS Signature Curve 1" (Proxy @BLS.Curve1)
        , testBlsSignature "BLS Signature Curve 2" (Proxy @BLS.Curve2)
        , testBlsPoP "BLS PoP Curve 1" (Proxy @BLS.Curve1)
        , testBlsPoP "BLS PoP Curve 2" (Proxy @BLS.Curve2)
        ]
    ]

testUtil :: String -> TestTree
testUtil name =
  testGroup
    name
    [ testProperty "Integer / C-String 32 round-trip" $
        \n ->
          n >= 0 ==>
            n < (1 `shiftL` 32 * 8) ==>
              n === unsafePerformIO (BLS.integerAsCStrL 32 n BLS.cstrToInteger)
    , testProperty "padBS min length" $ \n bsw ->
        BS.length (BLS.padBS n (BS.pack bsw)) >= n
    , testProperty "padBS adds zeroes to front" $ \bsw ->
        BS.index (BLS.padBS (length bsw + 1) (BS.pack bsw)) 0 === 0
    , testCase "integerToBS" $ do
        assertEqual "0x1234" (BS.pack [0x12, 0x34]) (BLS.integerToBS 0x1234)
        assertEqual "0x12345678" (BS.pack [0x12, 0x34, 0x56, 0x78]) (BLS.integerToBS 0x12345678)
    ]

testScalar :: String -> TestTree
testScalar name =
  testGroup
    name
    [ testProperty "self-equality" $
        \(a :: BLS.Scalar) -> a === a
    , testProperty "to/from BS round-trip" $
        \s -> Right s === (BLS.scalarFromBS . BLS.scalarToBS $ s)
    , testProperty "non-negative" $
        \s -> (unsafePerformIO . BLS.scalarToInteger $ s) >= 0
    , testProperty "to/from Integer round-trip" $
        \s -> s === unsafePerformIO (BLS.scalarToInteger s >>= BLS.scalarFromInteger)
    , testCase "integer from scalar" $ do
        s <- case BLS.scalarFromBS (BLS.padBS 32 (BS.pack [0x12, 0x34])) of
          Left err -> error (show err)
          Right x -> return x
        let expected = 0x1234
        actual <- BLS.scalarToInteger s
        assertEqual "0x1234" expected actual
    ]

testBLSCurve ::
  forall curve.
  BLS.BLS curve =>
  String -> Proxy curve -> TestTree
testBLSCurve name _ =
  testGroup
    name
    [ testCase "generator in group" $
        assertBool "" (BLS.blsInGroup (BLS.blsGenerator @curve))
    , testCase "neg generator in group" $
        assertBool "" (BLS.blsInGroup (BLS.blsNeg (BLS.blsGenerator @curve)))
    , testCase "add generator to itself" $
        assertBool
          ""
          (BLS.blsInGroup (BLS.blsAddOrDouble (BLS.blsGenerator @curve) (BLS.blsGenerator @curve)))
    , testProperty "in group" (BLS.blsInGroup @curve)
    , testProperty "neg in group" (BLS.blsInGroup @curve . BLS.blsNeg)
    , testProperty "self-equality" (\(a :: BLS.Point curve) -> a === a)
    , testProperty "double negation" (\(a :: BLS.Point curve) -> a === BLS.blsNeg (BLS.blsNeg a))
    , testProperty
        "adding infinity yields equality"
        (\(a :: BLS.Point curve) -> BLS.blsAddOrDouble a (BLS.blsZero @curve) === a)
    , testProperty
        "addition associative"
        (testAssoc (BLS.blsAddOrDouble :: BLS.Point curve -> BLS.Point curve -> BLS.Point curve))
    , testProperty
        "addition commutative"
        (testCommut (BLS.blsAddOrDouble :: BLS.Point curve -> BLS.Point curve -> BLS.Point curve))
    , testProperty "adding negation yields infinity" (testAddNegYieldsInf @curve)
    , testProperty "round-trip serialization" $
        testRoundTripEither @(BLS.Point curve) BLS.blsSerialize BLS.blsDeserialize
    , testProperty "round-trip compression" $
        testRoundTripEither @(BLS.Point curve) BLS.blsCompress BLS.blsUncompress
    , testProperty "mult by p is inf" $ \(a :: BLS.Point curve) ->
        BLS.blsIsInf (BLS.blsMult a BLS.scalarPeriod)
    , testProperty "mult by p+1 is identity" $ \(a :: BLS.Point curve) ->
        BLS.blsMult a (BLS.scalarPeriod + 1) === a
    , testProperty "scalar mult associative" $ \(a :: BLS.Point curve) (BigInteger b) (BigInteger c) ->
        BLS.blsMult (BLS.blsMult a b) c === BLS.blsMult (BLS.blsMult a c) b
    , testProperty "scalar mult distributive left" $ \(a :: BLS.Point curve) (BigInteger b) (BigInteger c) ->
        BLS.blsMult a (b + c) === BLS.blsAddOrDouble (BLS.blsMult a b) (BLS.blsMult a c)
    , testProperty "scalar mult distributive right" $ \(a :: BLS.Point curve) (b :: BLS.Point curve) (BigInteger c) ->
        BLS.blsMult (BLS.blsAddOrDouble a b) c === BLS.blsAddOrDouble (BLS.blsMult a c) (BLS.blsMult b c)
    , testProperty "MSM matches naive approach" $ \(ssAndPs :: [(BigInteger, BLS.Point curve)]) ->
        let pairs = [(i, p) | (BigInteger i, p) <- ssAndPs]
         in BLS.blsMSM pairs
              === foldr (\(s, p) acc -> BLS.blsAddOrDouble acc (BLS.blsMult p s)) (BLS.blsZero @curve) pairs
    , testProperty "mult by zero is inf" $ \(a :: BLS.Point curve) ->
        BLS.blsIsInf (BLS.blsMult a 0)
    , testProperty "mult by -1 is equal to neg" $ \(a :: BLS.Point curve) ->
        BLS.blsMult a (-1) === BLS.blsNeg a
    , testProperty "modular multiplication" $ \(BigInteger a) (BigInteger b) (p :: BLS.Point curve) ->
        BLS.blsMult p a === BLS.blsMult p (a + b * BLS.scalarPeriod)
    , testProperty "repeated addition" (prop_repeatedAddition @curve)
    , testCase "zero is inf" $ assertBool "Zero is at infinity" (BLS.blsIsInf (BLS.blsZero @curve))
    ]

testPT :: String -> TestTree
testPT name =
  testGroup
    name
    [ testProperty
        "mult associative"
        (testAssoc BLS.ptMult)
    , testProperty
        "mult commutative"
        (testCommut BLS.ptMult)
    , testProperty "self-equality" (\(a :: BLS.PT) -> a === a)
    , testProperty "self-final-verify" (\(a :: BLS.PT) -> BLS.ptFinalVerify a a)
    ]

testPairing :: String -> TestTree
testPairing name =
  testGroup
    name
    [ testProperty "identity" $ \a b ->
        pairingCheck
          (a, b)
          (a, b)
    , testProperty "simple" $ \a p q ->
        pairingCheck
          (BLS.blsMult p a, q)
          (p, BLS.blsMult q a)
    , testProperty "crossover" $ \a b p q ->
        pairingCheck
          (BLS.blsMult p a, BLS.blsMult q b)
          (BLS.blsMult p b, BLS.blsMult q a)
    , testProperty "shift" $ \a b p q ->
        pairingCheck
          (BLS.blsMult p (a * b), q)
          (BLS.blsMult p a, BLS.blsMult q b)
    , testProperty "three pairings" prop_threePairings
    , testProperty "four pairings" prop_fourPairings
    , testProperty "finalVerify fails on random inputs" prop_randomFailsFinalVerify
    ]
  where
    pairingCheck (a, b) (c, d) = BLS.ptFinalVerify (BLS.millerLoop a b) (BLS.millerLoop c d)

loadHexFile :: String -> IO [BS.ByteString]
loadHexFile filename = do
  mapM (either error pure . Base16.decode . BS8.filter (/= '\r')) . BS8.lines =<< BS.readFile filename

-- Generators to avoid discards in negative tests
-- Produce two Messages with different underlying bytes
genDistinctMessages :: Gen (Message, Message)
genDistinctMessages = do
  a <- arbitrary
  b <- arbitrary `suchThat` (\x -> messageBytes x /= messageBytes a)
  pure (a, b)

testVectors :: String -> TestTree
testVectors name =
  testGroup
    name
    [ testVectorPairings "pairings"
    , testVectorOperations "operations"
    , testVectorSerDe "serialization/compression"
    , testVectorSigAug "signature"
    , testVectorLargeDst "large-dst"
    ]

testVectorPairings :: String -> TestTree
testVectorPairings name =
  testCase name $ do
    [ p_raw
      , aP_raw
      , bP_raw
      , apbP_raw
      , axbP_raw
      , q_raw
      , aQ_raw
      , bQ_raw
      , apbQ_raw
      , axbQ_raw
      ] <-
      loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/pairing_test_vectors"

    p <- eitherShowError $ BLS.blsUncompress p_raw
    q <- eitherShowError $ BLS.blsUncompress q_raw
    aP <- eitherShowError $ BLS.blsUncompress aP_raw
    aQ <- eitherShowError $ BLS.blsUncompress aQ_raw
    bP <- eitherShowError $ BLS.blsUncompress bP_raw
    bQ <- eitherShowError $ BLS.blsUncompress bQ_raw
    apbP <- eitherShowError $ BLS.blsUncompress apbP_raw
    axbP <- eitherShowError $ BLS.blsUncompress axbP_raw
    apbQ <- eitherShowError $ BLS.blsUncompress apbQ_raw
    axbQ <- eitherShowError $ BLS.blsUncompress axbQ_raw

    assertBool "e([a]P, Q) = e(P, [a]Q)" $
      BLS.ptFinalVerify
        (BLS.millerLoop aP q)
        (BLS.millerLoop p aQ)
    assertBool "e([a]P, [b]Q) = e([b]P, [a]Q)" $
      BLS.ptFinalVerify
        (BLS.millerLoop aP bQ)
        (BLS.millerLoop bP aQ)
    assertBool "e([a]P, [b]Q) = e([a * b]P, Q)" $
      BLS.ptFinalVerify
        (BLS.millerLoop aP bQ)
        (BLS.millerLoop axbP q)
    assertBool "e([a]P, Q) * e([b]P, Q) = e([a + b]P, Q)" $
      BLS.ptFinalVerify
        (BLS.ptMult (BLS.millerLoop aP q) (BLS.millerLoop bP q))
        (BLS.millerLoop apbP q)
    assertBool "e([a]P, [b]Q) = e(P, [a * b]Q)" $
      BLS.ptFinalVerify
        (BLS.millerLoop aP bQ)
        (BLS.millerLoop p axbQ)
    assertBool "e(P, [a]Q) * e(P, [b]Q) = e(P, [a + b]Q)" $
      BLS.ptFinalVerify
        (BLS.ptMult (BLS.millerLoop p aQ) (BLS.millerLoop p bQ))
        (BLS.millerLoop p apbQ)

testVectorOperations :: String -> TestTree
testVectorOperations name =
  testCase name $ do
    [ g1p_raw
      , g1q_raw
      , g1add_raw
      , g1sub_raw
      , g1mul_raw
      , g1neg_raw
      , g2p_raw
      , g2q_raw
      , g2add_raw
      , g2sub_raw
      , g2mul_raw
      , g2neg_raw
      ] <-
      loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/ec_operations_test_vectors"

    let scalar = 0x40df499974f62e2f268cd5096b0d952073900054122ffce0a27c9d96932891a5
    g1p :: BLS.Point1 <- eitherShowError $ BLS.blsUncompress g1p_raw
    g1q :: BLS.Point1 <- eitherShowError $ BLS.blsUncompress g1q_raw
    g1add :: BLS.Point1 <- eitherShowError $ BLS.blsUncompress g1add_raw
    g1sub :: BLS.Point1 <- eitherShowError $ BLS.blsUncompress g1sub_raw
    g1mul :: BLS.Point1 <- eitherShowError $ BLS.blsUncompress g1mul_raw
    g1neg :: BLS.Point1 <- eitherShowError $ BLS.blsUncompress g1neg_raw
    g2p :: BLS.Point2 <- eitherShowError $ BLS.blsUncompress g2p_raw
    g2q :: BLS.Point2 <- eitherShowError $ BLS.blsUncompress g2q_raw
    g2add :: BLS.Point2 <- eitherShowError $ BLS.blsUncompress g2add_raw
    g2sub :: BLS.Point2 <- eitherShowError $ BLS.blsUncompress g2sub_raw
    g2mul :: BLS.Point2 <- eitherShowError $ BLS.blsUncompress g2mul_raw
    g2neg :: BLS.Point2 <- eitherShowError $ BLS.blsUncompress g2neg_raw

    assertEqual
      "g1 add"
      g1add
      (BLS.blsAddOrDouble g1p g1q)
    assertEqual
      "g1 sub"
      g1sub
      (BLS.blsAddOrDouble g1p (BLS.blsNeg g1q))
    assertEqual
      "g1 mul"
      g1mul
      (BLS.blsMult g1q scalar)
    assertEqual
      "g1 neg"
      g1neg
      (BLS.blsNeg g1p)

    assertEqual
      "g2 add"
      g2add
      (BLS.blsAddOrDouble g2p g2q)
    assertEqual
      "g2 sub"
      g2sub
      (BLS.blsAddOrDouble g2p (BLS.blsNeg g2q))
    assertEqual
      "g2 mul"
      g2mul
      (BLS.blsMult g2q scalar)
    assertEqual
      "g2 neg"
      g2neg
      (BLS.blsNeg g2p)

testVectorSerDe :: String -> TestTree
testVectorSerDe name =
  testCase name $ do
    [ g1UncompNotOnCurve
      , g1CompNotOnCurve
      , g1CompNotInGroup
      , g1UncompNotInGroup
      , g2UncompNotOnCurve
      , g2CompNotOnCurve
      , g2CompNotInGroup
      , g2UncompNotInGroup
      ] <-
      loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/serde_test_vectors"

    assertEqual
      "g1UncompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsDeserialize g1UncompNotOnCurve :: Either BLS.BLSTError BLS.Point1)

    assertEqual
      "g1CompNotInGroup"
      (Left BLS.BLST_POINT_NOT_IN_GROUP)
      (BLS.blsUncompress g1CompNotInGroup :: Either BLS.BLSTError BLS.Point1)

    assertEqual
      "g1CompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsUncompress g1CompNotOnCurve :: Either BLS.BLSTError BLS.Point1)

    assertEqual
      "g1UncompNotInGroup"
      (Left BLS.BLST_POINT_NOT_IN_GROUP)
      (BLS.blsDeserialize g1UncompNotInGroup :: Either BLS.BLSTError BLS.Point1)

    assertEqual
      "g2UncompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsDeserialize g2UncompNotOnCurve :: Either BLS.BLSTError BLS.Point2)

    assertEqual
      "g2CompNotInGroup"
      (Left BLS.BLST_POINT_NOT_IN_GROUP)
      (BLS.blsUncompress g2CompNotInGroup :: Either BLS.BLSTError BLS.Point2)

    assertEqual
      "g2CompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsUncompress g2CompNotOnCurve :: Either BLS.BLSTError BLS.Point2)

    assertEqual
      "g2UncompNotInGroup"
      (Left BLS.BLST_POINT_NOT_IN_GROUP)
      (BLS.blsDeserialize g2UncompNotInGroup :: Either BLS.BLSTError BLS.Point2)

testVectorSigAug :: String -> TestTree
testVectorSigAug name =
  testCase name $ do
    [sig_raw, pk_raw] <-
      loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/bls_sig_aug_test_vectors"
    let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
    let msg = "blst is such a blast"
    let aug = "Random value for test aug. "
    let hashedMsg = BLS.blsHash (aug <> msg) (Just dst) Nothing
    sig <- eitherShowError $ BLS.blsUncompress sig_raw
    pk <- eitherShowError $ BLS.blsUncompress pk_raw

    assertBool "valid signature" $
      BLS.ptFinalVerify
        (BLS.millerLoop sig BLS.blsGenerator)
        (BLS.millerLoop hashedMsg pk)

testVectorLargeDst :: String -> TestTree
testVectorLargeDst name =
  testCase name $ do
    [msg_raw, large_dst_raw, output_raw] <-
      loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/h2c_large_dst"
    let prefix = "H2C-OVERSIZE-DST-"
    let dst_sha = digest (Proxy @SHA256) (prefix <> large_dst_raw)
    let hashedMsg = BLS.blsHash msg_raw (Just dst_sha) Nothing
    expected_output :: BLS.Point1 <- eitherShowError $ BLS.blsUncompress output_raw

    assertEqual
      "expected hash output"
      hashedMsg
      expected_output

-- Low-level serialization helpers round-trips & guards (Internal.hs)
-- This validates secret/public key & signature byte encodings before DSIGN wiring.

testBlsSerDeHelpers :: String -> TestTree
testBlsSerDeHelpers name =
  testGroup
    name
    [ -- Secret keys -----------------------------------------------------------
      testProperty "SecretKey rejects bad length" $
        forAll genSecretKey $ \sk ->
          let bs = BLS.secretKeyToBS sk
              res =
                ( BLS.secretKeyFromBS (shorten bs)
                , BLS.secretKeyFromBS (lengthen bs)
                )
           in case res of
                (a, b) -> isBadScalar a && isBadScalar b
    , -- Public keys -----------------------------------------------------------
      testProperty "SecretKey class round-trip" $
        forAll genSecretKey $ \sk ->
          fmap BLS.toCompressedBytes (BLS.fromCompressedBytes @BLS.SecretKey (BLS.toCompressedBytes sk))
            === Right (BLS.toCompressedBytes sk)
    , testProperty "PublicKey class round-trip (Curve1)" $
        forAll genSecretKey $ \sk ->
          let pk = BLS.blsSkToPk @BLS.Curve1 sk
           in fmap
                BLS.toCompressedBytes
                (BLS.fromCompressedBytes @(BLS.PublicKey BLS.Curve1) (BLS.toCompressedBytes pk))
                === Right (BLS.toCompressedBytes pk)
    , testProperty "PublicKey class round-trip (Curve2)" $
        forAll genSecretKey $ \sk ->
          let pk = BLS.blsSkToPk @BLS.Curve2 sk
           in fmap
                BLS.toCompressedBytes
                (BLS.fromCompressedBytes @(BLS.PublicKey BLS.Curve2) (BLS.toCompressedBytes pk))
                === Right (BLS.toCompressedBytes pk)
    , testCase "PublicKey rejects infinity (Curve1) [compressed & uncompressed]" $ do
        let cbs = BLS.blsCompress (BLS.blsZero @BLS.Curve1)
            ubs = BLS.blsSerialize (BLS.blsZero @BLS.Curve1)
        assertBool
          "expected BLST_PK_IS_INFINITY"
          ( bothInfinity
              ( BLS.publicKeyFromCompressedBS @BLS.Curve1 cbs
              , BLS.publicKeyFromUncompressedBS @BLS.Curve1 ubs
              )
          )
    , testCase "PublicKey rejects infinity (Curve2) [compressed & uncompressed]" $ do
        let cbs = BLS.blsCompress (BLS.blsZero @BLS.Curve2)
            ubs = BLS.blsSerialize (BLS.blsZero @BLS.Curve2)
        assertBool
          "expected BLST_PK_IS_INFINITY"
          ( bothInfinity
              ( BLS.publicKeyFromCompressedBS @BLS.Curve2 cbs
              , BLS.publicKeyFromUncompressedBS @BLS.Curve2 ubs
              )
          )
    , -- Signatures ------------------------------------------------------------
      testCase "Signature rejects infinity (Curve1) [compressed & uncompressed]" $ do
        let cbs = BLS.blsCompress (BLS.blsZero @(BLS.Dual BLS.Curve1))
            ubs = BLS.blsSerialize (BLS.blsZero @(BLS.Dual BLS.Curve1))
        assertBool
          "expected BLST_PK_IS_INFINITY"
          ( bothInfinity
              ( BLS.signatureFromCompressedBS @BLS.Curve1 cbs
              , BLS.signatureFromUncompressedBS @BLS.Curve1 ubs
              )
          )
    , testCase "Signature rejects infinity (Curve2) [compressed & uncompressed]" $ do
        let cbs = BLS.blsCompress (BLS.blsZero @(BLS.Dual BLS.Curve2))
            ubs = BLS.blsSerialize (BLS.blsZero @(BLS.Dual BLS.Curve2))
        assertBool
          "expected BLST_PK_IS_INFINITY"
          ( bothInfinity
              ( BLS.signatureFromCompressedBS @BLS.Curve2 cbs
              , BLS.signatureFromUncompressedBS @BLS.Curve2 ubs
              )
          )
    , testProperty "Signature class round-trip (Curve1 sigs on G2)" $
        forAll genSecretKey $ \sk ->
          let sig = BLS.blsSign @BLS.Curve1 Proxy sk "hello" Nothing Nothing
           in fmap
                BLS.toCompressedBytes
                (BLS.fromCompressedBytes @(BLS.Signature BLS.Curve1) (BLS.toCompressedBytes sig))
                === Right (BLS.toCompressedBytes sig)
    , testProperty "Signature class round-trip (Curve2 sigs on G1)" $
        forAll genSecretKey $ \sk ->
          let sig = BLS.blsSign @BLS.Curve2 Proxy sk "world" Nothing Nothing
           in fmap
                BLS.toCompressedBytes
                (BLS.fromCompressedBytes @(BLS.Signature BLS.Curve2) (BLS.toCompressedBytes sig))
                === Right (BLS.toCompressedBytes sig)
    , testProperty "PublicKey class cross-group bytes rejected (Curve1 expects G1)" $
        forAll genSecretKey $ \sk ->
          let bs = BLS.toCompressedBytes (BLS.blsSkToPk @BLS.Curve2 sk)
              expected = BLS.compressedLength (Proxy @(BLS.PublicKey BLS.Curve1))
           in expectSerdeError
                (BLS.fromCompressedBytes @(BLS.PublicKey BLS.Curve1) bs)
                (BLS.BLSDeserializeWrongLength expected (BS.length bs))
    , testProperty "PublicKey class cross-group bytes rejected (Curve2 expects G2)" $
        forAll genSecretKey $ \sk ->
          let bs = BLS.toCompressedBytes (BLS.blsSkToPk @BLS.Curve1 sk)
              expected = BLS.compressedLength (Proxy @(BLS.PublicKey BLS.Curve2))
           in expectSerdeError
                (BLS.fromCompressedBytes @(BLS.PublicKey BLS.Curve2) bs)
                (BLS.BLSDeserializeWrongLength expected (BS.length bs))
    , testProperty "PublicKey uncompressed class round-trip (Curve1)" $
        forAll genSecretKey $ \sk ->
          let pk = BLS.blsSkToPk @BLS.Curve1 sk
           in fmap
                BLS.toUncompressedBytes
                (BLS.fromUncompressedBytes @(BLS.PublicKey BLS.Curve1) (BLS.toUncompressedBytes pk))
                === Right (BLS.toUncompressedBytes pk)
    , testProperty "PublicKey uncompressed class round-trip (Curve2)" $
        forAll genSecretKey $ \sk ->
          let pk = BLS.blsSkToPk @BLS.Curve2 sk
           in fmap
                BLS.toUncompressedBytes
                (BLS.fromUncompressedBytes @(BLS.PublicKey BLS.Curve2) (BLS.toUncompressedBytes pk))
                === Right (BLS.toUncompressedBytes pk)
    , testProperty "PublicKey uncompressed class cross-group bytes rejected (Curve1 expects G1)" $
        forAll genSecretKey $ \sk ->
          let bs = BLS.toUncompressedBytes (BLS.blsSkToPk @BLS.Curve2 sk)
              expected = BLS.uncompressedLength (Proxy @(BLS.PublicKey BLS.Curve1))
           in expectSerdeError
                (BLS.fromUncompressedBytes @(BLS.PublicKey BLS.Curve1) bs)
                (BLS.BLSDeserializeWrongLength expected (BS.length bs))
    , testProperty "PublicKey uncompressed class cross-group bytes rejected (Curve2 expects G2)" $
        forAll genSecretKey $ \sk ->
          let bs = BLS.toUncompressedBytes (BLS.blsSkToPk @BLS.Curve1 sk)
              expected = BLS.uncompressedLength (Proxy @(BLS.PublicKey BLS.Curve2))
           in expectSerdeError
                (BLS.fromUncompressedBytes @(BLS.PublicKey BLS.Curve2) bs)
                (BLS.BLSDeserializeWrongLength expected (BS.length bs))
    , testProperty "Signature class cross-group bytes rejected (Curve1 expects G2)" $
        forAll genSecretKey $ \sk ->
          let sig = BLS.blsSign @BLS.Curve2 Proxy sk "x" Nothing Nothing
              bs = BLS.toCompressedBytes sig
              expected = BLS.compressedLength (Proxy @(BLS.Signature BLS.Curve1))
           in expectSerdeError
                (BLS.fromCompressedBytes @(BLS.Signature BLS.Curve1) bs)
                (BLS.BLSDeserializeWrongLength expected (BS.length bs))
    , testProperty "Signature class cross-group bytes rejected (Curve2 expects G1)" $
        forAll genSecretKey $ \sk ->
          let sig = BLS.blsSign @BLS.Curve1 Proxy sk "y" Nothing Nothing
              bs = BLS.toCompressedBytes sig
              expected = BLS.compressedLength (Proxy @(BLS.Signature BLS.Curve2))
           in expectSerdeError
                (BLS.fromCompressedBytes @(BLS.Signature BLS.Curve2) bs)
                (BLS.BLSDeserializeWrongLength expected (BS.length bs))
    , testProperty "Signature uncompressed class round-trip (Curve1 sigs on G2)" $
        forAll genSecretKey $ \sk ->
          let sig = BLS.blsSign @BLS.Curve1 Proxy sk "hello" Nothing Nothing
           in fmap
                BLS.toUncompressedBytes
                (BLS.fromUncompressedBytes @(BLS.Signature BLS.Curve1) (BLS.toUncompressedBytes sig))
                === Right (BLS.toUncompressedBytes sig)
    , testProperty "Signature uncompressed class round-trip (Curve2 sigs on G1)" $
        forAll genSecretKey $ \sk ->
          let sig = BLS.blsSign @BLS.Curve2 Proxy sk "world" Nothing Nothing
           in fmap
                BLS.toUncompressedBytes
                (BLS.fromUncompressedBytes @(BLS.Signature BLS.Curve2) (BLS.toUncompressedBytes sig))
                === Right (BLS.toUncompressedBytes sig)
    , testProperty "Signature uncompressed class cross-group bytes rejected (Curve1 expects G2)" $
        forAll genSecretKey $ \sk ->
          let sig = BLS.blsSign @BLS.Curve2 Proxy sk "x" Nothing Nothing
              bs = BLS.toUncompressedBytes sig
              expected = BLS.uncompressedLength (Proxy @(BLS.Signature BLS.Curve1))
           in expectSerdeError
                (BLS.fromUncompressedBytes @(BLS.Signature BLS.Curve1) bs)
                (BLS.BLSDeserializeWrongLength expected (BS.length bs))
    , testProperty "Signature uncompressed class cross-group bytes rejected (Curve2 expects G1)" $
        forAll genSecretKey $ \sk ->
          let sig = BLS.blsSign @BLS.Curve1 Proxy sk "y" Nothing Nothing
              bs = BLS.toUncompressedBytes sig
              expected = BLS.uncompressedLength (Proxy @(BLS.Signature BLS.Curve2))
           in expectSerdeError
                (BLS.fromUncompressedBytes @(BLS.Signature BLS.Curve2) bs)
                (BLS.BLSDeserializeWrongLength expected (BS.length bs))
    , testProperty "Signature length corruption is rejected (Curve2 compressed)" $
        forAll genSecretKey $ \sk ->
          let sig = BLS.blsSign @BLS.Curve2 Proxy sk "!" Nothing Nothing
              bs = BLS.signatureToCompressedBS @BLS.Curve2 sig
              res =
                ( BLS.signatureFromCompressedBS @BLS.Curve2 (shorten bs)
                , BLS.signatureFromCompressedBS @BLS.Curve2 (lengthen bs)
                )
           in bothBadEncoding res
    ]

-- Generators and small helpers used above ------------------------------------

genIKM32 :: Gen BS.ByteString
genIKM32 = BS.pack <$> vectorOf 32 arbitrary

-- Deterministic SK via blsKeyGen(IKM, Nothing) for tests
-- (Retries are extremely unlikely to be needed.)
genSecretKey :: Gen BLS.SecretKey
genSecretKey = do
  ikm <- genIKM32
  case BLS.blsKeyGen ikm Nothing of
    Right sk -> pure sk
    Left _ -> genSecretKey

shorten :: BS.ByteString -> BS.ByteString
shorten bs
  | BS.null bs = bs
  | otherwise = BS.init bs

lengthen :: BS.ByteString -> BS.ByteString
lengthen bs = bs <> BS.singleton 0x00

bothInfinity :: (Either BLS.BLSTError a, Either BLS.BLSTError b) -> Bool
bothInfinity (Left BLS.BLST_PK_IS_INFINITY, Left BLS.BLST_PK_IS_INFINITY) = True
bothInfinity _ = False

bothBadEncoding :: (Either BLS.BLSTError a, Either BLS.BLSTError b) -> Bool
bothBadEncoding (Left BLS.BLST_BAD_ENCODING, Left BLS.BLST_BAD_ENCODING) = True
bothBadEncoding _ = False

expectSerdeError ::
  Either BLS.BLSDeserializeError a ->
  BLS.BLSDeserializeError ->
  Property
expectSerdeError result expected =
  case result of
    Left err | err == expected -> property True
    Left err ->
      counterexample ("expected " ++ show expected ++ ", got " ++ show err) (property False)
    Right _ ->
      counterexample ("expected " ++ show expected ++ ", got successful decode") (property False)

-- Property helper: round-trip via bytes (to keep tests concise)
propRoundTripBytes ::
  (Eq e, Show e) =>
  (a -> BS.ByteString) ->
  (BS.ByteString -> Either e a) ->
  a ->
  Property
propRoundTripBytes toBS fromBS x =
  Right (toBS x) === fmap toBS (fromBS (toBS x))

isBadScalar :: Either BLS.BLSTError a -> Bool
isBadScalar (Left BLS.BLST_BAD_SCALAR) = True
isBadScalar _ = False

testBlsKeyGenIKM :: String -> TestTree
testBlsKeyGenIKM name =
  testGroup
    name
    [ testCase "Same (IKM, info) -> same sk" $ do
        -- fixed IKM + info
        let ikm = BS.replicate 32 0x11
            info = "keygen-info"
        let sk1 = BLS.blsKeyGen ikm (Just info)
            sk2 = BLS.blsKeyGen ikm (Just info)
        case (sk1, sk2) of
          (Right s1, Right s2) -> do
            i1 <- BLS.scalarToInteger (BLS.unSecretKey s1)
            i2 <- BLS.scalarToInteger (BLS.unSecretKey s2)
            assertBool "Secret keys differ but should be identical" (i1 == i2)
          _ -> assertBool "KeyGen failed unexpectedly" False
    , testProperty
        "Deterministic pk derivation (sk -> pk)"
        ( \(seed :: Seed, info :: Message) ->
            case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
              Left _ -> True
              Right sk' ->
                let pk1 = BLS.blsSkToPk @BLS.Curve1 sk'
                    pk2 = BLS.blsSkToPk @BLS.Curve1 sk'
                 in BLS.unPublicKey pk1 == BLS.unPublicKey pk2
        )
    ]

testBlsSignature ::
  forall curve.
  BLS.FinalVerifyOrder curve => String -> Proxy curve -> TestTree
testBlsSignature name curve =
  testGroup
    name
    [ testProperty
        "generate key"
        ( \(seed :: Seed, info :: Message) ->
            let sk = BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info))
             in case sk of
                  Left _ -> True
                  Right sk' ->
                    let pk = BLS.blsSkToPk sk'
                     in BLS.unPublicKey pk
                          == BLS.blsMult (BLS.blsGenerator @curve) (unsafePerformIO (BLS.scalarToInteger (BLS.unSecretKey sk')))
        )
    , testProperty
        "sign/verify"
        ( \(seed :: Seed, info :: Message, msg :: Message, dst :: Message, aug :: Message) ->
            let sk = BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info))
             in case sk of
                  Left _ -> False
                  Right sk' ->
                    let pk = BLS.blsSkToPk sk'
                        sig = BLS.blsSign curve sk' (messageBytes msg) (Just (messageBytes dst)) (Just (messageBytes aug))
                     in BLS.blsSignatureVerify pk (messageBytes msg) sig (Just (messageBytes dst)) (Just (messageBytes aug))
        )
    , testProperty
        "Deterministic signature (same inputs)"
        ( \( seed :: Seed
             , info :: Message
             , msg :: Message
             , dst :: Message
             , aug :: Message
             ) ->
              case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
                Left _ -> True
                Right sk' ->
                  let sig1 = BLS.blsSign curve sk' (messageBytes msg) (Just (messageBytes dst)) (Just (messageBytes aug))
                      sig2 = BLS.blsSign curve sk' (messageBytes msg) (Just (messageBytes dst)) (Just (messageBytes aug))
                      BLS.Signature p1 = sig1
                      BLS.Signature p2 = sig2
                   in BLS.blsSerialize p1 == BLS.blsSerialize p2
        )
    , testProperty
        "Encoding invariants: compressed lengths (pk,sig)"
        ( \( seed :: Seed
             , info :: Message
             , msg :: Message
             , dst :: Message
             , aug :: Message
             ) ->
              case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
                Left _ -> True
                Right sk' ->
                  let pk = BLS.blsSkToPk @curve sk'
                      sig = BLS.blsSign curve sk' (messageBytes msg) (Just (messageBytes dst)) (Just (messageBytes aug))
                      -- compressed lengths for actual pk/sig
                      pkLen = BS.length (BLS.blsCompress (BLS.unPublicKey pk))
                      sigLen = case sig of BLS.Signature p -> BS.length (BLS.blsCompress p)
                      -- expected lengths by curve variant, derived from generators
                      expPkLen = BS.length (BLS.blsCompress (BLS.blsGenerator @curve))
                      expSigLen = BS.length (BLS.blsCompress (BLS.blsGenerator @(BLS.Dual curve)))
                      pair = (pkLen, sigLen)
                      expPair = (expPkLen, expSigLen)
                   in -- 1) match the curve's expected (pk,sig) layout
                      pair == expPair
                        -- 2) and specifically enforce the only valid byte-length pairs on BLS12-381
                        && (pair == (48, 96) || pair == (96, 48))
        )
    , testProperty
        "Random signature fails"
        ( \( seed :: Seed
             , info :: Message
             , randomSig :: BLS.Signature curve
             , msg :: Message
             , dst :: Message
             , aug :: Message
             ) ->
              let sk = BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info))
               in case sk of
                    Left _ -> True
                    Right sk' ->
                      let pk = BLS.blsSkToPk sk'
                       in not
                            ( BLS.blsSignatureVerify
                                pk
                                (messageBytes msg)
                                randomSig
                                (Just (messageBytes dst))
                                (Just (messageBytes aug))
                            )
        )
    , testProperty
        "Wrong DST fails"
        ( \( seed :: Seed
             , info :: Message
             , msg :: Message
             , aug :: Message
             ) ->
              forAll genDistinctMessages $ \(dstA, dstB) ->
                case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
                  Left _ -> False
                  Right sk' ->
                    let pk = BLS.blsSkToPk @curve sk'
                        sig = BLS.blsSign curve sk' (messageBytes msg) (Just (messageBytes dstA)) (Just (messageBytes aug))
                     in not
                          ( BLS.blsSignatureVerify
                              pk
                              (messageBytes msg)
                              sig
                              (Just (messageBytes dstB))
                              (Just (messageBytes aug))
                          )
        )
    , testProperty
        "Wrong AUG fails"
        ( \( seed :: Seed
             , info :: Message
             , msg :: Message
             , dst :: Message
             ) ->
              forAll genDistinctMessages $ \(augA, augB) ->
                case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
                  Left _ -> False
                  Right sk' ->
                    let pk = BLS.blsSkToPk @curve sk'
                        sig = BLS.blsSign curve sk' (messageBytes msg) (Just (messageBytes dst)) (Just (messageBytes augA))
                     in not
                          ( BLS.blsSignatureVerify
                              pk
                              (messageBytes msg)
                              sig
                              (Just (messageBytes dst))
                              (Just (messageBytes augB))
                          )
        )
    , testProperty
        "Wrong public key fails"
        ( \( seedA :: Seed
             , infoA :: Message
             , seedB :: Seed
             , infoB :: Message
             , msg :: Message
             , dst :: Message
             , aug :: Message
             ) ->
              case ( BLS.blsKeyGen (getSeedBytes seedA) (Just (messageBytes infoA))
                   , BLS.blsKeyGen (getSeedBytes seedB) (Just (messageBytes infoB))
                   ) of
                (Right skA, Right skB) ->
                  let pkB = BLS.blsSkToPk @curve skB
                      sigA = BLS.blsSign curve skA (messageBytes msg) (Just (messageBytes dst)) (Just (messageBytes aug))
                   in not
                        ( BLS.blsSignatureVerify
                            pkB
                            (messageBytes msg)
                            sigA
                            (Just (messageBytes dst))
                            (Just (messageBytes aug))
                        )
                _ -> False
        )
    ]

testBlsPoP ::
  forall curve.
  BLS.FinalVerifyOrder curve =>
  String -> Proxy curve -> TestTree
testBlsPoP name _ =
  testGroup
    name
    [ testProperty
        "prove/verify"
        ( \(seed :: Seed, info :: Message, dst :: Message, aug :: Message) ->
            case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
              Left _ -> False
              Right sk' ->
                let pk = BLS.blsSkToPk @curve sk'
                    pop = BLS.blsProofOfPossessionProve @curve sk' (Just (messageBytes dst)) (Just (messageBytes aug))
                 in BLS.blsProofOfPossessionVerify @curve pk pop (Just (messageBytes dst)) (Just (messageBytes aug))
        )
    , testProperty
        "wrong public key fails"
        ( \( seedA :: Seed
             , infoA :: Message
             , seedB :: Seed
             , infoB :: Message
             , dst :: Message
             , aug :: Message
             ) ->
              case ( BLS.blsKeyGen (getSeedBytes seedA) (Just (messageBytes infoA))
                   , BLS.blsKeyGen (getSeedBytes seedB) (Just (messageBytes infoB))
                   ) of
                (Right skA, Right skB) ->
                  let pkB = BLS.blsSkToPk @curve skB
                      popA = BLS.blsProofOfPossessionProve @curve skA (Just (messageBytes dst)) (Just (messageBytes aug))
                   in not
                        (BLS.blsProofOfPossessionVerify @curve pkB popA (Just (messageBytes dst)) (Just (messageBytes aug)))
                _ -> False
        )
    , testProperty
        "Wrong DST fails"
        ( \( seed :: Seed
             , info :: Message
             , aug :: Message
             ) ->
              forAll genDistinctMessages $ \(dstA, dstB) ->
                case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
                  Left _ -> False
                  Right sk' ->
                    let pk = BLS.blsSkToPk @curve sk'
                        pop = BLS.blsProofOfPossessionProve @curve sk' (Just (messageBytes dstA)) (Just (messageBytes aug))
                     in not
                          ( BLS.blsProofOfPossessionVerify @curve
                              pk
                              pop
                              (Just (messageBytes dstB))
                              (Just (messageBytes aug))
                          )
        )
    , testProperty
        "Wrong Aug fails"
        ( \( seed :: Seed
             , info :: Message
             , dst :: Message
             ) ->
              forAll genDistinctMessages $ \(augA, augB) ->
                case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
                  Left _ -> False
                  Right sk' ->
                    let pk = BLS.blsSkToPk @curve sk'
                        pop = BLS.blsProofOfPossessionProve @curve sk' (Just (messageBytes dst)) (Just (messageBytes augA))
                     in not
                          ( BLS.blsProofOfPossessionVerify @curve
                              pk
                              pop
                              (Just (messageBytes dst))
                              (Just (messageBytes augB))
                          )
        )
    , testProperty
        "changing both DST and Aug still fails"
        ( \( seed :: Seed
             , info :: Message
             ) ->
              forAll genDistinctMessages $ \(dstA, dstB) ->
                forAll genDistinctMessages $ \(augA, augB) ->
                  case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
                    Left _ -> False
                    Right sk' ->
                      let pk = BLS.blsSkToPk @curve sk'
                          pop = BLS.blsProofOfPossessionProve @curve sk' (Just (messageBytes dstA)) (Just (messageBytes augA))
                       in not
                            ( BLS.blsProofOfPossessionVerify @curve
                                pk
                                pop
                                (Just (messageBytes dstB))
                                (Just (messageBytes augB))
                            )
        )
    , testProperty
        "random PoP fails"
        ( \( seed :: Seed
             , info :: Message
             , randomPoP :: BLS.ProofOfPossession curve
             , dst :: Message
             , aug :: Message
             ) ->
              case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
                Left _ -> False
                Right sk' ->
                  let pk = BLS.blsSkToPk @curve sk'
                   in not
                        ( BLS.blsProofOfPossessionVerify @curve
                            pk
                            randomPoP
                            (Just (messageBytes dst))
                            (Just (messageBytes aug))
                        )
        )
    , testProperty
        "prove builds expected (mu1, mu2)"
        ( \(seed :: Seed, info :: Message, dst :: Message, aug :: Message) ->
            case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
              Left _ -> True
              Right sk' ->
                let pk = BLS.blsSkToPk @curve sk'
                    BLS.ProofOfPossession mu1 mu2 =
                      BLS.blsProofOfPossessionProve @curve sk' (Just (messageBytes dst)) (Just (messageBytes aug))
                    skI = unsafePerformIO (BLS.scalarToInteger (BLS.unSecretKey sk'))
                    expectedMu2 = BLS.blsMult (BLS.blsGenerator @(BLS.Dual curve)) skI
                    expectedMu1 =
                      BLS.blsMult
                        ( BLS.blsHash
                            ("PoP" <> BLS.blsCompress (BLS.unPublicKey pk))
                            (Just (messageBytes dst))
                            (Just (messageBytes aug))
                        )
                        skI
                 in mu1 == expectedMu1 && mu2 == expectedMu2
        )
    , testProperty
        "PoP is deterministic"
        ( \(seed :: Seed, info :: Message, dst :: Message, aug :: Message) ->
            case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
              Left _ -> True
              Right sk' ->
                let BLS.ProofOfPossession mu1 mu2 = BLS.blsProofOfPossessionProve @curve sk' (Just (messageBytes dst)) (Just (messageBytes aug))
                    BLS.ProofOfPossession mu1' mu2' = BLS.blsProofOfPossessionProve @curve sk' (Just (messageBytes dst)) (Just (messageBytes aug))
                 in mu1 == mu1' && mu2 == mu2'
        )
    , testProperty
        "DST/Aug: Nothing == Just \"\""
        ( \(seed :: Seed, info :: Message) ->
            case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
              Left _ -> True
              Right sk' ->
                let BLS.ProofOfPossession mu1 mu2 = BLS.blsProofOfPossessionProve @curve sk' Nothing Nothing
                    BLS.ProofOfPossession mu1' mu2' = BLS.blsProofOfPossessionProve @curve sk' (Just "") (Just "")
                 in mu1 == mu1' && mu2 == mu2'
        )
    , testProperty
        "Swapping (mu1, mu2) fails"
        ( \(seed :: Seed, info :: Message, dst :: Message, aug :: Message) ->
            case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
              Left _ -> True
              Right sk' ->
                let pk = BLS.blsSkToPk @curve sk'
                    BLS.ProofOfPossession mu1 mu2 =
                      BLS.blsProofOfPossessionProve @curve sk' (Just (messageBytes dst)) (Just (messageBytes aug))
                    swapped = BLS.ProofOfPossession mu2 mu1
                 in not
                      (BLS.blsProofOfPossessionVerify @curve pk swapped (Just (messageBytes dst)) (Just (messageBytes aug)))
        )
    , testProperty
        "infinity in PoP fails with valid PoP parts"
        ( \(seed :: Seed, info :: Message, dst :: Message, aug :: Message) ->
            case BLS.blsKeyGen (getSeedBytes seed) (Just (messageBytes info)) of
              Left _ -> True
              Right sk' ->
                let pk = BLS.blsSkToPk @curve sk'
                    BLS.ProofOfPossession mu1 mu2 =
                      BLS.blsProofOfPossessionProve @curve sk' (Just (messageBytes dst)) (Just (messageBytes aug))
                    popInf1 = BLS.ProofOfPossession BLS.blsZero mu2
                    popInf2 = BLS.ProofOfPossession mu1 BLS.blsZero
                 in not
                      (BLS.blsProofOfPossessionVerify @curve pk popInf1 (Just (messageBytes dst)) (Just (messageBytes aug)))
                      && not
                        (BLS.blsProofOfPossessionVerify @curve pk popInf2 (Just (messageBytes dst)) (Just (messageBytes aug)))
                      && BLS.blsProofOfPossessionVerify @curve
                        pk
                        (BLS.ProofOfPossession mu1 mu2)
                        (Just (messageBytes dst))
                        (Just (messageBytes aug))
        )
    ]

testAssoc :: (Show a, Eq a) => (a -> a -> a) -> a -> a -> a -> Property
testAssoc f a b c =
  f a (f b c) === f (f a b) c

testCommut :: (Show a, Eq a) => (a -> a -> a) -> a -> a -> Property
testCommut f a b =
  f a b === f b a

prop_repeatedAddition :: forall curve. BLS.BLS curve => Int -> BLS.Point curve -> Property
prop_repeatedAddition a p = BLS.blsMult p (fromIntegral a) === repeatedAdd a p
  where
    repeatedAdd :: Int -> BLS.Point curve -> BLS.Point curve
    repeatedAdd scalar point =
      F.foldl' BLS.blsAddOrDouble BLS.blsZero $ replicate (abs scalar) (BLS.blsCneg point (scalar < 0))

testAddNegYieldsInf ::
  forall curve.
  BLS.BLS curve =>
  BLS.Point curve -> Bool
testAddNegYieldsInf p =
  BLS.blsIsInf (BLS.blsAddOrDouble p (BLS.blsNeg p))

testRoundTripEither ::
  forall p a err.
  (Show p, Show err, Eq p, Eq err) =>
  (p -> a) ->
  (a -> Either err p) ->
  p ->
  Property
testRoundTripEither encode decode p =
  Right p === (decode . encode) p

prop_threePairings :: Integer -> Integer -> BLS.Point1 -> BLS.Point2 -> Bool
prop_threePairings a b p q = BLS.ptFinalVerify tt t3
  where
    t1 = BLS.millerLoop (BLS.blsMult p a) q
    t2 = BLS.millerLoop p (BLS.blsMult q b)
    t3 = BLS.millerLoop (BLS.blsMult p (a + b)) q
    tt = BLS.ptMult t1 t2

prop_fourPairings :: BLS.Point1 -> BLS.Point1 -> BLS.Point1 -> BLS.Point2 -> Bool
prop_fourPairings a1 a2 a3 b = BLS.ptFinalVerify tt t4
  where
    t1 = BLS.millerLoop a1 b
    t2 = BLS.millerLoop a2 b
    t3 = BLS.millerLoop a3 b
    t4 = BLS.millerLoop (BLS.blsAddOrDouble (BLS.blsAddOrDouble a1 a2) a3) b
    tt = BLS.ptMult (BLS.ptMult t1 t2) t3

prop_randomFailsFinalVerify :: BigInteger -> BigInteger -> BigInteger -> BigInteger -> Property
prop_randomFailsFinalVerify (BigInteger a) (BigInteger b) (BigInteger c) (BigInteger d) =
  (a * c `mod` BLS.scalarPeriod) /= (b * d `mod` BLS.scalarPeriod) ==>
    let a' = BLS.blsMult (BLS.blsGenerator @BLS.Curve1) a
        b' = BLS.blsMult (BLS.blsGenerator @BLS.Curve1) b
        c' = BLS.blsMult (BLS.blsGenerator @BLS.Curve2) c
        d' = BLS.blsMult (BLS.blsGenerator @BLS.Curve2) d
     in BLS.ptFinalVerify (BLS.millerLoop a' c') (BLS.millerLoop b' d') === False

newtype BigInteger = BigInteger Integer
  deriving (Eq, Show)
instance Arbitrary BigInteger where
  arbitrary = BigInteger <$> oneof [arbitrary, chooseAny, choose (-2 ^ (128 :: Int), 2 ^ (128 :: Int))]

instance BLS.BLS curve => Arbitrary (BLS.Point curve) where
  arbitrary =
    frequency
      [ (1, pure BLS.blsZero)
      ,
        ( 9
        , do
            str <- arbitrary
            let bs = BS.pack str
            pure (BLS.blsHash bs Nothing Nothing)
        )
      ]

instance BLS.BLS (BLS.Dual curve) => Arbitrary (BLS.Signature curve) where
  arbitrary = BLS.Signature <$> arbitrary

instance BLS.BLS (BLS.Dual curve) => Show (BLS.Signature curve) where
  show (BLS.Signature p) = show (BLS.blsSerialize p)

-- Show instance for PublicKey to improve counterexample readability
instance BLS.BLS curve => Show (BLS.PublicKey curve) where
  show (BLS.PublicKey p) = show (BLS.blsSerialize p)

instance BLS.BLS (BLS.Dual curve) => Arbitrary (BLS.ProofOfPossession curve) where
  arbitrary = BLS.ProofOfPossession <$> arbitrary <*> arbitrary

instance BLS.BLS (BLS.Dual curve) => Show (BLS.ProofOfPossession curve) where
  show (BLS.ProofOfPossession mu1 mu2) =
    "(PoP mu1=" <> show (BLS.blsSerialize mu1) <> ", mu2=" <> show (BLS.blsSerialize mu2) <> ")"

instance BLS.BLS curve => Arbitrary (BLS.Affine curve) where
  arbitrary = BLS.toAffine <$> arbitrary

instance Arbitrary BLS.PT where
  arbitrary = BLS.millerLoop <$> arbitrary <*> arbitrary

instance Show BLS.PT where
  show = const "<<<PT>>>"

instance Arbitrary BLS.Scalar where
  arbitrary =
    (BLS.scalarFromBS . BS.pack <$> arbitrary)
      `suchThatMap` ( \case
                        Left _ -> Nothing
                        Right v -> Just v
                    )

instance Arbitrary Seed where
  arbitrary = do
    n <- choose (32, 128)
    bytes <- vectorOf n (choose (0, 255))
    pure (mkSeedFromBytes (BS.pack bytes))

instance Show BLS.Scalar where
  show = show . BLS.scalarToBS

-- Show instance needed by QuickCheck for `forAll genSecretKey` counterexamples
instance Show BLS.SecretKey where
  show = show . BLS.scalarToBS . BLS.unSecretKey

instance BLS.BLS curve => Show (BLS.Point curve) where
  show = show . BLS.blsSerialize

instance BLS.BLS curve => Show (BLS.Affine curve) where
  show = show . BLS.fromAffine
