{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.EllipticCurve
where

import Paths_cardano_crypto_class (getDataFileName)

import Test.Crypto.Util (eitherShowError)

import qualified Cardano.Crypto.EllipticCurve.BLS12_381 as BLS
import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS
import Cardano.Crypto.Hash (SHA256, digest)
import Control.Monad ((>=>))
import Data.Bits (shiftL)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Data.Either (isLeft)
import qualified Data.Foldable as F (foldl')
import Data.Proxy (Proxy (..))
import System.IO.Unsafe (unsafePerformIO)
import Test.Crypto.Instances ()
import Test.HUnit (assertBool, assertEqual)
import Test.Hspec (Spec, describe, it)
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (
  Arbitrary (..),
  Property,
  choose,
  chooseAny,
  frequency,
  oneof,
  suchThatMap,
  (===),
  (==>),
 )

tests :: Spec
tests =
  describe "Crypto.EllipticCurve" $ do
    describe "BLS12_381" $ do
      testUtil "Utility"
      testScalar "Scalar"
      testBLSCurve "Curve 1" (Proxy @BLS.Curve1) taintPoint1
      testBLSCurve "Curve 2" (Proxy @BLS.Curve2) taintPoint2
      testPT "PT"
      testPairing "Pairing"
      testVectors "Vectors"

testUtil :: String -> Spec
testUtil name =
  describe name $ do
    prop "Integer / C-String 32 round-trip" $
      \n ->
        n >= 0 ==>
          n < (1 `shiftL` 32 * 8) ==>
            n === unsafePerformIO (BLS.integerAsCStrL 32 n BLS.cstrToInteger)
    prop "padBS min length" $ \n bsw ->
      BS.length (BLS.padBS n (BS.pack bsw)) >= n
    prop "padBS adds zeroes to front" $ \bsw ->
      BS.index (BLS.padBS (length bsw + 1) (BS.pack bsw)) 0 === 0
    it "integerToBS" $ do
      assertEqual "0x1234" (BS.pack [0x12, 0x34]) (BLS.integerToBS 0x1234)
      assertEqual "0x12345678" (BS.pack [0x12, 0x34, 0x56, 0x78]) (BLS.integerToBS 0x12345678)

testScalar :: String -> Spec
testScalar name =
  describe name $ do
    prop "self-equality" $
      \(a :: BLS.Scalar) -> a === a
    prop "to/from BS round-trip" $
      \s -> Right s === (BLS.scalarFromBS . BLS.scalarToBS $ s)
    prop "non-negative" $
      \s -> (unsafePerformIO . BLS.scalarToInteger $ s) >= 0
    prop "to/from Integer round-trip" $
      \s -> s === unsafePerformIO (BLS.scalarToInteger s >>= BLS.scalarFromInteger)
    it "integer from scalar" $ do
      s <- case BLS.scalarFromBS (BLS.padBS 32 (BS.pack [0x12, 0x34])) of
        Left err -> error (show err)
        Right x -> return x
      let expected = 0x1234
      actual <- BLS.scalarToInteger s
      assertEqual "0x1234" expected actual

testBLSCurve ::
  forall curve.
  BLS.BLS curve =>
  String ->
  Proxy curve ->
  -- | A point on the curve outside the prime-order subgroup
  BLS.UncheckedPoint curve ->
  Spec
testBLSCurve name _ taintPoint =
  describe name $ do
    it "generator in group" $
      assertBool "" (BLS.blsInGroup (BLS.blsGenerator @curve))
    it "neg generator in group" $
      assertBool "" (BLS.blsInGroup (BLS.blsNeg (BLS.blsGenerator @curve)))
    it "add generator to itself" $
      assertBool
        ""
        (BLS.blsInGroup (BLS.blsAddOrDouble (BLS.blsGenerator @curve) (BLS.blsGenerator @curve)))
    prop "in group" (BLS.blsInGroup @curve)
    prop "neg in group" (BLS.blsInGroup @curve . BLS.blsNeg)
    prop "self-equality" (\(a :: BLS.Point curve) -> a === a)
    prop "double negation" (\(a :: BLS.Point curve) -> a === BLS.blsNeg (BLS.blsNeg a))
    prop
      "adding infinity yields equality"
      (\(a :: BLS.Point curve) -> BLS.blsAddOrDouble a (BLS.blsZero @curve) === a)
    prop
      "addition associative"
      (testAssoc (BLS.blsAddOrDouble :: BLS.Point curve -> BLS.Point curve -> BLS.Point curve))
    prop
      "addition commutative"
      (testCommut (BLS.blsAddOrDouble :: BLS.Point curve -> BLS.Point curve -> BLS.Point curve))
    prop "adding negation yields infinity" (testAddNegYieldsInf @curve)
    prop "round-trip serialization" $
      testRoundTripEither @(BLS.Point curve) BLS.blsSerialize BLS.blsDeserialize
    prop "round-trip compression" $
      testRoundTripEither @(BLS.Point curve) BLS.blsCompress BLS.blsUncompress
    prop "round-trip unchecked serialization" $
      testRoundTripEither @(BLS.Point curve)
        BLS.blsSerialize
        (fmap BLS.unsafeAssumeInGroup . BLS.blsDeserializeUnchecked)
    prop "round-trip unchecked compression" $
      testRoundTripEither @(BLS.Point curve)
        BLS.blsCompress
        (fmap BLS.unsafeAssumeInGroup . BLS.blsUncompressUnchecked)
    prop "unchecked serialization passes checkInGroup" $
      testRoundTripEither @(BLS.Point curve)
        BLS.blsSerialize
        (BLS.blsDeserializeUnchecked >=> BLS.checkInGroup)
    -- Unchecked operations on points in the subgroup: they agree with their
    -- checked counterparts.
    prop "unchecked addition agrees with addition" $ \(a :: BLS.Point curve) b ->
      BLS.blsAddOrDoubleUnchecked (BLS.UncheckedPoint a) (BLS.UncheckedPoint b)
        === BLS.UncheckedPoint (BLS.blsAddOrDouble a b)
    prop "unchecked infinity check agrees with infinity check" $ \(a :: BLS.Point curve) ->
      BLS.blsIsInfUnchecked (BLS.UncheckedPoint a) === BLS.blsIsInf a
    prop "unchecked infinity check on infinity" $
      BLS.blsIsInfUnchecked (BLS.UncheckedPoint (BLS.blsZero @curve))
    prop "unchecked affine conversion agrees with affine conversion" $ \(a :: BLS.Point curve) ->
      BLS.fromAffine (BLS.toAffineUnchecked (BLS.UncheckedPoint a)) === a
    prop "unchecked compression agrees with compression" $ \(a :: BLS.Point curve) ->
      BLS.blsCompressUnchecked (BLS.UncheckedPoint a) === BLS.blsCompress a
    prop "unchecked serialization agrees with serialization" $ \(a :: BLS.Point curve) ->
      BLS.blsSerializeUnchecked (BLS.UncheckedPoint a) === BLS.blsSerialize a
    -- Unchecked operations on points outside the subgroup, which have no checked
    -- counterpart: their properties are checked directly. These "tainted" points
    -- are a random subgroup point plus 'taintPoint'; if the sum were in the
    -- subgroup, 'taintPoint' would be too.
    prop "tainted points are on the curve" $ \(a :: BLS.Point curve) ->
      onCurve (tainted a)
    prop "tainted points are outside the subgroup" $ \(a :: BLS.Point curve) ->
      BLS.checkInGroup (tainted a) === Left BLS.BLST_POINT_NOT_IN_GROUP
    prop "unchecked addition commutative on tainted points" $ \(a :: BLS.Point curve) b ->
      BLS.blsAddOrDoubleUnchecked (tainted a) (tainted b)
        === BLS.blsAddOrDoubleUnchecked (tainted b) (tainted a)
    prop "unchecked addition associative on tainted points" $ \(a :: BLS.Point curve) b c ->
      BLS.blsAddOrDoubleUnchecked (BLS.blsAddOrDoubleUnchecked (tainted a) (tainted b)) (tainted c)
        === BLS.blsAddOrDoubleUnchecked (tainted a) (BLS.blsAddOrDoubleUnchecked (tainted b) (tainted c))
    prop "unchecked addition of infinity to tainted points yields equality" $ \(a :: BLS.Point curve) ->
      BLS.blsAddOrDoubleUnchecked (tainted a) (BLS.UncheckedPoint BLS.blsZero) === tainted a
    prop "unchecked addition of a subgroup point to tainted points stays outside the subgroup" $
      \(a :: BLS.Point curve) b ->
        isLeft (BLS.checkInGroup (BLS.blsAddOrDoubleUnchecked (tainted a) (BLS.UncheckedPoint b)))
    prop "unchecked infinity check on tainted points" $ \(a :: BLS.Point curve) ->
      not (BLS.blsIsInfUnchecked (tainted a))
    prop "unchecked affine round trip on tainted points" $ \(a :: BLS.Point curve) ->
      BLS.UncheckedPoint (BLS.fromAffine (BLS.toAffineUnchecked (tainted a))) === tainted a
    prop "unchecked affine form of tainted points is outside the subgroup" $ \(a :: BLS.Point curve) ->
      not (BLS.affineInG (BLS.toAffineUnchecked (tainted a)))
    prop "unchecked compression round trip on tainted points" $ \(a :: BLS.Point curve) ->
      BLS.blsUncompressUnchecked (BLS.blsCompressUnchecked (tainted a)) === Right (tainted a)
    prop "unchecked serialization round trip on tainted points" $ \(a :: BLS.Point curve) ->
      BLS.blsDeserializeUnchecked (BLS.blsSerializeUnchecked (tainted a)) === Right (tainted a)
    prop "mult by p is inf" $ \(a :: BLS.Point curve) ->
      BLS.blsIsInf (BLS.blsMult a BLS.scalarPeriod)
    prop "mult by p+1 is identity" $ \(a :: BLS.Point curve) ->
      BLS.blsMult a (BLS.scalarPeriod + 1) === a
    prop "scalar mult associative" $ \(a :: BLS.Point curve) (BigInteger b) (BigInteger c) ->
      BLS.blsMult (BLS.blsMult a b) c === BLS.blsMult (BLS.blsMult a c) b
    prop "scalar mult distributive left" $ \(a :: BLS.Point curve) (BigInteger b) (BigInteger c) ->
      BLS.blsMult a (b + c) === BLS.blsAddOrDouble (BLS.blsMult a b) (BLS.blsMult a c)
    prop "scalar mult distributive right" $ \(a :: BLS.Point curve) (b :: BLS.Point curve) (BigInteger c) ->
      BLS.blsMult (BLS.blsAddOrDouble a b) c === BLS.blsAddOrDouble (BLS.blsMult a c) (BLS.blsMult b c)
    prop "MSM matches naive approach" $ \(ssAndPs :: [(BigInteger, BLS.Point curve)]) ->
      let pairs = [(i, p) | (BigInteger i, p) <- ssAndPs]
       in BLS.blsMSM pairs
            === foldr (\(s, p) acc -> BLS.blsAddOrDouble acc (BLS.blsMult p s)) (BLS.blsZero @curve) pairs
    prop "mult by zero is inf" $ \(a :: BLS.Point curve) ->
      BLS.blsIsInf (BLS.blsMult a 0)
    prop "mult by -1 is equal to neg" $ \(a :: BLS.Point curve) ->
      BLS.blsMult a (-1) === BLS.blsNeg a
    prop "modular multiplication" $ \(BigInteger a) (BigInteger b) (p :: BLS.Point curve) ->
      BLS.blsMult p a === BLS.blsMult p (a + b * BLS.scalarPeriod)
    prop "repeated addition" (prop_repeatedAddition @curve)
    it "zero is inf" $ assertBool "Zero is at infinity" (BLS.blsIsInf (BLS.blsZero @curve))
  where
    tainted :: BLS.Point curve -> BLS.UncheckedPoint curve
    tainted a = BLS.blsAddOrDoubleUnchecked (BLS.UncheckedPoint a) taintPoint

testPT :: String -> Spec
testPT name =
  describe name $ do
    prop
      "mult associative"
      (testAssoc BLS.ptMult)
    prop
      "mult commutative"
      (testCommut BLS.ptMult)
    prop "self-equality" (\(a :: BLS.PT) -> a === a)
    prop "self-final-verify" (\(a :: BLS.PT) -> BLS.ptFinalVerify a a)

testPairing :: String -> Spec
testPairing name =
  describe name $ do
    prop "identity" $ \a b ->
      pairingCheck
        (a, b)
        (a, b)
    prop "simple" $ \a p q ->
      pairingCheck
        (BLS.blsMult p a, q)
        (p, BLS.blsMult q a)
    prop "crossover" $ \a b p q ->
      pairingCheck
        (BLS.blsMult p a, BLS.blsMult q b)
        (BLS.blsMult p b, BLS.blsMult q a)
    prop "shift" $ \a b p q ->
      pairingCheck
        (BLS.blsMult p (a * b), q)
        (BLS.blsMult p a, BLS.blsMult q b)
    prop "three pairings" prop_threePairings
    prop "four pairings" prop_fourPairings
    prop "finalVerify fails on random inputs" prop_randomFailsFinalVerify
  where
    pairingCheck (a, b) (c, d) = BLS.ptFinalVerify (BLS.millerLoop a b) (BLS.millerLoop c d)

loadHexFile :: String -> IO [BS.ByteString]
loadHexFile filename = do
  mapM (either error pure . Base16.decode . BS8.filter (/= '\r')) . BS8.lines =<< BS.readFile filename

testVectors :: String -> Spec
testVectors name =
  describe name $ do
    testVectorPairings "pairings"
    testVectorOperations "operations"
    testVectorSerDe "serialization/compression"
    testVectorSigAug "signature"
    testVectorLargeDst "large-dst"

testVectorPairings :: String -> Spec
testVectorPairings name =
  it name $ do
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

testVectorOperations :: String -> Spec
testVectorOperations name =
  it name $ do
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

testVectorSerDe :: String -> Spec
testVectorSerDe name =
  it name $ do
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

    -- The unchecked decoders skip only the subgroup check, which 'checkInGroup'
    -- then performs.
    let notInGroup :: BLS.BLS curve => Either BLS.BLSTError (BLS.UncheckedPoint curve) -> Bool
        notInGroup =
          either (const False) ((== Left BLS.BLST_POINT_NOT_IN_GROUP) . BLS.checkInGroup)
    assertBool
      "unchecked g1CompNotInGroup"
      (notInGroup (BLS.blsUncompressUnchecked @BLS.Curve1 g1CompNotInGroup))
    assertBool
      "unchecked g1UncompNotInGroup"
      (notInGroup (BLS.blsDeserializeUnchecked @BLS.Curve1 g1UncompNotInGroup))
    assertBool
      "unchecked g2CompNotInGroup"
      (notInGroup (BLS.blsUncompressUnchecked @BLS.Curve2 g2CompNotInGroup))
    assertBool
      "unchecked g2UncompNotInGroup"
      (notInGroup (BLS.blsDeserializeUnchecked @BLS.Curve2 g2UncompNotInGroup))
    assertEqual
      "unchecked g1UncompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsDeserializeUnchecked @BLS.Curve1 g1UncompNotOnCurve)
    assertEqual
      "unchecked g1CompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsUncompressUnchecked @BLS.Curve1 g1CompNotOnCurve)
    assertEqual
      "unchecked g2UncompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsDeserializeUnchecked @BLS.Curve2 g2UncompNotOnCurve)
    assertEqual
      "unchecked g2CompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsUncompressUnchecked @BLS.Curve2 g2CompNotOnCurve)

testVectorSigAug :: String -> Spec
testVectorSigAug name =
  it name $ do
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

testVectorLargeDst :: String -> Spec
testVectorLargeDst name =
  it name $ do
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

testAssoc :: (Show a, Eq a) => (a -> a -> a) -> a -> a -> a -> Property
testAssoc f a b c =
  f a (f b c) === f (f a b) c

testCommut :: (Show a, Eq a) => (a -> a -> a) -> a -> a -> Property
testCommut f a b =
  f a b === f b a

prop_repeatedAddition :: forall curve. BLS.BLS curve => Int -> BLS.Point curve -> Property
prop_repeatedAddition a p = BLS.blsMult p (toInteger a) === repeatedAdd a p
  where
    repeatedAdd :: Int -> BLS.Point curve -> BLS.Point curve
    repeatedAdd scalar point =
      F.foldl' BLS.blsAddOrDouble BLS.blsZero $ replicate (abs scalar) (BLS.blsCneg point (scalar < 0))

-- | Points on the curve outside the prime-order subgroup, as uncompressed
-- (x, y) encodings: x = 4 on G1 and x = 2 on G2. Deserializing checks that the
-- point is on the curve (it fails with 'BLS.BLST_POINT_NOT_ON_CURVE'
-- otherwise); the tests check that it is outside the subgroup.
taintPoint1 :: BLS.UncheckedPoint BLS.Curve1
taintPoint1 =
  deserializeUncheckedHex $
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004"
      <> "0a989badd40d6212b33cffc3f3763e9bc760f988c9926b26da9dd85e928483446346b8ed00e1de5d5ea93e354abe706c"

taintPoint2 :: BLS.UncheckedPoint BLS.Curve2
taintPoint2 =
  deserializeUncheckedHex $
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      <> "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"
      <> "02d27e0ec3356299a346a09ad7dc4ef68a483c3aed53f9139d2f929a3eecebf72082e5e58c6da24ee32e03040c406d4f"
      <> "013a59858b6809fca4d9a3b6539246a70051a3c88899964a42bc9a69cf9acdd9dd387cfa9086b894185b9a46a402be73"

deserializeUncheckedHex :: BLS.BLS curve => String -> BLS.UncheckedPoint curve
deserializeUncheckedHex hex =
  case Base16.decode (BS8.pack hex) of
    Left err -> error err
    Right bs -> either (error . show) id (BLS.blsDeserializeUnchecked bs)

-- | Whether an 'BLS.UncheckedPoint' is on the curve, checked directly by blst.
onCurve :: BLS.BLS curve => BLS.UncheckedPoint curve -> Bool
onCurve (BLS.UncheckedPoint p) = unsafePerformIO $ BLS.withPoint p BLS.c_blst_on_curve

testAddNegYieldsInf ::
  forall curve.
  BLS.BLS curve =>
  BLS.Point curve ->
  Bool
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

instance BLS.BLS curve => Show (BLS.Affine curve) where
  show = show . BLS.fromAffine
