{-# OPTIONS_GHC -Wno-orphans #-}

{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.Crypto.EllipticCurve
where

import Paths_cardano_crypto_tests

import Test.Crypto.Util (eitherShowError)

import qualified Cardano.Crypto.EllipticCurve.BLS12_381 as BLS
import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS
import Cardano.Crypto.Hash (SHA256, digest)
import Test.Crypto.Instances ()
import Test.QuickCheck (
    (===),
    (==>),
    Arbitrary(..),
    Property,
    choose,
    chooseAny,
    oneof,
    suchThatMap,
  )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)
import Test.Tasty.HUnit (testCase, assertBool, assertEqual)
import Data.Proxy (Proxy (..))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Base16 as Base16
import System.IO.Unsafe (unsafePerformIO)
import Data.Bits (shiftL)
import Data.List (foldl')

tests :: TestTree
tests =
  testGroup "Crypto.EllipticCurve"
    [ testGroup "BLS12_381"
        [ testUtil "Utility"
        , testScalar "Scalar"
        , testBLSCurve "Curve 1" (Proxy @BLS.Curve1)
        , testBLSCurve "Curve 2" (Proxy @BLS.Curve2)
        , testPT "PT"
        , testPairing "Pairing"
        , testVectors "Vectors"
        ]
    ]

testUtil :: String -> TestTree
testUtil name =
  testGroup name
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
  testGroup name
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

testBLSCurve :: forall curve. BLS.BLS curve
             => String -> Proxy curve -> TestTree
testBLSCurve name _ =
  testGroup name
    [ testCase "generator in group" $
        assertBool "" (BLS.blsInGroup (BLS.blsGenerator @curve))
    , testCase "neg generator in group" $
        assertBool "" (BLS.blsInGroup (BLS.blsNeg (BLS.blsGenerator @curve)))
    , testCase "add generator to itself" $
        assertBool "" (BLS.blsInGroup (BLS.blsAddOrDouble (BLS.blsGenerator @curve) (BLS.blsGenerator @curve)))
    , testProperty "in group" (BLS.blsInGroup @curve)
    , testProperty "neg in group" (BLS.blsInGroup @curve . BLS.blsNeg)

    , testProperty "self-equality" (\(a :: BLS.Point curve) -> a === a)
    , testProperty "double negation" (\(a :: BLS.Point curve) -> a === BLS.blsNeg (BLS.blsNeg a))
    , testProperty "adding infinity yields equality" (\(a :: BLS.Point curve) -> BLS.blsAddOrDouble a (BLS.blsZero @curve) === a)
    , testProperty "addition associative" (testAssoc (BLS.blsAddOrDouble :: BLS.Point curve -> BLS.Point curve -> BLS.Point curve))
    , testProperty "addition commutative" (testCommut (BLS.blsAddOrDouble :: BLS.Point curve -> BLS.Point curve -> BLS.Point curve))
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
    , testProperty "scalar mult distributive right" $ \ (a :: BLS.Point curve) (b :: BLS.Point curve) (BigInteger c) ->
        BLS.blsMult (BLS.blsAddOrDouble a b) c === BLS.blsAddOrDouble (BLS.blsMult a c) (BLS.blsMult b c)
    , testProperty "mult by zero is inf" $ \(a :: BLS.Point curve) ->
        BLS.blsIsInf (BLS.blsMult a 0)
    , testProperty "mult by -1 is equal to neg" $ \(a :: BLS.Point curve) ->
        BLS.blsMult a (-1)  === BLS.blsNeg a
    , testProperty "modular multiplication" $ \(BigInteger a) (BigInteger b) (p :: BLS.Point curve) ->
        BLS.blsMult p a === BLS.blsMult p (a + b * BLS.scalarPeriod)
    , testProperty "repeated addition" (prop_repeatedAddition @curve)
    , testCase "zero is inf" $ assertBool "Zero is at infinity" (BLS.blsIsInf (BLS.blsZero @curve))
    ]

testPT :: String -> TestTree
testPT name =
  testGroup name
    [ testProperty "mult associative"
        (testAssoc BLS.ptMult)
    , testProperty "mult commutative"
        (testCommut BLS.ptMult)
    , testProperty "self-equality" (\(a :: BLS.PT) -> a === a)
    , testProperty "self-final-verify" (\(a :: BLS.PT) -> BLS.ptFinalVerify a a)
    ]

testPairing :: String -> TestTree
testPairing name =
  testGroup name
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
  mapM (either error pure . Base16.decode) . BS8.lines =<< BS.readFile filename

testVectors :: String -> TestTree
testVectors name =
  testGroup name
    [ testVectorPairings "pairings"
    , testVectorOperations "operations"
    , testVectorSerDe "serialization/compression"
    , testVectorSigAug "signature"
    , testVectorLargeDst "large-dst"
    ]

testVectorPairings :: String -> TestTree
testVectorPairings name =
  testCase name $ do
    [ p_raw,
      aP_raw,
      bP_raw,
      apbP_raw,
      axbP_raw,
      q_raw,
      aQ_raw,
      bQ_raw,
      apbQ_raw,
      axbQ_raw ] <- loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/pairing_test_vectors"

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
    [ g1p_raw,
      g1q_raw,
      g1add_raw,
      g1sub_raw,
      g1mul_raw,
      g1neg_raw,
      g2p_raw,
      g2q_raw,
      g2add_raw,
      g2sub_raw,
      g2mul_raw,
      g2neg_raw ] <- loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/ec_operations_test_vectors"

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

    assertEqual "g1 add"
      g1add (BLS.blsAddOrDouble g1p g1q)
    assertEqual "g1 sub"
      g1sub (BLS.blsAddOrDouble g1p (BLS.blsNeg g1q))
    assertEqual "g1 mul"
      g1mul (BLS.blsMult g1q scalar)
    assertEqual "g1 neg"
      g1neg (BLS.blsNeg g1p)

    assertEqual "g2 add"
      g2add (BLS.blsAddOrDouble g2p g2q)
    assertEqual "g2 sub"
      g2sub (BLS.blsAddOrDouble g2p (BLS.blsNeg g2q))
    assertEqual "g2 mul"
      g2mul (BLS.blsMult g2q scalar)
    assertEqual "g2 neg"
      g2neg (BLS.blsNeg g2p)

testVectorSerDe :: String -> TestTree
testVectorSerDe name =
  testCase name $ do
    [ g1UncompNotOnCurve,
      g1CompNotOnCurve,
      g1CompNotInGroup,
      g1UncompNotInGroup,
      g2UncompNotOnCurve,
      g2CompNotOnCurve,
      g2CompNotInGroup,
      g2UncompNotInGroup ] <- loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/serde_test_vectors"

    assertEqual "g1UncompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsDeserialize g1UncompNotOnCurve :: Either BLS.BLSTError BLS.Point1)

    assertEqual "g1CompNotInGroup"
      (Left BLS.BLST_POINT_NOT_IN_GROUP)
      (BLS.blsUncompress g1CompNotInGroup :: Either BLS.BLSTError BLS.Point1)

    assertEqual "g1CompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsUncompress g1CompNotOnCurve :: Either BLS.BLSTError BLS.Point1)

    assertEqual "g1UncompNotInGroup"
      (Left BLS.BLST_POINT_NOT_IN_GROUP)
      (BLS.blsDeserialize g1UncompNotInGroup :: Either BLS.BLSTError BLS.Point1)


    assertEqual "g2UncompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsDeserialize g2UncompNotOnCurve :: Either BLS.BLSTError BLS.Point2)

    assertEqual "g2CompNotInGroup"
      (Left BLS.BLST_POINT_NOT_IN_GROUP)
      (BLS.blsUncompress g2CompNotInGroup :: Either BLS.BLSTError BLS.Point2)

    assertEqual "g2CompNotOnCurve"
      (Left BLS.BLST_POINT_NOT_ON_CURVE)
      (BLS.blsUncompress g2CompNotOnCurve :: Either BLS.BLSTError BLS.Point2)

    assertEqual "g2UncompNotInGroup"
      (Left BLS.BLST_POINT_NOT_IN_GROUP)
      (BLS.blsDeserialize g2UncompNotInGroup :: Either BLS.BLSTError BLS.Point2)


testVectorSigAug :: String -> TestTree
testVectorSigAug name =
  testCase name $ do
    [ sig_raw, pk_raw ] <- loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/bls_sig_aug_test_vectors"
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
    [ msg_raw, large_dst_raw, output_raw ] <- loadHexFile =<< getDataFileName "bls12-381-test-vectors/test_vectors/h2c_large_dst"
    let prefix = "H2C-OVERSIZE-DST-"
    let dst_sha = digest (Proxy @SHA256) (prefix <> large_dst_raw)
    let hashedMsg = BLS.blsHash msg_raw (Just dst_sha) Nothing
    expected_output :: BLS.Point1 <- eitherShowError $ BLS.blsUncompress output_raw

    assertEqual "expected hash output"
      hashedMsg expected_output

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
         foldl' BLS.blsAddOrDouble BLS.blsZero $ replicate (abs scalar) (BLS.blsCneg point (scalar < 0))

testAddNegYieldsInf :: forall curve. BLS.BLS curve
        => BLS.Point curve -> Bool
testAddNegYieldsInf p =
  BLS.blsIsInf (BLS.blsAddOrDouble p (BLS.blsNeg p))

testRoundTripEither :: forall p a err. (Show p, Show err, Eq p, Eq err)
        => (p -> a)
        -> (a -> Either err p)
        -> p
        -> Property
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

prop_randomFailsFinalVerify :: BLS.Point1 -> BLS.Point1 -> BLS.Point2 -> BLS.Point2 -> Property
prop_randomFailsFinalVerify a b c d =
    a /= b && c /= d ==>
    BLS.ptFinalVerify (BLS.millerLoop a c) (BLS.millerLoop b d) === False

newtype BigInteger = BigInteger Integer
  deriving (Eq, Show)
instance Arbitrary BigInteger where
  arbitrary = BigInteger <$> oneof [arbitrary, chooseAny, choose (- 2 ^ (128 :: Int), 2 ^ (128 ::Int))]

instance BLS.BLS curve => Arbitrary (BLS.Point curve) where
  arbitrary = do
    str <- arbitrary
    let bs = BS.pack str
    return $ BLS.blsHash bs Nothing Nothing

instance BLS.BLS curve => Arbitrary (BLS.Affine curve) where
  arbitrary = BLS.toAffine <$> arbitrary

instance Arbitrary BLS.PT where
  arbitrary = BLS.millerLoop <$> arbitrary <*> arbitrary

instance Show BLS.PT where
  show = const "<<<PT>>>"

instance Arbitrary BLS.Scalar where
  arbitrary =
    (BLS.scalarFromBS . BS.pack <$> arbitrary)
      `suchThatMap`
      (\case
        Left _ -> Nothing
        Right v -> Just v
      )

instance Show BLS.Scalar where
  show = show . BLS.scalarToBS

instance BLS.BLS curve => Show (BLS.Point curve) where
  show = show . BLS.blsSerialize

instance BLS.BLS curve => Show (BLS.Affine curve) where
  show = show . BLS.fromAffine
