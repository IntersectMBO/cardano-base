{-# OPTIONS_GHC -Wno-orphans #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}

module Test.Crypto.EllipticCurve
where

import qualified Cardano.Crypto.EllipticCurve.BLS12_381 as BLS
import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS
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
