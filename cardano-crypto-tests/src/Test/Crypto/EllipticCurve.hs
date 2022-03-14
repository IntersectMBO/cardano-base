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
--   (=/=), 
    (===), 
    (==>), 
    Arbitrary(..), 
    Property,
    suchThatMap,
--   Gen, 
--   forAllShow
  )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)
import Test.Tasty.HUnit (testCase, assertBool, assertEqual)
import Data.Proxy (Proxy (..))
import qualified Data.ByteString as BS
import System.IO.Unsafe (unsafePerformIO)
import Numeric.Natural (Natural)

tests :: TestTree
tests =
  testGroup "Crypto.EllipticCurve"
    [ testGroup "BLS12_381"
        [ testUtil "Utility"
        , testScalar "Scalar"
        , testBLSCurve "Curve 1" (Proxy @BLS.Curve1)
        , testBLSCurve "Curve 2" (Proxy @BLS.Curve2)
        , testPairings "Pairings"
        ]
    ]

testUtil :: String -> TestTree
testUtil name =
  testGroup name
    [ testProperty "Natural / C-String round-trip" $
        \n ->
          n === unsafePerformIO (BLS.natAsCStr n BLS.cstrToNat)
    , testCase "natToBS" $ do
        assertEqual "0x1234" (BS.pack [0x12, 0x34]) (BLS.natToBS 0x1234)
        assertEqual "0x12345678" (BS.pack [0x12, 0x34, 0x56, 0x78]) (BLS.natToBS 0x12345678)
    ]

testScalar :: String -> TestTree
testScalar name =
  testGroup name
    [ testProperty "self-equality" (\(a :: BLS.Scalar) -> a === a)
    , testProperty "double negation" $ \a ->
        BLS.scalarCanonical (BLS.scalarFromFr a) && a /= BLS.frFromNatural 0
          ==>
          a === BLS.frNeg (BLS.frNeg a)
    , testProperty "double inversion" (\a -> a /= BLS.frFromNatural 0 ==> a === BLS.frInverse (BLS.frInverse a))
    , testProperty "addition associative" (testAssoc BLS.frAdd)
    , testProperty "addition commutative" (testCommut BLS.frAdd)
    , testProperty "multiplication associative" (testAssoc BLS.frMult)
    , testProperty "multiplication commutative" (testCommut BLS.frMult)
    , testProperty "p is neutral under addition" (testNeutral (BLS.frFromScalar magicPScalar) BLS.frAdd)
    , testProperty "sqr is equivalent to self-mult" $ \(a :: BLS.Fr) -> BLS.frMult a a === BLS.frSqr a
    , testProperty "to/from BS round-trip" $ \s -> Right s === (BLS.scalarFromBS . BLS.scalarToBS $ s)
    ]

testBLSCurve :: forall curve. BLS.BLS curve
             => String -> Proxy curve -> TestTree
testBLSCurve name _ =
  testGroup name
    [ testCase "generator on curve" $
        assertBool "" (BLS.onCurve (BLS.generator @curve))
    , testCase "negate generator" $
        assertBool "" (BLS.onCurve (BLS.neg (BLS.generator @curve)))
    , testCase "add generator to itself" $
        assertBool "" (BLS.onCurve (BLS.add (BLS.generator @curve) (BLS.generator @curve)))
    , testProperty "on curve" (BLS.onCurve @curve)
    , testProperty "neg on curv" (BLS.onCurve @curve . BLS.neg)
    , testProperty "self-equality" (\(a :: BLS.P curve) -> a === a)
    , testProperty "double negation" (\(a :: BLS.P curve) -> a === BLS.neg (BLS.neg a))
    , testProperty "addition associative" (testAssoc (BLS.add :: BLS.P curve -> BLS.P curve -> BLS.P curve))
    , testProperty "addition commutative" (testCommut (BLS.add :: BLS.P curve -> BLS.P curve -> BLS.P curve))
    , testProperty "adding negation yields infinity" (testAddNegYieldsInf @curve)
    , testProperty "round-trip serialization" $
        testRoundTrip @curve BLS.serialize BLS.deserialize
    , testProperty "round-trip compression" $
        testRoundTrip @curve BLS.compress BLS.uncompress
    , testProperty "mult by p is inf" $ \(a :: BLS.P curve) ->
        BLS.isInf (BLS.mult a magicPScalar)
    , testProperty "mult by p+1 is identity" $ \(a :: BLS.P curve) ->
        BLS.mult a (BLS.scalarFromFr (BLS.frAdd (BLS.frFromScalar magicPScalar) (BLS.frFromNatural 1))) === a
    ]

testPairings :: String -> TestTree
testPairings name =
  testGroup name
    [ testProperty "identity" $ \a b ->
        BLS.pairingCheck
          (a, b)
          (a, b)
    , testProperty "simple" $ \a p q ->
        BLS.pairingCheck
          (BLS.mult p a, q)
          (p, BLS.mult q a)
    , testProperty "crossover" $ \a b p q ->
        BLS.pairingCheck
          (BLS.mult p a, BLS.mult q b)
          (BLS.mult p b, BLS.mult q a)
    , testProperty "shift" $ \a b p q ->
        BLS.pairingCheck
          (BLS.mult p (BLS.scalarFromFr $ BLS.frMult (BLS.frFromScalar a) (BLS.frFromScalar b)), q)
          (BLS.mult p a, BLS.mult q b)
    ]

testAssoc :: (Show a, Eq a) => (a -> a -> a) -> a -> a -> a -> Property
testAssoc f a b c =
  f a (f b c) === f (f a b) c

testCommut :: (Show a, Eq a) => (a -> a -> a) -> a -> a -> Property
testCommut f a b =
  f a b === f b a

testNeutral :: (Show a, Eq a) => a -> (a -> a -> a) -> a -> Property
testNeutral z f x =
  f x z === x

testAddNegYieldsInf :: forall curve. BLS.BLS curve
        => BLS.P curve -> Bool
testAddNegYieldsInf p =
  BLS.isInf (BLS.add p (BLS.neg p))

testRoundTrip :: forall curve a. BLS.BLS curve
        => (BLS.P curve -> a)
        -> (a -> Either BLS.BLSTError (BLS.P curve))
        -> BLS.P curve
        -> Property
testRoundTrip encode decode p =
  Right p === (decode . encode) p

instance BLS.BLS curve => Arbitrary (BLS.P curve) where
  arbitrary = do
    str <- arbitrary
    let bs = BS.pack str
    return $ BLS.hash bs Nothing Nothing

instance BLS.BLS curve => Arbitrary (BLS.Affine curve) where
  arbitrary = BLS.toAffine <$> arbitrary

instance Arbitrary BLS.Scalar where
  arbitrary =
    (BLS.scalarFromBS . BS.pack <$> arbitrary)
      `suchThatMap`
      (\case
        Left _ -> Nothing
        Right v -> Just v
      )

instance Arbitrary BLS.Fr where
  arbitrary = BLS.frFromScalar <$> arbitrary

instance Show BLS.Scalar where
  show = show . BLS.scalarToBS

instance Show BLS.Fr where
  show = show . BLS.scalarFromFr

instance BLS.BLS curve => Show (BLS.P curve) where
  show = show . BLS.serialize

instance BLS.BLS curve => Show (BLS.Affine curve) where
  show = show . BLS.toXY

instance Arbitrary Natural where
  arbitrary = fromInteger . abs <$> arbitrary

magicPScalar :: BLS.Scalar
magicPScalar = BLS.scalarFromNatural 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
