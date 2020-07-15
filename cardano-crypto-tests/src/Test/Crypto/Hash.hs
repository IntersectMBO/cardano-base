{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.Hash
  ( tests
  )
where

import Cardano.Binary (ToCBOR(..))
import Cardano.Crypto.Hash
import qualified Data.ByteString as SB
import Data.Proxy (Proxy (..))
import Data.String (IsString (..))
import Test.Crypto.Util (prop_cbor, prop_cbor_size, prop_no_unexpected_thunks)
import Test.QuickCheck
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)
import Test.Tasty.HUnit (testCase, assertEqual, assertFailure, assertBool, Assertion)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteArray.Encoding (convertFromBase, convertToBase, Base (Base16))
import Data.Char (ord)
import Data.Word (Word8)
import Control.Monad (forM_)

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.Hash"
    [ testHashAlgorithm (Proxy :: Proxy MD5) "MD5"
    , testHashAlgorithm (Proxy :: Proxy SHA256) "SHA256"
    , testHashAlgorithm (Proxy :: Proxy SHA3_256) "SHA3_256"
    , testHashAlgorithm (Proxy :: Proxy Blake2b_224) "Blake2b_224"
    , testHashAlgorithm (Proxy :: Proxy Blake2b_256) "Blake2b_256"
    , testHashRegressions (Proxy :: Proxy SHA256) "fixtures/sha256.input"
    , testHashRegressions (Proxy :: Proxy MD5) "fixtures/md5.input"
    ]

testHashAlgorithm
  :: forall proxy h. HashAlgorithm h
  => proxy h
  -> String
  -> TestTree
testHashAlgorithm _ n =
  testGroup n
    [ testProperty "hash size" $ prop_hash_correct_sizeHash @h @[Int]
    , testProperty "serialise" $ prop_hash_cbor @h
    , testProperty "ToCBOR size" $ prop_hash_cbor_size @h
    , testProperty "show/fromString" $ prop_hash_show_fromString @h @Float
    , testProperty "NoUnexpectedThunks" $ prop_no_unexpected_thunks @(Hash h Int)
    ]

prop_hash_cbor :: HashAlgorithm h => Hash h Int -> Property
prop_hash_cbor = prop_cbor

prop_hash_cbor_size :: HashAlgorithm h => Hash h Int -> Property
prop_hash_cbor_size = prop_cbor_size

prop_hash_correct_sizeHash
  :: forall h a. HashAlgorithm h
  => Hash h a
  -> Property
prop_hash_correct_sizeHash h =
  SB.length (getHash h) === fromIntegral (sizeHash (Proxy :: Proxy h))

prop_hash_show_fromString :: Hash h a -> Property
prop_hash_show_fromString h = h === fromString (show h)

testHashRegressions
  :: forall h. (HashAlgorithm h)
  => Proxy h
  -> FilePath
  -> TestTree
testHashRegressions p fp =
  testCase ("Hash regressions " <> fp) (test_hash_regressions p fp)

test_hash_regressions
  :: forall h. (HashAlgorithm h)
  => Proxy h
  -> FilePath
  -> Assertion
test_hash_regressions p fixtureFilePath = do
  fixture <- parseFixture <$> BS.readFile fixtureFilePath
  forM_ (zip [1..] fixture) $ \(lineNum :: Int, (m, hm)) -> do
    let h = digest p m
    assertEqual
          ("hash " ++ fixtureFilePath ++ ":" ++ show lineNum)
          (convertToBase Base16 hm :: ByteString)
          (convertToBase Base16 h :: ByteString)
    let forged = BS.pack . forge . BS.unpack $ m
        hf = digest p forged
    assertBool ("forged " ++ fixtureFilePath ++ ":" ++ show lineNum) (hf /= hm)
  where
    forge :: [Word8] -> [Word8]
    forge [] = [fromIntegral $ ord 'x']
    forge xs = init xs ++ [last xs + 1]

    parseFixture input =
      [ ( either error id (convertFromBase Base16 m) :: ByteString
        , either error id (convertFromBase Base16 hm) :: ByteString
        )
      | [m, hm] <-
        map (BS.split (fromIntegral $ ord ':')) (BS.split (fromIntegral $ ord '\n') input)
      ]

--
-- Arbitrary instances
--

instance (ToCBOR a, Arbitrary a, HashAlgorithm h) => Arbitrary (Hash h a) where
  arbitrary = hash <$> arbitrary
  shrink = const []
