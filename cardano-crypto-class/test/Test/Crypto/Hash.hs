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
import Test.Crypto.Util (prop_cbor)
import Test.QuickCheck
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.Hash"
    [ testHashAlgorithm (Proxy :: Proxy MD5) "MD5"
    , testHashAlgorithm (Proxy :: Proxy SHA256) "SHA256"
    , testHashAlgorithm (Proxy :: Proxy Blake2b_224) "Blake2b_224"
    , testHashAlgorithm (Proxy :: Proxy Blake2b_256) "Blake2b_256"
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
    , testProperty "show/fromString" $ prop_hash_show_fromString @h @Float
    ]

prop_hash_cbor :: HashAlgorithm h => Hash h Int -> Property
prop_hash_cbor = prop_cbor

prop_hash_correct_sizeHash
  :: forall h a. HashAlgorithm h
  => Hash h a
  -> Property
prop_hash_correct_sizeHash h =
  SB.length (getHash h) === fromIntegral (sizeHash (Proxy :: Proxy h))

prop_hash_show_fromString :: Hash h a -> Property
prop_hash_show_fromString h = h === fromString (show h)


--
-- Arbitrary instances
--

instance (ToCBOR a, Arbitrary a, HashAlgorithm h) => Arbitrary (Hash h a) where
  arbitrary = hash <$> arbitrary
  shrink = const []
