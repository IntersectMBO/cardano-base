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
import Test.QuickCheck.Instances ()
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

import qualified Cardano.Crypto.Libsodium as NaCl

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.Hash"
    [ testHashAlgorithm (Proxy :: Proxy MD5)
    , testHashAlgorithm (Proxy :: Proxy SHA256)
    , testHashAlgorithm (Proxy :: Proxy SHA3_256)
    , testHashAlgorithm (Proxy :: Proxy Blake2b_224)
    , testHashAlgorithm (Proxy :: Proxy Blake2b_256)

    , testSodiumHashAlgorithm (Proxy :: Proxy SHA256)
    , testSodiumHashAlgorithm (Proxy :: Proxy Blake2b_256)
    ]

testHashAlgorithm
  :: forall proxy h. HashAlgorithm h
  => proxy h
  -> TestTree
testHashAlgorithm p =
  testGroup n
    [ testProperty "hash size" $ prop_hash_correct_sizeHash @h @[Int]
    , testProperty "serialise" $ prop_hash_cbor @h
    , testProperty "ToCBOR size" $ prop_hash_cbor_size @h
    , testProperty "show/fromString" $ prop_hash_show_fromString @h @Float
    , testProperty "NoUnexpectedThunks" $ prop_no_unexpected_thunks @(Hash h Int)
    ]
    where n = hashAlgorithmName p

testSodiumHashAlgorithm
  :: forall proxy h. NaCl.SodiumHashAlgorithm h
  => proxy h
  -> TestTree 
testSodiumHashAlgorithm p =
  testGroup n
    [ testProperty "sodium and cryptonite work the same" $ prop_libsodium_model @h Proxy
    ]
    where n = hashAlgorithmName p

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

prop_libsodium_model
  :: forall h. NaCl.SodiumHashAlgorithm h
  => Proxy h -> SB.ByteString -> Property
prop_libsodium_model p bs = ioProperty $ do
  mlfb <- NaCl.digestMLockedBS p bs
  let actual = NaCl.mlfbToByteString mlfb
  return (expected === actual)
  where
    expected = digest p bs
  

--
-- Arbitrary instances
--

instance (ToCBOR a, Arbitrary a, HashAlgorithm h) => Arbitrary (Hash h a) where
  arbitrary = hash <$> arbitrary
  shrink = const []
