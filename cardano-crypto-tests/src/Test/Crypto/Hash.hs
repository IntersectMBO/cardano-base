{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.Hash
  ( tests
  )
where

import Cardano.Crypto.Hash
import qualified Data.ByteString as SB
import Data.Maybe (fromJust)
import Data.Proxy (Proxy (..))
import Test.Crypto.Util (prop_cbor, prop_cbor_size, prop_no_thunks)
import Test.QuickCheck
import Data.String(fromString)
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

    -- TODO The following property is wrong because show and fromString are not inverses of each other
    -- Commenting the following out to fix CI and unblock other unrelated PRs to this project.

    , testProperty "hashFromStringAsHex/hashToStringFromHash" $ prop_hash_hashFromStringAsHex_hashToStringFromHash @h @Float
    , testProperty "hashFromStringAsHex/fromString" $ prop_hash_hashFromStringAsHex_fromString @h @Float
    , testProperty "show/read" $ prop_hash_show_read @h @Float
    , testProperty "NoThunks" $ prop_no_thunks @(Hash h Int)
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
  SB.length (hashToBytes h) === fromIntegral (sizeHash (Proxy :: Proxy h))

prop_hash_show_read
  :: forall h a. HashAlgorithm h
  => Hash h a -> Property
prop_hash_show_read h = read (show h) === h

prop_hash_hashFromStringAsHex_fromString
  :: forall h a. HashAlgorithm h
  => Hash h a -> Property
prop_hash_hashFromStringAsHex_fromString h = let s = hashToStringAsHex h in fromJust (hashFromStringAsHex @h @a s) === fromString s

prop_hash_hashFromStringAsHex_hashToStringFromHash
  :: forall h a. HashAlgorithm h
  => Hash h a -> Property
prop_hash_hashFromStringAsHex_hashToStringFromHash h = fromJust (hashFromStringAsHex @h @a (hashToStringAsHex h)) === h

prop_libsodium_model
  :: forall h. NaCl.SodiumHashAlgorithm h
  => Proxy h -> SB.ByteString -> Property
prop_libsodium_model p bs = expected === actual
  where
    mlsb = NaCl.digestMLockedBS p bs
    actual = NaCl.mlsbToByteString mlsb
    expected = digest p bs
  

--
-- Arbitrary instances
--

instance HashAlgorithm h => Arbitrary (Hash h a) where
  arbitrary = castHash . hashWith SB.pack <$> vector 16
  shrink = const []
