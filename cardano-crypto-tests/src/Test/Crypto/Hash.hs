{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.Hash
  ( tests
  )
where

import Cardano.Crypto.Hash
import Data.Bifunctor
import qualified Data.Bits as Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as SBS
import Data.Maybe (fromJust)
import Data.Proxy (Proxy(..))
import Data.String (fromString)
import GHC.TypeLits
import Test.Crypto.Util (prop_cbor, prop_cbor_size, prop_no_thunks)
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
    [testHashAlgorithm (Proxy :: Proxy SHA256)
    , testHashAlgorithm (Proxy :: Proxy SHA3_256)
    , testHashAlgorithm (Proxy :: Proxy Blake2b_224)
    , testHashAlgorithm (Proxy :: Proxy Blake2b_256)
    , testHashAlgorithm (Proxy :: Proxy Keccak256)

    , testSodiumHashAlgorithm (Proxy :: Proxy SHA256)
    , testSodiumHashAlgorithm (Proxy :: Proxy Blake2b_256)

    , testPackedBytes
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

testPackedBytesN :: forall n. KnownNat n => TestHash n -> TestTree
testPackedBytesN h = do
  testGroup
    (hashAlgorithmName (Proxy :: Proxy (TestHash n)))
    [ testProperty "roundtrip" $ prop_roundtrip h
    , testProperty "compare" $ prop_compare h
    , testProperty "xor" $ prop_xor h
    ]

testPackedBytes :: TestTree
testPackedBytes =
  testGroup
    "PackedBytes"
    [ testPackedBytesN (TestHash :: TestHash 0)
    , testPackedBytesN (TestHash :: TestHash 1)
    , testPackedBytesN (TestHash :: TestHash 2)
    , testPackedBytesN (TestHash :: TestHash 3)
    , testPackedBytesN (TestHash :: TestHash 4)
    , testPackedBytesN (TestHash :: TestHash 5)
    , testPackedBytesN (TestHash :: TestHash 6)
    , testPackedBytesN (TestHash :: TestHash 7)
    , testPackedBytesN (TestHash :: TestHash 8)
    , testPackedBytesN (TestHash :: TestHash 9)
    , testPackedBytesN (TestHash :: TestHash 10)
    , testPackedBytesN (TestHash :: TestHash 11)
    , testPackedBytesN (TestHash :: TestHash 12)
    , testPackedBytesN (TestHash :: TestHash 13)
    , testPackedBytesN (TestHash :: TestHash 14)
    , testPackedBytesN (TestHash :: TestHash 15)
    , testPackedBytesN (TestHash :: TestHash 16)
    , testPackedBytesN (TestHash :: TestHash 17)
    , testPackedBytesN (TestHash :: TestHash 18)
    , testPackedBytesN (TestHash :: TestHash 19)
    , testPackedBytesN (TestHash :: TestHash 20)
    , testPackedBytesN (TestHash :: TestHash 21)
    , testPackedBytesN (TestHash :: TestHash 22)
    , testPackedBytesN (TestHash :: TestHash 23)
    , testPackedBytesN (TestHash :: TestHash 24)
    , testPackedBytesN (TestHash :: TestHash 25)
    , testPackedBytesN (TestHash :: TestHash 26)
    , testPackedBytesN (TestHash :: TestHash 27)
    , testPackedBytesN (TestHash :: TestHash 28)
    , testPackedBytesN (TestHash :: TestHash 29)
    , testPackedBytesN (TestHash :: TestHash 30)
    , testPackedBytesN (TestHash :: TestHash 31)
    , testPackedBytesN (TestHash :: TestHash 32)
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
  BS.length (hashToBytes h) === fromIntegral (sizeHash (Proxy :: Proxy h))

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
  => Proxy h -> BS.ByteString -> Property
prop_libsodium_model p bs = expected === actual
  where
    mlsb = NaCl.digestMLockedBS p bs
    actual = NaCl.mlsbToByteString mlsb
    expected = digest p bs


--
-- Arbitrary instances
--

instance HashAlgorithm h => Arbitrary (Hash h a) where
  arbitrary = castHash . hashWith BS.pack <$> vector 16
  shrink = const []

--
-- Test Hash Algorithm
--

data TestHash (n :: Nat) = TestHash

instance KnownNat n => HashAlgorithm (TestHash n) where
  type SizeHash (TestHash n) = n
  hashAlgorithmName px = "TestHash " ++ show (sizeHash px)
  digest px _ = BS.pack (replicate (fromIntegral (sizeHash px)) 0)

prop_roundtrip ::
     forall n. KnownNat n
  => TestHash n
  -> Property
prop_roundtrip h =
  forAll (vectorOf (fromInteger (natVal h)) arbitrary) $ \xs ->
    let sbs = SBS.pack xs
        bs = SBS.fromShort sbs
        sbsHash = hashFromBytesShort sbs :: Maybe (Hash (TestHash n) ())
        bsHash = hashFromBytes bs :: Maybe (Hash (TestHash n) ())
     in fmap hashToBytesShort sbsHash === Just sbs .&&.
        fmap hashToBytes bsHash === Just bs

prop_compare ::
     forall n. KnownNat n
  => TestHash n
  -> Property
prop_compare h =
  let n = fromInteger (natVal h)
      distinct k = splitAt k <$> vectorOf (k * 2) arbitrary
      prefixCount = max 0 (n - 2)
      prefix = replicate prefixCount 0
      similar = bimap (prefix ++) (prefix ++) <$> distinct (n - prefixCount)
   in forAll (frequency [(10, distinct n), (40, similar)]) $ \(xs1, xs2) ->
        let sbs1 = SBS.pack xs1
            sbs2 = SBS.pack xs2
         in compare
              (hashFromBytesShort sbs1 :: Maybe (Hash (TestHash n) ()))
              (hashFromBytesShort sbs2 :: Maybe (Hash (TestHash n) ())) ===
            compare sbs1 sbs2

prop_xor ::
     forall n. KnownNat n
  => TestHash n
  -> Property
prop_xor h =
  let n = fromInteger (natVal h)
   in forAll (bimap BS.pack BS.pack . splitAt n <$> vectorOf (n * 2) arbitrary) $ \(bs1, bs2) ->
        Just (BS.pack (BS.zipWith Bits.xor bs1 bs2)) ===
        (hashToBytes <$>
         (xor <$> (hashFromBytes bs1 :: Maybe (Hash (TestHash n) ()))
              <*> (hashFromBytes bs2 :: Maybe (Hash (TestHash n) ()))))
