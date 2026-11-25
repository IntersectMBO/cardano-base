{-# LANGUAGE DataKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Property-based tests for 'Data.Bitmap'
module Test.Data.Bitmap (spec) where

import Data.Bitmap (Bitmap)
import qualified Data.Bitmap as Bitmap
import Data.Bits (setBit)
import Data.IntSet (IntSet)
import qualified Data.IntSet as IntSet
import Data.Primitive.ByteArray (byteArrayFromList, foldrByteArray)
import Data.Proxy (Proxy (..))
import Data.Word (Word8)
import GHC.TypeNats (KnownNat, SomeNat (..), someNatVal)
import Test.Hspec (Spec, describe, it, shouldBe)
import Test.Hspec.QuickCheck (modifyMaxSuccess, prop)
import Test.QuickCheck (
  Gen,
  Property,
  arbitrary,
  choose,
  forAll,
  property,
  vectorOf,
  (===),
  (==>),
 )

spec :: Spec
spec =
  describe "Bitmap" $
    modifyMaxSuccess (* 100) $ do
      prop "prop_roundtrip_toIndices" prop_roundtrip_toIndices
      prop "prop_fromIndicesIsCanonical" prop_fromIndicesIsCanonical
      prop "prop_numSetBitsAgreesWithToIndices" prop_numSetBitsAgreesWithToIndices
      prop "prop_fromByteArrayDropsTrailingZeroBytes" prop_fromByteArrayDropsTrailingZeroBytes
      prop "prop_fromByteArrayRejectsPastCapacity" prop_fromByteArrayRejectsPastCapacity
      prop "prop_fromByteArrayRejectsStrayBit" prop_fromByteArrayRejectsStrayBit
      prop "prop_roundtrip_fromByteArray" prop_roundtrip_fromByteArray
      it "serialises MSB-first: index i is bit 7 - (i mod 8) of byte (i div 8)" $ do
        toBytes (Bitmap.fromIndices @10 (IntSet.fromList [0, 2, 9])) `shouldBe` [0xA0, 0x40]
        toBytes (Bitmap.fromIndices @1 (IntSet.fromList [0])) `shouldBe` [0x80]
        Bitmap.toIndices <$> Bitmap.fromByteArray @10 (byteArrayFromList [0xA0, 0x40 :: Word8])
          `shouldBe` Just (IntSet.fromList [0, 2, 9])
      it "takes only the bytes its highest index needs, not its capacity" $ do
        toBytes (Bitmap.fromIndices @64 (IntSet.fromList [0, 7])) `shouldBe` [0x81]
        toBytes (Bitmap.fromIndices @64 (IntSet.fromList [])) `shouldBe` []
        toBytes (Bitmap.fromIndices @64 (IntSet.fromList [64])) `shouldBe` []
      it "a capacity of 0 holds only the empty bitmap" $ do
        toBytes (Bitmap.fromIndices @0 (IntSet.fromList [0, 1, 8])) `shouldBe` []
        toBytes <$> Bitmap.fromByteArray @0 (byteArrayFromList ([] :: [Word8])) `shouldBe` Just []
        toBytes <$> Bitmap.fromByteArray @0 (byteArrayFromList [0x00 :: Word8]) `shouldBe` Nothing
        toBytes <$> Bitmap.fromByteArray @0 (byteArrayFromList [0x80 :: Word8]) `shouldBe` Nothing

-- * Properties

-- | Converting from indices to bitmap and back preserves the indices.
prop_roundtrip_toIndices :: Property
prop_roundtrip_toIndices =
  forAllCapacities $ \(Proxy :: Proxy n) n ->
    forAll (genIndices n) $ \indices ->
      indices === Bitmap.toIndices (Bitmap.fromIndices @n indices)

-- | 'Bitmap.fromIndices' produces bytes that 'Bitmap.fromByteArray' accepts.
prop_fromIndicesIsCanonical :: Property
prop_fromIndicesIsCanonical =
  forAllCapacities $ \(Proxy :: Proxy n) n ->
    forAll (genIndices n) $ \indices ->
      let bitmap = Bitmap.fromIndices @n indices
       in Bitmap.fromByteArray @n (Bitmap.toByteArray bitmap) === Just bitmap

-- | 'Bitmap.numSetBits' agrees with the length of 'Bitmap.toIndices'.
prop_numSetBitsAgreesWithToIndices :: Property
prop_numSetBitsAgreesWithToIndices =
  forAllCapacities $ \(Proxy :: Proxy n) n ->
    forAll (genIndices n) $ \indices ->
      let bitmap = Bitmap.fromIndices @n indices
       in Bitmap.numSetBits bitmap === IntSet.size (Bitmap.toIndices bitmap)

-- | Trailing zero bytes up to the capacity are accepted and dropped, so the
-- result equals the bitmap without them.
prop_fromByteArrayDropsTrailingZeroBytes :: Property
prop_fromByteArrayDropsTrailingZeroBytes =
  forAllCapacities $ \(Proxy :: Proxy n) n ->
    forAll (genIndices n) $ \indices ->
      let bitmap = Bitmap.fromIndices @n indices
          bytes = toBytes bitmap
       in forAll (choose (0, numBytes n - length bytes)) $ \zeros ->
            Bitmap.fromByteArray @n (byteArrayFromList (bytes <> replicate zeros 0x00)) === Just bitmap

-- | More bytes than the capacity needs are rejected, whatever they hold.
prop_fromByteArrayRejectsPastCapacity :: Property
prop_fromByteArrayRejectsPastCapacity =
  forAllCapacities $ \(Proxy :: Proxy n) n ->
    Bitmap.fromByteArray @n
      (byteArrayFromList (replicate (numBytes n + 1) (0xff :: Word8)))
      === Nothing

-- | A bit set past the capacity in the last byte is rejected.
prop_fromByteArrayRejectsStrayBit :: Property
prop_fromByteArrayRejectsStrayBit =
  forAllCapacities $ \(Proxy :: Proxy n) n ->
    let strayBit = 6 - (n - 1) `rem` 8
        bytes = replicate (numBytes n - 1) 0x00 <> [0x00 `setBit` strayBit :: Word8]
     in (strayBit >= 0) ==>
          Bitmap.fromByteArray @n (byteArrayFromList bytes) === Nothing

-- | Whatever bytes 'Bitmap.fromByteArray' accepts survive a trip through their
-- indices unchanged.
prop_roundtrip_fromByteArray :: Property
prop_roundtrip_fromByteArray =
  forAllCapacities $ \(Proxy :: Proxy n) n ->
    forAll (choose (0, numBytes n) >>= \size -> vectorOf size arbitrary) $ \bytes ->
      let decoded = Bitmap.fromByteArray @n (byteArrayFromList (bytes :: [Word8]))
       in fmap (Bitmap.fromIndices @n . Bitmap.toIndices) decoded === decoded

-- * Generators

-- | Run a property at a random capacity, both as a type and as a value.
forAllCapacities :: (forall n. KnownNat n => Proxy n -> Int -> Property) -> Property
forAllCapacities k =
  forAll (choose (1, 10000)) $ \n ->
    case someNatVal (fromIntegral n) of
      SomeNat proxy -> property (k proxy n)

genIndices :: Int -> Gen IntSet
genIndices n = do
  numIndices <- choose (0, 100)
  IntSet.fromList <$> vectorOf numIndices (choose (0, n - 1))

-- * Helpers

numBytes :: Int -> Int
numBytes n = (n + 7) `quot` 8

toBytes :: Bitmap n -> [Word8]
toBytes = foldrByteArray (:) [] . Bitmap.toByteArray
