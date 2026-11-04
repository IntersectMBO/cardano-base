{-# LANGUAGE ScopedTypeVariables #-}

-- | Property-based tests for 'Data.Bitmap'
module Test.Data.Bitmap (spec) where

import Data.Bitmap (Bitmap (..))
import qualified Data.Bitmap as Bitmap
import Data.Bits (setBit)
import Data.Primitive.ByteArray (byteArrayFromList, foldrByteArray)
import qualified Data.Set as Set
import Data.Word (Word8)
import Test.Hspec (Spec, describe, it, shouldBe)
import Test.Hspec.QuickCheck (modifyMaxSuccess, prop)
import Test.QuickCheck (
  Gen,
  Property,
  choose,
  forAll,
  vectorOf,
  (===),
  (==>),
 )

spec :: Spec
spec =
  describe "Bitmap" $
    modifyMaxSuccess (* 100) $ do
      prop "prop_roundtrip_toIndices" prop_roundtrip_toIndices
      prop "prop_fromIndicesIsWellFormed" prop_fromIndicesIsWellFormed
      prop "prop_numSetBitsAgreesWithToIndices" prop_numSetBitsAgreesWithToIndices
      prop "prop_wellFormedRejectsStrayBit" prop_wellFormedRejectsStrayBit
      prop "prop_wellFormedRejectsWrongLength" prop_wellFormedRejectsWrongLength
      it "wellFormed rejects a non-positive number of indexes" $ do
        Bitmap.wellFormed 0 (bitmap []) `shouldBe` False
        Bitmap.wellFormed (-3) (bitmap [0x00]) `shouldBe` False
      it "serialises MSB-first: index i is bit 7 - (i mod 8) of byte (i div 8)" $ do
        Bitmap.fromIndices 10 [0, 2, 9] `shouldBe` bitmap [0xA0, 0x40]
        Bitmap.fromIndices 1 [0] `shouldBe` bitmap [0x80]
        Bitmap.toIndices 10 (bitmap [0xA0, 0x40]) `shouldBe` [0, 2, 9]

-- * Properties

-- | Converting from indices to bitmap and back preserves the indices.
prop_roundtrip_toIndices :: Property
prop_roundtrip_toIndices =
  forAll genNumIndexes $ \n ->
    forAll (genIndices n) $ \indices ->
      Set.fromList indices === Set.fromList (Bitmap.toIndices n (Bitmap.fromIndices n indices))

-- | 'Bitmap.fromIndices' produces a well-formed bitmap.
prop_fromIndicesIsWellFormed :: Property
prop_fromIndicesIsWellFormed =
  forAll genNumIndexes $ \n ->
    forAll (genIndices n) $ \indices ->
      Bitmap.wellFormed n (Bitmap.fromIndices n indices) === True

-- | 'Bitmap.numSetBits' agrees with the length of 'Bitmap.toIndices'.
prop_numSetBitsAgreesWithToIndices :: Property
prop_numSetBitsAgreesWithToIndices =
  forAll genNumIndexes $ \n ->
    forAll (genIndices n) $ \indices ->
      let bitmap' = Bitmap.fromIndices n indices
       in Bitmap.numSetBits bitmap' === length (Bitmap.toIndices n bitmap')

-- | 'Bitmap.wellFormed' rejects a bit set beyond the last index.
prop_wellFormedRejectsStrayBit :: Property
prop_wellFormedRejectsStrayBit =
  forAll genNumIndexes $ \n ->
    forAll (genIndices n) $ \indices ->
      let strayBit = 6 - (n - 1) `rem` 8
       in (strayBit >= 0) ==>
            Bitmap.wellFormed n (withLastBitSet strayBit (Bitmap.fromIndices n indices)) === False

-- | 'Bitmap.wellFormed' rejects a bitmap of the wrong length.
prop_wellFormedRejectsWrongLength :: Property
prop_wellFormedRejectsWrongLength =
  forAll genNumIndexes $ \n ->
    forAll (genIndices n) $ \indices ->
      let bytes = toBytes (Bitmap.fromIndices n indices)
       in (Bitmap.wellFormed n (bitmap (bytes <> [0x00])), Bitmap.wellFormed n (bitmap (drop 1 bytes)))
            === (False, False)

-- * Generators

genNumIndexes :: Gen Int
genNumIndexes =
  choose (1, 10000)

genIndices :: Int -> Gen [Int]
genIndices n = do
  numIndices <- choose (0, 100)
  vectorOf numIndices (choose (0, n - 1))

-- * Helpers

bitmap :: [Word8] -> Bitmap
bitmap = Bitmap . byteArrayFromList

toBytes :: Bitmap -> [Word8]
toBytes = foldrByteArray (:) [] . bitmapBytes

withLastBitSet :: Int -> Bitmap -> Bitmap
withLastBitSet bit bm = case reverse (toBytes bm) of
  [] -> bm
  lastByte : rest -> bitmap (reverse (lastByte `setBit` bit : rest))
