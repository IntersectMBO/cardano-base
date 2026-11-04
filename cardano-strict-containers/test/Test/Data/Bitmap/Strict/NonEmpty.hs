{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Property-based tests for 'Data.Bitmap.Strict.NonEmpty'
module Test.Data.Bitmap.Strict.NonEmpty (spec) where

import Control.Exception (evaluate)
import Data.Bitmap.Strict.NonEmpty (NonEmptyBitmap)
import qualified Data.Bitmap.Strict.NonEmpty as NEBitmap
import Data.Bits (setBit)
import qualified Data.IntSet as IntSet
import qualified Data.IntSet.NonEmpty as NEIntSet
import Data.List.NonEmpty (NonEmpty (..), (<|))
import Data.Primitive.ByteArray (byteArrayFromList, foldrByteArray)
import Data.Word (Word16, Word8)
import Test.Hspec (Spec, anyErrorCall, describe, it, shouldBe, shouldThrow)
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
  describe "NonEmptyBitmap" $
    modifyMaxSuccess (* 100) $ do
      prop "prop_roundtrip_toIndices" prop_roundtrip_toIndices
      prop "prop_mkNonEmptyBitmapAcceptsRawByteArray" prop_mkNonEmptyBitmapAcceptsRawByteArray
      prop "prop_numSetBitsAgreesWithToIndices" prop_numSetBitsAgreesWithToIndices
      prop "prop_toIndicesPrefixIsPrefix" prop_toIndicesPrefixIsPrefix
      prop "prop_fromIndicesRejectsOutOfRange" prop_fromIndicesRejectsOutOfRange
      prop "prop_mkNonEmptyBitmapRejectsPaddingBit" prop_mkNonEmptyBitmapRejectsPaddingBit
      prop "prop_mkNonEmptyBitmapRejectsWrongLength" prop_mkNonEmptyBitmapRejectsWrongLength
      prop "prop_mkNonEmptyBitmapRejectsNoBitSet" prop_mkNonEmptyBitmapRejectsNoBitSet
      it "mkNonEmptyBitmap rejects a non-positive number of bits" $ do
        fmap NEBitmap.bitmapNumBits (mkBitmapMaybe 0 []) `shouldBe` Nothing
        fmap NEBitmap.bitmapNumBits (mkBitmapMaybe (-3) []) `shouldBe` Nothing
      it "toIndicesPrefix rejects a negative or too large number of bits" $ do
        let bm = fromIndicesOrFail 10 (0 :| [2, 9])
        evaluate (IntSet.size (NEBitmap.toIndicesPrefix (-1) bm)) `shouldThrow` anyErrorCall
        evaluate (IntSet.size (NEBitmap.toIndicesPrefix 11 bm)) `shouldThrow` anyErrorCall
      it "serialises MSB-first: index i is bit 7 - (i mod 8) of byte (i div 8)" $ do
        toBytes (fromIndicesOrFail 10 (0 :| [2, 9])) `shouldBe` [0xA0, 0x40]
        toBytes (fromIndicesOrFail 1 (0 :| [])) `shouldBe` [0x80]
        fmap (NEIntSet.toList . NEBitmap.toIndices) (mkBitmapMaybe 10 [0xA0, 0x40])
          `shouldBe` Just (0 :| [2, 9])

-- * Properties

-- | Converting from indices to bitmap and back preserves the indices.
prop_roundtrip_toIndices :: Property
prop_roundtrip_toIndices =
  forAll genNumBits $ \n ->
    forAll (genIndices n) $ \indices ->
      NEIntSet.fromList (fromIntegral @Word16 @Int <$> indices)
        === NEBitmap.toIndices (fromIndicesOrFail n indices)

-- | 'NEBitmap.mkNonEmptyBitmap' accepts the bytes of any bitmap built by
-- 'NEBitmap.fromIndices', and gives back the same bitmap.
prop_mkNonEmptyBitmapAcceptsRawByteArray :: Property
prop_mkNonEmptyBitmapAcceptsRawByteArray =
  forAll genNumBits $ \n ->
    forAll (genIndices n) $ \indices ->
      let bm = fromIndicesOrFail n indices
       in NEBitmap.mkNonEmptyBitmap n (NEBitmap.bitmapRawByteArray bm) === Just bm

-- | 'NEBitmap.numSetBits' agrees with the size of 'NEBitmap.toIndices'.
prop_numSetBitsAgreesWithToIndices :: Property
prop_numSetBitsAgreesWithToIndices =
  forAll genNumBits $ \n ->
    forAll (genIndices n) $ \indices ->
      let bm = fromIndicesOrFail n indices
       in NEBitmap.numSetBits bm === NEIntSet.size (NEBitmap.toIndices bm)

-- | 'NEBitmap.toIndicesPrefix' gives the indices of 'NEBitmap.toIndices' below
-- the requested number of bits.
prop_toIndicesPrefixIsPrefix :: Property
prop_toIndicesPrefixIsPrefix =
  forAll genNumBits $ \n ->
    forAll (genIndices n) $ \indices ->
      forAll (choose (0, n)) $ \k ->
        let bm = fromIndicesOrFail n indices
         in NEBitmap.toIndicesPrefix k bm
              === IntSet.filter (< k) (NEIntSet.toSet (NEBitmap.toIndices bm))

-- | 'NEBitmap.fromIndices' rejects an index that is not below the number of
-- bits.
prop_fromIndicesRejectsOutOfRange :: Property
prop_fromIndicesRejectsOutOfRange =
  forAll genNumBits $ \n ->
    forAll (genIndices n) $ \indices ->
      forAll (choose (n, fromIntegral (maxBound :: Word16))) $ \bad ->
        fmap NEBitmap.bitmapNumBits (NEBitmap.fromIndices @_ @Maybe n (fromIntegral bad <| indices))
          === Nothing

-- | 'NEBitmap.mkNonEmptyBitmap' rejects a bit set beyond the last index.
prop_mkNonEmptyBitmapRejectsPaddingBit :: Property
prop_mkNonEmptyBitmapRejectsPaddingBit =
  forAll genNumBits $ \n ->
    forAll (genIndices n) $ \indices ->
      let strayBit = 6 - (n - 1) `rem` 8
          bytes = toBytes (fromIndicesOrFail n indices)
       in (strayBit >= 0) ==>
            mkBitmapMaybe n (init bytes <> [last bytes `setBit` strayBit]) === Nothing

-- | 'NEBitmap.mkNonEmptyBitmap' rejects a byte array of the wrong length.
prop_mkNonEmptyBitmapRejectsWrongLength :: Property
prop_mkNonEmptyBitmapRejectsWrongLength =
  forAll genNumBits $ \n ->
    forAll (genIndices n) $ \indices ->
      let bytes = toBytes (fromIndicesOrFail n indices)
       in (mkBitmapMaybe n (bytes <> [0x00]), mkBitmapMaybe n (drop 1 bytes))
            === (Nothing, Nothing)

-- | 'NEBitmap.mkNonEmptyBitmap' rejects a byte array with no bit set.
prop_mkNonEmptyBitmapRejectsNoBitSet :: Property
prop_mkNonEmptyBitmapRejectsNoBitSet =
  forAll genNumBits $ \n ->
    mkBitmapMaybe n (replicate ((n + 7) `div` 8) 0x00) === Nothing

-- * Generators

genNumBits :: Gen Int
genNumBits =
  choose (1, 10000)

genIndices :: Int -> Gen (NonEmpty Word16)
genIndices n = do
  numIndices <- choose (0, 100)
  (:|) <$> genIndex <*> vectorOf numIndices genIndex
  where
    genIndex = fromIntegral <$> choose (0, n - 1)

-- * Helpers

fromIndicesOrFail :: Int -> NonEmpty Word16 -> NonEmptyBitmap
fromIndicesOrFail n indices =
  case NEBitmap.fromIndices n indices of
    Just bm -> bm
    Nothing -> error $ "fromIndicesOrFail: indices out of range for " <> show n <> " bits"

mkBitmapMaybe :: Int -> [Word8] -> Maybe NonEmptyBitmap
mkBitmapMaybe n = NEBitmap.mkNonEmptyBitmap n . byteArrayFromList

toBytes :: NonEmptyBitmap -> [Word8]
toBytes = foldrByteArray (:) [] . NEBitmap.bitmapRawByteArray
