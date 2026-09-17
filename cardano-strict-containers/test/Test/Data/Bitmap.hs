{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Property-based tests for 'Bitmap'
module Test.Data.Bitmap (spec) where

import Cardano.Binary (
  decodeFull,
  serialize,
 )
import Data.Bitmap (Bitmap)
import qualified Data.Bitmap as Bitmap
import Data.Bits (setBit)
import qualified Data.ByteString as BS
import qualified Data.Set as Set
import Data.Word (Word16)
import Test.Cardano.StrictContainers.Instances (genBitmap)
import Test.Hspec (Spec, describe, it, shouldBe)
import Test.Hspec.QuickCheck (modifyMaxSuccess, prop)
import Test.QuickCheck (
  Gen,
  Property,
  Testable (..),
  arbitrary,
  choose,
  counterexample,
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
      prop "prop_roundtrip_serialisation" prop_roundtrip_serialisation
      prop "numSetBits agrees with toIndices" $
        forAll genWord16Bitmap $ \bm ->
          Bitmap.numSetBits bm === length (Bitmap.toIndices bm)
      prop "rawDeserialise rejects a bit set above the upper bound" $
        forAll genWord16Bitmap $ \bm ->
          let maxIx = Bitmap.logicalUpperBound bm
              strayBit = fromIntegral (maxIx `rem` 8) + 1
           in (strayBit <= 7) ==>
                Bitmap.rawDeserialise maxIx (withLastBitSet strayBit (Bitmap.rawSerialise bm))
                  === Nothing
      it "rawDeserialise rejects a negative upper bound" $ do
        Bitmap.rawDeserialise (-8 :: Int) "" `shouldBe` Nothing
        Bitmap.rawDeserialise (-3 :: Int) "\x00" `shouldBe` Nothing

-- * Properties

-- | Converting from indices to bitmap and back preserves the indices.
prop_roundtrip_toIndices :: Property
prop_roundtrip_toIndices =
  forAll genMaxIndex $ \maxIndex ->
    forAll genNumIndices $ \numIndices -> do
      forAll (genIndices numIndices maxIndex) $ \indices -> do
        let bitmap = Bitmap.fromIndices maxIndex indices
        let indices' = Bitmap.toIndices bitmap
        Set.fromList indices === Set.fromList indices'

-- | Serialisation roundtrip preserves the bitmap.
prop_roundtrip_serialisation :: Property
prop_roundtrip_serialisation =
  forAll genMaxIndex $ \maxIndex ->
    forAll genNumIndices $ \numIndices -> do
      forAll (genIndices numIndices maxIndex) $ \indices -> do
        let bitmap = Bitmap.fromIndices maxIndex indices
        let encoded = serialize bitmap
        case decodeFull encoded of
          Left err ->
            counterexample ("Deserialization failed: " <> show err) $
              property False
          Right bitmap' ->
            bitmap === bitmap'

-- * Generators

genMaxIndex :: Gen Int
genMaxIndex =
  choose (0, 10000)

genNumIndices :: Gen Int
genNumIndices =
  choose (0, 100)

genIndices :: Int -> Int -> Gen [Int]
genIndices numIndices maxIndex =
  vectorOf numIndices (choose (0, maxIndex))

genWord16Bitmap :: Gen (Bitmap Word16)
genWord16Bitmap = genBitmap arbitrary

withLastBitSet :: Int -> BS.ByteString -> BS.ByteString
withLastBitSet bit bs
  | BS.null bs = bs
  | otherwise = BS.init bs <> BS.singleton (BS.last bs `setBit` bit)
